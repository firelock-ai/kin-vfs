// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Windows ProjFS (Projected File System) provider.
//!
//! On Windows, we use the built-in Projected File System API (available since
//! Windows 10 1803) rather than syscall interception. ProjFS is ideal because:
//!
//! - Built into Windows, no driver or extension install needed
//! - Works for ALL processes, not just dynamically linked ones
//! - Microsoft uses it for their own "VFS for Git"
//! - Callbacks are synchronous and fast
//!
//! # Architecture
//!
//! 1. Create a "virtualization root" directory (the workspace)
//! 2. Register callbacks via `PrjStartVirtualizing`
//! 3. When any process accesses a file, Windows calls our callbacks:
//!    - Directory enumeration (start/get/end)
//!    - Get placeholder info (file metadata)
//!    - Get file data (content)
//!    - Notifications (write-through, stubbed)
//! 4. Callbacks fetch data from the VFS daemon over a named pipe
//!
//! # Testing
//!
//! This module only compiles on Windows (`#[cfg(target_os = "windows")]`).
//! To test manually on a Windows machine:
//!
//! 1. Enable the Windows Projected File System optional feature:
//!    `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`
//! 2. Ensure the VFS daemon is running with a named pipe listener at
//!    `\\.\pipe\kin-vfs-{workspace-hash}`
//! 3. Run `cargo test -p kin-vfs-shim` on Windows

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, E_INVALIDARG, E_OUTOFMEMORY, S_OK,
};
use windows::Win32::Storage::ProjectedFileSystem::{
    PrjAllocateAlignedBuffer, PrjCommandCallbacksInit, PrjFreeAlignedBuffer,
    PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing,
    PrjWriteFileData, PrjWritePlaceholderInfo,
    PRJ_CALLBACKS, PRJ_CALLBACK_DATA, PRJ_DIR_ENTRY_BUFFER_HANDLE,
    PRJ_FILE_BASIC_INFO, PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    PRJ_NOTIFICATION, PRJ_NOTIFICATION_PARAMETERS,
    PRJ_PLACEHOLDER_INFO, PRJ_STARTVIRTUALIZING_OPTIONS,
    PRJ_NOTIFICATION_FILE_OPENED, PRJ_NOTIFICATION_FILE_OVERWRITTEN,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED,
    PRJ_NOTIFICATION_FILE_RENAMED,
    PrjFillDirEntryBuffer,
};

use kin_vfs_core::{DirEntry, FileType, VirtualStat};

use crate::client;

// ── ProjFS Provider ─────────────────────────────────────────────────────

/// ProjFS virtualization provider. Manages the lifecycle of a single
/// virtualization root and dispatches ProjFS callbacks to the VFS daemon.
pub struct ProjFsProvider {
    /// Unique ID for this virtualization instance (persisted to root dir).
    instance_id: GUID,
    /// Absolute path to the workspace root / virtualization root.
    root_path: PathBuf,
    /// Named pipe path for daemon communication (e.g., `\\.\pipe\kin-vfs-{hash}`).
    pipe_name: String,
    /// ProjFS virtualization context handle; `None` before start / after stop.
    context: Option<PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT>,
    /// Shared state for directory enumeration sessions.
    enum_sessions: Arc<Mutex<HashMap<GUID, EnumSession>>>,
}

/// State for an in-progress directory enumeration.
struct EnumSession {
    /// Entries returned by the daemon for this directory.
    entries: Vec<DirEntry>,
    /// Current index into `entries`.
    index: usize,
    /// Whether the first batch has been sent (used for wildcard reset).
    started: bool,
}

impl ProjFsProvider {
    /// Create a new ProjFS provider.
    ///
    /// `root_path` is the workspace directory that will become the
    /// virtualization root. `pipe_name` is the named pipe the daemon
    /// listens on (e.g., `\\.\pipe\kin-vfs-abc123`).
    pub fn new(root_path: PathBuf, pipe_name: String) -> Self {
        Self {
            instance_id: create_deterministic_guid(&root_path),
            root_path,
            pipe_name,
            context: None,
            enum_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the ProjFS virtualization instance.
    ///
    /// This marks the root directory as a virtualization root and registers
    /// our callbacks with Windows. After this call, any process accessing
    /// files under `root_path` will trigger our callbacks.
    pub fn start(&mut self) -> Result<(), ProjFsError> {
        // Ensure the root directory exists.
        std::fs::create_dir_all(&self.root_path)
            .map_err(|e| ProjFsError::Setup(format!("create root dir: {e}")))?;

        // Mark the root as a ProjFS placeholder.
        let root_wide = to_wide(&self.root_path);
        unsafe {
            PrjMarkDirectoryAsPlaceholder(
                PCWSTR(root_wide.as_ptr()),
                PCWSTR::null(),
                std::ptr::null(),
                &self.instance_id,
            )
            .map_err(|e| ProjFsError::Setup(format!("mark root: {e}")))?;
        }

        // Set up callbacks.
        let callbacks = PRJ_CALLBACKS {
            StartDirectoryEnumerationCallback: Some(start_dir_enum_cb),
            EndDirectoryEnumerationCallback: Some(end_dir_enum_cb),
            GetDirectoryEnumerationCallback: Some(get_dir_enum_cb),
            GetPlaceholderInfoCallback: Some(get_placeholder_info_cb),
            GetFileDataCallback: Some(get_file_data_cb),
            NotificationCallback: Some(notification_cb),
            QueryFileNameCallback: None,
            CancelCommandCallback: None,
        };

        // Pack our state into a raw pointer that ProjFS will pass back in every callback.
        let cb_state = Box::new(CallbackState {
            pipe_name: self.pipe_name.clone(),
            root_path: self.root_path.clone(),
            enum_sessions: Arc::clone(&self.enum_sessions),
        });
        let cb_state_ptr = Box::into_raw(cb_state) as *const std::ffi::c_void;

        let options = PRJ_STARTVIRTUALIZING_OPTIONS {
            // Receive notifications for writes/deletes (for future write-through).
            NotificationMappings: std::ptr::null(),
            NotificationMappingsCount: 0,
            ..Default::default()
        };

        let mut context = PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT::default();
        unsafe {
            PrjStartVirtualizing(
                PCWSTR(root_wide.as_ptr()),
                &callbacks,
                cb_state_ptr,
                Some(&options),
                &mut context,
            )
            .map_err(|e| ProjFsError::Start(format!("PrjStartVirtualizing: {e}")))?;
        }

        self.context = Some(context);
        Ok(())
    }

    /// Stop the ProjFS virtualization instance.
    pub fn stop(&mut self) {
        if let Some(context) = self.context.take() {
            unsafe {
                PrjStopVirtualizing(context);
            }
        }
        // Clean up enum sessions.
        if let Ok(mut sessions) = self.enum_sessions.lock() {
            sessions.clear();
        }
    }

    /// Returns the instance GUID.
    pub fn instance_id(&self) -> &GUID {
        &self.instance_id
    }

    /// Returns the virtualization root path.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }
}

impl Drop for ProjFsProvider {
    fn drop(&mut self) {
        self.stop();
    }
}

// ── Error type ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ProjFsError {
    Setup(String),
    Start(String),
}

impl std::fmt::Display for ProjFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(msg) => write!(f, "ProjFS setup error: {msg}"),
            Self::Start(msg) => write!(f, "ProjFS start error: {msg}"),
        }
    }
}

impl std::error::Error for ProjFsError {}

// ── Callback state ──────────────────────────────────────────────────────

/// State shared across all ProjFS callbacks via the instance context pointer.
struct CallbackState {
    /// Named pipe path for daemon communication.
    pipe_name: String,
    /// Workspace root path.
    root_path: PathBuf,
    /// Active directory enumeration sessions.
    enum_sessions: Arc<Mutex<HashMap<GUID, EnumSession>>>,
}

/// Extract `CallbackState` from the raw pointer passed by ProjFS.
///
/// # Safety
/// The pointer must have been created by `Box::into_raw` in `ProjFsProvider::start`.
unsafe fn get_cb_state(callback_data: *const PRJ_CALLBACK_DATA) -> &'static CallbackState {
    let ptr = (*callback_data).InstanceContext as *const CallbackState;
    &*ptr
}

/// Extract the relative path from callback data as a Rust `String`.
///
/// ProjFS provides paths relative to the virtualization root.
unsafe fn get_relative_path(callback_data: *const PRJ_CALLBACK_DATA) -> Option<String> {
    let file_path_name = (*callback_data).FilePathName;
    if file_path_name.is_null() {
        return Some(String::new()); // Root directory
    }
    let wide = file_path_name;
    let len = (0..).take_while(|&i| *wide.0.add(i) != 0).count();
    let slice = std::slice::from_raw_parts(wide.0, len);
    String::from_utf16(slice).ok()
}

/// Convert a relative ProjFS path to the full workspace-relative path
/// suitable for daemon requests. ProjFS uses backslashes; the daemon uses
/// forward slashes.
fn to_daemon_path(root: &Path, relative: &str) -> String {
    if relative.is_empty() {
        return root.to_string_lossy().replace('\\', "/");
    }
    let full = root.join(relative);
    full.to_string_lossy().replace('\\', "/")
}

// ── ProjFS Callbacks ────────────────────────────────────────────────────

/// `PRJ_START_DIRECTORY_ENUMERATION_CB` — called when a process begins
/// enumerating (listing) a directory.
unsafe extern "system" fn start_dir_enum_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let state = get_cb_state(callback_data);
    let enum_id = *enumeration_id;

    let relative = match get_relative_path(callback_data) {
        Some(p) => p,
        None => return E_INVALIDARG,
    };

    let daemon_path = to_daemon_path(&state.root_path, &relative);

    // Fetch directory entries from the daemon.
    let entries = match client::client_read_dir_named_pipe(&state.pipe_name, &daemon_path) {
        Some(e) => e,
        None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    // Store the enumeration session.
    if let Ok(mut sessions) = state.enum_sessions.lock() {
        sessions.insert(
            enum_id,
            EnumSession {
                entries,
                index: 0,
                started: false,
            },
        );
    }

    S_OK
}

/// `PRJ_END_DIRECTORY_ENUMERATION_CB` — called when enumeration is complete.
unsafe extern "system" fn end_dir_enum_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let state = get_cb_state(callback_data);
    let enum_id = *enumeration_id;

    if let Ok(mut sessions) = state.enum_sessions.lock() {
        sessions.remove(&enum_id);
    }

    S_OK
}

/// `PRJ_GET_DIRECTORY_ENUMERATION_CB` — called to get the next batch of
/// directory entries.
unsafe extern "system" fn get_dir_enum_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
    _search_expression: PCWSTR,
    dir_entry_buffer_handle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> HRESULT {
    let state = get_cb_state(callback_data);
    let enum_id = *enumeration_id;

    let mut sessions = match state.enum_sessions.lock() {
        Ok(s) => s,
        Err(_) => return E_OUTOFMEMORY,
    };

    let session = match sessions.get_mut(&enum_id) {
        Some(s) => s,
        None => return E_INVALIDARG,
    };

    // If restarting enumeration, reset index.
    if (*callback_data).Flags & 0x1 != 0 {
        // PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN = 0x1
        session.index = 0;
    }

    if session.index >= session.entries.len() {
        // No more entries — return S_OK with nothing added to signal end.
        return S_OK;
    }

    // Fill entries into the ProjFS buffer.
    while session.index < session.entries.len() {
        let entry = &session.entries[session.index];
        let name_wide = to_wide_str(&entry.name);

        let basic_info = PRJ_FILE_BASIC_INFO {
            IsDirectory: entry.file_type == FileType::Directory,
            FileSize: 0, // Size is filled in when placeholder info is requested.
            ..Default::default()
        };

        let hr = PrjFillDirEntryBuffer(
            PCWSTR(name_wide.as_ptr()),
            Some(&basic_info),
            dir_entry_buffer_handle,
        );

        if hr == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
            // Buffer full — ProjFS will call us again for more entries.
            break;
        }

        if hr.is_err() {
            return hr;
        }

        session.index += 1;
    }

    session.started = true;
    S_OK
}

/// `PRJ_GET_PLACEHOLDER_INFO_CB` — called when Windows needs file metadata.
unsafe extern "system" fn get_placeholder_info_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
) -> HRESULT {
    let state = get_cb_state(callback_data);

    let relative = match get_relative_path(callback_data) {
        Some(p) => p,
        None => return E_INVALIDARG,
    };

    let daemon_path = to_daemon_path(&state.root_path, &relative);

    // Stat the file via the daemon.
    let vstat = match client::client_stat_named_pipe(&state.pipe_name, &daemon_path) {
        Some(s) => s,
        None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    // Build the placeholder info struct.
    let placeholder = build_placeholder_info(&vstat);
    let context = (*callback_data).NamespaceVirtualizationContext;

    let relative_wide = to_wide_str(&relative);

    PrjWritePlaceholderInfo(
        context,
        PCWSTR(relative_wide.as_ptr()),
        &placeholder as *const PRJ_PLACEHOLDER_INFO,
        std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
    )
}

/// `PRJ_GET_FILE_DATA_CB` — called when a process reads file content.
unsafe extern "system" fn get_file_data_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> HRESULT {
    let state = get_cb_state(callback_data);

    let relative = match get_relative_path(callback_data) {
        Some(p) => p,
        None => return E_INVALIDARG,
    };

    let daemon_path = to_daemon_path(&state.root_path, &relative);
    let context = (*callback_data).NamespaceVirtualizationContext;
    let data_stream_id = (*callback_data).DataStreamId;

    // Read the requested range from the daemon.
    let data = if byte_offset == 0 && length == 0 {
        // Full file read.
        match client::client_read_file_named_pipe(&state.pipe_name, &daemon_path) {
            Some(d) => d,
            None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
        }
    } else {
        match client::client_read_range_named_pipe(
            &state.pipe_name,
            &daemon_path,
            byte_offset,
            length as u64,
        ) {
            Some(d) => d,
            None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
        }
    };

    if data.is_empty() {
        return S_OK;
    }

    // ProjFS requires aligned buffers for writing file data.
    let aligned_buf = PrjAllocateAlignedBuffer(context, data.len());
    if aligned_buf.is_null() {
        return E_OUTOFMEMORY;
    }

    std::ptr::copy_nonoverlapping(data.as_ptr(), aligned_buf as *mut u8, data.len());

    let hr = PrjWriteFileData(
        context,
        &data_stream_id,
        aligned_buf,
        byte_offset,
        data.len() as u32,
    );

    PrjFreeAlignedBuffer(aligned_buf);

    hr
}

/// `PRJ_NOTIFICATION_CB` — called on file modifications/deletions.
///
/// Currently stubbed. In the future, this can be used to implement
/// write-through semantics (notifying the daemon when a user modifies
/// a materialized file).
unsafe extern "system" fn notification_cb(
    _callback_data: *const PRJ_CALLBACK_DATA,
    _is_directory: bool,
    _notification: PRJ_NOTIFICATION,
    _destination_file_name: PCWSTR,
    _operation_parameters: *mut PRJ_NOTIFICATION_PARAMETERS,
) -> HRESULT {
    // Stub: acknowledge all notifications without action.
    // Future: detect PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED
    // and notify the daemon of local writes for conflict resolution.
    S_OK
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build a `PRJ_PLACEHOLDER_INFO` from a `VirtualStat`.
fn build_placeholder_info(vstat: &VirtualStat) -> PRJ_PLACEHOLDER_INFO {
    let mut info: PRJ_PLACEHOLDER_INFO = unsafe { std::mem::zeroed() };

    info.FileBasicInfo.IsDirectory = vstat.is_dir;
    info.FileBasicInfo.FileSize = vstat.size as i64;

    // Convert epoch seconds to Windows FILETIME (100-nanosecond intervals
    // since 1601-01-01). Offset: 11644473600 seconds.
    let windows_ticks = epoch_to_filetime(vstat.mtime);
    info.FileBasicInfo.CreationTime = windows_ticks as i64;
    info.FileBasicInfo.LastAccessTime = windows_ticks as i64;
    info.FileBasicInfo.LastWriteTime = windows_ticks as i64;
    info.FileBasicInfo.ChangeTime = windows_ticks as i64;

    // File attributes.
    if vstat.is_dir {
        info.FileBasicInfo.FileAttributes = 0x10; // FILE_ATTRIBUTE_DIRECTORY
    } else {
        info.FileBasicInfo.FileAttributes = 0x80; // FILE_ATTRIBUTE_NORMAL
    }

    info
}

/// Convert Unix epoch seconds to Windows FILETIME ticks.
///
/// Windows FILETIME counts 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
/// Unix epoch is 1970-01-01 00:00:00 UTC. The difference is 11,644,473,600 seconds.
fn epoch_to_filetime(epoch_secs: u64) -> u64 {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;
    (epoch_secs + EPOCH_DIFF) * TICKS_PER_SEC
}

/// Create a deterministic GUID from a workspace path. This ensures the same
/// workspace always gets the same instance ID, which is important for ProjFS
/// to recognize the virtualization root across restarts.
fn create_deterministic_guid(path: &Path) -> GUID {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    let hash = hasher.finish();

    // Spread the 64-bit hash across the GUID fields.
    let bytes = hash.to_le_bytes();
    GUID {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        // Fill data4 with a repeated pattern from the hash.
        data4: [
            bytes[0] ^ bytes[7],
            bytes[1] ^ bytes[6],
            bytes[2] ^ bytes[5],
            bytes[3] ^ bytes[4],
            bytes[4] ^ bytes[3],
            bytes[5] ^ bytes[2],
            bytes[6] ^ bytes[1],
            bytes[7] ^ bytes[0],
        ],
    }
}

/// Convert a `Path` to a null-terminated wide string (UTF-16).
fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert a `&str` to a null-terminated wide string (UTF-16).
fn to_wide_str(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ── Unit tests (Windows-only) ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_guid_is_stable() {
        let path = PathBuf::from(r"C:\Users\test\workspace");
        let guid1 = create_deterministic_guid(&path);
        let guid2 = create_deterministic_guid(&path);
        assert_eq!(guid1, guid2);
    }

    #[test]
    fn deterministic_guid_differs_for_different_paths() {
        let path1 = PathBuf::from(r"C:\Users\test\workspace1");
        let path2 = PathBuf::from(r"C:\Users\test\workspace2");
        let guid1 = create_deterministic_guid(&path1);
        let guid2 = create_deterministic_guid(&path2);
        assert_ne!(guid1, guid2);
    }

    #[test]
    fn epoch_to_filetime_known_value() {
        // 2024-01-01 00:00:00 UTC = 1704067200 epoch
        // Expected FILETIME: (1704067200 + 11644473600) * 10_000_000
        let ft = epoch_to_filetime(1704067200);
        assert_eq!(ft, (1704067200u64 + 11_644_473_600) * 10_000_000);
    }

    #[test]
    fn to_daemon_path_with_backslashes() {
        let root = PathBuf::from(r"C:\workspace");
        let result = to_daemon_path(&root, r"src\main.rs");
        assert!(result.contains("src/main.rs"));
        assert!(!result.contains('\\'));
    }

    #[test]
    fn to_daemon_path_empty_relative() {
        let root = PathBuf::from(r"C:\workspace");
        let result = to_daemon_path(&root, "");
        assert_eq!(result, "C:/workspace");
    }

    #[test]
    fn to_wide_str_roundtrip() {
        let s = "hello.txt";
        let wide = to_wide_str(s);
        // Last element is null terminator.
        assert_eq!(*wide.last().unwrap(), 0);
        // Decode back (without null terminator).
        let decoded = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(decoded, s);
    }
}
