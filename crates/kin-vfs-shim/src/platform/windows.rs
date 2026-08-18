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
//!    - Notifications, which carry write-through to graph authority
//! 4. Callbacks fetch data from the VFS daemon over a named pipe
//!
//! # Live proof
//!
//! Compiling is not projecting. The `live_proof` module at the bottom of this
//! file stands up a real daemon on a named pipe, virtualizes a real directory,
//! and reads and writes it from a separate PowerShell process, so the evidence
//! for this provider is a live filesystem rather than a green build. It runs in
//! the `ProjFS live proof (windows-latest)` CI job, which is the only machine in
//! the fleet where ProjFS exists.
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
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    FreeLibrary, BOOLEAN, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_NAME,
    E_INVALIDARG, E_OUTOFMEMORY, S_OK,
};
use windows::Win32::Storage::ProjectedFileSystem::{
    PrjAllocateAlignedBuffer, PrjFillDirEntryBuffer, PrjFreeAlignedBuffer,
    PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing, PrjWriteFileData,
    PrjWritePlaceholderInfo, PRJ_CALLBACKS, PRJ_CALLBACK_DATA, PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN,
    PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO, PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    PRJ_NOTIFICATION, PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED, PRJ_NOTIFICATION_FILE_OVERWRITTEN,
    PRJ_NOTIFICATION_FILE_RENAMED, PRJ_NOTIFICATION_MAPPING, PRJ_NOTIFICATION_NEW_FILE_CREATED,
    PRJ_NOTIFICATION_PARAMETERS, PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED,
    PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED, PRJ_NOTIFY_FILE_OVERWRITTEN,
    PRJ_NOTIFY_FILE_RENAMED, PRJ_NOTIFY_NEW_FILE_CREATED, PRJ_NOTIFY_TYPES, PRJ_PLACEHOLDER_INFO,
    PRJ_STARTVIRTUALIZING_OPTIONS,
};
use windows::Win32::System::LibraryLoader::LoadLibraryW;

use kin_vfs_core::{DirEntry, FileType, VirtualStat};

use crate::client;

/// The notifications `notification_cb` acts on, as one explicit mapping over the
/// whole virtualization root.
///
/// Every notification the callback handles has to be named here. ProjFS's
/// documented default when a provider supplies no mapping is FILE_OPENED,
/// NEW_FILE_CREATED and FILE_OVERWRITTEN, which excludes the close-after-modify
/// that an ordinary editor save produces, the close-after-delete, and the
/// rename. A handler for a notification that is never delivered is not
/// write-through.
const WRITE_THROUGH_NOTIFY_MASK: PRJ_NOTIFY_TYPES = PRJ_NOTIFY_TYPES(
    PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED.0
        | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED.0
        | PRJ_NOTIFY_FILE_OVERWRITTEN.0
        | PRJ_NOTIFY_FILE_RENAMED.0
        | PRJ_NOTIFY_NEW_FILE_CREATED.0,
);

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
    ///
    /// Returns `ProjFsError::Unavailable` if ProjFS is not present on this
    /// system (Windows < 10 1803 or the optional feature is not enabled).
    pub fn start(&mut self) -> Result<(), ProjFsError> {
        // Verify ProjFS is available before attempting any ProjFS API calls.
        check_projfs_available()?;

        // Ensure the root directory exists.
        std::fs::create_dir_all(&self.root_path)
            .map_err(|e| ProjFsError::Setup(format!("create root dir: {e}")))?;

        // Mark the root as a ProjFS placeholder.
        let root_wide = to_wide(&self.root_path);
        unsafe {
            PrjMarkDirectoryAsPlaceholder(
                PCWSTR(root_wide.as_ptr()),
                PCWSTR::null(),
                None,
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
            enum_sessions: Arc::clone(&self.enum_sessions),
        });
        let cb_state_ptr = Box::into_raw(cb_state) as *const std::ffi::c_void;

        // Name the notifications this provider acts on. ProjFS sends only
        // FILE_OPENED, NEW_FILE_CREATED and FILE_OVERWRITTEN when a provider
        // supplies no mapping, so under the default the ordinary edit (open,
        // write, close) never reaches `notification_cb` and write-through
        // silently does nothing while the handler code reads as if it works.
        // The empty string is the virtualization root, and the mapping covers
        // its descendants.
        let notification_root = to_wide_str("");
        let mut notification_mappings = [PRJ_NOTIFICATION_MAPPING {
            NotificationBitMask: WRITE_THROUGH_NOTIFY_MASK,
            NotificationRoot: PCWSTR(notification_root.as_ptr()),
        }];

        let options = PRJ_STARTVIRTUALIZING_OPTIONS {
            NotificationMappings: notification_mappings.as_mut_ptr(),
            NotificationMappingsCount: notification_mappings.len() as u32,
            ..Default::default()
        };

        let context = unsafe {
            PrjStartVirtualizing(
                PCWSTR(root_wide.as_ptr()),
                &callbacks,
                Some(cb_state_ptr),
                Some(&options),
            )
            .map_err(|e| ProjFsError::Start(format!("PrjStartVirtualizing: {e}")))?
        };

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
    /// ProjFS is not available on this system (Windows < 10 1803, or the
    /// optional feature is not enabled).
    Unavailable(String),
    Setup(String),
    Start(String),
}

impl std::fmt::Display for ProjFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "ProjFS unavailable: {msg}"),
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

/// Convert the relative path supplied by ProjFS into Kin's repo-relative graph
/// key. ProjFS uses backslashes; the VFS protocol uses forward slashes and must
/// never receive the absolute virtualization-root path.
fn to_daemon_path(
    relative: &str,
) -> Result<kin_vfs_core::VfsPath, kin_vfs_core::pathmap::WorkspacePathError> {
    use kin_vfs_core::pathmap::{workspace_graph_key, WorkspacePathError};

    let normalized = relative.replace('\\', "/");
    if normalized.starts_with('/') || normalized.contains(':') {
        return Err(WorkspacePathError::OutsideRoot);
    }

    const SYNTHETIC_ROOT: &[u8] = b"C:/__kin_vfs_projfs_root";
    let mut absolute = SYNTHETIC_ROOT.to_vec();
    absolute.push(b'/');
    absolute.extend_from_slice(normalized.as_bytes());
    workspace_graph_key(&absolute, SYNTHETIC_ROOT)
}

/// Read a graph entry name as text for the Windows APIs that require it.
///
/// Windows has no byte-path API: a graph-owned name that is not valid UTF-8
/// cannot be represented here. Rather than coerce it (which would project a
/// **different** name than the graph holds and let a tool read or overwrite the
/// wrong artifact), this returns `None` and the caller fails the operation
/// loudly. Such a repository is unsupported on Windows, not silently mangled.
fn graph_name_as_str(name: &[u8]) -> Option<&str> {
    std::str::from_utf8(name).ok()
}

/// Collapse a `windows` API `Result<()>` into the `HRESULT` that ProjFS
/// callbacks must return: `S_OK` on success, the failure `HRESULT` otherwise.
fn result_to_hresult(result: windows::core::Result<()>) -> HRESULT {
    match result {
        Ok(()) => S_OK,
        Err(err) => err.code(),
    }
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

    let daemon_path = match to_daemon_path(&relative) {
        Ok(path) => path,
        Err(_) => return E_INVALIDARG,
    };

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
    if (*callback_data).Flags.0 & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN.0 != 0 {
        session.index = 0;
    }

    if session.index >= session.entries.len() {
        // No more entries — return S_OK with nothing added to signal end.
        return S_OK;
    }

    // The directory being enumerated, needed to address each child against
    // graph authority.
    let dir_relative = match get_relative_path(callback_data) {
        Some(path) => path,
        None => return E_INVALIDARG,
    };

    // Fill entries into the ProjFS buffer.
    //
    // The metadata supplied here is what a caller's directory listing reports,
    // so every field has to come from graph authority. Filling zeros would make
    // every projected file list as zero bytes last written in 1601, which is a
    // wrong answer a build tool acts on rather than an error it reports.
    // `DirEntry` carries only a name and a type, so each child is stat'ed.
    while session.index < session.entries.len() {
        let entry = &session.entries[session.index];
        // A graph name that cannot be represented on Windows is refused, never
        // coerced into a different name.
        let Some(name_text) = graph_name_as_str(entry.name.as_bytes()).map(str::to_owned) else {
            return HRESULT::from_win32(ERROR_INVALID_NAME.0);
        };
        let is_gitlink = matches!(entry.file_type, FileType::Gitlink);

        let basic_info = if is_gitlink {
            // A gitlink is a repository boundary: per-path operations on it
            // fail by design, so stat'ing one would fail the whole listing.
            // Carry it as the directory-shaped placeholder the listing needs.
            PRJ_FILE_BASIC_INFO {
                IsDirectory: true.into(),
                FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
                ..Default::default()
            }
        } else {
            let child_relative = if dir_relative.is_empty() {
                name_text.clone()
            } else {
                format!("{dir_relative}\\{name_text}")
            };
            let child_key = match to_daemon_path(&child_relative) {
                Ok(key) => key,
                Err(_) => return E_INVALIDARG,
            };
            match client::client_stat_named_pipe(&state.pipe_name, &child_key) {
                Some(vstat) => basic_info_from_stat(&vstat),
                None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
            }
        };

        let name_wide = to_wide_str(&name_text);
        let fill_result = PrjFillDirEntryBuffer(
            PCWSTR(name_wide.as_ptr()),
            Some(&basic_info),
            dir_entry_buffer_handle,
        );

        if let Err(err) = fill_result {
            if err.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
                // Buffer full — ProjFS will call us again for more entries.
                break;
            }
            return err.code();
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

    let daemon_path = match to_daemon_path(&relative) {
        Ok(path) => path,
        Err(_) => return E_INVALIDARG,
    };

    // Stat the file via the daemon.
    let vstat = match client::client_stat_named_pipe(&state.pipe_name, &daemon_path) {
        Some(s) => s,
        None => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    // Build the placeholder info struct.
    let placeholder = build_placeholder_info(&vstat);
    let context = (*callback_data).NamespaceVirtualizationContext;

    let relative_wide = to_wide_str(&relative);

    result_to_hresult(PrjWritePlaceholderInfo(
        context,
        PCWSTR(relative_wide.as_ptr()),
        &placeholder as *const PRJ_PLACEHOLDER_INFO,
        std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
    ))
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

    let daemon_path = match to_daemon_path(&relative) {
        Ok(path) => path,
        Err(_) => return E_INVALIDARG,
    };
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

    let write_result = PrjWriteFileData(
        context,
        &data_stream_id,
        aligned_buf,
        byte_offset,
        data.len() as u32,
    );

    PrjFreeAlignedBuffer(aligned_buf);

    result_to_hresult(write_result)
}

/// `PRJ_NOTIFICATION_CB` — called on file modifications/deletions.
///
/// Detects creation, modification, overwrite, delete, and rename notifications
/// from ProjFS and forwards the affected graph key to the kin daemon's
/// `/vfs/write-notify` endpoint through the shim's fire-and-forget notification
/// channel, which is the same seam the Unix interception path uses. That POST
/// is what makes a write through the projected root converge into graph truth
/// rather than living only on disk.
///
/// Delivery is not automatic: only the notifications named in
/// [`WRITE_THROUGH_NOTIFY_MASK`] reach this callback at all.
unsafe extern "system" fn notification_cb(
    callback_data: *const PRJ_CALLBACK_DATA,
    _is_directory: BOOLEAN,
    notification: PRJ_NOTIFICATION,
    destination_file_name: PCWSTR,
    _operation_parameters: *mut PRJ_NOTIFICATION_PARAMETERS,
) -> HRESULT {
    // Only process notifications that indicate a file was changed on disk.
    // This set and `WRITE_THROUGH_NOTIFY_MASK` have to stay in step: a
    // notification named here but absent from the mask is never delivered, and
    // one in the mask but not here is delivered and dropped.
    let dominated = notification == PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED
        || notification == PRJ_NOTIFICATION_FILE_OVERWRITTEN
        || notification == PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED
        || notification == PRJ_NOTIFICATION_NEW_FILE_CREATED
        || notification == PRJ_NOTIFICATION_FILE_RENAMED;

    if !dominated {
        return S_OK;
    }

    // Determine the affected path.
    let relative =
        if notification == PRJ_NOTIFICATION_FILE_RENAMED && !destination_file_name.is_null() {
            // For renames, the destination is the new name. Notify both old and new.
            if let Some(old_path) = get_relative_path(callback_data) {
                if let Ok(old_key) = to_daemon_path(&old_path) {
                    client::notify_file_changed(&old_key);
                }
            }
            // Decode the destination file name (new path after rename).
            let len = (0..)
                .take_while(|&i| *destination_file_name.0.add(i) != 0)
                .count();
            let slice = std::slice::from_raw_parts(destination_file_name.0, len);
            String::from_utf16(slice).ok()
        } else {
            get_relative_path(callback_data)
        };

    if let Some(rel) = relative {
        if let Ok(graph_key) = to_daemon_path(&rel) {
            client::notify_file_changed(&graph_key);
        }
    }

    S_OK
}

// ── ProjFS availability check ───────────────────────────────────────────

/// Check whether ProjFS is available on this system by probing for the
/// `projectedfslib.dll` library. ProjFS requires Windows 10 version 1803+
/// AND the "Windows Projected File System" optional feature to be enabled.
///
/// Returns `Ok(())` if available, or `Err(ProjFsError::Unavailable)` with
/// an actionable message explaining how to enable it.
fn check_projfs_available() -> Result<(), ProjFsError> {
    let dll_name = to_wide_str("projectedfslib.dll");
    let handle = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) };

    match handle {
        Ok(h) => {
            // DLL loaded successfully — ProjFS is available. Free the handle
            // since we only needed to probe; actual calls go through the
            // `windows` crate's static bindings.
            unsafe {
                let _ = FreeLibrary(h);
            }
            Ok(())
        }
        Err(_) => Err(ProjFsError::Unavailable(
            "Windows Projected File System (ProjFS) is not available. \
             ProjFS requires Windows 10 version 1803 or later with the optional \
             feature enabled. To enable it, run as Administrator:\n  \
             Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart\n\
             Or enable it via Settings > Apps > Optional Features > \
             \"Windows Projected File System\"."
                .to_string(),
        )),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

/// Render a graph-owned stat as the metadata block ProjFS reports.
///
/// One builder for both the enumeration path and the placeholder path, so a
/// listing and an open cannot describe the same artifact differently.
fn basic_info_from_stat(vstat: &VirtualStat) -> PRJ_FILE_BASIC_INFO {
    // Convert epoch seconds to Windows FILETIME (100-nanosecond intervals
    // since 1601-01-01). Offset: 11644473600 seconds.
    let windows_ticks = epoch_to_filetime(vstat.mtime) as i64;

    PRJ_FILE_BASIC_INFO {
        IsDirectory: vstat.is_dir.into(),
        FileSize: vstat.size as i64,
        CreationTime: windows_ticks,
        LastAccessTime: windows_ticks,
        LastWriteTime: windows_ticks,
        ChangeTime: windows_ticks,
        FileAttributes: if vstat.is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        },
    }
}

/// Build a `PRJ_PLACEHOLDER_INFO` from a `VirtualStat`.
fn build_placeholder_info(vstat: &VirtualStat) -> PRJ_PLACEHOLDER_INFO {
    let mut info: PRJ_PLACEHOLDER_INFO = unsafe { std::mem::zeroed() };
    info.FileBasicInfo = basic_info_from_stat(vstat);
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
        assert_eq!(
            to_daemon_path(r"src\main.rs").unwrap().as_bytes(),
            b"src/main.rs".as_slice()
        );
    }

    #[test]
    fn to_daemon_path_empty_relative() {
        assert!(to_daemon_path("").unwrap().is_root());
    }

    #[test]
    fn to_daemon_path_never_serializes_the_windows_workspace_root() {
        let key = to_daemon_path(r"nested\file.rs").unwrap();
        assert_eq!(key.as_bytes(), b"nested/file.rs".as_slice());
        assert!(!key.as_bytes().windows(3).any(|window| window == b"C:/"));
        assert!(!key.as_bytes().starts_with(b"/"));
    }

    #[test]
    fn to_daemon_path_rejects_absolute_and_traversal_paths() {
        use kin_vfs_core::pathmap::WorkspacePathError;

        assert_eq!(
            to_daemon_path(r"C:\outside\file.rs"),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            to_daemon_path(r"\outside\file.rs"),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            to_daemon_path(r"src\..\secret.rs"),
            Err(WorkspacePathError::ParentTraversal)
        );
    }

    #[test]
    fn notification_key_carries_no_host_root() {
        // The notification sends these exact graph-key bytes. There is no
        // second host-path rendering that could disagree with the key, and no
        // component of the Windows root may survive into it.
        let key = to_daemon_path(r"src\main.rs").unwrap();
        assert_eq!(key.as_bytes(), b"src/main.rs".as_slice());
        assert!(!key.as_bytes().windows(2).any(|window| window == b"C:"));
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

    #[test]
    fn projfs_unavailable_error_is_actionable() {
        // Verify the Unavailable error message contains remediation instructions.
        let err = ProjFsError::Unavailable("test".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("ProjFS unavailable"));

        // Verify Display for all variants doesn't panic.
        let _ = format!("{}", ProjFsError::Setup("s".into()));
        let _ = format!("{}", ProjFsError::Start("s".into()));
    }

    #[test]
    fn check_projfs_available_returns_result() {
        // On a Windows machine with ProjFS enabled, this returns Ok.
        // On machines without ProjFS, this returns Err(Unavailable).
        // Either way, it must not panic.
        let result = check_projfs_available();
        match &result {
            Ok(()) => {
                // ProjFS is available — great.
            }
            Err(ProjFsError::Unavailable(msg)) => {
                // Expected on systems without ProjFS.
                assert!(msg.contains("Enable-WindowsOptionalFeature"));
                assert!(msg.contains("Client-ProjFS"));
            }
            Err(other) => {
                panic!("unexpected error variant: {other}");
            }
        }
    }
}

// ── Live proof (Windows, ProjFS-enabled machines only) ──────────────────

/// A real ProjFS projection, exercised by a separate process.
///
/// Everything else in this file is checkable by a compiler. None of it answers
/// the only question that matters for a filesystem: does an ordinary Windows
/// program that knows nothing about Kin read graph-owned bytes when it opens a
/// path under the virtualization root, and does writing there reach graph
/// authority. This module answers both against a live filesystem.
///
/// It stands up the real `kin-vfs-daemon` on a real named pipe, enters through
/// the shipping entry point `shim_init_windows`, and then shells out to
/// PowerShell so the reader and writer are a different process with no shim
/// loaded and no shared memory with the provider.
///
/// `KIN_VFS_PROJFS_LIVE=1` makes an unavailable ProjFS a failure instead of a
/// skip. Without it the test skips on machines that have no ProjFS, which is
/// every machine in this fleet except the CI runner; with it, the CI job cannot
/// pass by quietly proving nothing.
#[cfg(test)]
mod live_proof {
    use super::*;

    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use kin_vfs_core::{ContentProvider, VfsError, VfsPath, VfsResult};
    use kin_vfs_daemon::VfsDaemonServer;

    /// Fixture mtime: 2024-01-01T00:00:00Z. A listing that reports this date
    /// proves the timestamp came from graph authority, because ProjFS's own
    /// zero-filled default renders as 1601-01-01.
    const FIXTURE_MTIME: u64 = 1_704_067_200;
    const HELLO_BODY: &[u8] = b"graph-owned bytes, not disk bytes\n";
    const NESTED_BODY: &[u8] = b"pub fn projected() -> u32 { 7 }\n";
    const EDITED_BODY: &str = "edited through the projected root";

    /// An in-memory graph stand-in. The daemon speaks the real wire protocol to
    /// the real callbacks; only the bytes behind it are a fixture.
    struct FixtureProvider {
        files: BTreeMap<&'static str, &'static [u8]>,
    }

    impl FixtureProvider {
        fn new() -> Self {
            let mut files = BTreeMap::new();
            files.insert("hello.txt", HELLO_BODY);
            files.insert("src/lib.rs", NESTED_BODY);
            Self { files }
        }

        fn key(path: &VfsPath) -> String {
            String::from_utf8_lossy(path.as_bytes()).into_owned()
        }

        fn is_dir(&self, key: &str) -> bool {
            key.is_empty() || self.files.keys().any(|f| f.starts_with(&format!("{key}/")))
        }
    }

    impl ContentProvider for FixtureProvider {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            let key = Self::key(path);
            self.files
                .get(key.as_str())
                .map(|bytes| bytes.to_vec())
                .ok_or(VfsError::NotFound { path: key })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let bytes = self.read_file(path)?;
            let start = (offset as usize).min(bytes.len());
            let end = start.saturating_add(len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            let key = Self::key(path);
            if let Some(bytes) = self.files.get(key.as_str()) {
                return Ok(VirtualStat::regular_file(
                    bytes.len() as u64,
                    [0u8; 32],
                    false,
                    FIXTURE_MTIME,
                ));
            }
            if self.is_dir(&key) {
                return Ok(VirtualStat::directory(FIXTURE_MTIME));
            }
            Err(VfsError::NotFound { path: key })
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            let key = Self::key(path);
            if !self.is_dir(&key) {
                return Err(VfsError::NotDirectory { path: key });
            }
            let prefix = if key.is_empty() {
                String::new()
            } else {
                format!("{key}/")
            };
            let mut names: BTreeMap<&str, FileType> = BTreeMap::new();
            for full in self.files.keys() {
                let Some(rest) = full.strip_prefix(prefix.as_str()) else {
                    continue;
                };
                match rest.split_once('/') {
                    Some((dir, _)) => {
                        names.insert(dir, FileType::Directory);
                    }
                    None => {
                        names.insert(rest, FileType::File);
                    }
                }
            }
            names
                .into_iter()
                .map(|(name, file_type)| {
                    Ok(DirEntry {
                        name: kin_vfs_core::VfsName::from_utf8(name)
                            .map_err(|err| VfsError::Provider(err.to_string()))?,
                        file_type,
                    })
                })
                .collect()
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(self.stat(path).is_ok())
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::InvalidInput {
                path: Self::key(path),
            })
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Run a PowerShell script and return its stdout, failing loudly with both
    /// streams when it exits nonzero.
    fn powershell(script: &str) -> String {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("spawn powershell.exe");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "powershell exited {:?}\n--- script ---\n{script}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            output.status.code()
        );
        stdout
    }

    /// A loopback listener standing in for the kin daemon's write-notify
    /// endpoint. Returns its port and a receiver of whole received requests.
    fn write_notify_listener() -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind write-notify listener");
        let port = listener.local_addr().expect("listener addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut request = String::new();
                let mut buf = [0u8; 4096];
                for _ in 0..8 {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(read) => {
                            request.push_str(&String::from_utf8_lossy(&buf[..read]));
                            if request.contains("bytes_hex") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"reindexed\":true}",
                );
                let _ = stream.flush();
                let _ = tx.send(request);
            }
        });

        (port, rx)
    }

    // Ignored by default for two reasons, both load-bearing. It needs ProjFS,
    // which exists on no developer machine in this fleet. And it enters through
    // `shim_init_windows`, whose state is a process-wide `OnceLock` that another
    // test in the same binary claims first, which is what makes the ordinary
    // `cargo test` run of this crate report "shim disabled" here. The CI job
    // runs it alone, by exact name, under `--ignored`.
    #[test]
    #[ignore = "needs ProjFS and a process where no other test has claimed the shim state"]
    fn projfs_projects_graph_bytes_to_a_separate_win32_process() {
        let required = std::env::var("KIN_VFS_PROJFS_LIVE").as_deref() == Ok("1");
        if let Err(err) = check_projfs_available() {
            assert!(
                !required,
                "KIN_VFS_PROJFS_LIVE=1 demands a live proof, but {err}"
            );
            eprintln!("PROJFS LIVE PROOF: skipped, {err}");
            return;
        }

        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("kin-projfs-live-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create virtualization root");
        let root_display = root.display().to_string();
        let pipe_name = format!(r"\\.\pipe\kin-vfs-projfs-live-{pid}");

        // The write-notify endpoint has to exist before the shim reads its
        // address out of the environment.
        let (notify_port, notify_rx) = write_notify_listener();
        std::env::set_var("KIN_DAEMON_URL", format!("http://127.0.0.1:{notify_port}"));
        std::env::set_var("KIN_VFS_WORKSPACE", &root);
        std::env::set_var("KIN_VFS_PIPE", &pipe_name);

        // The real daemon, on a real named pipe, on its own runtime threads.
        let server = VfsDaemonServer::new_named_pipe(FixtureProvider::new(), pipe_name.clone());
        let shutdown = server.shutdown_handle();
        let daemon_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("daemon runtime");
            runtime.block_on(async move {
                let _ = server.run().await;
            });
        });

        // Wait for the pipe to accept a connection before virtualizing.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut pipe_ready = false;
        while Instant::now() < deadline {
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_name)
                .is_ok()
            {
                pipe_ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(pipe_ready, "daemon never opened {pipe_name}");

        // Enter through the shipping entry point rather than building a
        // provider by hand: this is the code a Windows install would run, and
        // it is what puts the shim state the write-notify path reads in place.
        let mut provider = crate::shim_init_windows().unwrap_or_else(|err| {
            panic!(
                "shim_init_windows refused: {err}. Shim state is a process-wide \
                 OnceLock, so run this test alone by exact name rather than \
                 alongside the tests that set that state themselves."
            )
        });
        eprintln!("PROJFS LIVE PROOF: virtualizing {root_display}");

        // ── Read: a separate process enumerates and reads ──────────────────

        // Single-quoted throughout and concatenated rather than interpolated:
        // this script crosses Rust's argv escaping into PowerShell's own
        // command-line parsing, and an embedded double quote is the one thing
        // that mangling reliably reaches.
        let listing = powershell(&format!(
            "Get-ChildItem -LiteralPath '{root_display}' -Force | ForEach-Object {{ \
             $len = if ($_.PSIsContainer) {{ 'dir' }} else {{ $_.Length }}; \
             'ENTRY ' + $_.Name + ' ' + $len + ' ' \
             + $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') }}"
        ));
        eprintln!("PROJFS LIVE PROOF: listing\n{listing}");
        let expected_entry = format!("ENTRY hello.txt {} 2024-01-01", HELLO_BODY.len());
        assert!(
            listing.contains(&expected_entry),
            "directory listing did not report graph size and mtime; \
             wanted a line reading `{expected_entry}`, got:\n{listing}"
        );
        assert!(
            listing.contains("ENTRY src dir"),
            "directory listing did not report the nested directory:\n{listing}"
        );

        for (relative, body) in [("hello.txt", HELLO_BODY), (r"src\lib.rs", NESTED_BODY)] {
            let hex = powershell(&format!(
                "$b = [System.IO.File]::ReadAllBytes('{root_display}\\{relative}'); \
                 ($b | ForEach-Object {{ $_.ToString('x2') }}) -join ''"
            ));
            let hex = hex.trim();
            assert_eq!(
                hex,
                hex_encode(body),
                "a separate Win32 reader did not get graph-owned bytes for {relative}"
            );
            eprintln!(
                "PROJFS LIVE PROOF: read {} bytes of {relative} through Win32",
                body.len()
            );
        }

        // ── Write: a separate process edits, graph authority hears about it ─

        powershell(&format!(
            "Set-Content -LiteralPath '{root_display}\\hello.txt' -Value '{EDITED_BODY}' -NoNewline"
        ));
        let notification = notify_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("no write-notify reached the kin daemon endpoint after the projected write");
        eprintln!("PROJFS LIVE PROOF: write-notify\n{notification}");
        assert!(
            notification.starts_with("POST /vfs/write-notify "),
            "write-notify did not POST to the graph-authority endpoint:\n{notification}"
        );
        assert!(
            notification.contains(&hex_encode(b"hello.txt")),
            "write-notify did not name the edited graph key:\n{notification}"
        );

        provider.stop();
        shutdown.shutdown();
        let _ = daemon_thread.join();
        let _ = std::fs::remove_dir_all(&root);
        eprintln!("PROJFS LIVE PROOF: complete");
    }
}
