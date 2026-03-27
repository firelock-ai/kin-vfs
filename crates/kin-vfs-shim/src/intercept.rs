// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Syscall interception via `dlsym(RTLD_NEXT, ...)`.
//!
//! Each intercepted function follows the same pattern:
//! 1. Lazily resolve the real libc function via `OnceLock` + `dlsym`.
//! 2. If the shim is disabled, passthrough immediately.
//! 3. If the path is outside the workspace, passthrough.
//! 4. If the operation is a write, materialize-on-write then passthrough.
//! 5. Otherwise, serve from the VFS daemon.
//!
//! CRITICAL: Never panic in any of these functions. On any error, passthrough
//! to the real syscall.
//!
//! # Signal Safety Limitation
//!
//! This shim uses `parking_lot::RwLock` for the virtual FD table and
//! thread-local `RefCell` for socket connections. Neither primitive is
//! async-signal-safe. If a signal handler interrupts a thread while it
//! holds the fd_table write lock and then calls a hooked function (open,
//! read, close, etc.), deadlock will occur.
//!
//! This is an inherent limitation of LD_PRELOAD/DYLD_INSERT_LIBRARIES
//! shims that intercept low-level I/O syscalls. The same constraint
//! exists in other widely-used shims (e.g., jemalloc, tcmalloc).
//!
//! Mitigation: The shim's kill switch (`KIN_VFS_DISABLE=1`) and the
//! fail-open design (`is_disabled()` check at entry of every hook)
//! allow users to disable interception for processes with aggressive
//! signal handling.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use crate::client;
use crate::fd_table::{DirEntryRaw, vfd_base};
use crate::platform;
use crate::{is_disabled, is_workspace_path, shim_state};

// ── Helper: resolve the real function via dlsym ─────────────────────────

/// Resolves a function pointer via `dlsym(RTLD_NEXT, sym)`, cached in a
/// `OnceLock`. The macro creates a static `STORAGE_$name` and a getter
/// function `$name()` that returns the function pointer.
macro_rules! real_fn {
    ($name:ident, $storage:ident, $sym:expr, $ty:ty) => {
        static $storage: OnceLock<$ty> = OnceLock::new();

        #[inline]
        #[allow(non_snake_case)]
        fn $name() -> $ty {
            *$storage.get_or_init(|| unsafe {
                let ptr = libc::dlsym(libc::RTLD_NEXT, $sym.as_ptr() as *const c_char);
                if ptr.is_null() {
                    // If dlsym fails, we cannot proceed. This is a fatal
                    // initialization error — the process was already running
                    // with libc, so this should never happen.
                    std::process::abort();
                }
                std::mem::transmute(ptr)
            })
        }
    };
}

// Type aliases for readability.
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int;
type CloseFn = unsafe extern "C" fn(c_int) -> c_int;
type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, libc::size_t) -> libc::ssize_t;
type PreadFn = unsafe extern "C" fn(c_int, *mut c_void, libc::size_t, libc::off_t) -> libc::ssize_t;
type LseekFn = unsafe extern "C" fn(c_int, libc::off_t, c_int) -> libc::off_t;
type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type FaccessatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int;
type MmapFn = unsafe extern "C" fn(
    *mut c_void,
    libc::size_t,
    c_int,
    c_int,
    c_int,
    libc::off_t,
) -> *mut c_void;
type MunmapFn = unsafe extern "C" fn(*mut c_void, libc::size_t) -> c_int;
type ReadlinkFn = unsafe extern "C" fn(*const c_char, *mut c_char, libc::size_t) -> libc::ssize_t;
type ReadlinkatFn =
    unsafe extern "C" fn(c_int, *const c_char, *mut c_char, libc::size_t) -> libc::ssize_t;

#[cfg(target_os = "linux")]
type Getdents64Fn = unsafe extern "C" fn(c_int, *mut c_void, libc::size_t) -> libc::ssize_t;

#[cfg(target_os = "macos")]
type GetdirentriesFn =
    unsafe extern "C" fn(c_int, *mut c_char, libc::size_t, *mut libc::c_long) -> libc::ssize_t;

#[cfg(target_os = "macos")]
type StatFn = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;
#[cfg(target_os = "macos")]
type FstatFn = unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int;
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;

// Resolve real functions — shared across platforms.
real_fn!(get_real_open, STORE_OPEN, b"open\0", OpenFn);
real_fn!(get_real_openat, STORE_OPENAT, b"openat\0", OpenatFn);
real_fn!(get_real_close, STORE_CLOSE, b"close\0", CloseFn);
real_fn!(get_real_read, STORE_READ, b"read\0", ReadFn);
real_fn!(get_real_pread, STORE_PREAD, b"pread\0", PreadFn);
real_fn!(get_real_lseek, STORE_LSEEK, b"lseek\0", LseekFn);
real_fn!(get_real_access, STORE_ACCESS, b"access\0", AccessFn);
real_fn!(get_real_faccessat, STORE_FACCESSAT, b"faccessat\0", FaccessatFn);
real_fn!(get_real_fstatat, STORE_FSTATAT, b"fstatat\0", FstatatFn);
real_fn!(get_real_mmap, STORE_MMAP, b"mmap\0", MmapFn);
real_fn!(get_real_munmap, STORE_MUNMAP, b"munmap\0", MunmapFn);
real_fn!(get_real_readlink, STORE_READLINK, b"readlink\0", ReadlinkFn);
real_fn!(get_real_readlinkat, STORE_READLINKAT, b"readlinkat\0", ReadlinkatFn);

#[cfg(target_os = "linux")]
real_fn!(get_real_getdents64, STORE_GETDENTS64, b"getdents64\0", Getdents64Fn);

// macOS: getdirentries is available as __getdirentries64 on modern macOS.
#[cfg(target_os = "macos")]
real_fn!(
    get_real_getdirentries,
    STORE_GETDIRENTRIES,
    b"__getdirentries64\0",
    GetdirentriesFn
);

// Platform-specific stat resolution.
#[cfg(target_os = "linux")]
mod stat_fns {
    use super::*;

    type XstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat) -> c_int;
    type FxstatFn = unsafe extern "C" fn(c_int, c_int, *mut libc::stat) -> c_int;

    real_fn!(get_real_xstat, STORE_XSTAT, b"__xstat\0", XstatFn);
    real_fn!(get_real_fxstat, STORE_FXSTAT, b"__fxstat\0", FxstatFn);
    real_fn!(get_real_lxstat, STORE_LXSTAT, b"__lxstat\0", XstatFn);

    pub unsafe fn real_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_xstat()(1, path, buf)
    }

    pub unsafe fn real_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_lxstat()(1, path, buf)
    }

    pub unsafe fn real_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
        get_real_fxstat()(1, fd, buf)
    }

    pub unsafe fn call_real_xstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_xstat()(ver, path, buf)
    }

    pub unsafe fn call_real_lxstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_lxstat()(ver, path, buf)
    }

    pub unsafe fn call_real_fxstat(ver: c_int, fd: c_int, buf: *mut libc::stat) -> c_int {
        get_real_fxstat()(ver, fd, buf)
    }
}

#[cfg(target_os = "macos")]
mod stat_fns {
    use super::*;

    real_fn!(get_real_stat, STORE_STAT, b"stat\0", StatFn);
    real_fn!(get_real_lstat, STORE_LSTAT, b"lstat\0", StatFn);
    real_fn!(get_real_fstat, STORE_FSTAT, b"fstat\0", FstatFn);

    pub unsafe fn real_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_stat()(path, buf)
    }

    pub unsafe fn real_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_lstat()(path, buf)
    }

    pub unsafe fn real_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
        get_real_fstat()(fd, buf)
    }
}

// ── errno helper ────────────────────────────────────────────────────────

/// Set errno in a cross-platform way.
#[inline]
unsafe fn set_errno(val: c_int) {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location() = val;
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error() = val;
    }
}

// ── Synthetic inode ──────────────────────────────────────────────────────

/// Compute a unique synthetic inode from a file path using FNV-1a hash.
/// This ensures different virtual files get different inode numbers,
/// which tools like `find`, `tar`, and hardlink detectors depend on.
#[inline]
fn path_to_inode(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for byte in path.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV-1a prime
    }
    hash
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert a C string pointer to a Rust &str. Returns None on null or
/// invalid UTF-8 (which triggers passthrough).
#[inline]
unsafe fn c_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

/// Resolve a potentially relative path (for `openat`/`fstatat`) to an
/// absolute path string. Returns `None` if resolution fails.
unsafe fn resolve_at_path(dirfd: c_int, path: *const c_char) -> Option<String> {
    let path_str = c_to_str(path)?;

    // Absolute path — use directly.
    if path_str.starts_with('/') {
        return Some(path_str.to_string());
    }

    // AT_FDCWD means relative to cwd.
    if dirfd == libc::AT_FDCWD {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let cwd = libc::getcwd(buf.as_mut_ptr() as *mut c_char, buf.len());
        if cwd.is_null() {
            return None;
        }
        let cwd_str = CStr::from_ptr(cwd).to_str().ok()?;
        return Some(format!("{}/{}", cwd_str, path_str));
    }

    // dirfd is an actual fd — read its path.
    #[cfg(target_os = "linux")]
    {
        let link = format!("/proc/self/fd/{}", dirfd);
        let link_c = CString::new(link).ok()?;
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let len = libc::readlink(link_c.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len());
        if len <= 0 {
            return None;
        }
        let dir_path = std::str::from_utf8(&buf[..len as usize]).ok()?;
        return Some(format!("{}/{}", dir_path, path_str));
    }

    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let ret = libc::fcntl(dirfd, libc::F_GETPATH, buf.as_mut_ptr());
        if ret == -1 {
            return None;
        }
        let dir_path = CStr::from_ptr(buf.as_ptr() as *const c_char)
            .to_str()
            .ok()?;
        return Some(format!("{}/{}", dir_path, path_str));
    }
}

/// Check if flags indicate a write operation.
#[inline]
fn is_write_flags(flags: c_int) -> bool {
    (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC)) != 0
}

/// Generate the temp file path for atomic writes.
/// Format: `{target_path}.kin_tmp_{pid}`
fn atomic_temp_path(target: &str) -> String {
    let pid = unsafe { libc::getpid() };
    format!("{}.kin_tmp_{}", target, pid)
}

/// Clean up stale `.kin_tmp_*` files for a given target path.
/// Called on open to remove leftovers from crashed processes.
fn cleanup_stale_temps(path_str: &str) {
    if let Some(parent) = std::path::Path::new(path_str).parent() {
        if let Some(file_name) = std::path::Path::new(path_str).file_name() {
            let prefix = format!("{}.kin_tmp_", file_name.to_string_lossy());
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with(&prefix) {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}

/// Materialize-on-write: fetch content from daemon, write to a temp file
/// atomically. The caller opens the temp file; on close it is renamed to
/// the final path. Returns the temp path on success.
fn materialize_file(path_str: &str) -> Option<String> {
    let state = match shim_state() {
        Some(s) => s,
        None => return None,
    };

    // Clean up stale temp files from previous crashed processes.
    cleanup_stale_temps(path_str);

    // If the file already exists on disk, nothing to do — caller opens it directly.
    let c_path = match CString::new(path_str) {
        Ok(c) => c,
        Err(_) => return None,
    };
    unsafe {
        if libc::access(c_path.as_ptr(), libc::F_OK) == 0 {
            return None;
        }
    }

    // Fetch content from daemon.
    let content = match client::client_read_file(&state.sock_path, path_str) {
        Some(c) => c,
        None => return None, // Daemon doesn't know about this file either.
    };

    // Create parent directories.
    if let Some(parent) = std::path::Path::new(path_str).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Write content to a temp file (atomic write pattern).
    let temp = atomic_temp_path(path_str);
    match std::fs::write(&temp, &content) {
        Ok(()) => Some(temp),
        Err(_) => {
            // Fallback: write directly to target path.
            let _ = std::fs::write(path_str, &content);
            None
        }
    }
}

/// Allocate a virtual fd for a file served by the daemon.
fn allocate_vfd(path_str: &str, size: u64, content: Option<Vec<u8>>) -> c_int {
    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    match state.fd_table.write().allocate(path_str, size, content) {
        Some(fd) => fd,
        None => -1,
    }
}

/// Allocate a virtual directory fd, fetching entries from the daemon.
fn allocate_dir_vfd(path_str: &str) -> c_int {
    use kin_vfs_core::FileType;

    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    let entries = match client::client_read_dir(&state.sock_path, path_str) {
        Some(e) => e,
        None => return -1,
    };

    let raw_entries: Vec<DirEntryRaw> = entries
        .into_iter()
        .map(|e| {
            let d_type = match e.file_type {
                FileType::File => 8,      // DT_REG
                FileType::Directory => 4,  // DT_DIR
                FileType::Symlink => 10,   // DT_LNK
            };
            // Synthetic inode from name hash.
            let d_ino = {
                let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
                for b in e.name.as_bytes() {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x100000001b3); // FNV-1a prime
                }
                h
            };
            DirEntryRaw {
                name: e.name,
                d_ino,
                d_type,
            }
        })
        .collect();

    match state.fd_table.write().allocate_dir(path_str, raw_entries) {
        Some(fd) => fd,
        None => -1,
    }
}

/// Check whether a path should be opened as a directory (O_DIRECTORY flag
/// or daemon reports the path is a directory).
fn should_open_as_dir(flags: c_int, path_str: &str) -> bool {
    if flags & libc::O_DIRECTORY != 0 {
        return true;
    }
    // If no explicit O_DIRECTORY, check with the daemon.
    let state = match shim_state() {
        Some(s) => s,
        None => return false,
    };
    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) if vstat.is_dir => true,
        _ => false,
    }
}

// ── Intercepted syscalls ────────────────────────────────────────────────

/// Intercepted `open(2)`.
///
/// On the C ABI level, `open()` is variadic (mode is only present when
/// O_CREAT is set). However, at the machine level the third argument is
/// always passed in a register, so we can safely declare a fixed 3-arg
/// signature. This avoids requiring nightly `c_variadic`.
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let real_open = get_real_open();

    if is_disabled() {
        return real_open(path, flags, mode);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return real_open(path, flags, mode),
    };

    if !is_workspace_path(path_str) {
        return real_open(path, flags, mode);
    }

    // Write flags -> materialize then passthrough, tracking the fd.
    if is_write_flags(flags) {
        let temp = materialize_file(path_str);
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match CString::new(temp_path.as_str()) {
                Ok(c) => c,
                Err(_) => return real_open(path, flags, mode),
            };
            let fd = real_open(c_temp.as_ptr(), flags, mode);
            if fd >= 0 {
                if let Some(state) = shim_state() {
                    let mut ft = state.fd_table.write();
                    ft.track_write(fd, path_str.to_string());
                    ft.track_atomic_write(fd, path_str.to_string(), temp_path.clone());
                }
            }
            return fd;
        }
        // No temp (file existed on disk or daemon didn't know it) — open normally.
        let fd = real_open(path, flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, path_str.to_string());
            }
        }
        return fd;
    }

    // Directory open -> virtual directory fd from daemon.
    if should_open_as_dir(flags, path_str) {
        match allocate_dir_vfd(path_str) {
            fd if fd >= vfd_base() => return fd,
            _ => return real_open(path, flags, mode),
        }
    }

    // Read-only open -> virtual fd from daemon.
    let state = match shim_state() {
        Some(s) => s,
        None => return real_open(path, flags, mode),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) if vstat.is_file => {
            let content = client::client_read_file(&state.sock_path, path_str);
            // Use content length as effective size when stat reports 0
            // (KinDaemonProvider only caches path→hash, not sizes).
            let effective_size = content.as_ref().map(|c| c.len() as u64).unwrap_or(vstat.size);
            match allocate_vfd(path_str, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_open(path, flags, mode),
            }
        }
        _ => real_open(path, flags, mode),
    }
}

/// Intercepted `openat(2)`.
#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    let real_openat = get_real_openat();

    if is_disabled() {
        return real_openat(dirfd, path, flags, mode);
    }

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_openat(dirfd, path, flags, mode),
    };

    if !is_workspace_path(&resolved) {
        return real_openat(dirfd, path, flags, mode);
    }

    if is_write_flags(flags) {
        let temp = materialize_file(&resolved);
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match CString::new(temp_path.as_str()) {
                Ok(c) => c,
                Err(_) => return real_openat(dirfd, path, flags, mode),
            };
            let fd = real_openat(libc::AT_FDCWD, c_temp.as_ptr(), flags, mode);
            if fd >= 0 {
                if let Some(state) = shim_state() {
                    let mut ft = state.fd_table.write();
                    ft.track_write(fd, resolved.clone());
                    ft.track_atomic_write(fd, resolved.clone(), temp_path.clone());
                }
            }
            return fd;
        }
        // No temp — open normally.
        let fd = real_openat(dirfd, path, flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, resolved.clone());
            }
        }
        return fd;
    }

    // Directory open -> virtual directory fd from daemon.
    if should_open_as_dir(flags, &resolved) {
        match allocate_dir_vfd(&resolved) {
            fd if fd >= vfd_base() => return fd,
            _ => return real_openat(dirfd, path, flags, mode),
        }
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_openat(dirfd, path, flags, mode),
    };

    match client::client_stat(&state.sock_path, &resolved) {
        Some(vstat) if vstat.is_file => {
            let content = client::client_read_file(&state.sock_path, &resolved);
            // Use content length as effective size when stat reports 0
            // (KinDaemonProvider only caches path→hash, not sizes).
            let effective_size = content.as_ref().map(|c| c.len() as u64).unwrap_or(vstat.size);
            match allocate_vfd(&resolved, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_openat(dirfd, path, flags, mode),
            }
        }
        _ => real_openat(dirfd, path, flags, mode),
    }
}

/// Intercepted `read(2)`.
#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    let real_read = get_real_read();

    if is_disabled() || fd < vfd_base() {
        return real_read(fd, buf, count);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_read(fd, buf, count),
    };

    // Get handle info under write lock (we may need to advance offset).
    let mut fd_table = state.fd_table.write();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return real_read(fd, buf, count),
    };

    let offset = handle.offset;
    let size = handle.size;
    let path = handle.path.clone();

    // Check if we're at or past EOF.
    if offset >= size {
        return 0;
    }

    let bytes_to_read = count.min((size - offset) as usize);
    if bytes_to_read == 0 {
        return 0;
    }

    // Try cached content first.
    if let Some(ref content) = handle.cached_content {
        let start = offset as usize;
        let end = (start + bytes_to_read).min(content.len());
        if start < content.len() {
            let slice = &content[start..end];
            let n = slice.len();
            std::ptr::copy_nonoverlapping(slice.as_ptr(), buf as *mut u8, n);
            fd_table.advance_offset(fd, n as u64);
            return n as libc::ssize_t;
        }
    }

    // Not cached — read range from daemon. Must drop the lock first.
    drop(fd_table);

    let data = match client::client_read_range(&state.sock_path, &path, offset, bytes_to_read as u64)
    {
        Some(d) => d,
        None => {
            set_errno(libc::EIO);
            return -1;
        }
    };

    let n = data.len().min(bytes_to_read);
    std::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, n);

    let mut fd_table = state.fd_table.write();
    fd_table.advance_offset(fd, n as u64);

    n as libc::ssize_t
}

/// Intercepted `pread(2)` / `pread64(2)`.
#[no_mangle]
pub unsafe extern "C" fn pread(
    fd: c_int,
    buf: *mut c_void,
    count: libc::size_t,
    offset: libc::off_t,
) -> libc::ssize_t {
    let real_pread = get_real_pread();

    if is_disabled() || fd < vfd_base() {
        return real_pread(fd, buf, count, offset);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_pread(fd, buf, count, offset),
    };

    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return real_pread(fd, buf, count, offset),
    };

    let size = handle.size;
    let path = handle.path.clone();
    let off = offset as u64;

    if off >= size {
        return 0;
    }

    let bytes_to_read = count.min((size - off) as usize);
    if bytes_to_read == 0 {
        return 0;
    }

    // Try cached content.
    if let Some(ref content) = handle.cached_content {
        let start = off as usize;
        let end = (start + bytes_to_read).min(content.len());
        if start < content.len() {
            let slice = &content[start..end];
            let n = slice.len();
            std::ptr::copy_nonoverlapping(slice.as_ptr(), buf as *mut u8, n);
            return n as libc::ssize_t;
        }
    }

    drop(fd_table);

    let data = match client::client_read_range(&state.sock_path, &path, off, bytes_to_read as u64) {
        Some(d) => d,
        None => {
            set_errno(libc::EIO);
            return -1;
        }
    };

    let n = data.len().min(bytes_to_read);
    std::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, n);
    // pread does NOT advance the file offset.
    n as libc::ssize_t
}

/// Intercepted `close(2)`.
#[no_mangle]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    let real_close = get_real_close();

    // Always try to close in our table first (even if disabled, to clean up).
    if fd >= vfd_base() {
        if let Some(state) = shim_state() {
            if state.fd_table.write().close(fd).is_some() {
                return 0;
            }
        }
    }

    // Check if this is an atomic write fd — rename temp to target, then notify.
    if let Some(state) = shim_state() {
        let mut ft = state.fd_table.write();
        let atomic = ft.close_atomic_write(fd);
        let write_path = ft.close_write(fd);
        drop(ft);

        if let Some(entry) = atomic {
            // Close the real fd first so the temp file is flushed.
            let ret = real_close(fd);
            // Atomic rename: temp -> target. If rename fails, the temp file
            // stays on disk but the real file is not corrupted.
            let _ = std::fs::rename(&entry.temp_path, &entry.target_path);
            if let Some(wp) = write_path {
                client::notify_file_changed(&wp);
            }
            return ret;
        }

        if let Some(wp) = write_path {
            let ret = real_close(fd);
            client::notify_file_changed(&wp);
            return ret;
        }
    }

    real_close(fd)
}

/// Intercepted `lseek(2)`.
#[no_mangle]
pub unsafe extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    let real_lseek = get_real_lseek();

    if is_disabled() || fd < vfd_base() {
        return real_lseek(fd, offset, whence);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_lseek(fd, offset, whence),
    };

    match state.fd_table.write().seek(fd, offset as i64, whence) {
        Some(new_offset) => new_offset as libc::off_t,
        None => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Intercepted `stat(2)`.
#[no_mangle]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::real_stat(path, buf);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat_fns::real_stat(path, buf),
    };

    if !is_workspace_path(path_str) {
        return stat_fns::real_stat(path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::real_stat(path, buf),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            0
        }
        None => stat_fns::real_stat(path, buf),
    }
}

/// Intercepted `lstat(2)`.
#[no_mangle]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::real_lstat(path, buf);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat_fns::real_lstat(path, buf),
    };

    if !is_workspace_path(path_str) {
        return stat_fns::real_lstat(path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::real_lstat(path, buf),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            0
        }
        None => stat_fns::real_lstat(path, buf),
    }
}

/// Intercepted `fstat(2)`.
#[no_mangle]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat_fns::real_fstat(fd, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::real_fstat(fd, buf),
    };

    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return stat_fns::real_fstat(fd, buf),
    };

    let path = handle.path.clone();
    drop(fd_table);

    match client::client_stat(&state.sock_path, &path) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path);
            0
        }
        None => {
            set_errno(libc::EBADF);
            -1
        }
    }
}

/// Intercepted `fstatat(2)`.
#[no_mangle]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    let real_fstatat = get_real_fstatat();

    if is_disabled() {
        return real_fstatat(dirfd, path, buf, flags);
    }

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_fstatat(dirfd, path, buf, flags),
    };

    if !is_workspace_path(&resolved) {
        return real_fstatat(dirfd, path, buf, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_fstatat(dirfd, path, buf, flags),
    };

    match client::client_stat(&state.sock_path, &resolved) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            0
        }
        None => real_fstatat(dirfd, path, buf, flags),
    }
}

/// Intercepted `access(2)`.
#[no_mangle]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    let real_access = get_real_access();

    if is_disabled() {
        return real_access(path, mode);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return real_access(path, mode),
    };

    if !is_workspace_path(path_str) {
        return real_access(path, mode);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_access(path, mode),
    };

    match client::client_access(&state.sock_path, path_str, mode as u32) {
        Some(true) => 0,
        Some(false) => {
            set_errno(libc::EACCES);
            -1
        }
        None => real_access(path, mode),
    }
}

/// Intercepted `faccessat(2)`.
#[no_mangle]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    let real_faccessat = get_real_faccessat();

    if is_disabled() {
        return real_faccessat(dirfd, path, mode, flags);
    }

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_faccessat(dirfd, path, mode, flags),
    };

    if !is_workspace_path(&resolved) {
        return real_faccessat(dirfd, path, mode, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_faccessat(dirfd, path, mode, flags),
    };

    match client::client_access(&state.sock_path, &resolved, mode as u32) {
        Some(true) => 0,
        Some(false) => {
            set_errno(libc::EACCES);
            -1
        }
        None => real_faccessat(dirfd, path, mode, flags),
    }
}

// ── getdents64 (Linux) ──────────────────────────────────────────────────

/// Pack directory entries into a Linux `getdents64` buffer.
///
/// Returns the number of bytes written into `buf`, or 0 if no more entries.
#[cfg(target_os = "linux")]
unsafe fn pack_getdents64(
    buf: *mut c_void,
    buf_size: libc::size_t,
    entries: &[DirEntryRaw],
    offset: &mut usize,
) -> libc::ssize_t {
    // Linux getdents64 struct layout:
    //   u64  d_ino
    //   i64  d_off
    //   u16  d_reclen
    //   u8   d_type
    //   char d_name[]  (null terminated, padded to 8-byte alignment)
    let buf_ptr = buf as *mut u8;
    let mut written: usize = 0;

    while *offset < entries.len() {
        let entry = &entries[*offset];
        let name_bytes = entry.name.as_bytes();
        // Fixed header: 8 (d_ino) + 8 (d_off) + 2 (d_reclen) + 1 (d_type) = 19 bytes
        // Then name + null terminator, padded to 8-byte alignment.
        let name_with_null = name_bytes.len() + 1;
        let reclen_unaligned = 19 + name_with_null;
        let reclen = (reclen_unaligned + 7) & !7; // align to 8 bytes

        if written + reclen > buf_size {
            break; // buffer full
        }

        let base = buf_ptr.add(written);

        // d_ino (u64 at offset 0)
        (base as *mut u64).write_unaligned(entry.d_ino);
        // d_off (i64 at offset 8) — offset to next entry (1-indexed position)
        (base.add(8) as *mut i64).write_unaligned((*offset + 1) as i64);
        // d_reclen (u16 at offset 16)
        (base.add(16) as *mut u16).write_unaligned(reclen as u16);
        // d_type (u8 at offset 18)
        *base.add(18) = entry.d_type;
        // d_name (at offset 19)
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), base.add(19), name_bytes.len());
        // Null terminator and zero-fill padding.
        let pad_start = 19 + name_bytes.len();
        for i in pad_start..reclen {
            *base.add(i) = 0;
        }

        written += reclen;
        *offset += 1;
    }

    written as libc::ssize_t
}

/// Intercepted `getdents64(2)` (Linux only).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn getdents64(
    fd: c_int,
    buf: *mut c_void,
    buf_size: libc::size_t,
) -> libc::ssize_t {
    let real_getdents64 = get_real_getdents64();

    if is_disabled() || fd < vfd_base() {
        return real_getdents64(fd, buf, buf_size);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_getdents64(fd, buf, buf_size),
    };

    let mut fd_table = state.fd_table.write();
    let handle = match fd_table.get_mut(fd) {
        Some(h) if h.is_directory => h,
        _ => return real_getdents64(fd, buf, buf_size),
    };

    let entries = match handle.dir_entries.as_ref() {
        Some(e) => e.clone(),
        None => return 0,
    };

    let mut dir_offset = handle.dir_offset;
    let result = pack_getdents64(buf, buf_size, &entries, &mut dir_offset);
    handle.dir_offset = dir_offset;

    result
}

// ── getdirentries (macOS) ───────────────────────────────────────────────

/// Pack directory entries into a macOS `dirent` buffer (getdirentries).
///
/// Returns the number of bytes written into `buf`, or 0 if no more entries.
#[cfg(target_os = "macos")]
unsafe fn pack_getdirentries(
    buf: *mut c_char,
    buf_size: libc::size_t,
    entries: &[DirEntryRaw],
    offset: &mut usize,
    basep: *mut libc::c_long,
) -> libc::ssize_t {
    // macOS dirent struct layout:
    //   u64  d_ino       (d_fileno)
    //   u16  d_seekoff   (high 16 bits, we use 0)
    //   u16  d_reclen
    //   u16  d_namlen
    //   u8   d_type
    //   char d_name[1024]
    //
    // Actual reclen = offsetof(d_name) + d_namlen + 1, aligned to 4 bytes.
    // The header before d_name is: 8 + 2 + 2 + 2 + 1 = 15 bytes, but
    // Apple's struct uses:
    //   __uint64_t  d_ino;       // 8
    //   __uint64_t  d_seekoff;   // 8  (only low 16 used for d_seekoff on some, but 8 bytes in struct)
    //   __uint16_t  d_reclen;    // 2
    //   __uint16_t  d_namlen;    // 2
    //   __uint8_t   d_type;      // 1
    //   char        d_name[1024];// at offset 21, but due to alignment it's at a known offset
    //
    // In practice, the macOS dirent is:
    //   offset 0:   d_ino (u64)
    //   offset 8:   d_seekoff (u64) — used internally
    //   offset 16:  d_reclen (u16)
    //   offset 18:  d_namlen (u16)
    //   offset 20:  d_type (u8)
    //   offset 21:  d_name[...]
    const HEADER_SIZE: usize = 21; // bytes before d_name

    let buf_ptr = buf as *mut u8;
    let mut written: usize = 0;

    while *offset < entries.len() {
        let entry = &entries[*offset];
        let name_bytes = entry.name.as_bytes();
        let namlen = name_bytes.len();

        // reclen = header + namlen + 1 (null), aligned to 4 bytes
        let reclen_unaligned = HEADER_SIZE + namlen + 1;
        let reclen = (reclen_unaligned + 3) & !3;

        if written + reclen > buf_size {
            break; // buffer full
        }

        let base = buf_ptr.add(written);

        // Zero the entire record first.
        std::ptr::write_bytes(base, 0, reclen);

        // d_ino (u64 at offset 0)
        (base as *mut u64).write_unaligned(entry.d_ino);
        // d_seekoff (u64 at offset 8) — sequential offset
        (base.add(8) as *mut u64).write_unaligned((*offset + 1) as u64);
        // d_reclen (u16 at offset 16)
        (base.add(16) as *mut u16).write_unaligned(reclen as u16);
        // d_namlen (u16 at offset 18)
        (base.add(18) as *mut u16).write_unaligned(namlen as u16);
        // d_type (u8 at offset 20)
        *base.add(20) = entry.d_type;
        // d_name (at offset 21)
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), base.add(HEADER_SIZE), namlen);
        // null terminator already set by write_bytes(0) above

        written += reclen;
        *offset += 1;
    }

    // Set base position if caller wants it.
    if !basep.is_null() {
        *basep = *offset as libc::c_long;
    }

    written as libc::ssize_t
}

/// Intercepted `__getdirentries64` (macOS only).
///
/// macOS libc routes `readdir()` through `__getdirentries64` internally.
#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn __getdirentries64(
    fd: c_int,
    buf: *mut c_char,
    buf_size: libc::size_t,
    basep: *mut libc::c_long,
) -> libc::ssize_t {
    let real_fn = get_real_getdirentries();

    if is_disabled() || fd < vfd_base() {
        return real_fn(fd, buf, buf_size, basep);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_fn(fd, buf, buf_size, basep),
    };

    let mut fd_table = state.fd_table.write();
    let handle = match fd_table.get_mut(fd) {
        Some(h) if h.is_directory => h,
        _ => return real_fn(fd, buf, buf_size, basep),
    };

    let entries = match handle.dir_entries.as_ref() {
        Some(e) => e.clone(),
        None => return 0,
    };

    let mut dir_offset = handle.dir_offset;
    let result = pack_getdirentries(buf, buf_size, &entries, &mut dir_offset, basep);
    handle.dir_offset = dir_offset;

    result
}

// ── mmap / munmap ───────────────────────────────────────────────────────

/// Intercepted `mmap(2)`.
///
/// When mmap is called on a virtual fd, we materialize the file content
/// to a temp file and mmap that. This lets the OS page cache handle lazy
/// loading — pages only fault in when accessed, which is much better for
/// large files where only a portion is read (e.g., tree-sitter parsing a
/// header region). The temp file is unlinked immediately after mmap so it
/// is cleaned up when the mapping is released.
///
/// Fallback: if temp file creation fails, we fall back to the anonymous
/// mapping + memcpy approach.
#[no_mangle]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: libc::size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    let real_mmap = get_real_mmap();

    if is_disabled() || fd < vfd_base() {
        return real_mmap(addr, len, prot, flags, fd, offset);
    }

    // MAP_SHARED on a virtual fd cannot be safely emulated because writes
    // to a shared mapping would need to propagate back to the blob store,
    // which is content-addressed and immutable. Reject with EINVAL so
    // callers get a clear error rather than silent data loss.
    if (flags & libc::MAP_SHARED) != 0 {
        set_errno(libc::EINVAL);
        return libc::MAP_FAILED;
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_mmap(addr, len, prot, flags, fd, offset),
    };

    // Get file content from the virtual fd.
    let content = {
        let fd_table = state.fd_table.read();
        let handle = match fd_table.get(fd) {
            Some(h) if !h.is_directory => h,
            _ => return real_mmap(addr, len, prot, flags, fd, offset),
        };

        if let Some(ref cached) = handle.cached_content {
            cached.clone()
        } else {
            let path = handle.path.clone();
            drop(fd_table);
            match client::client_read_file(&state.sock_path, &path) {
                Some(data) => data,
                None => {
                    set_errno(libc::EIO);
                    return libc::MAP_FAILED;
                }
            }
        }
    };

    // Determine the actual mapping size.
    let map_len = if len == 0 { content.len() } else { len };
    if map_len == 0 {
        set_errno(libc::EINVAL);
        return libc::MAP_FAILED;
    }

    // Strategy: materialize to a temp file, mmap it, then unlink.
    // The OS page cache handles lazy fault-in, so only accessed pages
    // consume physical memory. The unlinked temp file is automatically
    // cleaned up when the last fd/mapping is released.
    let result = mmap_via_tempfile(
        &content, map_len, prot, flags, offset, real_mmap,
    );

    let ptr = match result {
        Some(p) => p,
        None => {
            // Fallback: anonymous mapping + memcpy.
            mmap_anonymous(&content, map_len, prot, offset, real_mmap)
        }
    };

    if ptr == libc::MAP_FAILED {
        return libc::MAP_FAILED;
    }

    // Track this region so we can intercept munmap.
    state
        .fd_table
        .write()
        .track_mmap(ptr as usize, map_len);

    ptr
}

/// Materialize content to a temp file and mmap it. Returns None on failure.
unsafe fn mmap_via_tempfile(
    content: &[u8],
    map_len: usize,
    prot: c_int,
    _flags: c_int,
    offset: libc::off_t,
    real_mmap: MmapFn,
) -> Option<*mut c_void> {
    // Create a temp file in the system temp dir.
    let template = CString::new("/tmp/kin-vfs-mmap-XXXXXX").ok()?;
    let mut buf = template.into_bytes_with_nul();
    let tmp_fd = libc::mkstemp(buf.as_mut_ptr() as *mut c_char);
    if tmp_fd < 0 {
        return None;
    }

    // Unlink immediately — the file stays alive via the fd until close/munmap.
    libc::unlink(buf.as_ptr() as *const c_char);

    // Write content to the temp file.
    let mut written = 0usize;
    while written < content.len() {
        let n = libc::write(
            tmp_fd,
            content.as_ptr().add(written) as *const c_void,
            content.len() - written,
        );
        if n <= 0 {
            libc::close(tmp_fd);
            return None;
        }
        written += n as usize;
    }

    // mmap the temp file — the kernel pages in lazily from the file.
    let ptr = real_mmap(
        std::ptr::null_mut(),
        map_len,
        prot,
        libc::MAP_PRIVATE,
        tmp_fd,
        offset,
    );

    libc::close(tmp_fd);

    if ptr == libc::MAP_FAILED {
        return None;
    }

    Some(ptr)
}

/// Fallback: anonymous mapping + memcpy for when tempfile fails.
unsafe fn mmap_anonymous(
    content: &[u8],
    map_len: usize,
    prot: c_int,
    offset: libc::off_t,
    real_mmap: MmapFn,
) -> *mut c_void {
    let anon_ptr = real_mmap(
        std::ptr::null_mut(),
        map_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    );

    if anon_ptr == libc::MAP_FAILED {
        return libc::MAP_FAILED;
    }

    let file_offset = offset as usize;
    if file_offset < content.len() {
        let copy_len = (content.len() - file_offset).min(map_len);
        std::ptr::copy_nonoverlapping(
            content.as_ptr().add(file_offset),
            anon_ptr as *mut u8,
            copy_len,
        );
    }

    // If the caller only wanted PROT_READ, downgrade the protection.
    if prot & libc::PROT_WRITE == 0 {
        libc::mprotect(anon_ptr, map_len, prot);
    }

    anon_ptr
}

/// Intercepted `munmap(2)`.
///
/// If the address was a virtual mmap region, untrack it and call real munmap.
#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: libc::size_t) -> c_int {
    let real_munmap = get_real_munmap();

    if !is_disabled() {
        if let Some(state) = shim_state() {
            // Untrack if this is a virtual mmap region. Even if it is,
            // we still call real_munmap because we allocated real anonymous memory.
            let _ = state.fd_table.write().untrack_mmap(addr as usize);
        }
    }

    real_munmap(addr, len)
}

// ── readlink / readlinkat ───────────────────────────────────────────────

/// Intercepted `readlink(2)`.
#[no_mangle]
pub unsafe extern "C" fn readlink(
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: libc::size_t,
) -> libc::ssize_t {
    let real_readlink = get_real_readlink();

    if is_disabled() {
        return real_readlink(path, buf, bufsiz);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return real_readlink(path, buf, bufsiz),
    };

    if !is_workspace_path(path_str) {
        return real_readlink(path, buf, bufsiz);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_readlink(path, buf, bufsiz),
    };

    match client::client_read_link(&state.sock_path, path_str) {
        Some(target) => {
            // If the symlink target points outside the workspace, fall through
            // to the real readlink so the kernel resolves it normally. This
            // prevents the VFS from serving content outside its trust boundary.
            if !is_workspace_path(&target) {
                return real_readlink(path, buf, bufsiz);
            }
            let target_bytes = target.as_bytes();
            let copy_len = target_bytes.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target_bytes.as_ptr(), buf as *mut u8, copy_len);
            copy_len as libc::ssize_t
        }
        None => real_readlink(path, buf, bufsiz),
    }
}

/// Intercepted `readlinkat(2)`.
#[no_mangle]
pub unsafe extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: libc::size_t,
) -> libc::ssize_t {
    let real_readlinkat = get_real_readlinkat();

    if is_disabled() {
        return real_readlinkat(dirfd, path, buf, bufsiz);
    }

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_readlinkat(dirfd, path, buf, bufsiz),
    };

    if !is_workspace_path(&resolved) {
        return real_readlinkat(dirfd, path, buf, bufsiz);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_readlinkat(dirfd, path, buf, bufsiz),
    };

    match client::client_read_link(&state.sock_path, &resolved) {
        Some(target) => {
            // If the symlink target points outside the workspace, fall through
            // to the real readlinkat so the kernel resolves it normally. This
            // prevents the VFS from serving content outside its trust boundary.
            if !is_workspace_path(&target) {
                return real_readlinkat(dirfd, path, buf, bufsiz);
            }
            let target_bytes = target.as_bytes();
            let copy_len = target_bytes.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target_bytes.as_ptr(), buf as *mut u8, copy_len);
            copy_len as libc::ssize_t
        }
        None => real_readlinkat(dirfd, path, buf, bufsiz),
    }
}

// ── Linux-specific __xstat family ───────────────────────────────────────

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __xstat(
    ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
) -> c_int {
    if is_disabled() {
        return stat_fns::call_real_xstat(ver, path, buf);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat_fns::call_real_xstat(ver, path, buf),
    };

    if !is_workspace_path(path_str) {
        return stat_fns::call_real_xstat(ver, path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::call_real_xstat(ver, path, buf),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            0
        }
        None => stat_fns::call_real_xstat(ver, path, buf),
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __lxstat(
    ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
) -> c_int {
    if is_disabled() {
        return stat_fns::call_real_lxstat(ver, path, buf);
    }

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat_fns::call_real_lxstat(ver, path, buf),
    };

    if !is_workspace_path(path_str) {
        return stat_fns::call_real_lxstat(ver, path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::call_real_lxstat(ver, path, buf),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            0
        }
        None => stat_fns::call_real_lxstat(ver, path, buf),
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __fxstat(
    ver: c_int,
    fd: c_int,
    buf: *mut libc::stat,
) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat_fns::call_real_fxstat(ver, fd, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::call_real_fxstat(ver, fd, buf),
    };

    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return stat_fns::call_real_fxstat(ver, fd, buf),
    };

    let path = handle.path.clone();
    drop(fd_table);

    match client::client_stat(&state.sock_path, &path) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path);
            0
        }
        None => {
            set_errno(libc::EBADF);
            -1
        }
    }
}

// ── Linux pread64 alias ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn pread64(
    fd: c_int,
    buf: *mut c_void,
    count: libc::size_t,
    offset: libc::off_t,
) -> libc::ssize_t {
    pread(fd, buf, count, offset)
}

// ── macOS stat64 aliases ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn stat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    stat(path, buf)
}

#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn lstat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    lstat(path, buf)
}

#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn fstat64(fd: c_int, buf: *mut libc::stat) -> c_int {
    fstat(fd, buf)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd_table::DirEntryRaw;

    fn test_entries() -> Vec<DirEntryRaw> {
        vec![
            DirEntryRaw {
                name: "hello.rs".to_string(),
                d_ino: 0x1234,
                d_type: 8, // DT_REG
            },
            DirEntryRaw {
                name: "subdir".to_string(),
                d_ino: 0x5678,
                d_type: 4, // DT_DIR
            },
            DirEntryRaw {
                name: "link".to_string(),
                d_ino: 0x9abc,
                d_type: 10, // DT_LNK
            },
        ]
    }

    // ── getdents64 packing (Linux) ──────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn pack_getdents64_basic() {
        let entries = test_entries();
        let mut buf = vec![0u8; 4096];
        let mut offset = 0usize;

        let n = unsafe {
            pack_getdents64(
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &entries,
                &mut offset,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 3); // all 3 entries consumed

        // Verify first entry structure.
        unsafe {
            let base = buf.as_ptr();
            // d_ino at offset 0
            let d_ino = (base as *const u64).read_unaligned();
            assert_eq!(d_ino, 0x1234);
            // d_off at offset 8
            let d_off = (base.add(8) as *const i64).read_unaligned();
            assert_eq!(d_off, 1); // first entry, offset to next = 1
            // d_reclen at offset 16
            let d_reclen = (base.add(16) as *const u16).read_unaligned();
            assert!(d_reclen > 0);
            assert_eq!(d_reclen as usize % 8, 0); // 8-byte aligned
            // d_type at offset 18
            assert_eq!(*base.add(18), 8); // DT_REG
            // d_name at offset 19
            let name_ptr = base.add(19);
            let name = CStr::from_ptr(name_ptr as *const c_char);
            assert_eq!(name.to_str().unwrap(), "hello.rs");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pack_getdents64_small_buffer_partial() {
        let entries = test_entries();
        // Use a buffer that can only fit one entry.
        let mut buf = vec![0u8; 32]; // 19 header + "hello.rs" (8) + null + pad = 28 -> 32 aligned
        let mut offset = 0usize;

        let n = unsafe {
            pack_getdents64(
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &entries,
                &mut offset,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 1); // only first entry fits
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pack_getdents64_empty_entries() {
        let entries: Vec<DirEntryRaw> = vec![];
        let mut buf = vec![0u8; 4096];
        let mut offset = 0usize;

        let n = unsafe {
            pack_getdents64(
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &entries,
                &mut offset,
            )
        };

        assert_eq!(n, 0);
        assert_eq!(offset, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pack_getdents64_offset_resumes() {
        let entries = test_entries();
        let mut buf = vec![0u8; 4096];
        let mut offset = 1usize; // skip first entry

        let n = unsafe {
            pack_getdents64(
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &entries,
                &mut offset,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 3); // consumed remaining 2 entries

        // First entry in buffer should be "subdir".
        unsafe {
            let base = buf.as_ptr();
            let d_ino = (base as *const u64).read_unaligned();
            assert_eq!(d_ino, 0x5678);
            assert_eq!(*base.add(18), 4); // DT_DIR
            let name = CStr::from_ptr(base.add(19) as *const c_char);
            assert_eq!(name.to_str().unwrap(), "subdir");
        }
    }

    // ── getdirentries packing (macOS) ───────────────────────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn pack_getdirentries_basic() {
        let entries = test_entries();
        let mut buf = vec![0u8; 4096];
        let mut offset = 0usize;
        let mut basep: libc::c_long = 0;

        let n = unsafe {
            pack_getdirentries(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &entries,
                &mut offset,
                &mut basep,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 3); // all 3 entries consumed
        assert_eq!(basep, 3);

        // Verify first entry structure.
        unsafe {
            let base = buf.as_ptr();
            // d_ino at offset 0 (u64)
            let d_ino = (base as *const u64).read_unaligned();
            assert_eq!(d_ino, 0x1234);
            // d_seekoff at offset 8 (u64)
            let d_seekoff = (base.add(8) as *const u64).read_unaligned();
            assert_eq!(d_seekoff, 1);
            // d_reclen at offset 16 (u16)
            let d_reclen = (base.add(16) as *const u16).read_unaligned();
            assert!(d_reclen > 0);
            assert_eq!(d_reclen as usize % 4, 0); // 4-byte aligned
            // d_namlen at offset 18 (u16)
            let d_namlen = (base.add(18) as *const u16).read_unaligned();
            assert_eq!(d_namlen, 8); // "hello.rs".len()
            // d_type at offset 20 (u8)
            assert_eq!(*base.add(20), 8); // DT_REG
            // d_name at offset 21
            let name_ptr = base.add(21);
            let name = CStr::from_ptr(name_ptr as *const c_char);
            assert_eq!(name.to_str().unwrap(), "hello.rs");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pack_getdirentries_small_buffer_partial() {
        let entries = test_entries();
        // Header is 21 + "hello.rs"(8) + null(1) = 30 -> aligned to 32
        let mut buf = vec![0u8; 32];
        let mut offset = 0usize;
        let mut basep: libc::c_long = 0;

        let n = unsafe {
            pack_getdirentries(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &entries,
                &mut offset,
                &mut basep,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 1); // only first entry fits
        assert_eq!(basep, 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pack_getdirentries_empty_entries() {
        let entries: Vec<DirEntryRaw> = vec![];
        let mut buf = vec![0u8; 4096];
        let mut offset = 0usize;
        let mut basep: libc::c_long = 0;

        let n = unsafe {
            pack_getdirentries(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &entries,
                &mut offset,
                &mut basep,
            )
        };

        assert_eq!(n, 0);
        assert_eq!(offset, 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pack_getdirentries_offset_resumes() {
        let entries = test_entries();
        let mut buf = vec![0u8; 4096];
        let mut offset = 1usize; // skip first entry
        let mut basep: libc::c_long = 0;

        let n = unsafe {
            pack_getdirentries(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &entries,
                &mut offset,
                &mut basep,
            )
        };

        assert!(n > 0);
        assert_eq!(offset, 3); // consumed remaining 2 entries

        // First entry in buffer should be "subdir".
        unsafe {
            let base = buf.as_ptr();
            let d_ino = (base as *const u64).read_unaligned();
            assert_eq!(d_ino, 0x5678);
            assert_eq!(*base.add(20), 4); // DT_DIR
            let name = CStr::from_ptr(base.add(21) as *const c_char);
            assert_eq!(name.to_str().unwrap(), "subdir");
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn mmap_private_write_does_not_leak_between_mappings() {
        let content = b"semantic truth";
        let map_len = content.len();

        unsafe {
            let first = mmap_via_tempfile(
                content,
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                0,
                libc::mmap,
            )
            .expect("initial mmap should succeed");
            let first_slice = std::slice::from_raw_parts_mut(first as *mut u8, map_len);
            assert_eq!(first_slice, content);

            first_slice[0] = b'X';
            assert_eq!(first_slice[0], b'X');
            assert_eq!(content[0], b's');
            assert_eq!(libc::munmap(first, map_len), 0);

            let second = mmap_via_tempfile(
                content,
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                0,
                libc::mmap,
            )
            .expect("remap should succeed");
            let second_slice = std::slice::from_raw_parts(second as *const u8, map_len);
            assert_eq!(second_slice, content);
            assert_eq!(libc::munmap(second, map_len), 0);
        }
    }
}
