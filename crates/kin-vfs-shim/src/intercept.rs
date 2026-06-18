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

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use crate::client;
use crate::fd_table::{vfd_base, DirEntryRaw};
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
#[cfg(not(target_os = "macos"))]
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
#[cfg(not(target_os = "macos"))]
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int;
#[cfg(not(target_os = "macos"))]
type CloseFn = unsafe extern "C" fn(c_int) -> c_int;
type DupFn = unsafe extern "C" fn(c_int) -> c_int;
type Dup2Fn = unsafe extern "C" fn(c_int, c_int) -> c_int;
#[cfg(any(target_os = "linux", target_os = "android"))]
type Dup3Fn = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;
type FlockFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
#[cfg(not(target_os = "macos"))]
type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, libc::size_t) -> libc::ssize_t;
#[cfg(not(target_os = "macos"))]
type PreadFn = unsafe extern "C" fn(c_int, *mut c_void, libc::size_t, libc::off_t) -> libc::ssize_t;
#[cfg(not(target_os = "macos"))]
type LseekFn = unsafe extern "C" fn(c_int, libc::off_t, c_int) -> libc::off_t;
#[cfg(not(target_os = "macos"))]
type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;

// Resolve real functions — shared across platforms.
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_open, STORE_OPEN, b"open\0", OpenFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_openat, STORE_OPENAT, b"openat\0", OpenatFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_close, STORE_CLOSE, b"close\0", CloseFn);
real_fn!(get_real_dup, STORE_DUP, b"dup\0", DupFn);
real_fn!(get_real_dup2, STORE_DUP2, b"dup2\0", Dup2Fn);
#[cfg(any(target_os = "linux", target_os = "android"))]
real_fn!(get_real_dup3, STORE_DUP3, b"dup3\0", Dup3Fn);
real_fn!(get_real_flock, STORE_FLOCK, b"flock\0", FlockFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_read, STORE_READ, b"read\0", ReadFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_pread, STORE_PREAD, b"pread\0", PreadFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_lseek, STORE_LSEEK, b"lseek\0", LseekFn);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_access, STORE_ACCESS, b"access\0", AccessFn);
#[cfg(not(target_os = "macos"))]
real_fn!(
    get_real_faccessat,
    STORE_FACCESSAT,
    b"faccessat\0",
    FaccessatFn
);
#[cfg(not(target_os = "macos"))]
real_fn!(get_real_fstatat, STORE_FSTATAT, b"fstatat\0", FstatatFn);
real_fn!(get_real_mmap, STORE_MMAP, b"mmap\0", MmapFn);
real_fn!(get_real_munmap, STORE_MUNMAP, b"munmap\0", MunmapFn);
real_fn!(get_real_readlink, STORE_READLINK, b"readlink\0", ReadlinkFn);
real_fn!(
    get_real_readlinkat,
    STORE_READLINKAT,
    b"readlinkat\0",
    ReadlinkatFn
);

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_open_call(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_OPEN: c_int = 5;
    libc::syscall(SYS_OPEN, path, flags, mode as libc::c_uint) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_open_call(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    get_real_open()(path, flags, mode)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_openat_call(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_OPENAT: c_int = 463;
    libc::syscall(SYS_OPENAT, dirfd, path, flags, mode as libc::c_uint) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_openat_call(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    get_real_openat()(dirfd, path, flags, mode)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_read_call(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_READ: c_int = 3;
    libc::syscall(SYS_READ, fd, buf, count) as libc::ssize_t
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_read_call(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    get_real_read()(fd, buf, count)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_pread_call(
    fd: c_int,
    buf: *mut c_void,
    count: libc::size_t,
    offset: libc::off_t,
) -> libc::ssize_t {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_PREAD: c_int = 153;
    libc::syscall(SYS_PREAD, fd, buf, count, offset) as libc::ssize_t
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_pread_call(
    fd: c_int,
    buf: *mut c_void,
    count: libc::size_t,
    offset: libc::off_t,
) -> libc::ssize_t {
    get_real_pread()(fd, buf, count, offset)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_lseek_call(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_LSEEK: c_int = 199;
    libc::syscall(SYS_LSEEK, fd, offset, whence) as libc::off_t
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_lseek_call(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    get_real_lseek()(fd, offset, whence)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_close_call(fd: c_int) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_CLOSE: c_int = 6;
    libc::syscall(SYS_CLOSE, fd) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_close_call(fd: c_int) -> c_int {
    get_real_close()(fd)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_access_call(path: *const c_char, mode: c_int) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_ACCESS: c_int = 33;
    libc::syscall(SYS_ACCESS, path, mode) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_access_call(path: *const c_char, mode: c_int) -> c_int {
    get_real_access()(path, mode)
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_faccessat_call(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_FACCESSAT: c_int = 466;
    libc::syscall(SYS_FACCESSAT, dirfd, path, mode, flags) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_faccessat_call(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    get_real_faccessat()(dirfd, path, mode, flags)
}

#[cfg(target_os = "linux")]
real_fn!(
    get_real_getdents64,
    STORE_GETDENTS64,
    b"getdents64\0",
    Getdents64Fn
);

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

    // Darwin syscall numbers from `<sys/syscall.h>`. Use the 64-bit stat
    // family because `libc::stat` is the 64-bit ABI on supported macOS.
    const SYS_STAT64: c_int = 338;
    const SYS_FSTAT64: c_int = 339;
    const SYS_LSTAT64: c_int = 340;

    pub unsafe fn real_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        libc::syscall(SYS_STAT64, path, buf) as c_int
    }

    pub unsafe fn real_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        libc::syscall(SYS_LSTAT64, path, buf) as c_int
    }

    pub unsafe fn real_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
        libc::syscall(SYS_FSTAT64, fd, buf) as c_int
    }
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn real_fstatat_call(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    // Darwin syscall number from `<sys/syscall.h>`.
    const SYS_FSTATAT64: c_int = 470;
    libc::syscall(SYS_FSTATAT64, dirfd, path, buf, flags) as c_int
}

#[cfg(not(target_os = "macos"))]
#[inline]
unsafe fn real_fstatat_call(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    get_real_fstatat()(dirfd, path, buf, flags)
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

/// Read errno in a cross-platform way.
#[inline]
unsafe fn errno() -> c_int {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error()
    }
}

// ── Re-entry guard ───────────────────────────────────────────────────────
//
// LD_PRELOAD/DYLD interposition makes the symbols this shim exports (`close`,
// `access`, `openat`, …) shadow libc *even for calls the shim itself makes*.
// So a hooked function that internally calls one of those symbols — or a signal
// handler that runs on a thread already inside a hook and calls a hooked I/O
// function — re-enters the shim. That re-entry is fatal in three ways:
//
//   1. `parking_lot::RwLock` on the fd table is NOT recursive: a second
//      acquisition on the same thread deadlocks.
//   2. The thread-local daemon client is a `RefCell`; a second `borrow_mut`
//      while one is live panics, and a panic unwinding across the cdylib FFI
//      boundary aborts the host process.
//   3. A signal handler that calls a hooked function while the interrupted
//      frame holds either lock would deadlock/panic the host.
//
// The guard makes every primary hook re-entry-safe: the outermost hook on a
// thread sets a thread-local flag; any nested hook entry sees the flag and
// passes straight through to the real libc function, touching no shim state.
// This is the same technique malloc-replacement shims (jemalloc/tcmalloc) use.
// It also makes the shim's own intra-library libc calls (`libc::close` of a
// socket fd, `libc::access` in `materialize_file`) resolve to the REAL libc
// rather than recursing through our own hooks.
//
// The flag is `const`-initialized so its TLS slot needs no lazy allocation
// (matching the `CLIENT` thread-local in client.rs); reads/writes are plain
// loads/stores, which is the most async-signal-safe TLS can be. The slot is
// materialized on the outermost (normal-context) entry, so a signal handler
// re-entering only ever loads an already-allocated slot.

thread_local! {
    static IN_SHIM: Cell<bool> = const { Cell::new(false) };
}

/// RAII re-entry guard. [`enter`](ReentryGuard::enter) returns `None` when the
/// current thread is already executing inside a hook — the caller must then
/// pass straight through to the real libc function. Otherwise it marks the
/// thread as in-shim and captures the caller's `errno`, clearing the flag on
/// drop.
struct ReentryGuard {
    /// errno as the host had it on entry; restored by [`ok`](ReentryGuard::ok)
    /// on synthesized-success paths.
    saved_errno: c_int,
}

impl ReentryGuard {
    #[inline]
    fn enter() -> Option<Self> {
        IN_SHIM.with(|flag| {
            if flag.get() {
                None
            } else {
                flag.set(true);
                Some(ReentryGuard {
                    saved_errno: unsafe { errno() },
                })
            }
        })
    }

    /// Restore `errno` to its entry value and return `ret`. Used on
    /// synthesized-success paths so a successful hook leaves errno exactly as
    /// the caller had it. Real libc never sets errno on success, but the shim's
    /// daemon socket I/O (connect/poll/read) clobbers it; host libc wrappers
    /// that inspect errno after a successful call (`readdir` EOF detection,
    /// `read` EOF) would otherwise misread the stale value as a failure.
    #[inline]
    unsafe fn ok<T>(&self, ret: T) -> T {
        set_errno(self.saved_errno);
        ret
    }
}

impl Drop for ReentryGuard {
    #[inline]
    fn drop(&mut self) {
        IN_SHIM.with(|flag| flag.set(false));
    }
}

// ── Synthetic inode ──────────────────────────────────────────────────────

/// Compute a unique synthetic inode from a file path using FNV-1a hash.
/// This ensures different virtual files get different inode numbers,
/// which tools like `find`, `tar`, and hardlink detectors depend on.
///
/// Delegates to the pure [`kin_vfs_core::pathmap::synthetic_inode`] seam so the
/// inode hashing has a single definition that is unit-tested and fuzzed in
/// kin-vfs-core without pulling these interposing hooks into the fuzz binary.
#[inline]
fn path_to_inode(path: &str) -> u64 {
    kin_vfs_core::pathmap::synthetic_inode(path)
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
// The trailing `return Some(...)` in each platform `#[cfg]` block is required:
// clippy sees only the active cfg branch and flags it as needless, but those
// branches are `#[cfg]`-attributed *statements*, not tail expressions, so
// dropping `return` would leave the fn with no value on the other platform.
#[allow(clippy::needless_return)]
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
        return Some(kin_vfs_core::pathmap::join_at_path(cwd_str, path_str));
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
        return Some(kin_vfs_core::pathmap::join_at_path(dir_path, path_str));
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
        return Some(kin_vfs_core::pathmap::join_at_path(dir_path, path_str));
    }
}

/// Check if flags indicate a write operation.
#[inline]
fn is_write_flags(flags: c_int) -> bool {
    (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC)) != 0
}

/// Generate the temp file path for atomic writes.
/// Format: `{target_path}.kin_tmp_{pid}`
///
/// Delegates the formatting to the pure [`kin_vfs_core::pathmap::atomic_temp_path`]
/// seam, whose round-trip with `is_interpose_temp_artifact` is fuzzed so the
/// temp-file exclusion in [`is_workspace_path`](crate::is_workspace_path) can
/// never drift out of sync with the names produced here.
fn atomic_temp_path(target: &str) -> String {
    let pid = unsafe { libc::getpid() };
    kin_vfs_core::pathmap::atomic_temp_path(target, pid)
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

/// Materialize-on-write: seed the on-disk file from **graph truth** before a
/// tool writes to it, atomically. The caller opens the returned temp file; on
/// close it is renamed to the final path. Returns the temp path on success, or
/// `None` when there is no graph truth to seed (a genuinely new file, or the
/// daemon is unreachable) — in which case the caller opens the real path.
///
/// FIR-950: the previous implementation short-circuited whenever the file
/// already existed on disk (`access(F_OK)`), handing the tool the **stale disk
/// copy** without ever consulting the graph. That silently entrenched
/// filesystem authority over graph truth — exactly the drift the thesis warns
/// against. Authority semantics now: **graph wins.** If the daemon has content
/// for this path, we materialize THAT (overwriting any stale on-disk bytes) so
/// a read-modify-write or append starts from graph truth. Only when the graph
/// has no record of the path do we defer to the disk / let the tool create it.
fn materialize_file(path_str: &str) -> Option<String> {
    let state = shim_state()?;

    // Clean up stale temp files from previous crashed processes.
    cleanup_stale_temps(path_str);

    // Consult graph truth FIRST. `None` means the daemon doesn't know this path
    // (new file, or daemon unreachable) — defer to the real filesystem: return
    // None so the caller opens the path directly and the tool can create it.
    let content = client::client_read_file(&state.sock_path, path_str)?;

    // Graph truth exists -> it is authoritative. Seed the file from graph
    // content, overwriting any stale on-disk copy (the FIR-950 fix). Create
    // parent directories first so the write lands even for not-yet-checked-out
    // paths.
    if let Some(parent) = std::path::Path::new(path_str).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Write content to a temp file (atomic write pattern); the caller renames
    // temp -> target on close.
    let temp = atomic_temp_path(path_str);
    match std::fs::write(&temp, &content) {
        Ok(()) => Some(temp),
        Err(_) => {
            // Temp write failed (e.g. read-only dir): fall back to writing graph
            // truth straight to the target so the tool still starts from it.
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

    state
        .fd_table
        .write()
        .allocate(path_str, size, content)
        .unwrap_or(-1)
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
                FileType::Directory => 4, // DT_DIR
                FileType::Symlink => 10,  // DT_LNK
            };
            // Synthetic inode from name hash (same pure FNV-1a seam as
            // `path_to_inode`, defined once in kin-vfs-core).
            let d_ino = kin_vfs_core::pathmap::synthetic_inode(&e.name);
            DirEntryRaw {
                name: e.name,
                d_ino,
                d_type,
            }
        })
        .collect();

    state
        .fd_table
        .write()
        .allocate_dir(path_str, raw_entries)
        .unwrap_or(-1)
}

fn duplicate_virtual_fd(src_fd: c_int) -> c_int {
    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    state.fd_table.write().duplicate(src_fd).unwrap_or(-1)
}

fn duplicate_virtual_fd_into(src_fd: c_int, dst_fd: c_int) -> c_int {
    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    state
        .fd_table
        .write()
        .duplicate_into(src_fd, dst_fd)
        .unwrap_or(-1)
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
    matches!(
        client::client_stat(&state.sock_path, path_str),
        Some(vstat) if vstat.is_dir
    )
}

// ── Intercepted syscalls ────────────────────────────────────────────────

/// Intercepted `open(2)`.
///
/// On the C ABI level, `open()` is variadic (mode is only present when
/// O_CREAT is set). However, at the machine level the third argument is
/// always passed in a register, so we can safely declare a fixed 3-arg
/// signature. This avoids requiring nightly `c_variadic`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    if is_disabled() {
        return real_open_call(path, flags, mode);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_open_call(path, flags, mode),
    };

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return real_open_call(path, flags, mode),
    };

    if !is_workspace_path(path_str) {
        return real_open_call(path, flags, mode);
    }

    // Write flags -> materialize then passthrough, tracking the fd.
    if is_write_flags(flags) {
        let temp = materialize_file(path_str);
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match CString::new(temp_path.as_str()) {
                Ok(c) => c,
                Err(_) => return real_open_call(path, flags, mode),
            };
            let fd = real_open_call(c_temp.as_ptr(), flags, mode);
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
        let fd = real_open_call(path, flags, mode);
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
            _ => return real_open_call(path, flags, mode),
        }
    }

    // Read-only open -> virtual fd from daemon.
    let state = match shim_state() {
        Some(s) => s,
        None => return real_open_call(path, flags, mode),
    };

    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) if vstat.is_file => {
            let content = client::client_read_file(&state.sock_path, path_str);
            // Use content length as effective size when stat reports 0
            // (KinDaemonProvider only caches path→hash, not sizes).
            let effective_size = content
                .as_ref()
                .map(|c| c.len() as u64)
                .unwrap_or(vstat.size);
            match allocate_vfd(path_str, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_open_call(path, flags, mode),
            }
        }
        _ => real_open_call(path, flags, mode),
    }
}

/// Intercepted `openat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    if is_disabled() {
        return real_openat_call(dirfd, path, flags, mode);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_openat_call(dirfd, path, flags, mode),
    };

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_openat_call(dirfd, path, flags, mode),
    };

    if !is_workspace_path(&resolved) {
        return real_openat_call(dirfd, path, flags, mode);
    }

    if is_write_flags(flags) {
        let temp = materialize_file(&resolved);
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match CString::new(temp_path.as_str()) {
                Ok(c) => c,
                Err(_) => return real_openat_call(dirfd, path, flags, mode),
            };
            let fd = real_openat_call(libc::AT_FDCWD, c_temp.as_ptr(), flags, mode);
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
        let fd = real_openat_call(dirfd, path, flags, mode);
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
            _ => return real_openat_call(dirfd, path, flags, mode),
        }
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_openat_call(dirfd, path, flags, mode),
    };

    match client::client_stat(&state.sock_path, &resolved) {
        Some(vstat) if vstat.is_file => {
            let content = client::client_read_file(&state.sock_path, &resolved);
            // Use content length as effective size when stat reports 0
            // (KinDaemonProvider only caches path→hash, not sizes).
            let effective_size = content
                .as_ref()
                .map(|c| c.len() as u64)
                .unwrap_or(vstat.size);
            match allocate_vfd(&resolved, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_openat_call(dirfd, path, flags, mode),
            }
        }
        _ => real_openat_call(dirfd, path, flags, mode),
    }
}

/// Intercepted `dup(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn dup(fd: c_int) -> c_int {
    let real_dup = get_real_dup();

    if is_disabled() || fd < vfd_base() {
        return real_dup(fd);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_dup(fd),
    };

    let duplicated = duplicate_virtual_fd(fd);
    if duplicated >= vfd_base() {
        duplicated
    } else {
        real_dup(fd)
    }
}

/// Intercepted `dup2(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let real_dup2 = get_real_dup2();

    if is_disabled() || oldfd < vfd_base() {
        return real_dup2(oldfd, newfd);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_dup2(oldfd, newfd),
    };

    if oldfd == newfd {
        return newfd;
    }

    if newfd < vfd_base() {
        return real_dup2(oldfd, newfd);
    }

    let duplicated = duplicate_virtual_fd_into(oldfd, newfd);
    if duplicated >= vfd_base() {
        duplicated
    } else {
        real_dup2(oldfd, newfd)
    }
}

/// Intercepted `dup3(2)`.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[no_mangle]
pub unsafe extern "C" fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
    let real_dup3 = get_real_dup3();

    if is_disabled() || oldfd < vfd_base() {
        return real_dup3(oldfd, newfd, flags);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_dup3(oldfd, newfd, flags),
    };

    if oldfd == newfd {
        set_errno(libc::EINVAL);
        return -1;
    }

    if flags & !libc::O_CLOEXEC != 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    if newfd < vfd_base() {
        return real_dup3(oldfd, newfd, flags);
    }

    let duplicated = duplicate_virtual_fd_into(oldfd, newfd);
    if duplicated >= vfd_base() {
        duplicated
    } else {
        real_dup3(oldfd, newfd, flags)
    }
}

/// Intercepted `flock(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let real_flock = get_real_flock();

    if is_disabled() || fd < vfd_base() {
        return real_flock(fd, operation);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_flock(fd, operation),
    };

    let state = match shim_state() {
        Some(s) => s,
        None => return real_flock(fd, operation),
    };

    let mut fd_table = state.fd_table.write();
    if fd_table.get(fd).is_none() {
        return real_flock(fd, operation);
    }

    match operation & !libc::LOCK_NB {
        libc::LOCK_UN => fd_table.set_flock(fd, false),
        libc::LOCK_SH | libc::LOCK_EX => fd_table.set_flock(fd, true),
        _ => fd_table.set_flock(fd, true),
    }

    0
}

/// Intercepted `read(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    if is_disabled() || fd < vfd_base() {
        return real_read_call(fd, buf, count);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_read_call(fd, buf, count),
    };

    let state = match shim_state() {
        Some(s) => s,
        None => return real_read_call(fd, buf, count),
    };

    // Get handle info under write lock (we may need to advance offset).
    let mut fd_table = state.fd_table.write();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return real_read_call(fd, buf, count),
    };

    let offset = handle.offset;
    let size = handle.size;
    let path = handle.path.clone();

    // Check if we're at or past EOF.
    if offset >= size {
        return guard.ok(0);
    }

    let bytes_to_read = count.min((size - offset) as usize);
    if bytes_to_read == 0 {
        return guard.ok(0);
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
            return guard.ok(n as libc::ssize_t);
        }
    }

    // Not cached — read range from daemon. Must drop the lock first.
    drop(fd_table);

    let data =
        match client::client_read_range(&state.sock_path, &path, offset, bytes_to_read as u64) {
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

    guard.ok(n as libc::ssize_t)
}

/// Intercepted `pread(2)` / `pread64(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn pread(
    fd: c_int,
    buf: *mut c_void,
    count: libc::size_t,
    offset: libc::off_t,
) -> libc::ssize_t {
    if is_disabled() || fd < vfd_base() {
        return real_pread_call(fd, buf, count, offset);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_pread_call(fd, buf, count, offset),
    };

    let state = match shim_state() {
        Some(s) => s,
        None => return real_pread_call(fd, buf, count, offset),
    };

    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return real_pread_call(fd, buf, count, offset),
    };

    let size = handle.size;
    let path = handle.path.clone();
    let off = offset as u64;

    if off >= size {
        return guard.ok(0);
    }

    let bytes_to_read = count.min((size - off) as usize);
    if bytes_to_read == 0 {
        return guard.ok(0);
    }

    // Try cached content.
    if let Some(ref content) = handle.cached_content {
        let start = off as usize;
        let end = (start + bytes_to_read).min(content.len());
        if start < content.len() {
            let slice = &content[start..end];
            let n = slice.len();
            std::ptr::copy_nonoverlapping(slice.as_ptr(), buf as *mut u8, n);
            return guard.ok(n as libc::ssize_t);
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
    guard.ok(n as libc::ssize_t)
}

/// Intercepted `close(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    if is_disabled() {
        return real_close_call(fd);
    }

    // Re-entry (e.g. the shim's own `libc::close` of a socket or temp fd)
    // passes straight through — those are real fds we never track.
    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_close_call(fd),
    };

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
            let ret = real_close_call(fd);
            // Atomic rename: temp -> target. If rename fails, the temp file
            // stays on disk but the real file is not corrupted.
            let _ = std::fs::rename(&entry.temp_path, &entry.target_path);
            if let Some(wp) = write_path {
                client::notify_file_changed(&wp);
            }
            return ret;
        }

        if let Some(wp) = write_path {
            let ret = real_close_call(fd);
            client::notify_file_changed(&wp);
            return ret;
        }
    }

    real_close_call(fd)
}

/// Intercepted `lseek(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    if is_disabled() || fd < vfd_base() {
        return real_lseek_call(fd, offset, whence);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_lseek_call(fd, offset, whence),
    };

    let state = match shim_state() {
        Some(s) => s,
        None => return real_lseek_call(fd, offset, whence),
    };

    match state.fd_table.write().seek(fd, offset, whence) {
        Some(new_offset) => new_offset as libc::off_t,
        None => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Intercepted `stat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::real_stat(path, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::real_stat(path, buf),
    };

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
            guard.ok(0)
        }
        None => stat_fns::real_stat(path, buf),
    }
}

/// Intercepted `lstat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::real_lstat(path, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::real_lstat(path, buf),
    };

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
            guard.ok(0)
        }
        None => stat_fns::real_lstat(path, buf),
    }
}

/// Intercepted `fstat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat_fns::real_fstat(fd, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::real_fstat(fd, buf),
    };

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
            guard.ok(0)
        }
        None => {
            set_errno(libc::EBADF);
            -1
        }
    }
}

/// Intercepted `fstatat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    if is_disabled() {
        return real_fstatat_call(dirfd, path, buf, flags);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_fstatat_call(dirfd, path, buf, flags),
    };

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_fstatat_call(dirfd, path, buf, flags),
    };

    if !is_workspace_path(&resolved) {
        return real_fstatat_call(dirfd, path, buf, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_fstatat_call(dirfd, path, buf, flags),
    };

    match client::client_stat(&state.sock_path, &resolved) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        None => real_fstatat_call(dirfd, path, buf, flags),
    }
}

/// Intercepted `access(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    if is_disabled() {
        return real_access_call(path, mode);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_access_call(path, mode),
    };

    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return real_access_call(path, mode),
    };

    if !is_workspace_path(path_str) {
        return real_access_call(path, mode);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_access_call(path, mode),
    };

    match client::client_access(&state.sock_path, path_str, mode as u32) {
        Some(true) => guard.ok(0),
        Some(false) => {
            set_errno(libc::EACCES);
            -1
        }
        None => real_access_call(path, mode),
    }
}

/// Intercepted `faccessat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    if is_disabled() {
        return real_faccessat_call(dirfd, path, mode, flags);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_faccessat_call(dirfd, path, mode, flags),
    };

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return real_faccessat_call(dirfd, path, mode, flags),
    };

    if !is_workspace_path(&resolved) {
        return real_faccessat_call(dirfd, path, mode, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_faccessat_call(dirfd, path, mode, flags),
    };

    match client::client_access(&state.sock_path, &resolved, mode as u32) {
        Some(true) => guard.ok(0),
        Some(false) => {
            set_errno(libc::EACCES);
            -1
        }
        None => real_faccessat_call(dirfd, path, mode, flags),
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

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_getdents64(fd, buf, buf_size),
    };

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

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_fn(fd, buf, buf_size, basep),
    };

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
#[cfg_attr(not(target_os = "macos"), no_mangle)]
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

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_mmap(addr, len, prot, flags, fd, offset),
    };

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
    let result = mmap_via_tempfile(&content, map_len, prot, flags, offset, real_mmap);

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
    state.fd_table.write().track_mmap(ptr as usize, map_len);

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
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: libc::size_t) -> c_int {
    let real_munmap = get_real_munmap();

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_munmap(addr, len),
    };

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
#[cfg_attr(not(target_os = "macos"), no_mangle)]
pub unsafe extern "C" fn readlink(
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: libc::size_t,
) -> libc::ssize_t {
    let real_readlink = get_real_readlink();

    if is_disabled() {
        return real_readlink(path, buf, bufsiz);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_readlink(path, buf, bufsiz),
    };

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
            guard.ok(copy_len as libc::ssize_t)
        }
        None => real_readlink(path, buf, bufsiz),
    }
}

/// Intercepted `readlinkat(2)`.
#[cfg_attr(not(target_os = "macos"), no_mangle)]
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

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_readlinkat(dirfd, path, buf, bufsiz),
    };

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
            guard.ok(copy_len as libc::ssize_t)
        }
        None => real_readlinkat(dirfd, path, buf, bufsiz),
    }
}

// ── Linux-specific __xstat family ───────────────────────────────────────

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __xstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::call_real_xstat(ver, path, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::call_real_xstat(ver, path, buf),
    };

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
            guard.ok(0)
        }
        None => stat_fns::call_real_xstat(ver, path, buf),
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __lxstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    if is_disabled() {
        return stat_fns::call_real_lxstat(ver, path, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::call_real_lxstat(ver, path, buf),
    };

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
            guard.ok(0)
        }
        None => stat_fns::call_real_lxstat(ver, path, buf),
    }
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __fxstat(ver: c_int, fd: c_int, buf: *mut libc::stat) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat_fns::call_real_fxstat(ver, fd, buf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat_fns::call_real_fxstat(ver, fd, buf),
    };

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
            guard.ok(0)
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
pub unsafe extern "C" fn stat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    stat(path, buf)
}

#[cfg(target_os = "macos")]
pub unsafe extern "C" fn lstat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    lstat(path, buf)
}

#[cfg(target_os = "macos")]
pub unsafe extern "C" fn fstat64(fd: c_int, buf: *mut libc::stat) -> c_int {
    fstat(fd, buf)
}

// ── Linux statx(2) ──────────────────────────────────────────────────────
//
// Modern coreutils (`ls`, `stat`, `cp`, GNU `find`, …) issue `statx(2)` instead
// of `stat`/`lstat`/`fstat`. Without this hook those tools bypass the projection
// and silently read the real disk — the Linux analogue of the macOS SIP gap.

#[cfg(target_os = "linux")]
type StatxFn =
    unsafe extern "C" fn(c_int, *const c_char, c_int, libc::c_uint, *mut libc::statx) -> c_int;
#[cfg(target_os = "linux")]
real_fn!(get_real_statx, STORE_STATX, b"statx\0", StatxFn);

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn statx(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_int,
    mask: libc::c_uint,
    statxbuf: *mut libc::statx,
) -> c_int {
    let real = get_real_statx();

    if is_disabled() {
        return real(dirfd, pathname, flags, mask, statxbuf);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real(dirfd, pathname, flags, mask, statxbuf),
    };

    // Resolve the target path. statx supports AT_EMPTY_PATH (operate on `dirfd`
    // itself when the pathname is empty) — coreutils use it for fstat-like
    // queries, including against our virtual fds.
    let empty = pathname.is_null() || c_to_str(pathname).map(str::is_empty).unwrap_or(true);
    let resolved = if empty && (flags & libc::AT_EMPTY_PATH) != 0 {
        if dirfd >= vfd_base() {
            match shim_state() {
                Some(state) => {
                    let fd_table = state.fd_table.read();
                    match fd_table.get(dirfd) {
                        Some(handle) => handle.path.clone(),
                        None => return real(dirfd, pathname, flags, mask, statxbuf),
                    }
                }
                None => return real(dirfd, pathname, flags, mask, statxbuf),
            }
        } else {
            // Real fd / cwd — let the kernel answer.
            return real(dirfd, pathname, flags, mask, statxbuf);
        }
    } else {
        match resolve_at_path(dirfd, pathname) {
            Some(p) => p,
            None => return real(dirfd, pathname, flags, mask, statxbuf),
        }
    };

    if !is_workspace_path(&resolved) {
        return real(dirfd, pathname, flags, mask, statxbuf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real(dirfd, pathname, flags, mask, statxbuf),
    };

    match client::client_stat(&state.sock_path, &resolved) {
        Some(vstat) => {
            platform::fill_statx_buf(&vstat, statxbuf);
            (*statxbuf).stx_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        None => real(dirfd, pathname, flags, mask, statxbuf),
    }
}

// ── Linux _FORTIFY_SOURCE hooks ─────────────────────────────────────────
//
// Distros (Debian/Ubuntu/Fedora) build binaries with `_FORTIFY_SOURCE`, which
// rewrites `open`/`read`/`readlink` to fortified `__*_2` / `__*_chk` variants.
// Unhooked, those bypass the shim. Each fortified hook discards the
// compile-time-size bookkeeping and routes through our standard hook, except
// when the request would overflow the caller's buffer — then we delegate to the
// real fortified entry so glibc's `__chk_fail` abort fires instead of letting an
// overflow through.

#[cfg(target_os = "linux")]
type Open2Fn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
#[cfg(target_os = "linux")]
type Openat2Fn = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
#[cfg(target_os = "linux")]
type ReadChkFn =
    unsafe extern "C" fn(c_int, *mut c_void, libc::size_t, libc::size_t) -> libc::ssize_t;
#[cfg(target_os = "linux")]
type PreadChkFn = unsafe extern "C" fn(
    c_int,
    *mut c_void,
    libc::size_t,
    libc::off_t,
    libc::size_t,
) -> libc::ssize_t;
#[cfg(target_os = "linux")]
type ReadlinkChkFn =
    unsafe extern "C" fn(*const c_char, *mut c_char, libc::size_t, libc::size_t) -> libc::ssize_t;
#[cfg(target_os = "linux")]
type ReadlinkatChkFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    *mut c_char,
    libc::size_t,
    libc::size_t,
) -> libc::ssize_t;

#[cfg(target_os = "linux")]
real_fn!(get_real_open_2, STORE_OPEN_2, b"__open_2\0", Open2Fn);
#[cfg(target_os = "linux")]
real_fn!(get_real_open64_2, STORE_OPEN64_2, b"__open64_2\0", Open2Fn);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_openat_2,
    STORE_OPENAT_2,
    b"__openat_2\0",
    Openat2Fn
);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_openat64_2,
    STORE_OPENAT64_2,
    b"__openat64_2\0",
    Openat2Fn
);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_read_chk,
    STORE_READ_CHK,
    b"__read_chk\0",
    ReadChkFn
);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_pread_chk,
    STORE_PREAD_CHK,
    b"__pread_chk\0",
    PreadChkFn
);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_readlink_chk,
    STORE_READLINK_CHK,
    b"__readlink_chk\0",
    ReadlinkChkFn
);
#[cfg(target_os = "linux")]
real_fn!(
    get_real_readlinkat_chk,
    STORE_READLINKAT_CHK,
    b"__readlinkat_chk\0",
    ReadlinkatChkFn
);

/// Fortified 2-arg `open`. glibc aborts when `O_CREAT` is set (a mode arg is
/// required but absent); preserve that, otherwise route through `open`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    if (flags & libc::O_CREAT) != 0 {
        return get_real_open_2()(path, flags);
    }
    open(path, flags, 0)
}

/// Fortified 2-arg `open64` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    if (flags & libc::O_CREAT) != 0 {
        return get_real_open64_2()(path, flags);
    }
    open(path, flags, 0)
}

/// Fortified 3-arg `openat`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    if (flags & libc::O_CREAT) != 0 {
        return get_real_openat_2()(dirfd, path, flags);
    }
    openat(dirfd, path, flags, 0)
}

/// Fortified 3-arg `openat64` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    if (flags & libc::O_CREAT) != 0 {
        return get_real_openat64_2()(dirfd, path, flags);
    }
    openat(dirfd, path, flags, 0)
}

/// Fortified `read`. Overflow (`nbytes > buflen`) is delegated to the real
/// `__read_chk` so glibc's abort fires; real fds pass straight through.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __read_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: libc::size_t,
    buflen: libc::size_t,
) -> libc::ssize_t {
    if is_disabled() || fd < vfd_base() || !crate::statfill::fortify_within_bounds(nbytes, buflen) {
        return get_real_read_chk()(fd, buf, nbytes, buflen);
    }
    read(fd, buf, nbytes)
}

/// Fortified `pread` / `pread64`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __pread_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: libc::size_t,
    offset: libc::off_t,
    buflen: libc::size_t,
) -> libc::ssize_t {
    if is_disabled() || fd < vfd_base() || !crate::statfill::fortify_within_bounds(nbytes, buflen) {
        return get_real_pread_chk()(fd, buf, nbytes, offset, buflen);
    }
    pread(fd, buf, nbytes, offset)
}

/// Fortified `pread64` (LFS) — same 64-bit offset width as `pread` on LP64.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __pread64_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: libc::size_t,
    offset: libc::off_t,
    buflen: libc::size_t,
) -> libc::ssize_t {
    __pread_chk(fd, buf, nbytes, offset, buflen)
}

/// Fortified `readlink`. Overflow is delegated to the real `__readlink_chk`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __readlink_chk(
    path: *const c_char,
    buf: *mut c_char,
    len: libc::size_t,
    buflen: libc::size_t,
) -> libc::ssize_t {
    if is_disabled() || !crate::statfill::fortify_within_bounds(len, buflen) {
        return get_real_readlink_chk()(path, buf, len, buflen);
    }
    readlink(path, buf, len)
}

/// Fortified `readlinkat`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __readlinkat_chk(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: libc::size_t,
    buflen: libc::size_t,
) -> libc::ssize_t {
    if is_disabled() || !crate::statfill::fortify_within_bounds(len, buflen) {
        return get_real_readlinkat_chk()(dirfd, path, buf, len, buflen);
    }
    readlinkat(dirfd, path, buf, len)
}

// ── Linux Large File Support (LFS) open/stat aliases ────────────────────
//
// Binaries compiled with `_FILE_OFFSET_BITS=64` call the `*64` symbols. The
// open variants funnel into the standard hooks; the stat64 variants fill the
// 64-bit `stat64` struct. Each real-passthrough resolves the *same* symbol it
// hooks, so it is safe across glibc versions and musl (the host only calls a
// symbol its libc actually exports).

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    open(path, flags, mode)
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    openat(dirfd, path, flags, mode)
}

#[cfg(target_os = "linux")]
mod stat64_fns {
    use super::*;

    type Stat64Fn = unsafe extern "C" fn(*const c_char, *mut libc::stat64) -> c_int;
    type Fstat64Fn = unsafe extern "C" fn(c_int, *mut libc::stat64) -> c_int;
    type Xstat64Fn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat64) -> c_int;
    type Fxstat64Fn = unsafe extern "C" fn(c_int, c_int, *mut libc::stat64) -> c_int;

    real_fn!(get_real_stat64, STORE_STAT64, b"stat64\0", Stat64Fn);
    real_fn!(get_real_lstat64, STORE_LSTAT64, b"lstat64\0", Stat64Fn);
    real_fn!(get_real_fstat64, STORE_FSTAT64, b"fstat64\0", Fstat64Fn);
    real_fn!(get_real_xstat64, STORE_XSTAT64, b"__xstat64\0", Xstat64Fn);
    real_fn!(
        get_real_lxstat64,
        STORE_LXSTAT64,
        b"__lxstat64\0",
        Xstat64Fn
    );
    real_fn!(
        get_real_fxstat64,
        STORE_FXSTAT64,
        b"__fxstat64\0",
        Fxstat64Fn
    );

    pub unsafe fn real_stat64(path: *const c_char, buf: *mut libc::stat64) -> c_int {
        get_real_stat64()(path, buf)
    }
    pub unsafe fn real_lstat64(path: *const c_char, buf: *mut libc::stat64) -> c_int {
        get_real_lstat64()(path, buf)
    }
    pub unsafe fn real_fstat64(fd: c_int, buf: *mut libc::stat64) -> c_int {
        get_real_fstat64()(fd, buf)
    }
    pub unsafe fn call_real_xstat64(
        ver: c_int,
        path: *const c_char,
        buf: *mut libc::stat64,
    ) -> c_int {
        get_real_xstat64()(ver, path, buf)
    }
    pub unsafe fn call_real_lxstat64(
        ver: c_int,
        path: *const c_char,
        buf: *mut libc::stat64,
    ) -> c_int {
        get_real_lxstat64()(ver, path, buf)
    }
    pub unsafe fn call_real_fxstat64(ver: c_int, fd: c_int, buf: *mut libc::stat64) -> c_int {
        get_real_fxstat64()(ver, fd, buf)
    }
}

/// Intercepted `stat64(2)` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn stat64(path: *const c_char, buf: *mut libc::stat64) -> c_int {
    if is_disabled() {
        return stat64_fns::real_stat64(path, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::real_stat64(path, buf),
    };
    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat64_fns::real_stat64(path, buf),
    };
    if !is_workspace_path(path_str) {
        return stat64_fns::real_stat64(path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::real_stat64(path, buf),
    };
    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        None => stat64_fns::real_stat64(path, buf),
    }
}

/// Intercepted `lstat64(2)` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn lstat64(path: *const c_char, buf: *mut libc::stat64) -> c_int {
    if is_disabled() {
        return stat64_fns::real_lstat64(path, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::real_lstat64(path, buf),
    };
    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat64_fns::real_lstat64(path, buf),
    };
    if !is_workspace_path(path_str) {
        return stat64_fns::real_lstat64(path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::real_lstat64(path, buf),
    };
    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        None => stat64_fns::real_lstat64(path, buf),
    }
}

/// Intercepted `fstat64(2)` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn fstat64(fd: c_int, buf: *mut libc::stat64) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat64_fns::real_fstat64(fd, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::real_fstat64(fd, buf),
    };
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::real_fstat64(fd, buf),
    };
    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return stat64_fns::real_fstat64(fd, buf),
    };
    let path = handle.path.clone();
    drop(fd_table);

    match client::client_stat(&state.sock_path, &path) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path);
            guard.ok(0)
        }
        None => {
            set_errno(libc::EBADF);
            -1
        }
    }
}

/// Intercepted versioned `__xstat64` (older glibc LFS stat).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __xstat64(
    ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat64,
) -> c_int {
    if is_disabled() {
        return stat64_fns::call_real_xstat64(ver, path, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::call_real_xstat64(ver, path, buf),
    };
    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat64_fns::call_real_xstat64(ver, path, buf),
    };
    if !is_workspace_path(path_str) {
        return stat64_fns::call_real_xstat64(ver, path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::call_real_xstat64(ver, path, buf),
    };
    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        None => stat64_fns::call_real_xstat64(ver, path, buf),
    }
}

/// Intercepted versioned `__lxstat64` (older glibc LFS lstat).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __lxstat64(
    ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat64,
) -> c_int {
    if is_disabled() {
        return stat64_fns::call_real_lxstat64(ver, path, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::call_real_lxstat64(ver, path, buf),
    };
    let path_str = match c_to_str(path) {
        Some(s) => s,
        None => return stat64_fns::call_real_lxstat64(ver, path, buf),
    };
    if !is_workspace_path(path_str) {
        return stat64_fns::call_real_lxstat64(ver, path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::call_real_lxstat64(ver, path, buf),
    };
    match client::client_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        None => stat64_fns::call_real_lxstat64(ver, path, buf),
    }
}

/// Intercepted versioned `__fxstat64` (older glibc LFS fstat).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __fxstat64(ver: c_int, fd: c_int, buf: *mut libc::stat64) -> c_int {
    if is_disabled() || fd < vfd_base() {
        return stat64_fns::call_real_fxstat64(ver, fd, buf);
    }
    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return stat64_fns::call_real_fxstat64(ver, fd, buf),
    };
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::call_real_fxstat64(ver, fd, buf),
    };
    let fd_table = state.fd_table.read();
    let handle = match fd_table.get(fd) {
        Some(h) => h,
        None => return stat64_fns::call_real_fxstat64(ver, fd, buf),
    };
    let path = handle.path.clone();
    drop(fd_table);

    match client::client_stat(&state.sock_path, &path) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path);
            guard.ok(0)
        }
        None => {
            set_errno(libc::EBADF);
            -1
        }
    }
}

// ── macOS DYLD interposition table (FIR-909) ─────────────────────────────
//
// On macOS the dynamic linker uses a **two-level namespace**: every call site
// records which library a symbol was bound from (e.g. `open` → `libsystem_
// kernel.dylib`). A plain replacement function in a dylib inserted via
// `DYLD_INSERT_LIBRARIES` therefore does NOT shadow those already-recorded
// bindings — unlike Linux `LD_PRELOAD`, where a preloaded global symbol wins.
//
// The supported mechanism is a `__DATA,__interpose` section: an array of
// `{ replacement, replacee }` function-pointer pairs. dyld reads this section
// at load time and rewrites the binding table so every call to `replacee`
// (the real libc symbol) lands on `replacement` (our hook) — process-wide,
// across all already-linked images. This is exactly what the C `DYLD_INTERPOSE`
// macro emits; we reproduce its layout here in Rust.
//
// Without this table the macOS hooks below compile and the constructor runs,
// but the hooks NEVER fire for cargo/rustc/an editor — reads silently fall
// through to the real disk instead of the graph. (The Linux `.init_array` +
// global-symbol path needs no interpose table; this section is macOS-only.)
//
// `RTLD_NEXT` inside our `get_real_*()` resolvers still finds the genuine libc
// symbol (it skips our own image), so the existing hook bodies are unchanged;
// this table only routes *external* callers' libc calls into those hooks.
#[cfg(target_os = "macos")]
mod macos_interpose {
    use super::*;
    use std::os::raw::{c_char, c_long, c_void};

    // Symbol not exposed as a function by the `libc` crate on macOS, declared
    // so its address can be placed in the interpose table as the `replacee`.
    // Signature mirrors the corresponding hook above.
    extern "C" {
        fn __getdirentries64(
            fd: c_int,
            buf: *mut c_char,
            nbytes: libc::size_t,
            basep: *mut c_long,
        ) -> libc::ssize_t;
    }

    /// One `{ replacement, replacee }` pair, matching the C ABI dyld expects
    /// for `__DATA,__interpose` entries (two pointer-sized words).
    #[repr(C)]
    struct Interpose {
        replacement: *const c_void,
        replacee: *const c_void,
    }

    // The table holds raw function pointers; it is read-only after load and
    // only ever consulted by dyld, so it is safe to share across threads.
    unsafe impl Sync for Interpose {}

    /// Helper to construct an entry, casting both fns to opaque pointers.
    const fn entry(replacement: *const c_void, replacee: *const c_void) -> Interpose {
        Interpose {
            replacement,
            replacee,
        }
    }

    /// The interpose table. `#[used]` keeps the linker from dead-stripping it;
    /// `link_section = "__DATA_CONST,__interpose"` is the section dyld scans on
    /// modern macOS toolchains. Each
    /// replacement is one of our exported hooks; each replacee is the real libc
    /// symbol it must shadow.
    #[used]
    #[link_section = "__DATA_CONST,__interpose"]
    static INTERPOSE_TABLE: [Interpose; 18] = [
        entry(super::open as *const c_void, libc::open as *const c_void),
        entry(
            super::openat as *const c_void,
            libc::openat as *const c_void,
        ),
        entry(super::close as *const c_void, libc::close as *const c_void),
        entry(super::dup as *const c_void, libc::dup as *const c_void),
        entry(super::dup2 as *const c_void, libc::dup2 as *const c_void),
        entry(super::flock as *const c_void, libc::flock as *const c_void),
        entry(super::read as *const c_void, libc::read as *const c_void),
        entry(super::pread as *const c_void, libc::pread as *const c_void),
        entry(super::lseek as *const c_void, libc::lseek as *const c_void),
        entry(super::stat as *const c_void, libc::stat as *const c_void),
        entry(super::lstat as *const c_void, libc::lstat as *const c_void),
        entry(super::fstat as *const c_void, libc::fstat as *const c_void),
        entry(
            super::fstatat as *const c_void,
            libc::fstatat as *const c_void,
        ),
        entry(
            super::access as *const c_void,
            libc::access as *const c_void,
        ),
        entry(
            super::faccessat as *const c_void,
            libc::faccessat as *const c_void,
        ),
        entry(
            super::readlink as *const c_void,
            libc::readlink as *const c_void,
        ),
        entry(
            super::readlinkat as *const c_void,
            libc::readlinkat as *const c_void,
        ),
        // Symbol without a `libc` binding (declared in the extern block above).
        entry(
            super::__getdirentries64 as *const c_void,
            __getdirentries64 as *const c_void,
        ),
    ];

    /// Number of interpose entries, exposed so a test can assert the table is
    /// non-empty and matches the macOS hook count (guards against silently
    /// shipping an empty/short table — the FIR-909 failure mode).
    #[cfg(test)]
    pub fn interpose_entry_count() -> usize {
        INTERPOSE_TABLE.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd_table::DirEntryRaw;

    // ── macOS interposition table (FIR-909) ─────────────────────────────

    /// The interpose table must be non-empty and cover every macOS-active hook.
    /// The FIR-909 regression was a *missing* table (zero entries); this guards
    /// against silently shipping an empty or truncated one. The count must match
    /// the macOS replacement hooks declared in `macos_interpose::INTERPOSE_TABLE`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_interpose_table_covers_all_hooks() {
        let n = super::macos_interpose::interpose_entry_count();
        // 17 libc-bound hooks + __getdirentries64 = 18. The legacy stat64
        // aliases are intentionally not interposed on macOS because libSystem
        // can route fstat through fstat64 during early process initialization.
        // mmap/munmap also stay out of the Darwin table until the real-symbol
        // resolver can bypass dyld interposition for pointer-returning syscalls.
        assert_eq!(
            n, 18,
            "interpose table entry count changed; update this assertion and \
             verify every macOS-active hook is still interposed (FIR-909)"
        );
    }

    // ── Re-entry guard ──────────────────────────────────────────────────

    #[test]
    fn reentry_guard_refuses_nested_entry() {
        // Defensive: a panicked sibling test could leave the flag set on a
        // reused worker thread. Start from a known-clear state.
        IN_SHIM.with(|f| f.set(false));

        let outer = ReentryGuard::enter();
        assert!(
            outer.is_some(),
            "first entry on a fresh thread must succeed"
        );

        // A nested entry on the same thread is refused → the real hook must
        // pass straight through to libc instead of touching shim state. This
        // is what prevents the non-recursive fd-table lock from deadlocking
        // and the client RefCell from double-borrowing on re-entry.
        assert!(
            ReentryGuard::enter().is_none(),
            "nested entry while already in-shim must be refused"
        );

        // Dropping the outermost guard clears the flag so the next top-level
        // call can enter again.
        drop(outer);
        let again = ReentryGuard::enter();
        assert!(
            again.is_some(),
            "entry must succeed again after the outermost guard drops"
        );
        drop(again);
    }

    #[test]
    fn reentry_guard_ok_restores_entry_errno() {
        IN_SHIM.with(|f| f.set(false));
        unsafe {
            // Round-trip the raw errno accessors first.
            set_errno(0);
            assert_eq!(errno(), 0);
            set_errno(libc::EACCES);
            assert_eq!(errno(), libc::EACCES);

            // The guard captures errno on entry; `ok` restores it on a
            // synthesized-success path even if daemon I/O clobbered it.
            set_errno(libc::EIO);
            let g = ReentryGuard::enter().expect("fresh entry");
            set_errno(libc::ENOENT); // simulate socket I/O clobbering errno
            let ret = g.ok(0_i32);
            assert_eq!(ret, 0, "ok must return its argument unchanged");
            assert_eq!(errno(), libc::EIO, "ok must restore the entry errno");
            drop(g);
            set_errno(0);
        }
    }

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
