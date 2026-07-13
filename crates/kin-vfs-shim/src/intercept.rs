// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Syscall interception hooks. On Linux the real libc functions are resolved
//! via `dlsym(RTLD_NEXT, ...)`; on macOS the hooks are bound by the
//! `__DATA,__interpose` table at load time and the real pointers come from the
//! `macos_interpose.c` accessors (no `dlsym` — see the helper note below).
//!
//! Each intercepted function follows the same pattern:
//! 1. Lazily resolve the real libc function via `OnceLock` (Linux: `dlsym`;
//!    macOS: the C interpose TU's `kin_real_*` accessor).
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
use crate::{is_disabled, is_workspace_path, shim_state, workspace_graph_key};

// ── Helper: resolve the real libc function ──────────────────────────────
//
// On Linux the real function is resolved with `dlsym(RTLD_NEXT, sym)`: the
// shim's symbol shadows libc globally (LD_PRELOAD), and `RTLD_NEXT` skips our
// definition to find the genuine one.
//
// On macOS `dlsym` is NOT safe here. With the `__interpose` table live,
// the first `dlsym` during early startup runs libc internals that
// are themselves interposed, recursing into our hooks before init completes →
// stack overflow. Instead we read the real pointer from the C interpose TU,
// whose `kin_real_<name>()` returns `&<libSystem symbol>` (a plain load-time
// bind, never routed through `__interpose`) — zero dlsym, zero recursion.

/// Resolve a real libc function, caching it in a `OnceLock`. On Linux uses
/// `dlsym(RTLD_NEXT, $sym)`; on macOS uses the C-provided `$macos_real` accessor
/// (see `src/macos_interpose.c`). The macro creates `static $storage` and the
/// getter `$name()`.
macro_rules! real_fn {
    ($name:ident, $storage:ident, $sym:expr, $macos_real:ident, $ty:ty) => {
        static $storage: OnceLock<$ty> = OnceLock::new();

        // C accessor returning the genuine libSystem pointer (macOS only).
        #[cfg(target_os = "macos")]
        extern "C" {
            fn $macos_real() -> *const c_void;
        }

        #[inline]
        #[allow(non_snake_case)]
        fn $name() -> $ty {
            *$storage.get_or_init(|| unsafe {
                #[cfg(target_os = "macos")]
                let ptr = $macos_real();
                #[cfg(not(target_os = "macos"))]
                let ptr = libc::dlsym(libc::RTLD_NEXT, $sym.as_ptr() as *const c_char);

                if ptr.is_null() {
                    // Cannot proceed without the real function. The process was
                    // already running with libc, so this should never happen.
                    std::process::abort();
                }
                std::mem::transmute(ptr)
            })
        }
    };
    // Linux/Android-only hooks have no macOS counterpart: keep the dlsym path.
    ($name:ident, $storage:ident, $sym:expr, $ty:ty) => {
        static $storage: OnceLock<$ty> = OnceLock::new();

        #[inline]
        #[allow(non_snake_case)]
        fn $name() -> $ty {
            *$storage.get_or_init(|| unsafe {
                let ptr = libc::dlsym(libc::RTLD_NEXT, $sym.as_ptr() as *const c_char);
                if ptr.is_null() {
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
type DupFn = unsafe extern "C" fn(c_int) -> c_int;
type Dup2Fn = unsafe extern "C" fn(c_int, c_int) -> c_int;
#[cfg(any(target_os = "linux", target_os = "android"))]
type Dup3Fn = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;
type FlockFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
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
real_fn!(get_real_open, STORE_OPEN, b"open\0", kin_real_open, OpenFn);
real_fn!(
    get_real_openat,
    STORE_OPENAT,
    b"openat\0",
    kin_real_openat,
    OpenatFn
);
real_fn!(
    get_real_close,
    STORE_CLOSE,
    b"close\0",
    kin_real_close,
    CloseFn
);
real_fn!(get_real_dup, STORE_DUP, b"dup\0", kin_real_dup, DupFn);
real_fn!(get_real_dup2, STORE_DUP2, b"dup2\0", kin_real_dup2, Dup2Fn);
#[cfg(any(target_os = "linux", target_os = "android"))]
real_fn!(get_real_dup3, STORE_DUP3, b"dup3\0", Dup3Fn);
real_fn!(
    get_real_flock,
    STORE_FLOCK,
    b"flock\0",
    kin_real_flock,
    FlockFn
);
real_fn!(get_real_read, STORE_READ, b"read\0", kin_real_read, ReadFn);
real_fn!(
    get_real_pread,
    STORE_PREAD,
    b"pread\0",
    kin_real_pread,
    PreadFn
);
real_fn!(
    get_real_lseek,
    STORE_LSEEK,
    b"lseek\0",
    kin_real_lseek,
    LseekFn
);
real_fn!(
    get_real_access,
    STORE_ACCESS,
    b"access\0",
    kin_real_access,
    AccessFn
);
real_fn!(
    get_real_faccessat,
    STORE_FACCESSAT,
    b"faccessat\0",
    kin_real_faccessat,
    FaccessatFn
);
real_fn!(
    get_real_fstatat,
    STORE_FSTATAT,
    b"fstatat\0",
    kin_real_fstatat,
    FstatatFn
);
real_fn!(get_real_mmap, STORE_MMAP, b"mmap\0", kin_real_mmap, MmapFn);
real_fn!(
    get_real_munmap,
    STORE_MUNMAP,
    b"munmap\0",
    kin_real_munmap,
    MunmapFn
);
real_fn!(
    get_real_readlink,
    STORE_READLINK,
    b"readlink\0",
    kin_real_readlink,
    ReadlinkFn
);
real_fn!(
    get_real_readlinkat,
    STORE_READLINKAT,
    b"readlinkat\0",
    kin_real_readlinkat,
    ReadlinkatFn
);

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
    kin_real___getdirentries64,
    GetdirentriesFn
);

// Platform-specific stat resolution.
#[cfg(target_os = "linux")]
mod stat_fns {
    use super::*;

    type StatFn = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;
    type FstatFn = unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int;
    type XstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat) -> c_int;
    type FxstatFn = unsafe extern "C" fn(c_int, c_int, *mut libc::stat) -> c_int;

    // Direct stat-family entry points are the only safe passthrough for the
    // direct hooks below. The legacy __xstat/__fxstat ABI version is
    // architecture-specific (0 on glibc AArch64, 1 on x86_64), so translating
    // a direct fstat call to __fxstat with a hard-coded version can reject an
    // ordinary real fd with EINVAL before the target opens a workspace file.
    real_fn!(get_real_stat, STORE_STAT, b"stat\0", StatFn);
    real_fn!(get_real_lstat, STORE_LSTAT, b"lstat\0", StatFn);
    real_fn!(get_real_fstat, STORE_FSTAT, b"fstat\0", FstatFn);

    // Keep the versioned symbols only for callers that explicitly entered via
    // __xstat/__lxstat/__fxstat; those hooks forward the caller-provided ABI
    // version unchanged.
    real_fn!(get_real_xstat, STORE_XSTAT, b"__xstat\0", XstatFn);
    real_fn!(get_real_fxstat, STORE_FXSTAT, b"__fxstat\0", FxstatFn);
    real_fn!(get_real_lxstat, STORE_LXSTAT, b"__lxstat\0", XstatFn);

    pub unsafe fn real_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_stat()(path, buf)
    }

    pub unsafe fn real_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
        get_real_lstat()(path, buf)
    }

    pub unsafe fn real_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
        get_real_fstat()(fd, buf)
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

    real_fn!(get_real_stat, STORE_STAT, b"stat\0", kin_real_stat, StatFn);
    real_fn!(
        get_real_lstat,
        STORE_LSTAT,
        b"lstat\0",
        kin_real_lstat,
        StatFn
    );
    real_fn!(
        get_real_fstat,
        STORE_FSTAT,
        b"fstat\0",
        kin_real_fstat,
        FstatFn
    );

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

/// Translate one intercepted host path at the last possible point before the
/// shim serializes a request. The daemon and graph speak repo-relative keys;
/// absolute host paths are kept only for the real libc fd/materialization side.
#[inline]
fn graph_request_key(path: &str) -> Option<String> {
    workspace_graph_key(path).ok()
}

#[inline]
fn graph_stat(sock_path: &std::path::Path, host_path: &str) -> Option<kin_vfs_core::VirtualStat> {
    let key = graph_request_key(host_path)?;
    client::client_stat(sock_path, &key)
}

#[inline]
fn graph_read_file(sock_path: &std::path::Path, host_path: &str) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    client::client_read_file(sock_path, &key)
}

#[inline]
fn graph_read_range(
    sock_path: &std::path::Path,
    host_path: &str,
    offset: u64,
    len: u64,
) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    client::client_read_range(sock_path, &key, offset, len)
}

#[inline]
fn graph_read_dir(
    sock_path: &std::path::Path,
    host_path: &str,
) -> Option<Vec<kin_vfs_core::DirEntry>> {
    let key = graph_request_key(host_path)?;
    client::client_read_dir(sock_path, &key)
}

#[inline]
fn graph_access(sock_path: &std::path::Path, host_path: &str, mode: u32) -> Option<bool> {
    let key = graph_request_key(host_path)?;
    client::client_access(sock_path, &key, mode)
}

#[inline]
fn graph_read_link(sock_path: &std::path::Path, host_path: &str) -> Option<String> {
    let key = graph_request_key(host_path)?;
    client::client_read_link(sock_path, &key)
}

/// Materialize-on-write: seed the on-disk file from **graph truth** before a
/// tool writes to it, atomically. The caller opens the returned temp file; on
/// close it is renamed to the final path. Returns the temp path on success, or
/// `None` when there is no graph truth to seed (a genuinely new file, or the
/// daemon is unreachable) — in which case the caller opens the real path.
///
/// A previous implementation short-circuited whenever the file
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
    let content = graph_read_file(&state.sock_path, path_str)?;

    // Graph truth exists -> it is authoritative. Seed the file from graph
    // content, overwriting any stale on-disk copy. Create parent directories
    // first so the write lands even for not-yet-checked-out paths.
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

    let entries = match graph_read_dir(&state.sock_path, path_str) {
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
        graph_stat(&state.sock_path, path_str),
        Some(vstat) if vstat.is_dir
    )
}

/// Whether an authority-path miss must fail loud instead of reading raw disk.
///
/// Returns `true` only when strict mode (`KIN_VFS_STRICT=1`) is on AND the most
/// recent daemon call failed because the daemon was *unreachable* (not merely a
/// "path not in graph" answer). In that case the interpose hooks return `EIO`
/// rather than passing through to the real filesystem, so a proof/benchmark run
/// can never let stale disk masquerade as graph truth. With strict mode off, or
/// for an ordinary not-found miss, this is `false` and the caller keeps its
/// labeled compatibility pass-through.
#[inline]
fn strict_daemon_miss() -> bool {
    shim_state().map(|s| s.strict).unwrap_or(false) && client::last_call_unreachable()
}

/// Resolve the `(size, cached-content)` payload for a read-only virtual fd.
///
/// Only small files (≤ [`SMALL_FILE_THRESHOLD`]) are fetched whole and cached for
/// zero-roundtrip reads; a larger file is left uncached and served by range
/// reads, so the shim never loads it wholesale — nor fetches bytes it would
/// immediately discard (the fd table only caches content under the threshold).
/// When the daemon reports size 0 (an older daemon with no size, or a genuinely
/// empty file) we still fetch once to learn the true length rather than trust a
/// possibly-stale zero.
///
/// [`SMALL_FILE_THRESHOLD`]: crate::fd_table::SMALL_FILE_THRESHOLD
fn open_read_payload(
    sock_path: &std::path::Path,
    path_str: &str,
    vstat: &kin_vfs_core::VirtualStat,
) -> (u64, Option<Vec<u8>>) {
    let small = vstat.size == 0 || (vstat.size as usize) <= crate::fd_table::SMALL_FILE_THRESHOLD;
    if small {
        let content = graph_read_file(sock_path, path_str);
        let size = content
            .as_ref()
            .map(|c| c.len() as u64)
            .unwrap_or(vstat.size);
        (size, content)
    } else {
        // Large file: trust the stat size and let range reads serve the data.
        (vstat.size, None)
    }
}

// ── Intercepted syscalls ────────────────────────────────────────────────

/// Intercepted `open(2)`.
///
/// On the C ABI level, `open()` is variadic (mode is only present when
/// O_CREAT is set). However, at the machine level the third argument is
/// always passed in a register, so we can safely declare a fixed 3-arg
/// signature. This avoids requiring nightly `c_variadic`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let real_open = get_real_open();

    if is_disabled() {
        return real_open(path, flags, mode);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_open(path, flags, mode),
    };

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
        // No temp: either the daemon has no record (a genuinely new file) or the
        // daemon was unreachable. In strict mode the unreachable case must fail
        // loud rather than write to raw disk without seeding from graph truth.
        if strict_daemon_miss() {
            set_errno(libc::EIO);
            return -1;
        }
        // Open normally (new file, or labeled compatibility pass-through).
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

    match graph_stat(&state.sock_path, path_str) {
        Some(vstat) if vstat.is_file => {
            let (effective_size, content) = open_read_payload(&state.sock_path, path_str, &vstat);
            match allocate_vfd(path_str, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_open(path, flags, mode),
            }
        }
        // Miss: fail loud in strict mode when the daemon was unreachable, else
        // pass through to the real filesystem.
        _ => {
            if strict_daemon_miss() {
                set_errno(libc::EIO);
                return -1;
            }
            real_open(path, flags, mode)
        }
    }
}

/// Intercepted `openat(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_openat(dirfd, path, flags, mode),
    };

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
        // No temp: genuinely new file, or the daemon was unreachable. Strict
        // mode fails the unreachable case loud rather than writing to raw disk
        // without seeding from graph truth.
        if strict_daemon_miss() {
            set_errno(libc::EIO);
            return -1;
        }
        // Open normally (new file, or labeled compatibility pass-through).
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

    match graph_stat(&state.sock_path, &resolved) {
        Some(vstat) if vstat.is_file => {
            let (effective_size, content) = open_read_payload(&state.sock_path, &resolved, &vstat);
            match allocate_vfd(&resolved, effective_size, content) {
                fd if fd >= vfd_base() => fd,
                _ => real_openat(dirfd, path, flags, mode),
            }
        }
        // Miss: fail loud in strict mode when the daemon was unreachable, else
        // pass through to the real filesystem.
        _ => {
            if strict_daemon_miss() {
                set_errno(libc::EIO);
                return -1;
            }
            real_openat(dirfd, path, flags, mode)
        }
    }
}

/// Intercepted `dup(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    let real_read = get_real_read();

    if is_disabled() || fd < vfd_base() {
        return real_read(fd, buf, count);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_read(fd, buf, count),
    };

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

    let data = match graph_read_range(&state.sock_path, &path, offset, bytes_to_read as u64) {
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_pread(fd, buf, count, offset),
    };

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

    let data = match graph_read_range(&state.sock_path, &path, off, bytes_to_read as u64) {
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

/// Whether a finished write should be announced to the graph.
///
/// The graph must hear about a write only when the bytes actually landed at the
/// target path. A non-zero `close` return (buffered data may not have flushed)
/// or a failed atomic rename (`rename_ok == false`, target left untouched) must
/// never produce a success notification — otherwise a close-after-write error
/// becomes a false "graph converged" signal. Plain (non-atomic) tracked writes
/// pass `rename_ok = true` since they have no rename step.
#[inline]
fn atomic_write_should_notify(close_ret: c_int, rename_ok: bool) -> bool {
    close_ret == 0 && rename_ok
}

/// Intercepted `close(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    let real_close = get_real_close();

    // Fast path BEFORE touching any thread-local. On macOS the interpose table
    // makes this fire during `libSystem_initializer` (e.g. malloc/featureflag
    // setup calls close) — before TLS is bootstrapped, so reaching the
    // `ReentryGuard` thread-local there aborts (`_tlv_bootstrap_error`). While
    // disabled there are no virtual fds to reclaim, so pass straight through.
    if is_disabled() {
        return real_close(fd);
    }

    // Re-entry (e.g. the shim's own `libc::close` of a socket or temp fd)
    // passes straight through — those are real fds we never track.
    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_close(fd),
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
            // Flush + close the temp fd first. A non-zero close means the bytes
            // may not have reached disk, so the write did NOT land: do not rename
            // over the target and do not notify — surface the real errno so the
            // caller sees the failure instead of a false success.
            let ret = real_close(fd);
            if ret != 0 {
                return ret;
            }
            // Promote temp -> target atomically. A rename failure means the
            // target was NOT updated (the temp stays on disk, reclaimed on a
            // later open); notifying the daemon here would falsely record that
            // the file changed, so fail loud instead of sending a phantom
            // reconcile.
            let rename_ok = std::fs::rename(&entry.temp_path, &entry.target_path).is_ok();
            if atomic_write_should_notify(ret, rename_ok) {
                if let Some(wp) = write_path {
                    client::notify_file_changed(&wp);
                }
                return ret;
            }
            set_errno(libc::EIO);
            return -1;
        }

        if let Some(wp) = write_path {
            // Plain (non-atomic) tracked write: notify only if the close itself
            // succeeded. A failed close means the write may not have persisted,
            // so a notification would misrepresent it as a converged change.
            let ret = real_close(fd);
            if atomic_write_should_notify(ret, true) {
                client::notify_file_changed(&wp);
            }
            return ret;
        }
    }

    real_close(fd)
}

/// Intercepted `lseek(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    let real_lseek = get_real_lseek();

    if is_disabled() || fd < vfd_base() {
        return real_lseek(fd, offset, whence);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_lseek(fd, offset, whence),
    };

    let state = match shim_state() {
        Some(s) => s,
        None => return real_lseek(fd, offset, whence),
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    match graph_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        // Miss: fail loud in strict mode when the daemon was unreachable, else
        // fall through to the real stat.
        None => {
            if strict_daemon_miss() {
                set_errno(libc::EIO);
                return -1;
            }
            stat_fns::real_stat(path, buf)
        }
    }
}

/// Intercepted `lstat(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    match graph_stat(&state.sock_path, path_str) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(path_str);
            guard.ok(0)
        }
        // Miss: fail loud in strict mode when the daemon was unreachable, else
        // fall through to the real lstat.
        None => {
            if strict_daemon_miss() {
                set_errno(libc::EIO);
                return -1;
            }
            stat_fns::real_lstat(path, buf)
        }
    }
}

/// Intercepted `fstat(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    match graph_stat(&state.sock_path, &path) {
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_fstatat(dirfd, path, buf, flags),
    };

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

    match graph_stat(&state.sock_path, &resolved) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        // Miss: fail loud in strict mode when the daemon was unreachable, else
        // fall through to the real fstatat.
        None => {
            if strict_daemon_miss() {
                set_errno(libc::EIO);
                return -1;
            }
            real_fstatat(dirfd, path, buf, flags)
        }
    }
}

/// Intercepted `access(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    let real_access = get_real_access();

    if is_disabled() {
        return real_access(path, mode);
    }

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_access(path, mode),
    };

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

    match graph_access(&state.sock_path, path_str, mode as u32) {
        Some(true) => guard.ok(0),
        Some(false) => {
            set_errno(libc::EACCES);
            -1
        }
        None => real_access(path, mode),
    }
}

/// Intercepted `faccessat(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    let guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_faccessat(dirfd, path, mode, flags),
    };

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

    match graph_access(&state.sock_path, &resolved, mode as u32) {
        Some(true) => guard.ok(0),
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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
            match graph_read_file(&state.sock_path, &path) {
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
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: libc::size_t) -> c_int {
    let real_munmap = get_real_munmap();

    // Fast path BEFORE touching any thread-local — see `close` for why this is
    // required on macOS (interposed calls fire before TLS is bootstrapped).
    // Nothing is tracked while disabled, so pass straight through.
    if is_disabled() {
        return real_munmap(addr, len);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return real_munmap(addr, len),
    };

    if let Some(state) = shim_state() {
        // Untrack if this is a virtual mmap region. Even if it is, we still call
        // real_munmap because we allocated real anonymous memory.
        let _ = state.fd_table.write().untrack_mmap(addr as usize);
    }

    real_munmap(addr, len)
}

// ── readlink / readlinkat ───────────────────────────────────────────────

/// Intercepted `readlink(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    match graph_read_link(&state.sock_path, path_str) {
        Some(target) => {
            // If the symlink target points outside the workspace, fall through
            // to the real readlink so the kernel resolves it normally. This
            // prevents the VFS from serving content outside its trust boundary.
            if !is_workspace_path(&target) {
                return real_readlink(path, buf, bufsiz);
            }
            let target_bytes = target.as_bytes();
            let copy_len = target_bytes.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target_bytes.as_ptr().cast::<c_char>(), buf, copy_len);
            guard.ok(copy_len as libc::ssize_t)
        }
        None => real_readlink(path, buf, bufsiz),
    }
}

/// Intercepted `readlinkat(2)`.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
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

    match graph_read_link(&state.sock_path, &resolved) {
        Some(target) => {
            // If the symlink target points outside the workspace, fall through
            // to the real readlinkat so the kernel resolves it normally. This
            // prevents the VFS from serving content outside its trust boundary.
            if !is_workspace_path(&target) {
                return real_readlinkat(dirfd, path, buf, bufsiz);
            }
            let target_bytes = target.as_bytes();
            let copy_len = target_bytes.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target_bytes.as_ptr().cast::<c_char>(), buf, copy_len);
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

    match graph_stat(&state.sock_path, path_str) {
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

    match graph_stat(&state.sock_path, path_str) {
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

    match graph_stat(&state.sock_path, &path) {
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

    match graph_stat(&state.sock_path, &resolved) {
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
    match graph_stat(&state.sock_path, path_str) {
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
    match graph_stat(&state.sock_path, path_str) {
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

    match graph_stat(&state.sock_path, &path) {
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
    match graph_stat(&state.sock_path, path_str) {
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
    match graph_stat(&state.sock_path, path_str) {
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

    match graph_stat(&state.sock_path, &path) {
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

// ── macOS DYLD interposition ──────────────────────────────────────────────
//
// On macOS the dynamic linker uses a **two-level namespace**: every call site
// records which library a symbol was bound from (e.g. `open` → `libsystem_
// kernel.dylib`). A plain exported `#[no_mangle] fn open` in a dylib inserted
// via `DYLD_INSERT_LIBRARIES` therefore does NOT shadow those already-recorded
// bindings — unlike Linux `LD_PRELOAD`, where a preloaded global symbol wins.
// So the bare hooks above, while required on Linux, never fire on macOS by
// themselves: reads would silently fall through to the real disk.
//
// The supported mechanism is a `__DATA,__interpose` section: an array of
// `{ replacement, replacee }` function-pointer pairs. dyld reads this section
// at load time and rewrites the binding table so every external call to
// `replacee` (the real libc symbol) lands on `replacement` (our hook).
//
// CRITICAL — why this table is built in C (`src/macos_interpose.c`), not Rust:
// the `replacee` slot MUST resolve to libSystem's symbol via a load-time *bind*
// relocation. A pure-Rust table written as `libc::open as *const c_void` had
// the linker coalesce that reference with our own `#[no_mangle] open`
// definition, so BOTH slots pointed at our hook (`{our_open, our_open}`) — a
// verified no-op for external callers (`otool -s __DATA __interpose` showed
// identical addresses; `dyld_info -fixups` showed no `libSystem` bind). C keeps
// the replacee an undefined external (`extern open` from `<fcntl.h>`), which the
// static linker emits as `bind libSystem/_open`, while the replacement targets a
// distinctly-named alias below so it rebases into our image. (Both confirmed
// with `dyld_info -fixups` on the produced dylib.)
//
// The hooks above keep their canonical libc names for Linux; each macOS alias
// here is a thin, zero-state forwarder so the C table has a non-coalescing
// symbol to point at. `RTLD_NEXT` inside `get_real_*()` still finds genuine
// libc (it skips our image), so the hook bodies are unchanged.
#[cfg(target_os = "macos")]
mod macos_interpose {
    use super::*;
    use std::os::raw::{c_char, c_long, c_ulong, c_void};

    // Every forwarder calls `super::<hook>` — the parent module's macOS hooks
    // (including its `stat64`/`lstat64`/`fstat64`/`__getdirentries64` exports) —
    // so no local libc declarations are needed here. The REAL libSystem symbols
    // are referenced as the interpose `replacee` from the C table instead.

    // Anchor into the C object that carries the `__DATA,__interpose` section.
    // Without an inbound reference the linker drops the whole C object (and the
    // section with it — verified: the dylib shipped with no `__interpose`), so
    // we keep a `#[used]` function-pointer reference to force it in.
    extern "C" {
        fn kin_macos_interpose_entry_count() -> c_ulong;
    }
    #[used]
    static KIN_INTERPOSE_ANCHOR: unsafe extern "C" fn() -> c_ulong =
        kin_macos_interpose_entry_count;

    /// Number of interpose entries the C table must contain — one per macOS
    /// alias forwarder below. `build.rs` passes the same value to the C compile
    /// as `KIN_INTERPOSE_EXPECTED`, where a `_Static_assert` checks the table
    /// length, so a missing/truncated table fails the build instead of silently
    /// shipping. Consumed by the coverage test below;
    /// `#[cfg(test)]` because the build-time guarantee lives on the C side.
    #[cfg(test)]
    pub const INTERPOSE_ENTRY_COUNT: usize = 23;

    /// Define a `#[no_mangle]` alias `__kin_interpose_<hook>` forwarding to
    /// `super::<hook>`. The alias gives the C interpose table a symbol distinct
    /// from the libc name, so its `replacement` slot rebases into our image
    /// while the `replacee` slot binds to libSystem (see the module comment).
    macro_rules! interpose_alias {
        ($alias:ident => $hook:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
            #[no_mangle]
            pub unsafe extern "C" fn $alias($($arg: $ty),*) -> $ret {
                super::$hook($($arg),*)
            }
        };
    }

    interpose_alias!(__kin_interpose_open => open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int);
    interpose_alias!(__kin_interpose_openat => openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int);
    interpose_alias!(__kin_interpose_close => close(fd: c_int) -> c_int);
    interpose_alias!(__kin_interpose_dup => dup(fd: c_int) -> c_int);
    interpose_alias!(__kin_interpose_dup2 => dup2(oldfd: c_int, newfd: c_int) -> c_int);
    interpose_alias!(__kin_interpose_flock => flock(fd: c_int, operation: c_int) -> c_int);
    interpose_alias!(__kin_interpose_read => read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t);
    interpose_alias!(__kin_interpose_pread => pread(fd: c_int, buf: *mut c_void, count: libc::size_t, offset: libc::off_t) -> libc::ssize_t);
    interpose_alias!(__kin_interpose_lseek => lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t);
    interpose_alias!(__kin_interpose_stat => stat(path: *const c_char, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_lstat => lstat(path: *const c_char, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_fstat => fstat(fd: c_int, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_fstatat => fstatat(dirfd: c_int, path: *const c_char, buf: *mut libc::stat, flags: c_int) -> c_int);
    interpose_alias!(__kin_interpose_access => access(path: *const c_char, mode: c_int) -> c_int);
    interpose_alias!(__kin_interpose_faccessat => faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int);
    interpose_alias!(__kin_interpose_mmap => mmap(addr: *mut c_void, len: libc::size_t, prot: c_int, flags: c_int, fd: c_int, offset: libc::off_t) -> *mut c_void);
    interpose_alias!(__kin_interpose_munmap => munmap(addr: *mut c_void, len: libc::size_t) -> c_int);
    interpose_alias!(__kin_interpose_readlink => readlink(path: *const c_char, buf: *mut c_char, bufsiz: libc::size_t) -> libc::ssize_t);
    interpose_alias!(__kin_interpose_readlinkat => readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, bufsiz: libc::size_t) -> libc::ssize_t);
    interpose_alias!(__kin_interpose_stat64 => stat64(path: *const c_char, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_lstat64 => lstat64(path: *const c_char, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_fstat64 => fstat64(fd: c_int, buf: *mut libc::stat) -> c_int);
    interpose_alias!(__kin_interpose_getdirentries64 => __getdirentries64(fd: c_int, buf: *mut c_char, nbytes: libc::size_t, basep: *mut c_long) -> libc::ssize_t);

    /// Entry count for the table-coverage test (mirrors the C `_Static_assert`).
    #[cfg(test)]
    pub fn interpose_entry_count() -> usize {
        INTERPOSE_ENTRY_COUNT
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd_table::DirEntryRaw;

    // ── macOS interposition table ───────────────────────────────────────

    /// The interpose table must be non-empty and cover every macOS-active hook.
    /// A regression here would be a *missing* table (zero entries); this guards
    /// against silently shipping an empty or truncated one. The count must match
    /// the macOS replacement hooks declared in `macos_interpose::INTERPOSE_TABLE`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_interpose_table_covers_all_hooks() {
        let n = super::macos_interpose::interpose_entry_count();
        // 19 libc-bound hooks + stat64/lstat64/fstat64 + __getdirentries64 = 23.
        assert_eq!(
            n, 23,
            "interpose table entry count changed; update this assertion and \
             verify every macOS-active hook is still interposed"
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

    /// Passthrough from the direct Linux hooks must call the native libc
    /// stat-family symbols. This specifically catches the AArch64 regression
    /// where forwarding to `__xstat`/`__fxstat` with x86_64's ABI version `1`
    /// returns `EINVAL` (AArch64 accepts version `0`), breaking tools while
    /// they inspect stdout before any workspace path is opened.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_direct_stat_passthrough_uses_native_abi() {
        let path = CString::new("/dev/null").unwrap();

        unsafe {
            let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();
            set_errno(0);
            assert_eq!(
                stat_fns::real_fstat(libc::STDOUT_FILENO, stat_buf.as_mut_ptr()),
                0,
                "native fstat(stdout) failed with errno {}",
                errno()
            );

            set_errno(0);
            assert_eq!(
                stat_fns::real_stat(path.as_ptr(), stat_buf.as_mut_ptr()),
                0,
                "native stat(/dev/null) failed with errno {}",
                errno()
            );

            set_errno(0);
            assert_eq!(
                stat_fns::real_lstat(path.as_ptr(), stat_buf.as_mut_ptr()),
                0,
                "native lstat(/dev/null) failed with errno {}",
                errno()
            );
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

    // ── Close-after-write notification gating (AC2) ──────────────────────
    //
    // A write may be announced to the graph ONLY when the bytes actually landed:
    // a failed close (data may not have flushed) or a failed atomic rename
    // (target untouched) must never produce a success notification, or a
    // close-after-write error becomes a phantom "graph converged" signal.

    #[test]
    fn atomic_write_notifies_only_on_clean_close_and_rename() {
        // Clean close + successful rename → notify.
        assert!(atomic_write_should_notify(0, true));
        // Successful close but failed rename → do NOT notify (target untouched).
        assert!(!atomic_write_should_notify(0, false));
        // Failed close → do NOT notify regardless of rename outcome.
        assert!(!atomic_write_should_notify(-1, true));
        assert!(!atomic_write_should_notify(-1, false));
    }

    #[test]
    fn plain_write_notifies_only_on_clean_close() {
        // Plain (non-atomic) writes pass rename_ok = true, so the gate reduces to
        // "close succeeded".
        assert!(atomic_write_should_notify(0, true));
        assert!(!atomic_write_should_notify(-1, true));
    }

    // ── Bounded read prefetch (AC4) ──────────────────────────────────────
    //
    // The read-only open path must not pull a large file wholesale into the
    // per-fd cache (nor fetch bytes the fd table would immediately discard):
    // small files are fetched + cached, large files are left to range reads.
    // NOTE: `open_read_payload` fetches via the daemon client, so these tests
    // only exercise the *large* branch, which is decided from the stat size
    // alone and performs no fetch.

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn large_file_open_defers_to_range_reads_without_prefetch() {
        use crate::fd_table::SMALL_FILE_THRESHOLD;
        use kin_vfs_core::VirtualStat;

        let big = (SMALL_FILE_THRESHOLD as u64) + 1;
        let vstat = VirtualStat::file(big, [0u8; 32], 1);
        // A path that no daemon serves; the large branch must NOT attempt a fetch
        // (which would hang/None here) — it trusts the stat size and caches
        // nothing, leaving reads to the range path.
        let (size, content) = open_read_payload(
            std::path::Path::new("/nonexistent-vfs.sock"),
            "big.bin",
            &vstat,
        );
        assert_eq!(size, big, "large file must report its stat size");
        assert!(
            content.is_none(),
            "large file must not be prefetched/cached at open"
        );
    }
}
