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
//! CRITICAL: Never panic in any of these functions. Disabled, re-entrant,
//! outside-workspace, and explicit write-boundary calls pass through. A graph
//! authority error on an in-workspace read must fail loud.
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
use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
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
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int;
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

/// Compute a unique synthetic inode from exact path bytes.
/// This ensures different virtual files get different inode numbers,
/// which tools like `find`, `tar`, and hardlink detectors depend on.
/// Delegates to the fuzzed seam in `kin-vfs-core` so there is one definition.
#[inline]
fn path_to_inode(path: &[u8]) -> u64 {
    kin_vfs_core::pathmap::synthetic_inode(path)
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Borrow a C string pointer's exact bytes (NUL excluded). `None` only on a
/// null pointer.
///
/// Deliberately NOT UTF-8 gated. Unix paths are byte sequences: rejecting
/// invalid UTF-8 here would pass a workspace file through to the real syscall
/// and let raw disk answer for it — a graph-authority hole for any repository
/// containing a non-UTF8 name.
#[inline]
unsafe fn c_to_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(CStr::from_ptr(ptr).to_bytes())
}

/// Build a NUL-terminated C string from exact path bytes for handing back to
/// the real libc. Fails only when the bytes contain an interior NUL, which no
/// valid path does.
#[inline]
fn bytes_to_cstring(bytes: &[u8]) -> Option<CString> {
    CString::new(bytes).ok()
}

/// The calling process's current working directory, as exact bytes.
///
/// `getcwd` is not one of the interposed symbols, so this reaches real libc
/// directly and cannot re-enter the shim. It is read per call rather than
/// captured at init because the host may `chdir` at any point in its lifetime;
/// a cached value would map a later relative path onto the wrong graph key.
#[inline]
unsafe fn process_cwd() -> Option<Vec<u8>> {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let cwd = libc::getcwd(buf.as_mut_ptr() as *mut c_char, buf.len());
    if cwd.is_null() {
        return None;
    }
    Some(CStr::from_ptr(cwd).to_bytes().to_vec())
}

/// Resolve an intercepted path argument to absolute host bytes.
///
/// Workspace containment — and therefore graph authority — is decided on
/// absolute bytes. A relative argument left unresolved never matches the
/// workspace root, so the hook would pass it through and raw disk would answer
/// for a graph-owned file. Joining it against the process cwd lands it on
/// exactly the graph key its absolute twin resolves to.
#[inline]
unsafe fn resolve_host_path(path: *const c_char) -> Option<Vec<u8>> {
    let path_bytes = c_to_bytes(path)?;
    if path_bytes.first() == Some(&b'/') {
        return Some(path_bytes.to_vec());
    }
    Some(join_at(&process_cwd()?, path_bytes))
}

/// Resolve a potentially relative path (for `openat`/`fstatat`) to an
/// absolute path string. Returns `None` if resolution fails.
// The trailing `return Some(...)` in each platform `#[cfg]` block is required:
// clippy sees only the active cfg branch and flags it as needless, but those
// branches are `#[cfg]`-attributed *statements*, not tail expressions, so
// dropping `return` would leave the fn with no value on the other platform.
#[allow(clippy::needless_return)]
unsafe fn resolve_at_path(dirfd: c_int, path: *const c_char) -> Option<Vec<u8>> {
    let path_bytes = c_to_bytes(path)?;

    // Absolute path — use directly.
    if path_bytes.first() == Some(&b'/') {
        return Some(path_bytes.to_vec());
    }

    // AT_FDCWD means relative to cwd.
    if dirfd == libc::AT_FDCWD {
        return Some(join_at(&process_cwd()?, path_bytes));
    }

    // A graph-backed directory has no kernel fd for `/proc/self/fd` or
    // `F_GETPATH` to inspect. Resolve it from the virtual descriptor table,
    // preserving openat/fstatat/readlinkat semantics entirely in graph space.
    if dirfd >= vfd_base() {
        let state = shim_state()?;
        let fd_table = state.fd_table.read();
        let handle = fd_table.get(dirfd)?;
        return Some(join_at(&handle.path, path_bytes));
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
        return Some(join_at(&buf[..len as usize], path_bytes));
    }

    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let ret = libc::fcntl(dirfd, libc::F_GETPATH, buf.as_mut_ptr());
        if ret == -1 {
            return None;
        }
        let dir_path = CStr::from_ptr(buf.as_ptr() as *const c_char).to_bytes();
        return Some(join_at(dir_path, path_bytes));
    }
}

/// Join `rel` against directory `base` — delegates to the fuzzed byte seam.
#[inline]
fn join_at(base: &[u8], rel: &[u8]) -> Vec<u8> {
    kin_vfs_core::pathmap::join_at_path(base, rel)
}

/// Check if flags indicate a write operation.
#[inline]
fn is_write_flags(flags: c_int) -> bool {
    (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC)) != 0
}

/// Whether native `open`/`openat` consumes its variadic mode argument.
#[inline]
fn open_requires_mode(flags: c_int) -> bool {
    if flags & libc::O_CREAT != 0 {
        return true;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // O_TMPFILE contains O_DIRECTORY; test the full compound value.
        return flags & libc::O_TMPFILE == libc::O_TMPFILE;
    }
    #[cfg(target_os = "macos")]
    {
        false
    }
}

/// Call the real variadic libc entry without inventing an optional argument.
#[inline]
unsafe fn call_real_open(
    real: OpenFn,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    if open_requires_mode(flags) {
        real(path, flags, mode as c_int)
    } else {
        real(path, flags)
    }
}

/// `openat` counterpart to [`call_real_open`].
#[inline]
unsafe fn call_real_openat(
    real: OpenatFn,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    if open_requires_mode(flags) {
        real(dirfd, path, flags, mode as c_int)
    } else {
        real(dirfd, path, flags)
    }
}

/// Generate the temp file path for atomic writes.
/// Format: `{target_path}.kin_tmp_{pid}`. Delegates to the fuzzed seam so the
/// exclusion in `is_interpose_temp_artifact` can never drift out of sync.
fn atomic_temp_path(target: &[u8]) -> Vec<u8> {
    let pid = unsafe { libc::getpid() };
    kin_vfs_core::pathmap::atomic_temp_path(target, pid)
}

/// Clean up stale `.kin_tmp_*` files for a given target path.
/// Called on open to remove leftovers from crashed processes.
///
/// Byte-exact throughout: entry names are compared as `OsStr` bytes so a
/// non-UTF8 target's temp artifacts are still reclaimed. This is explicit
/// projection-artifact IO, not a semantic answer path.
fn cleanup_stale_temps(path_bytes: &[u8]) {
    use std::os::unix::ffi::OsStrExt;

    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path_bytes));
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let mut prefix = file_name.as_bytes().to_vec();
    prefix.extend_from_slice(b".kin_tmp_");
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            if entry.file_name().as_bytes().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Translate one intercepted host path at the last possible point before the
/// shim serializes a request. The daemon and graph speak repo-relative keys;
/// absolute host paths are kept only for the real libc fd/materialization side.
#[inline]
fn graph_request_key(path: &[u8]) -> Option<kin_vfs_core::VfsPath> {
    workspace_graph_key(path).ok()
}

#[inline]
fn graph_stat(sock_path: &std::path::Path, host_path: &[u8]) -> Option<kin_vfs_core::VirtualStat> {
    let key = graph_request_key(host_path)?;
    client::client_stat(sock_path, &key)
}

#[inline]
fn graph_read_file(sock_path: &std::path::Path, host_path: &[u8]) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    client::client_read_file(sock_path, &key)
}

#[inline]
fn graph_read_range(
    sock_path: &std::path::Path,
    host_path: &[u8],
    offset: u64,
    len: u64,
    total_size: u64,
) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    client::client_read_range(sock_path, &key, offset, len, total_size)
}

#[inline]
fn graph_read_dir(
    sock_path: &std::path::Path,
    host_path: &[u8],
) -> Option<Vec<kin_vfs_core::DirEntry>> {
    let key = graph_request_key(host_path)?;
    client::client_read_dir(sock_path, &key)
}

#[inline]
fn graph_read_link(sock_path: &std::path::Path, host_path: &[u8]) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    client::client_read_link(sock_path, &key)
}

#[derive(Debug, Clone)]
enum GraphPathError {
    Authority,
    MissingFinal,
    InvalidSymlink,
    SymlinkLoop,
    OutsideWorkspace,
    NotDirectory,
}

/// Normalize `.` and `..` lexically on exact bytes, without consulting the
/// host filesystem.
///
/// Returns `None` when the path is relative or `..` escapes above the root —
/// either case must fail closed rather than resolve to something outside the
/// workspace.
fn normalize_graph_path(path: &[u8]) -> Option<Vec<u8>> {
    if path.first() != Some(&b'/') {
        return None;
    }
    let mut components: Vec<&[u8]> = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                components.pop()?;
            }
            normal => components.push(normal),
        }
    }
    let mut normalized = Vec::with_capacity(path.len());
    for component in components {
        normalized.push(b'/');
        normalized.extend_from_slice(component);
    }
    if normalized.is_empty() {
        normalized.push(b'/');
    }
    Some(normalized)
}

/// Follow graph-owned symlinks without asking the host filesystem to resolve
/// any component. The final returned path is the path whose blob must be read.
fn graph_stat_follow(
    sock_path: &Path,
    host_path: &[u8],
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    let state = shim_state().ok_or(GraphPathError::Authority)?;
    let root = state.workspace_root.clone();
    let key = workspace_graph_key(host_path).map_err(|_| GraphPathError::OutsideWorkspace)?;
    let mut pending: VecDeque<Vec<u8>> = key.components().map(<[u8]>::to_vec).collect();
    let mut current = root.clone();
    let mut followed = 0;

    if pending.is_empty() {
        let stat = graph_stat(sock_path, &root).ok_or(GraphPathError::Authority)?;
        return Ok((root, stat));
    }

    while let Some(component) = pending.pop_front() {
        let candidate = join_at(&current, &component);
        let stat = match graph_stat(sock_path, &candidate) {
            Some(stat) => stat,
            None if client::last_call_failure() == client::ClientCallFailure::NotFound
                && pending.is_empty() =>
            {
                return Err(GraphPathError::MissingFinal);
            }
            None => return Err(GraphPathError::Authority),
        };
        if stat.is_symlink {
            followed += 1;
            if followed > 40 {
                return Err(GraphPathError::SymlinkLoop);
            }

            // The link target is exact graph-owned bytes; it is never required
            // to be UTF-8, only NUL-free (a NUL cannot appear in a path).
            let target = graph_read_link(sock_path, &candidate).ok_or(GraphPathError::Authority)?;
            if target.contains(&0) || target.is_empty() {
                return Err(GraphPathError::InvalidSymlink);
            }

            let joined = if target.first() == Some(&b'/') {
                target
            } else {
                join_at(&current, &target)
            };
            let normalized = normalize_graph_path(&joined).ok_or(GraphPathError::InvalidSymlink)?;
            let target_key =
                workspace_graph_key(&normalized).map_err(|_| GraphPathError::OutsideWorkspace)?;
            let mut redirected: VecDeque<Vec<u8>> =
                target_key.components().map(<[u8]>::to_vec).collect();
            redirected.append(&mut pending);
            pending = redirected;
            current = root.clone();
            if pending.is_empty() {
                let root_stat = graph_stat(sock_path, &root).ok_or(GraphPathError::Authority)?;
                return Ok((root.clone(), root_stat));
            }
            continue;
        }

        if !pending.is_empty() && !stat.is_dir {
            return Err(GraphPathError::NotDirectory);
        }
        current = candidate;
        if pending.is_empty() {
            return Ok((current, stat));
        }
    }
    Err(GraphPathError::Authority)
}

/// Materialize-on-write: seed the on-disk file from **graph truth** before a
/// tool writes to it, atomically. The caller opens the returned temp file; on
/// close it is renamed to the final path. `Ok(None)` means the exact graph has
/// no entry and the caller may create a new file at the explicit projection
/// boundary. Authority and staging failures are returned separately; neither
/// permits a raw-filesystem fallback.
///
/// A previous implementation short-circuited whenever the file
/// already existed on disk (`access(F_OK)`), handing the tool the **stale disk
/// copy** without ever consulting the graph. That silently entrenched
/// filesystem authority over graph truth — exactly the drift the thesis warns
/// against. Authority semantics now: **graph wins.** If the daemon has content
/// for this path, we materialize THAT (overwriting any stale on-disk bytes) so
/// a read-modify-write or append starts from graph truth. Only an exact
/// `NotFound` answer allows creation of a new projection file.
fn materialize_file(path_bytes: &[u8]) -> Result<Option<Vec<u8>>, c_int> {
    use std::os::unix::ffi::OsStrExt;

    let state = shim_state().ok_or(libc::EIO)?;

    // Clean up stale temp files from previous crashed processes.
    cleanup_stale_temps(path_bytes);

    // Consult graph truth FIRST. Only a precise graph NotFound is creation;
    // transport, protocol, and integrity failures are authority failures.
    let content = match graph_read_file(&state.sock_path, path_bytes) {
        Some(content) => content,
        None if client::last_call_failure() == client::ClientCallFailure::NotFound => {
            return Ok(None);
        }
        None => return Err(graph_failure_errno(client::last_call_failure())),
    };

    // Graph truth exists -> it is authoritative. Seed the file from graph
    // content, overwriting any stale on-disk copy. Create parent directories
    // first so the write lands even for not-yet-checked-out paths.
    let target = std::path::Path::new(std::ffi::OsStr::from_bytes(path_bytes));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
    }

    // Write content to a temp file (atomic write pattern); the caller renames
    // temp -> target on close.
    let temp = atomic_temp_path(path_bytes);
    std::fs::write(
        std::path::Path::new(std::ffi::OsStr::from_bytes(&temp)),
        &content,
    )
    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
    Ok(Some(temp))
}

/// Allocate a virtual fd for a file served by the daemon.
fn allocate_vfd(path_bytes: &[u8], size: u64, content: Option<Vec<u8>>) -> c_int {
    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    state
        .fd_table
        .write()
        .allocate(path_bytes, size, content)
        .unwrap_or(-1)
}

/// Allocate a virtual directory fd, fetching entries from the daemon.
///
/// Entry names are carried as exact bytes into the `dirent` records, so a
/// non-UTF8 name reaches the host tool unchanged. A gitlink child is projected
/// as `DT_DIR`: it is a real nested-repository boundary that `readdir` must
/// show, while any per-path operation on it fails with the typed
/// unsupported-boundary error rather than pretending it is an ordinary
/// directory.
fn allocate_dir_vfd(path_bytes: &[u8]) -> c_int {
    use kin_vfs_core::FileType;

    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    let entries = match graph_read_dir(&state.sock_path, path_bytes) {
        Some(e) => e,
        None => return -1,
    };

    let raw_entries: Vec<DirEntryRaw> = entries
        .into_iter()
        .map(|entry| {
            let d_type = match entry.file_type {
                FileType::File => 8,      // DT_REG
                FileType::Directory => 4, // DT_DIR
                FileType::Symlink => 10,  // DT_LNK
                FileType::Gitlink => 4,   // DT_DIR — a repository boundary
            };
            let name = entry.name.into_bytes();
            // Synthetic inode from the exact name bytes.
            let d_ino = kin_vfs_core::pathmap::synthetic_inode(&name);
            DirEntryRaw {
                name,
                d_ino,
                d_type,
            }
        })
        .collect();

    state
        .fd_table
        .write()
        .allocate_dir(path_bytes, raw_entries)
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

/// Errno for a definitive "the graph does not hold this path" answer about a
/// path inside the workspace.
///
/// By default this is an absence: ENOENT, the same answer any tool expects for
/// a path that is not there. Under strict mode it is a refusal on the same EIO
/// path as unavailable graph authority, so a caller that must stay inside graph
/// truth cannot read a workspace miss as an ordinary missing file. Neither mode
/// consults raw disk.
#[inline]
fn graph_miss_errno_in_mode(strict: bool) -> c_int {
    if strict {
        libc::EIO
    } else {
        libc::ENOENT
    }
}

#[inline]
fn graph_miss_errno() -> c_int {
    graph_miss_errno_in_mode(crate::is_strict())
}

/// A graph-authority miss must never be answered by the raw filesystem.
///
/// A reachable daemon that has no entry maps to [`graph_miss_errno_in_mode`].
/// Transport failure maps to EIO so callers can distinguish an absent graph
/// path from unavailable graph authority.
#[inline]
fn graph_failure_errno_in_mode(failure: client::ClientCallFailure, strict: bool) -> c_int {
    use client::ClientCallFailure;
    match failure {
        ClientCallFailure::None | ClientCallFailure::NotFound => graph_miss_errno_in_mode(strict),
        ClientCallFailure::PermissionDenied => libc::EACCES,
        ClientCallFailure::IsDirectory => libc::EISDIR,
        ClientCallFailure::NotDirectory => libc::ENOTDIR,
        ClientCallFailure::InvalidInput => libc::EINVAL,
        // A nested-repository boundary with no child projection: the path
        // exists but its contents are not ours to serve. ENOTSUP says exactly
        // that, instead of a misleading ENOENT/EISDIR.
        ClientCallFailure::UnsupportedBoundary => libc::ENOTSUP,
        ClientCallFailure::Unreachable | ClientCallFailure::Authority => libc::EIO,
    }
}

#[inline]
fn graph_failure_errno(failure: client::ClientCallFailure) -> c_int {
    graph_failure_errno_in_mode(failure, crate::is_strict())
}

#[inline]
fn fail_graph_authority() -> c_int {
    let errno = graph_failure_errno(client::last_call_failure());
    // SAFETY: errno is thread-local process state and this helper is called
    // from an intercepted libc operation on the current thread.
    unsafe { set_errno(errno) };
    -1
}

#[inline]
fn fail_graph_authority_read() -> libc::ssize_t {
    fail_graph_authority() as libc::ssize_t
}

/// Errno for a failed graph-owned path resolution. `MissingFinal` is the
/// definitive miss (every component resolved, the last one has no entry) and so
/// follows the strict-mode rule; the remaining classes describe *how* the graph
/// answered and keep their exact meaning in both modes.
#[inline]
fn graph_path_errno(error: &GraphPathError, strict: bool) -> c_int {
    match error {
        GraphPathError::Authority => {
            graph_failure_errno_in_mode(client::last_call_failure(), strict)
        }
        GraphPathError::MissingFinal => graph_miss_errno_in_mode(strict),
        GraphPathError::InvalidSymlink => libc::EINVAL,
        GraphPathError::SymlinkLoop => libc::ELOOP,
        GraphPathError::OutsideWorkspace => libc::EACCES,
        GraphPathError::NotDirectory => libc::ENOTDIR,
    }
}

#[inline]
fn fail_graph_path(error: GraphPathError) -> c_int {
    let errno = graph_path_errno(&error, crate::is_strict());
    // SAFETY: see `fail_graph_authority`.
    unsafe { set_errno(errno) };
    -1
}

#[inline]
fn graph_mode_allows(stat: &kin_vfs_core::VirtualStat, requested: c_int) -> bool {
    (requested & libc::R_OK == 0 || stat.mode & 0o444 != 0)
        && (requested & libc::W_OK == 0 || stat.mode & 0o222 != 0)
        && (requested & libc::X_OK == 0 || stat.mode & 0o111 != 0)
}

/// Resolve the `(size, cached-content)` payload for a read-only virtual fd.
///
/// Only small files (≤ [`SMALL_FILE_THRESHOLD`]) are fetched whole and cached for
/// zero-roundtrip reads; a larger file is left uncached and served by range
/// reads, so the shim never loads it wholesale — nor fetches bytes it would
/// immediately discard (the fd table only caches content under the threshold).
/// Empty files are still fetched so their exact hash/size contract is verified
/// before a descriptor is exposed.
///
/// [`SMALL_FILE_THRESHOLD`]: crate::fd_table::SMALL_FILE_THRESHOLD
fn open_read_payload(
    sock_path: &std::path::Path,
    path_bytes: &[u8],
    vstat: &kin_vfs_core::VirtualStat,
) -> Result<(u64, Option<Vec<u8>>), GraphPathError> {
    let small = usize::try_from(vstat.size)
        .map(|size| size <= crate::fd_table::SMALL_FILE_THRESHOLD)
        .unwrap_or(false);
    if small {
        let content = graph_read_file(sock_path, path_bytes).ok_or(GraphPathError::Authority)?;
        Ok((vstat.size, Some(content)))
    } else {
        // Large file: exact tree metadata supplies the size and verified
        // ranged reads serve the data.
        Ok((vstat.size, None))
    }
}

// ── Intercepted syscalls ────────────────────────────────────────────────

/// Intercepted `open(2)`.
///
/// Linux exposes this fixed Rust entry point directly. Darwin's dyld
/// replacement is a genuine C variadic function in `macos_interpose.c`; it
/// reads the optional mode only for `O_CREAT` and forwards the decoded value
/// here. Rust therefore never reads an argument the caller did not pass.
#[cfg_attr(any(target_os = "linux", target_os = "android"), no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let real_open = get_real_open();

    if is_disabled() {
        return call_real_open(real_open, path, flags, mode);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return call_real_open(real_open, path, flags, mode),
    };

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return call_real_open(real_open, path, flags, mode),
    };

    if !is_workspace_path(&path_bytes) {
        return call_real_open(real_open, path, flags, mode);
    }

    // Write flags -> materialize then passthrough, tracking the fd.
    if is_write_flags(flags) {
        let temp = match materialize_file(&path_bytes) {
            Ok(temp) => temp,
            Err(errno) => {
                set_errno(errno);
                return -1;
            }
        };
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match bytes_to_cstring(temp_path) {
                Some(c) => c,
                None => {
                    set_errno(libc::EINVAL);
                    return -1;
                }
            };
            let fd = call_real_open(real_open, c_temp.as_ptr(), flags, mode);
            if fd >= 0 {
                if let Some(state) = shim_state() {
                    let mut ft = state.fd_table.write();
                    ft.track_write(fd, path_bytes.clone());
                    ft.track_atomic_write(fd, path_bytes.clone(), temp_path.clone());
                }
            }
            return fd;
        }
        // A graph-absent path crosses into the projection boundary only when
        // the caller explicitly requested creation. A stale disk-only path
        // cannot make a write appear graph-authoritative.
        if flags & libc::O_CREAT == 0 {
            set_errno(graph_miss_errno());
            return -1;
        }
        // Create a genuinely new file at the explicit projection/write boundary.
        let fd = call_real_open(real_open, path, flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, path_bytes.clone());
            }
        }
        return fd;
    }

    // Read-only open resolves symlinks wholly through graph authority.
    let state = match shim_state() {
        Some(s) => s,
        None => return call_real_open(real_open, path, flags, mode),
    };

    let resolved = if flags & libc::O_NOFOLLOW != 0 {
        match graph_stat(&state.sock_path, &path_bytes) {
            Some(stat) if stat.is_symlink => {
                set_errno(libc::ELOOP);
                return -1;
            }
            Some(stat) => Ok((path_bytes.clone(), stat)),
            None => Err(GraphPathError::Authority),
        }
    } else {
        graph_stat_follow(&state.sock_path, &path_bytes)
    };

    match resolved {
        Ok((resolved_path, vstat)) if vstat.is_dir => match allocate_dir_vfd(&resolved_path) {
            fd if fd >= vfd_base() => fd,
            _ => fail_graph_authority(),
        },
        Ok((_, _)) if flags & libc::O_DIRECTORY != 0 => {
            set_errno(libc::ENOTDIR);
            -1
        }
        Ok((resolved_path, vstat)) if vstat.is_file => {
            match open_read_payload(&state.sock_path, &resolved_path, &vstat) {
                Ok((effective_size, content)) => {
                    match allocate_vfd(&resolved_path, effective_size, content) {
                        fd if fd >= vfd_base() => fd,
                        _ => {
                            set_errno(libc::EIO);
                            -1
                        }
                    }
                }
                Err(error) => fail_graph_path(error),
            }
        }
        Ok(_) => {
            set_errno(libc::EINVAL);
            -1
        }
        Err(error) => fail_graph_path(error),
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
        return call_real_openat(real_openat, dirfd, path, flags, mode);
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return call_real_openat(real_openat, dirfd, path, flags, mode),
    };

    let resolved = match resolve_at_path(dirfd, path) {
        Some(p) => p,
        None => return call_real_openat(real_openat, dirfd, path, flags, mode),
    };

    if !is_workspace_path(&resolved) {
        return call_real_openat(real_openat, dirfd, path, flags, mode);
    }

    if is_write_flags(flags) {
        let temp = match materialize_file(&resolved) {
            Ok(temp) => temp,
            Err(errno) => {
                set_errno(errno);
                return -1;
            }
        };
        if let Some(ref temp_path) = temp {
            // Open the temp file instead; on close we rename to target.
            let c_temp = match bytes_to_cstring(temp_path) {
                Some(c) => c,
                None => {
                    set_errno(libc::EINVAL);
                    return -1;
                }
            };
            let fd = call_real_openat(real_openat, libc::AT_FDCWD, c_temp.as_ptr(), flags, mode);
            if fd >= 0 {
                if let Some(state) = shim_state() {
                    let mut ft = state.fd_table.write();
                    ft.track_write(fd, resolved.clone());
                    ft.track_atomic_write(fd, resolved.clone(), temp_path.clone());
                }
            }
            return fd;
        }
        if flags & libc::O_CREAT == 0 {
            set_errno(libc::ENOENT);
            return -1;
        }
        // Create a genuinely new file at the explicit projection/write boundary.
        let fd = call_real_openat(real_openat, dirfd, path, flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, resolved.clone());
            }
        }
        return fd;
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return call_real_openat(real_openat, dirfd, path, flags, mode),
    };

    let graph_resolved = if flags & libc::O_NOFOLLOW != 0 {
        match graph_stat(&state.sock_path, &resolved) {
            Some(stat) if stat.is_symlink => {
                set_errno(libc::ELOOP);
                return -1;
            }
            Some(stat) => Ok((resolved.clone(), stat)),
            None => Err(GraphPathError::Authority),
        }
    } else {
        graph_stat_follow(&state.sock_path, &resolved)
    };

    match graph_resolved {
        Ok((resolved_path, vstat)) if vstat.is_dir => match allocate_dir_vfd(&resolved_path) {
            fd if fd >= vfd_base() => fd,
            _ => fail_graph_authority(),
        },
        Ok((_, _)) if flags & libc::O_DIRECTORY != 0 => {
            set_errno(libc::ENOTDIR);
            -1
        }
        Ok((resolved_path, vstat)) if vstat.is_file => {
            match open_read_payload(&state.sock_path, &resolved_path, &vstat) {
                Ok((effective_size, content)) => {
                    match allocate_vfd(&resolved_path, effective_size, content) {
                        fd if fd >= vfd_base() => fd,
                        _ => {
                            set_errno(libc::EIO);
                            -1
                        }
                    }
                }
                Err(error) => fail_graph_path(error),
            }
        }
        Ok(_) => {
            set_errno(libc::EINVAL);
            -1
        }
        Err(error) => fail_graph_path(error),
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

    let data = match graph_read_range(&state.sock_path, &path, offset, bytes_to_read as u64, size) {
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

    let data = match graph_read_range(&state.sock_path, &path, off, bytes_to_read as u64, size) {
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

/// Rename `from` -> `to` using exact path bytes (no UTF-8 requirement).
fn rename_bytes(from: &[u8], to: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    std::fs::rename(
        std::path::Path::new(std::ffi::OsStr::from_bytes(from)),
        std::path::Path::new(std::ffi::OsStr::from_bytes(to)),
    )
    .is_ok()
}

/// Announce a landed write to the graph using its **canonical repo-relative
/// path bytes**.
///
/// The tracked write path is an absolute host path; the graph names artifacts
/// by repo-relative key, so it is translated through the same authority
/// boundary every read uses. A path that no longer maps (workspace
/// reconfigured mid-write) is dropped rather than announced under a guessed
/// identity — a wrong reconcile target is worse than a missed one, and the
/// daemon's watcher remains the backstop.
fn notify_write_path(write_path: &Option<Vec<u8>>) {
    let Some(host_path) = write_path else {
        return;
    };
    if let Ok(key) = workspace_graph_key(host_path) {
        client::notify_file_changed(&key);
    }
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
            let rename_ok = rename_bytes(&entry.temp_path, &entry.target_path);
            if atomic_write_should_notify(ret, rename_ok) {
                notify_write_path(&write_path);
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
                notify_write_path(&Some(wp));
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat_fns::real_stat(path, buf),
    };

    if !is_workspace_path(&path_bytes) {
        return stat_fns::real_stat(path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::real_stat(path, buf),
    };

    match graph_stat_follow(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat_fns::real_lstat(path, buf),
    };

    if !is_workspace_path(&path_bytes) {
        return stat_fns::real_lstat(path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::real_lstat(path, buf),
    };

    match graph_stat(&state.sock_path, &path_bytes) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path_bytes);
            guard.ok(0)
        }
        None => fail_graph_authority(),
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

    let result = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        graph_stat(&state.sock_path, &resolved)
            .map(|stat| (resolved.clone(), stat))
            .ok_or(GraphPathError::Authority)
    } else {
        graph_stat_follow(&state.sock_path, &resolved)
    };

    match result {
        Ok((resolved, vstat)) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return real_access(path, mode),
    };

    if !is_workspace_path(&path_bytes) {
        return real_access(path, mode);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_access(path, mode),
    };

    match graph_stat_follow(&state.sock_path, &path_bytes) {
        Ok((_, stat)) if graph_mode_allows(&stat, mode) => guard.ok(0),
        Ok(_) => {
            set_errno(libc::EACCES);
            -1
        }
        Err(error) => fail_graph_path(error),
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

    match graph_stat_follow(&state.sock_path, &resolved) {
        Ok((_, stat)) if graph_mode_allows(&stat, mode) => guard.ok(0),
        Ok(_) => {
            set_errno(libc::EACCES);
            -1
        }
        Err(error) => fail_graph_path(error),
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
        let name_bytes = entry.name.as_slice();
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
        let name_bytes = entry.name.as_slice();
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return real_readlink(path, buf, bufsiz),
    };

    if !is_workspace_path(&path_bytes) {
        return real_readlink(path, buf, bufsiz);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_readlink(path, buf, bufsiz),
    };

    match graph_read_link(&state.sock_path, &path_bytes) {
        Some(target) => {
            let copy_len = target.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len);
            guard.ok(copy_len as libc::ssize_t)
        }
        None => fail_graph_authority_read(),
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
            let copy_len = target.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len);
            guard.ok(copy_len as libc::ssize_t)
        }
        None => fail_graph_authority_read(),
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat_fns::call_real_xstat(ver, path, buf),
    };

    if !is_workspace_path(&path_bytes) {
        return stat_fns::call_real_xstat(ver, path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::call_real_xstat(ver, path, buf),
    };

    match graph_stat_follow(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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

    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat_fns::call_real_lxstat(ver, path, buf),
    };

    if !is_workspace_path(&path_bytes) {
        return stat_fns::call_real_lxstat(ver, path, buf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return stat_fns::call_real_lxstat(ver, path, buf),
    };

    match graph_stat(&state.sock_path, &path_bytes) {
        Some(vstat) => {
            platform::fill_stat_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path_bytes);
            guard.ok(0)
        }
        None => fail_graph_authority(),
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
    let empty = pathname.is_null() || c_to_bytes(pathname).map(<[u8]>::is_empty).unwrap_or(true);
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

    let result = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        graph_stat(&state.sock_path, &resolved)
            .map(|stat| (resolved.clone(), stat))
            .ok_or(GraphPathError::Authority)
    } else {
        graph_stat_follow(&state.sock_path, &resolved)
    };
    match result {
        Ok((resolved, vstat)) => {
            platform::fill_statx_buf(&vstat, statxbuf);
            (*statxbuf).stx_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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
    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat64_fns::real_stat64(path, buf),
    };
    if !is_workspace_path(&path_bytes) {
        return stat64_fns::real_stat64(path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::real_stat64(path, buf),
    };
    match graph_stat_follow(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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
    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat64_fns::real_lstat64(path, buf),
    };
    if !is_workspace_path(&path_bytes) {
        return stat64_fns::real_lstat64(path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::real_lstat64(path, buf),
    };
    match graph_stat(&state.sock_path, &path_bytes) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path_bytes);
            guard.ok(0)
        }
        None => fail_graph_authority(),
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
    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat64_fns::call_real_xstat64(ver, path, buf),
    };
    if !is_workspace_path(&path_bytes) {
        return stat64_fns::call_real_xstat64(ver, path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::call_real_xstat64(ver, path, buf),
    };
    match graph_stat_follow(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&resolved);
            guard.ok(0)
        }
        Err(error) => fail_graph_path(error),
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
    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return stat64_fns::call_real_lxstat64(ver, path, buf),
    };
    if !is_workspace_path(&path_bytes) {
        return stat64_fns::call_real_lxstat64(ver, path, buf);
    }
    let state = match shim_state() {
        Some(s) => s,
        None => return stat64_fns::call_real_lxstat64(ver, path, buf),
    };
    match graph_stat(&state.sock_path, &path_bytes) {
        Some(vstat) => {
            platform::fill_stat64_buf(&vstat, buf);
            (*buf).st_ino = path_to_inode(&path_bytes);
            guard.ok(0)
        }
        None => fail_graph_authority(),
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

    // `open` and `openat` are not generated by `interpose_alias!`: Darwin
    // declares them variadic, so their replacement functions live in C and
    // call these fixed, already-decoded Rust boundaries.
    #[no_mangle]
    pub unsafe extern "C" fn __kin_interpose_open_decoded(
        path: *const c_char,
        flags: c_int,
        mode: libc::mode_t,
    ) -> c_int {
        super::open(path, flags, mode)
    }

    #[no_mangle]
    pub unsafe extern "C" fn __kin_interpose_openat_decoded(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: libc::mode_t,
    ) -> c_int {
        super::openat(dirfd, path, flags, mode)
    }

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

    #[test]
    fn graph_failure_errno_never_grants_raw_filesystem_fallback() {
        use crate::client::ClientCallFailure;

        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::NotFound, false),
            libc::ENOENT
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::PermissionDenied, false),
            libc::EACCES
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::NotDirectory, false),
            libc::ENOTDIR
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::InvalidInput, false),
            libc::EINVAL
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::Unreachable, false),
            libc::EIO
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::Authority, false),
            libc::EIO,
            "size/hash/protocol disagreement must surface as EIO"
        );
    }

    /// Strict mode turns a definitive workspace miss into the same refusal the
    /// caller gets when graph authority is unavailable, so a tool cannot read a
    /// path the graph does not hold as an ordinary absent file.
    #[test]
    fn strict_mode_refuses_a_definitive_graph_miss() {
        use crate::client::ClientCallFailure;

        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::NotFound, true),
            libc::EIO
        );
        assert_eq!(
            graph_path_errno(&GraphPathError::MissingFinal, true),
            libc::EIO
        );
        assert_eq!(
            graph_path_errno(&GraphPathError::MissingFinal, false),
            libc::ENOENT
        );
        assert_eq!(graph_miss_errno_in_mode(true), libc::EIO);
        assert_eq!(graph_miss_errno_in_mode(false), libc::ENOENT);

        // Answers that describe an entry the graph *does* hold keep their exact
        // meaning: strict hardens the miss, it does not blur every failure.
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::PermissionDenied, true),
            libc::EACCES
        );
        assert_eq!(
            graph_failure_errno_in_mode(ClientCallFailure::UnsupportedBoundary, true),
            libc::ENOTSUP
        );
        assert_eq!(
            graph_path_errno(&GraphPathError::SymlinkLoop, true),
            libc::ELOOP
        );
        assert_eq!(
            graph_path_errno(&GraphPathError::NotDirectory, true),
            libc::ENOTDIR
        );
        assert_eq!(
            graph_path_errno(&GraphPathError::OutsideWorkspace, true),
            libc::EACCES
        );
    }

    /// Containment is decided on absolute bytes, so a relative argument must be
    /// resolved against the live cwd before the workspace check — otherwise the
    /// hook passes it through and raw disk answers for a graph-owned file.
    #[test]
    fn relative_paths_resolve_against_the_live_cwd() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let resolve = |text: &str| unsafe {
            let c_path = CString::new(text).unwrap();
            resolve_host_path(c_path.as_ptr()).expect("cwd is readable")
        };
        let cwd_bytes = || {
            std::env::current_dir()
                .expect("cwd is readable")
                .into_os_string()
                .into_vec()
        };

        // An absolute argument is authoritative and travels unchanged.
        assert_eq!(
            resolve("/ws/project/src/main.rs"),
            b"/ws/project/src/main.rs"
        );

        let start = cwd_bytes();
        assert_eq!(resolve("main.rs"), join_at(&start, b"main.rs"));
        assert_eq!(resolve("src/main.rs"), join_at(&start, b"src/main.rs"));

        // Read per call, never captured at init: a host that chdirs mid-life
        // must map the next relative path onto the new directory's graph key.
        let scratch = std::env::temp_dir().join(format!("kin-vfs-cwd-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch dir is creatable");
        std::env::set_current_dir(&scratch).expect("scratch dir is enterable");
        let moved_cwd = cwd_bytes();
        let moved = resolve("main.rs");
        std::env::set_current_dir(std::ffi::OsStr::from_bytes(&start)).expect("cwd restored");
        let _ = std::fs::remove_dir(&scratch);

        assert_eq!(moved, join_at(&moved_cwd, b"main.rs"));
        assert_ne!(moved, join_at(&start, b"main.rs"));
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
                name: b"hello.rs".to_vec(),
                d_ino: 0x1234,
                d_type: 8, // DT_REG
            },
            DirEntryRaw {
                name: b"subdir".to_vec(),
                d_ino: 0x5678,
                d_type: 4, // DT_DIR
            },
            DirEntryRaw {
                name: b"link".to_vec(),
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
        let vstat = VirtualStat::regular_file(big, [0u8; 32], false, 1);
        // A path that no daemon serves; the large branch must NOT attempt a fetch
        // (which would hang/None here) — it trusts the stat size and caches
        // nothing, leaving reads to the range path.
        let (size, content) = open_read_payload(
            std::path::Path::new("/nonexistent-vfs.sock"),
            b"big.bin",
            &vstat,
        )
        .expect("large-file open must use exact stat metadata without a fetch");
        assert_eq!(size, big, "large file must report its stat size");
        assert!(
            content.is_none(),
            "large file must not be prefetched/cached at open"
        );
    }
}
