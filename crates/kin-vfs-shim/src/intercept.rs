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
use crate::fd_table::{vfd_base, DirEntryRaw, VirtualFileHandle};
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

/// Compute the host-visible inode from stable graph identity when available.
///
/// Compatibility providers that do not expose object identity retain the
/// legacy path-derived inode. Kin-backed providers never use path spelling as
/// object identity, so rename and same-path replacement match native stat
/// semantics.
#[inline]
fn stat_to_inode(stat: &kin_vfs_core::VirtualStat, path: &[u8]) -> u64 {
    stat.object_id
        .as_ref()
        .map(kin_vfs_core::pathmap::synthetic_object_inode)
        .unwrap_or_else(|| kin_vfs_core::pathmap::synthetic_inode(path))
}

#[inline]
fn directory_entry_inode(object_id: Option<&[u8; 32]>) -> u64 {
    object_id
        .map(kin_vfs_core::pathmap::synthetic_object_inode)
        .unwrap_or(0)
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
    // Preserve the native empty-path contract. Joining `""` to cwd would turn
    // an ENOENT input into the workspace directory and could allocate a
    // graph-backed directory descriptor for a pathname the caller never gave.
    // Keeping it empty makes the workspace check fail and delegates the
    // impossible pathname to libc, which owns the exact errno precedence.
    if path_bytes.is_empty() {
        return Some(Vec::new());
    }
    if path_bytes.first() == Some(&b'/') {
        return Some(path_bytes.to_vec());
    }
    Some(join_at(&process_cwd()?, path_bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyAtPath {
    /// Empty is an ordinary empty pathname and fails with ENOENT.
    Reject,
    /// Resolve an empty string through the descriptor itself.
    ResolveDescriptor,
    /// Linux 6.11+ also accepts NULL with AT_EMPTY_PATH for stat-family calls.
    ResolveDescriptorIncludingNull,
}

struct ResolvedAtPath {
    path: Vec<u8>,
    /// Exact starting directory for relative lookups, used by Darwin beneath
    /// enforcement without resolving the descriptor a second time.
    directory_base: Option<Vec<u8>>,
    /// Exact provider snapshot returned with a virtual directory capability.
    snapshot: Option<kin_vfs_core::SnapshotToken>,
}

enum AtPathResolution {
    Resolved(ResolvedAtPath),
    VirtualDescriptor(Box<VirtualFileHandle>),
    Passthrough,
}

struct ResolvedDescriptorPath {
    path: Vec<u8>,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
}

fn virtual_descriptor_snapshot(fd: c_int) -> Result<Option<VirtualFileHandle>, c_int> {
    if fd < vfd_base() {
        return Ok(None);
    }
    let state = shim_state().ok_or(libc::EBADF)?;
    state
        .fd_table
        .read()
        .get(fd)
        .cloned()
        .map(Some)
        .ok_or(libc::EBADF)
}

unsafe fn resolve_empty_descriptor(dirfd: c_int) -> Result<AtPathResolution, c_int> {
    if let Some(handle) = virtual_descriptor_snapshot(dirfd)? {
        return Ok(AtPathResolution::VirtualDescriptor(Box::new(handle)));
    }
    if dirfd == libc::AT_FDCWD {
        return resolve_descriptor_path(dirfd, false).map(|resolved| {
            AtPathResolution::Resolved(ResolvedAtPath {
                path: resolved.path,
                directory_base: None,
                snapshot: resolved.snapshot,
            })
        });
    }
    Ok(AtPathResolution::Passthrough)
}

/// Resolve a real or virtual descriptor to exact host-path bytes.
///
/// A non-empty relative pathname requires a directory fd. Empty-path
/// operations explicitly set `require_directory = false` because they act on
/// the descriptor itself.
unsafe fn resolve_descriptor_path(
    dirfd: c_int,
    require_directory: bool,
) -> Result<ResolvedDescriptorPath, c_int> {
    if dirfd == libc::AT_FDCWD {
        return process_cwd()
            .map(|path| ResolvedDescriptorPath {
                path,
                snapshot: None,
            })
            .ok_or_else(|| errno());
    }

    if dirfd >= vfd_base() {
        let state = shim_state().ok_or(libc::EBADF)?;
        let handle = state
            .fd_table
            .read()
            .get(dirfd)
            .cloned()
            .ok_or(libc::EBADF)?;
        if require_directory && !handle.is_directory {
            return Err(libc::ENOTDIR);
        }
        if handle.is_directory {
            let object_id = handle
                .opened_stat
                .as_ref()
                .and_then(|stat| stat.object_id)
                .ok_or(libc::EIO)?;
            let (key, snapshot) = client::client_resolve_directory(&state.sock_path, object_id)
                .ok_or_else(|| graph_failure_errno(client::last_call_failure()))?;
            let path = if key.is_root() {
                state.workspace_root.clone()
            } else {
                join_at(&state.workspace_root, key.as_bytes())
            };
            return Ok(ResolvedDescriptorPath {
                path,
                snapshot: Some(snapshot),
            });
        }
        return Ok(ResolvedDescriptorPath {
            path: handle.path.clone(),
            snapshot: None,
        });
    }

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if stat_fns::real_fstat(dirfd, stat.as_mut_ptr()) != 0 {
        return Err(errno());
    }
    let stat = stat.assume_init();
    if require_directory && stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(libc::ENOTDIR);
    }

    #[cfg(target_os = "linux")]
    {
        let link = CString::new(format!("/proc/self/fd/{dirfd}")).map_err(|_| libc::EINVAL)?;
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let len = get_real_readlink()(link.as_ptr(), buf.as_mut_ptr().cast::<c_char>(), buf.len());
        if len < 0 {
            return Err(errno());
        }
        Ok(ResolvedDescriptorPath {
            path: buf[..len as usize].to_vec(),
            snapshot: None,
        })
    }

    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        if libc::fcntl(dirfd, libc::F_GETPATH, buf.as_mut_ptr()) == -1 {
            return Err(errno());
        }
        Ok(ResolvedDescriptorPath {
            path: CStr::from_ptr(buf.as_ptr().cast::<c_char>())
                .to_bytes()
                .to_vec(),
            snapshot: None,
        })
    }
}

/// Resolve a potentially relative `*at` pathname to exact absolute host bytes
/// while preserving native null/empty/dirfd errno precedence.
//
// The trailing `return Ok(...)` in each platform `#[cfg]` block is required:
// clippy sees only the active cfg branch and flags it as needless, but those
// branches are `#[cfg]`-attributed *statements*, not tail expressions, so
// dropping `return` would leave the fn with no value on the other platform.
#[allow(clippy::needless_return)]
unsafe fn resolve_at_path(
    dirfd: c_int,
    path: *const c_char,
    empty: EmptyAtPath,
) -> Result<AtPathResolution, c_int> {
    if path.is_null() {
        #[cfg(target_os = "linux")]
        if empty == EmptyAtPath::ResolveDescriptorIncludingNull {
            return resolve_empty_descriptor(dirfd);
        }
        return Err(libc::EFAULT);
    }

    let path_bytes = CStr::from_ptr(path).to_bytes();
    if path_bytes.is_empty() {
        return match empty {
            EmptyAtPath::Reject => Err(libc::ENOENT),
            EmptyAtPath::ResolveDescriptor | EmptyAtPath::ResolveDescriptorIncludingNull => {
                resolve_empty_descriptor(dirfd)
            }
        };
    }

    // Absolute path — use directly.
    if path_bytes.first() == Some(&b'/') {
        return Ok(AtPathResolution::Resolved(ResolvedAtPath {
            path: path_bytes.to_vec(),
            directory_base: None,
            snapshot: None,
        }));
    }

    let base = resolve_descriptor_path(dirfd, true)?;
    Ok(AtPathResolution::Resolved(ResolvedAtPath {
        path: join_at(&base.path, path_bytes),
        directory_base: Some(base.path),
        snapshot: base.snapshot,
    }))
}

/// Join `rel` against directory `base` — delegates to the fuzzed byte seam.
#[inline]
fn join_at(base: &[u8], rel: &[u8]) -> Vec<u8> {
    kin_vfs_core::pathmap::join_at_path(base, rel)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn open_tmpfile_requested(flags: c_int) -> bool {
    // O_TMPFILE is a compound value containing O_DIRECTORY.
    flags & libc::O_TMPFILE == libc::O_TMPFILE
}

#[cfg(target_os = "macos")]
#[inline]
fn open_tmpfile_requested(_flags: c_int) -> bool {
    false
}

/// Linux discards every ordinary open flag except the path-descriptor subset
/// once `O_PATH` is present. Apply that mask before unsupported-operation
/// policy so `O_PATH|O_TMPFILE` means `O_PATH|O_DIRECTORY`, exactly as the
/// kernel sees it.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn effective_graph_open_flags(flags: c_int) -> c_int {
    if flags & libc::O_PATH != 0 {
        flags & (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    } else {
        flags
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn effective_graph_open_flags(flags: c_int) -> c_int {
    flags
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn descriptor_check_only(flags: c_int) -> bool {
    // O_PATH makes every access-mode bit irrelevant. In particular,
    // O_PATH|3 is still a path-only descriptor, not Linux mode-3
    // read+write permission checking.
    flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE == libc::O_ACCMODE
}

#[cfg(target_os = "macos")]
#[inline]
fn descriptor_check_only(_flags: c_int) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn descriptor_path_only(flags: c_int) -> bool {
    flags & libc::O_PATH != 0
}

#[cfg(target_os = "macos")]
#[inline]
fn descriptor_path_only(_flags: c_int) -> bool {
    false
}

#[inline]
fn descriptor_io_permitted(flags: c_int) -> bool {
    !descriptor_check_only(flags) && !descriptor_path_only(flags)
}

/// Check if flags indicate a write operation.
#[inline]
fn is_write_flags(flags: c_int) -> bool {
    // Linux ignores ordinary access/mutation flags when O_PATH is present.
    // Treating O_CREAT/O_TRUNC on an O_PATH request as a projection write
    // would grant a mutation capability the kernel explicitly withheld.
    if descriptor_check_only(flags) || descriptor_path_only(flags) {
        return false;
    }
    let access = flags & libc::O_ACCMODE;
    access == libc::O_WRONLY
        || access == libc::O_RDWR
        || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
}

#[inline]
unsafe fn fail_errno(value: c_int) -> c_int {
    set_errno(value);
    -1
}

#[inline]
fn opened_stat(handle: &VirtualFileHandle) -> Result<&kin_vfs_core::VirtualStat, c_int> {
    handle.opened_stat.as_ref().ok_or(libc::EIO)
}

#[inline]
unsafe fn fill_stat_checked(
    stat: &kin_vfs_core::VirtualStat,
    inode: u64,
    buf: *mut libc::stat,
) -> Result<(), c_int> {
    if buf.is_null() {
        return Err(libc::EFAULT);
    }
    platform::fill_stat_buf(stat, buf);
    (*buf).st_ino = inode;
    Ok(())
}

#[cfg(target_os = "linux")]
#[inline]
unsafe fn fill_stat64_checked(
    stat: &kin_vfs_core::VirtualStat,
    inode: u64,
    buf: *mut libc::stat64,
) -> Result<(), c_int> {
    if buf.is_null() {
        return Err(libc::EFAULT);
    }
    platform::fill_stat64_buf(stat, buf);
    (*buf).st_ino = inode;
    Ok(())
}

#[cfg(target_os = "linux")]
#[inline]
unsafe fn fill_statx_checked(
    stat: &kin_vfs_core::VirtualStat,
    inode: u64,
    buf: *mut libc::statx,
) -> Result<(), c_int> {
    if buf.is_null() {
        return Err(libc::EFAULT);
    }
    platform::fill_statx_buf(stat, buf);
    (*buf).stx_ino = inode;
    Ok(())
}

/// Darwin rejects the otherwise-reserved `O_ACCMODE == 3` combination. Linux
/// gives that value a kernel-specific descriptor-check meaning, so it must not
/// be rejected cross-platform.
#[inline]
fn open_flags_are_valid(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        flags & libc::O_ACCMODE != libc::O_ACCMODE
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = flags;
        true
    }
}

#[cfg(target_os = "macos")]
const DARWIN_O_RESOLVE_BENEATH: c_int = 0x0000_1000;
#[cfg(target_os = "macos")]
const DARWIN_O_UNIQUE: c_int = 0x0000_2000;
#[cfg(target_os = "macos")]
const DARWIN_AT_SYMLINK_NOFOLLOW_ANY: c_int = 0x0800;
#[cfg(target_os = "macos")]
const DARWIN_AT_RESOLVE_BENEATH: c_int = 0x2000;
#[cfg(target_os = "macos")]
const DARWIN_AT_UNIQUE: c_int = 0x8000;
#[cfg(target_os = "macos")]
const DARWIN_AT_REALDEV: c_int = 0x0200;
#[cfg(target_os = "macos")]
const DARWIN_AT_FDONLY: c_int = 0x0400;

/// Return the fail-closed errno for a graph-owned open contract KinVFS cannot
/// faithfully expose.
///
/// Callers invoke this only after lexical path/dirfd resolution establishes
/// that the target is inside the workspace, but before graph I/O or
/// materialization. Native operations outside the workspace retain their
/// platform semantics instead of being globally disabled by the injected shim.
#[inline]
fn graph_open_rejection_errno(flags: c_int) -> Option<c_int> {
    let effective_flags = effective_graph_open_flags(flags);
    if open_tmpfile_requested(effective_flags) {
        // An unnamed inode cannot be represented by the current graph/write
        // transaction contract. Never reinterpret it as an ordinary named
        // materialization.
        return Some(libc::EOPNOTSUPP);
    }
    if descriptor_check_only(flags) && flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
        // Linux mode 3 is metadata/check-only. Creation or truncation would
        // require a mutation-capable descriptor and must not be reinterpreted
        // as either a graph read or a projection write.
        return Some(libc::EOPNOTSUPP);
    }
    #[cfg(target_os = "macos")]
    {
        // These descriptor kinds require rights/state the current virtual-fd
        // table does not model. Explicit refusal is safer than returning an
        // ordinary readable descriptor with silently stronger capabilities.
        if flags & (libc::O_SYMLINK | libc::O_EXEC | libc::O_EVTONLY) != 0 {
            return Some(libc::EOPNOTSUPP);
        }

        // The graph-native read path implements these lookup guarantees below.
        // The materialize/write path does not yet have a path-resolution CAS,
        // so refuse the combination before it can weaken the requested guard.
        let guarded_lookup = libc::O_NOFOLLOW_ANY | DARWIN_O_RESOLVE_BENEATH | DARWIN_O_UNIQUE;
        if is_write_flags(flags) && flags & guarded_lookup != 0 {
            return Some(libc::EOPNOTSUPP);
        }
    }
    None
}

#[inline]
fn fstatat_flags_are_valid(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    let allowed = libc::AT_SYMLINK_NOFOLLOW
        | DARWIN_AT_REALDEV
        | DARWIN_AT_FDONLY
        | DARWIN_AT_SYMLINK_NOFOLLOW_ANY
        | DARWIN_AT_RESOLVE_BENEATH
        | DARWIN_AT_UNIQUE;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let allowed = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT;
    flags & !allowed == 0
}

#[inline]
fn faccessat_flags_are_valid(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    let allowed = libc::AT_EACCESS
        | libc::AT_SYMLINK_NOFOLLOW
        | DARWIN_AT_SYMLINK_NOFOLLOW_ANY
        | DARWIN_AT_RESOLVE_BENEATH
        | DARWIN_AT_UNIQUE;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let allowed = libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    flags & !allowed == 0
}

/// Validate `access`/`faccessat` mode in the same platform-specific way as the
/// native libc. Linux rejects every bit outside RWX. Darwin masks to the RWX
/// bits (confirmed by the native differential), including for negative input.
#[inline]
fn access_mode_is_valid(mode: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        let _ = mode;
        true
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        mode & !(libc::R_OK | libc::W_OK | libc::X_OK) == 0
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn at_empty_path_requested(flags: c_int) -> bool {
    flags & libc::AT_EMPTY_PATH != 0
}

#[cfg(target_os = "macos")]
#[inline]
fn at_empty_path_requested(_flags: c_int) -> bool {
    false
}

#[cfg(target_os = "linux")]
#[inline]
fn statx_flags_are_valid(flags: c_int) -> bool {
    let allowed = libc::AT_SYMLINK_NOFOLLOW
        | libc::AT_EMPTY_PATH
        | libc::AT_NO_AUTOMOUNT
        | libc::AT_STATX_SYNC_TYPE;
    let sync = flags & libc::AT_STATX_SYNC_TYPE;
    flags & !allowed == 0 && sync != libc::AT_STATX_SYNC_TYPE
}

/// Whether native `open`/`openat` consumes its variadic mode argument.
#[inline]
fn open_requires_mode(flags: c_int) -> bool {
    if flags & libc::O_CREAT != 0 {
        return true;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return open_tmpfile_requested(flags);
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
fn graph_stat_in_snapshot(
    sock_path: &std::path::Path,
    host_path: &[u8],
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Option<kin_vfs_core::VirtualStat> {
    let key = graph_request_key(host_path)?;
    match snapshot {
        Some(snapshot) => client::client_stat_at_snapshot(sock_path, snapshot, &key),
        None => client::client_stat(sock_path, &key),
    }
}

#[inline]
fn graph_read_opened_blob(
    sock_path: &std::path::Path,
    host_path: &[u8],
    stat: &kin_vfs_core::VirtualStat,
    offset: u64,
    len: u64,
) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    let content_hash = stat.content_hash?;
    client::client_read_blob(sock_path, content_hash, stat.size, &key, offset, len)
}

#[inline]
fn graph_read_dir_in_snapshot(
    sock_path: &std::path::Path,
    host_path: &[u8],
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Option<Vec<kin_vfs_core::DirEntry>> {
    let key = graph_request_key(host_path)?;
    match snapshot {
        Some(snapshot) => client::client_read_dir_at_snapshot(sock_path, snapshot, &key),
        None => client::client_read_dir(sock_path, &key),
    }
}

#[inline]
fn graph_read_link(sock_path: &std::path::Path, host_path: &[u8]) -> Option<Vec<u8>> {
    graph_read_link_in_snapshot(sock_path, host_path, None)
}

#[inline]
fn graph_read_link_in_snapshot(
    sock_path: &std::path::Path,
    host_path: &[u8],
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Option<Vec<u8>> {
    let key = graph_request_key(host_path)?;
    match snapshot {
        Some(snapshot) => client::client_read_link_at_snapshot(sock_path, snapshot, &key),
        None => client::client_read_link(sock_path, &key),
    }
}

#[derive(Debug, Clone)]
enum GraphPathError {
    Authority,
    MissingFinal(Vec<u8>),
    InvalidSymlink,
    SymlinkLoop,
    SymlinkForbidden,
    OutsideWorkspace,
    BeneathEscape,
    NotUnique,
    NotDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum GraphSymlinkPolicy {
    FollowAll,
    PreserveFinal,
    RejectAny,
    RejectIntermediatePreserveFinal,
}

#[derive(Debug, Clone, Copy)]
struct GraphResolveOptions<'a> {
    symlinks: GraphSymlinkPolicy,
    beneath_base: Option<&'a [u8]>,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
}

impl Default for GraphResolveOptions<'_> {
    fn default() -> Self {
        Self {
            symlinks: GraphSymlinkPolicy::FollowAll,
            beneath_base: None,
            snapshot: None,
        }
    }
}

/// Split a relative component stream while preserving parent traversals.
///
/// Empty and `.` components have no lookup effect. `..` remains in the queue
/// so it is applied only after every preceding symlink has expanded.
fn graph_components(path: &[u8]) -> Result<VecDeque<Vec<u8>>, GraphPathError> {
    if path.contains(&0) {
        return Err(GraphPathError::OutsideWorkspace);
    }
    Ok(path
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .map(<[u8]>::to_vec)
        .collect())
}

/// Return the raw suffix of `path` below an absolute trusted root.
fn host_suffix_below<'a>(path: &'a [u8], root: &[u8]) -> Option<&'a [u8]> {
    let root = if root.len() > 1 {
        root.strip_suffix(b"/").unwrap_or(root)
    } else {
        root
    };
    if root == b"/" {
        return path.strip_prefix(b"/");
    }
    if !kin_vfs_core::pathmap::path_within_root(path, root) {
        return None;
    }
    let suffix = &path[root.len()..];
    Some(suffix.strip_prefix(b"/").unwrap_or(suffix))
}

/// Map a host spelling to the component stream below the canonical graph root
/// without normalizing `..` or consulting the host filesystem.
fn graph_components_from_host(path: &[u8]) -> Result<VecDeque<Vec<u8>>, GraphPathError> {
    if path.first() != Some(&b'/') || path.contains(&0) {
        return Err(GraphPathError::OutsideWorkspace);
    }
    let state = shim_state().ok_or(GraphPathError::Authority)?;
    let mut selected: Option<VecDeque<Vec<u8>>> = None;
    for root in std::iter::once(&state.workspace_root).chain(&state.workspace_aliases) {
        let Some(suffix) = host_suffix_below(path, root) else {
            continue;
        };
        let candidate = graph_components(suffix)?;
        if selected
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(GraphPathError::OutsideWorkspace);
        }
        selected = Some(candidate);
    }
    selected.ok_or(GraphPathError::OutsideWorkspace)
}

/// Convert one trusted host spelling to the canonical workspace-root spelling.
fn canonical_graph_host_path(path: &[u8]) -> Result<Vec<u8>, GraphPathError> {
    let state = shim_state().ok_or(GraphPathError::Authority)?;
    let key = workspace_graph_key(path).map_err(|_| GraphPathError::OutsideWorkspace)?;
    if key.is_root() {
        Ok(state.workspace_root.clone())
    } else {
        Ok(join_at(&state.workspace_root, key.as_bytes()))
    }
}

fn graph_parent(current: &[u8], floor: &[u8], beneath: bool) -> Result<Vec<u8>, GraphPathError> {
    if current == floor {
        return Err(if beneath {
            GraphPathError::BeneathEscape
        } else {
            GraphPathError::OutsideWorkspace
        });
    }
    let slash = current
        .iter()
        .rposition(|byte| *byte == b'/')
        .ok_or(GraphPathError::OutsideWorkspace)?;
    let parent = if slash == 0 {
        b"/".to_vec()
    } else {
        current[..slash].to_vec()
    };
    if !kin_vfs_core::pathmap::path_within_root(&parent, floor) && parent != floor {
        return Err(if beneath {
            GraphPathError::BeneathEscape
        } else {
            GraphPathError::OutsideWorkspace
        });
    }
    Ok(parent)
}

/// Resolve graph-owned path components without asking the host filesystem.
///
/// `symlinks` models the native distinction between following all links,
/// preserving only the final component, and refusing any/intermediate links.
/// `beneath_base` is enforced in graph-key space after every redirect so an
/// alias spelling or graph symlink cannot escape the starting directory.
fn graph_stat_resolve(
    sock_path: &Path,
    host_path: &[u8],
    options: GraphResolveOptions<'_>,
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    let state = shim_state().ok_or(GraphPathError::Authority)?;
    let root = state.workspace_root.clone();
    let (mut current, mut pending, constraint) = if let Some(base) = options.beneath_base {
        let canonical_base =
            canonical_graph_host_path(base).map_err(|_| GraphPathError::BeneathEscape)?;
        let suffix = host_suffix_below(host_path, base).ok_or(GraphPathError::BeneathEscape)?;
        (
            canonical_base.clone(),
            graph_components(suffix)?,
            canonical_base,
        )
    } else {
        (
            root.clone(),
            graph_components_from_host(host_path)?,
            root.clone(),
        )
    };
    let mut followed = 0;

    if pending.is_empty() {
        let stat = graph_stat_in_snapshot(sock_path, &current, options.snapshot)
            .ok_or(GraphPathError::Authority)?;
        return Ok((current, stat));
    }

    while let Some(component) = pending.pop_front() {
        if component == b".." {
            current = graph_parent(&current, &constraint, options.beneath_base.is_some())?;
            if pending.is_empty() {
                let stat = graph_stat_in_snapshot(sock_path, &current, options.snapshot)
                    .ok_or(GraphPathError::Authority)?;
                return Ok((current, stat));
            }
            continue;
        }

        let candidate = join_at(&current, &component);
        let stat = match graph_stat_in_snapshot(sock_path, &candidate, options.snapshot) {
            Some(stat) => stat,
            None if client::last_call_failure() == client::ClientCallFailure::NotFound
                && pending.is_empty() =>
            {
                return Err(GraphPathError::MissingFinal(candidate));
            }
            None => return Err(GraphPathError::Authority),
        };
        if stat.is_symlink {
            let is_final = pending.is_empty();
            match options.symlinks {
                GraphSymlinkPolicy::PreserveFinal
                | GraphSymlinkPolicy::RejectIntermediatePreserveFinal
                    if is_final =>
                {
                    return Ok((candidate, stat));
                }
                GraphSymlinkPolicy::RejectAny
                | GraphSymlinkPolicy::RejectIntermediatePreserveFinal => {
                    return Err(GraphPathError::SymlinkForbidden);
                }
                GraphSymlinkPolicy::FollowAll | GraphSymlinkPolicy::PreserveFinal => {}
            }

            followed += 1;
            if followed > 40 {
                return Err(GraphPathError::SymlinkLoop);
            }

            // The link target is exact graph-owned bytes; it is never required
            // to be UTF-8, only NUL-free (a NUL cannot appear in a path).
            let target = graph_read_link_in_snapshot(sock_path, &candidate, options.snapshot)
                .ok_or(GraphPathError::Authority)?;
            if target.contains(&0) || target.is_empty() {
                return Err(GraphPathError::InvalidSymlink);
            }

            let mut redirected = if target.first() == Some(&b'/') {
                if options.beneath_base.is_some() {
                    return Err(GraphPathError::BeneathEscape);
                }
                current = root.clone();
                graph_components_from_host(&target)?
            } else {
                graph_components(&target)?
            };
            redirected.append(&mut pending);
            pending = redirected;
            if pending.is_empty() {
                let current_stat = graph_stat_in_snapshot(sock_path, &current, options.snapshot)
                    .ok_or(GraphPathError::Authority)?;
                return Ok((current.clone(), current_stat));
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

/// Follow every graph-owned symlink. The final returned path is the graph path
/// whose blob must be read.
fn graph_stat_follow(
    sock_path: &Path,
    host_path: &[u8],
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    graph_stat_resolve(sock_path, host_path, GraphResolveOptions::default())
}

fn graph_stat_preserve_final(
    sock_path: &Path,
    host_path: &[u8],
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    graph_stat_preserve_final_in_snapshot(sock_path, host_path, None)
}

fn graph_stat_preserve_final_in_snapshot(
    sock_path: &Path,
    host_path: &[u8],
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    graph_stat_resolve(
        sock_path,
        host_path,
        GraphResolveOptions {
            symlinks: GraphSymlinkPolicy::PreserveFinal,
            beneath_base: None,
            snapshot,
        },
    )
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
fn materialize_file(
    path_bytes: &[u8],
    opened_stat: Option<&kin_vfs_core::VirtualStat>,
) -> Result<Option<Vec<u8>>, c_int> {
    use std::os::unix::ffi::OsStrExt;

    let state = shim_state().ok_or(libc::EIO)?;

    // Clean up stale temp files from previous crashed processes.
    cleanup_stale_temps(path_bytes);

    // Resolution already established either an exact object or a missing final
    // component. Existing objects are materialized by their captured content
    // hash, never by a second refreshable pathname lookup.
    let content = match opened_stat {
        Some(stat) => graph_read_opened_blob(&state.sock_path, path_bytes, stat, 0, 0)
            .ok_or_else(|| graph_failure_errno(client::last_call_failure()))?,
        None => return Ok(None),
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
fn allocate_vfd(
    path_bytes: &[u8],
    stat: kin_vfs_core::VirtualStat,
    content: Option<Vec<u8>>,
    io_permitted: bool,
    path_only: bool,
    link_target: Option<Vec<u8>>,
) -> c_int {
    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    state
        .fd_table
        .write()
        .allocate_opened(
            path_bytes,
            stat,
            content,
            io_permitted,
            path_only,
            link_target,
        )
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
fn allocate_dir_vfd(
    path_bytes: &[u8],
    stat: kin_vfs_core::VirtualStat,
    io_permitted: bool,
    path_only: bool,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> c_int {
    use kin_vfs_core::FileType;

    let state = match shim_state() {
        Some(s) => s,
        None => return -1,
    };

    let entries = if io_permitted {
        match graph_read_dir_in_snapshot(&state.sock_path, path_bytes, snapshot) {
            Some(e) => e,
            None => return -1,
        }
    } else {
        Vec::new()
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
            // Match stat/fstatat identity exactly. A compatibility provider
            // that cannot supply object identity reports zero rather than a
            // basename-derived inode that can collide or contradict stat.
            let d_ino = directory_entry_inode(entry.object_id.as_ref());
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
        .allocate_opened_dir(path_bytes, stat, raw_entries, io_permitted, path_only)
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

#[inline]
fn graph_capability_errno() -> c_int {
    #[cfg(target_os = "macos")]
    {
        libc::ENOTCAPABLE
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        libc::EACCES
    }
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
        GraphPathError::MissingFinal(_) => graph_miss_errno_in_mode(strict),
        GraphPathError::InvalidSymlink => libc::EINVAL,
        GraphPathError::SymlinkLoop | GraphPathError::SymlinkForbidden => libc::ELOOP,
        GraphPathError::OutsideWorkspace => libc::EACCES,
        GraphPathError::BeneathEscape | GraphPathError::NotUnique => graph_capability_errno(),
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

fn process_belongs_to_group(group: libc::gid_t, effective: bool) -> bool {
    let primary = unsafe {
        if effective {
            libc::getegid()
        } else {
            libc::getgid()
        }
    };
    if primary == group {
        return true;
    }

    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let written = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    written > 0 && groups[..written as usize].contains(&group)
}

/// Evaluate projected Unix permissions using the same real/effective identity
/// selection as access/faccessat. Platform stat filling presents graph entries
/// as owned by the process's real uid/gid, so this calculation matches the
/// metadata callers observe.
fn graph_mode_allows(stat: &kin_vfs_core::VirtualStat, requested: c_int, effective: bool) -> bool {
    let owner_uid = unsafe { libc::getuid() };
    let owner_gid = unsafe { libc::getgid() };
    let caller_uid = unsafe {
        if effective {
            libc::geteuid()
        } else {
            libc::getuid()
        }
    };

    if caller_uid == 0 {
        return requested & libc::X_OK == 0 || stat.mode & 0o111 != 0;
    }

    let permission_bits = if caller_uid == owner_uid {
        (stat.mode >> 6) & 0o7
    } else if process_belongs_to_group(owner_gid, effective) {
        (stat.mode >> 3) & 0o7
    } else {
        stat.mode & 0o7
    };
    (requested & libc::R_OK == 0 || permission_bits & 0o4 != 0)
        && (requested & libc::W_OK == 0 || permission_bits & 0o2 != 0)
        && (requested & libc::X_OK == 0 || permission_bits & 0o1 != 0)
}

/// Linux access mode 3 asks the kernel to check read+write permission without
/// granting data I/O. It is not `O_PATH`: directories fail with `EISDIR`, and
/// an inaccessible regular file fails at open rather than producing a handle.
#[inline]
fn descriptor_open_error(stat: &kin_vfs_core::VirtualStat, flags: c_int) -> Option<c_int> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if descriptor_check_only(flags) {
            if stat.is_dir {
                return Some(libc::EISDIR);
            }
            if !graph_mode_allows(stat, libc::R_OK | libc::W_OK, true) {
                return Some(libc::EACCES);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (stat, flags);
    }
    None
}

#[inline]
fn open_symlink_policy(flags: c_int) -> GraphSymlinkPolicy {
    #[cfg(target_os = "macos")]
    if flags & libc::O_NOFOLLOW_ANY != 0 {
        return GraphSymlinkPolicy::RejectAny;
    }
    if flags & libc::O_NOFOLLOW != 0 {
        GraphSymlinkPolicy::PreserveFinal
    } else {
        GraphSymlinkPolicy::FollowAll
    }
}

#[inline]
fn at_symlink_policy(flags: c_int) -> GraphSymlinkPolicy {
    #[cfg(target_os = "macos")]
    if flags & DARWIN_AT_SYMLINK_NOFOLLOW_ANY != 0 {
        return GraphSymlinkPolicy::RejectIntermediatePreserveFinal;
    }
    if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        GraphSymlinkPolicy::PreserveFinal
    } else {
        GraphSymlinkPolicy::FollowAll
    }
}

#[inline]
fn open_unique_requested(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        flags & DARWIN_O_UNIQUE != 0
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = flags;
        false
    }
}

#[inline]
fn at_unique_requested(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        flags & DARWIN_AT_UNIQUE != 0
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = flags;
        false
    }
}

#[inline]
fn open_beneath_requested(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        flags & DARWIN_O_RESOLVE_BENEATH != 0
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = flags;
        false
    }
}

#[inline]
fn at_beneath_requested(flags: c_int) -> bool {
    #[cfg(target_os = "macos")]
    {
        flags & DARWIN_AT_RESOLVE_BENEATH != 0
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = flags;
        false
    }
}

/// Derive the starting-directory constraint for a Darwin beneath lookup.
///
/// Absolute paths are not relative to the supplied descriptor and Darwin
/// rejects them with ENOTCAPABLE under *_RESOLVE_BENEATH.
fn at_beneath_base(resolved: &ResolvedAtPath, enabled: bool) -> Result<Option<Vec<u8>>, c_int> {
    if !enabled {
        return Ok(None);
    }
    resolved
        .directory_base
        .clone()
        .map(Some)
        .ok_or_else(graph_capability_errno)
}

unsafe fn plain_beneath_base(path: *const c_char, enabled: bool) -> Result<Option<Vec<u8>>, c_int> {
    if !enabled {
        return Ok(None);
    }
    let path = c_to_bytes(path).ok_or(libc::EFAULT)?;
    if path.first() == Some(&b'/') {
        return Err(graph_capability_errno());
    }
    process_cwd().ok_or_else(|| errno()).map(Some)
}

fn enforce_unique(
    result: Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError>,
    required: bool,
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    match result {
        Ok((_, stat)) if required && stat.nlink != 1 => Err(GraphPathError::NotUnique),
        other => other,
    }
}

fn resolve_graph_open(
    sock_path: &Path,
    host_path: &[u8],
    flags: c_int,
    beneath_base: Option<&[u8]>,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    let symlinks = open_symlink_policy(flags);
    let result = graph_stat_resolve(
        sock_path,
        host_path,
        GraphResolveOptions {
            symlinks,
            beneath_base,
            snapshot,
        },
    );
    let result = match result {
        // O_NOFOLLOW preserves the final component only so the open layer can
        // return ELOOP for a final symlink after intermediate links resolved.
        Ok((_, stat))
            if symlinks == GraphSymlinkPolicy::PreserveFinal
                && stat.is_symlink
                && !descriptor_path_only(flags) =>
        {
            Err(GraphPathError::SymlinkForbidden)
        }
        other => other,
    };
    enforce_unique(result, open_unique_requested(flags))
}

fn resolve_graph_at(
    sock_path: &Path,
    host_path: &[u8],
    flags: c_int,
    beneath_base: Option<&[u8]>,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Result<(Vec<u8>, kin_vfs_core::VirtualStat), GraphPathError> {
    let result = graph_stat_resolve(
        sock_path,
        host_path,
        GraphResolveOptions {
            symlinks: at_symlink_policy(flags),
            beneath_base,
            snapshot,
        },
    );
    enforce_unique(result, at_unique_requested(flags))
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
        // Metadata and bytes are separate socket requests. Resolve the body by
        // the hash captured in `vstat`, not by the path a second time, so a
        // replacement between stat and read cannot seed the new descriptor
        // with bytes from a different object.
        let content = graph_read_opened_blob(sock_path, path_bytes, vstat, 0, 0)
            .ok_or(GraphPathError::Authority)?;
        Ok((vstat.size, Some(content)))
    } else {
        // Large file: exact tree metadata supplies the size and verified
        // ranged reads serve the data.
        Ok((vstat.size, None))
    }
}

fn resolve_graph_write_target(
    sock_path: &Path,
    host_path: &[u8],
    flags: c_int,
    beneath_base: Option<&[u8]>,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> Result<(Vec<u8>, Option<kin_vfs_core::VirtualStat>), GraphPathError> {
    match resolve_graph_open(sock_path, host_path, flags, beneath_base, snapshot) {
        Ok((resolved, stat)) => Ok((resolved, Some(stat))),
        Err(GraphPathError::MissingFinal(candidate)) if flags & libc::O_CREAT != 0 => {
            Ok((candidate, None))
        }
        Err(error) => Err(error),
    }
}

fn allocate_graph_open(
    state: &crate::ShimState,
    resolved_path: Vec<u8>,
    vstat: kin_vfs_core::VirtualStat,
    flags: c_int,
    snapshot: Option<kin_vfs_core::SnapshotToken>,
) -> c_int {
    if flags & libc::O_DIRECTORY != 0 && !vstat.is_dir {
        // Native lookup resolves the required object kind before access-mode
        // permission checks, including Linux's metadata-only mode 3.
        unsafe { set_errno(libc::ENOTDIR) };
        return -1;
    }

    if let Some(error) = descriptor_open_error(&vstat, flags) {
        // SAFETY: errno is thread-local state for the intercepted call.
        unsafe { set_errno(error) };
        return -1;
    }

    let io_permitted = descriptor_io_permitted(flags);
    let path_only = descriptor_path_only(flags);

    if vstat.is_dir {
        return match allocate_dir_vfd(&resolved_path, vstat, io_permitted, path_only, snapshot) {
            fd if fd >= vfd_base() => fd,
            _ => fail_graph_authority(),
        };
    }

    if vstat.is_file {
        let payload = if io_permitted {
            open_read_payload(&state.sock_path, &resolved_path, &vstat)
        } else {
            Ok((vstat.size, None))
        };
        return match payload {
            Ok((_effective_size, content)) => match allocate_vfd(
                &resolved_path,
                vstat,
                content,
                io_permitted,
                path_only,
                None,
            ) {
                fd if fd >= vfd_base() => fd,
                _ => {
                    // SAFETY: see above.
                    unsafe { set_errno(libc::EIO) };
                    -1
                }
            },
            Err(error) => fail_graph_path(error),
        };
    }

    if vstat.is_symlink && path_only {
        let target = match graph_read_link_in_snapshot(&state.sock_path, &resolved_path, snapshot) {
            Some(target) => target,
            None => return fail_graph_authority(),
        };
        return match allocate_vfd(&resolved_path, vstat, None, false, true, Some(target)) {
            fd if fd >= vfd_base() => fd,
            _ => {
                // SAFETY: see above.
                unsafe { set_errno(libc::EIO) };
                -1
            }
        };
    }

    // SAFETY: see above.
    unsafe { set_errno(libc::EINVAL) };
    -1
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

    if !open_flags_are_valid(flags) {
        return fail_errno(libc::EINVAL);
    }

    let beneath_base = match plain_beneath_base(path, open_beneath_requested(flags)) {
        Ok(base) => base,
        Err(error) => return fail_errno(error),
    };
    let path_bytes = match resolve_host_path(path) {
        Some(p) => p,
        None => return call_real_open(real_open, path, flags, mode),
    };

    if !is_workspace_path(&path_bytes) {
        return call_real_open(real_open, path, flags, mode);
    }
    if let Some(error) = graph_open_rejection_errno(flags) {
        return fail_errno(error);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return call_real_open(real_open, path, flags, mode),
    };

    // Write flags -> materialize then passthrough, tracking the fd.
    if is_write_flags(flags) {
        let (target_path, target_stat) = match resolve_graph_write_target(
            &state.sock_path,
            &path_bytes,
            flags,
            beneath_base.as_deref(),
            None,
        ) {
            Ok(target) => target,
            Err(error) => return fail_graph_path(error),
        };
        let temp = match materialize_file(&target_path, target_stat.as_ref()) {
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
                    ft.track_write(fd, target_path.clone());
                    ft.track_atomic_write(fd, target_path.clone(), temp_path.clone());
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
        let c_target = match bytes_to_cstring(&target_path) {
            Some(path) => path,
            None => return fail_errno(libc::EINVAL),
        };
        let fd = call_real_open(real_open, c_target.as_ptr(), flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, target_path);
            }
        }
        return fd;
    }

    // Read-only open resolves symlinks wholly through graph authority.
    let resolved = resolve_graph_open(
        &state.sock_path,
        &path_bytes,
        flags,
        beneath_base.as_deref(),
        None,
    );

    match resolved {
        Ok((resolved_path, vstat)) => allocate_graph_open(state, resolved_path, vstat, flags, None),
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

    if !open_flags_are_valid(flags) {
        return fail_errno(libc::EINVAL);
    }

    let resolved_at = match resolve_at_path(dirfd, path, EmptyAtPath::Reject) {
        Ok(AtPathResolution::Resolved(resolved)) => resolved,
        Ok(AtPathResolution::VirtualDescriptor(_)) => return fail_errno(libc::EINVAL),
        Ok(AtPathResolution::Passthrough) => {
            return call_real_openat(real_openat, dirfd, path, flags, mode);
        }
        Err(error) => return fail_errno(error),
    };
    let beneath_base = match at_beneath_base(&resolved_at, open_beneath_requested(flags)) {
        Ok(base) => base,
        Err(error) => return fail_errno(error),
    };
    let resolved = resolved_at.path;
    let snapshot = resolved_at.snapshot;
    if !is_workspace_path(&resolved) {
        return call_real_openat(real_openat, dirfd, path, flags, mode);
    }
    if let Some(error) = graph_open_rejection_errno(flags) {
        return fail_errno(error);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return call_real_openat(real_openat, dirfd, path, flags, mode),
    };

    if is_write_flags(flags) {
        let (target_path, target_stat) = match resolve_graph_write_target(
            &state.sock_path,
            &resolved,
            flags,
            beneath_base.as_deref(),
            snapshot,
        ) {
            Ok(target) => target,
            Err(error) => return fail_graph_path(error),
        };
        let temp = match materialize_file(&target_path, target_stat.as_ref()) {
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
                    ft.track_write(fd, target_path.clone());
                    ft.track_atomic_write(fd, target_path.clone(), temp_path.clone());
                }
            }
            return fd;
        }
        if flags & libc::O_CREAT == 0 {
            set_errno(libc::ENOENT);
            return -1;
        }
        // Create a genuinely new file at the explicit projection/write boundary.
        let c_target = match bytes_to_cstring(&target_path) {
            Some(path) => path,
            None => return fail_errno(libc::EINVAL),
        };
        let fd = call_real_openat(real_openat, libc::AT_FDCWD, c_target.as_ptr(), flags, mode);
        if fd >= 0 {
            if let Some(state) = shim_state() {
                state.fd_table.write().track_write(fd, target_path);
            }
        }
        return fd;
    }

    let graph_resolved = resolve_graph_open(
        &state.sock_path,
        &resolved,
        flags,
        beneath_base.as_deref(),
        snapshot,
    );

    match graph_resolved {
        Ok((resolved_path, vstat)) => {
            allocate_graph_open(state, resolved_path, vstat, flags, snapshot)
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
    match fd_table.get(fd) {
        Some(handle) if handle.path_only => return fail_errno(libc::EBADF),
        Some(_) => {}
        None => return real_flock(fd, operation),
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
    if !handle.io_permitted {
        set_errno(libc::EBADF);
        return -1;
    }

    let offset = handle.offset;
    let size = handle.size;
    let path = handle.path.clone();
    let identity = match opened_stat(handle) {
        Ok(stat) => stat.clone(),
        Err(error) => return fail_errno(error) as libc::ssize_t,
    };

    // Check if we're at or past EOF.
    if offset >= size {
        return guard.ok(0);
    }

    let bytes_to_read = count.min((size - offset) as usize);
    if bytes_to_read == 0 {
        return guard.ok(0);
    }
    if buf.is_null() {
        return fail_errno(libc::EFAULT) as libc::ssize_t;
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

    let data = match graph_read_opened_blob(
        &state.sock_path,
        &path,
        &identity,
        offset,
        bytes_to_read as u64,
    ) {
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
    if !handle.io_permitted {
        set_errno(libc::EBADF);
        return -1;
    }

    let size = handle.size;
    let path = handle.path.clone();
    let identity = match opened_stat(handle) {
        Ok(stat) => stat.clone(),
        Err(error) => return fail_errno(error) as libc::ssize_t,
    };
    if offset < 0 {
        return fail_errno(libc::EINVAL) as libc::ssize_t;
    }
    let off = offset as u64;

    if off >= size {
        return guard.ok(0);
    }

    let bytes_to_read = count.min((size - off) as usize);
    if bytes_to_read == 0 {
        return guard.ok(0);
    }
    if buf.is_null() {
        return fail_errno(libc::EFAULT) as libc::ssize_t;
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

    let data = match graph_read_opened_blob(
        &state.sock_path,
        &path,
        &identity,
        off,
        bytes_to_read as u64,
    ) {
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

    if state
        .fd_table
        .read()
        .get(fd)
        .is_some_and(|handle| !handle.io_permitted)
    {
        set_errno(libc::EBADF);
        return -1;
    }

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
            match fill_stat_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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

    match graph_stat_preserve_final(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            match fill_stat_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
        }
        Err(error) => fail_graph_path(error),
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

    let stat = match opened_stat(handle) {
        Ok(stat) => stat,
        Err(error) => return fail_errno(error),
    };
    match fill_stat_checked(stat, handle.opened_inode, buf) {
        Ok(()) => guard.ok(0),
        Err(error) => fail_errno(error),
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

    if !fstatat_flags_are_valid(flags) {
        return fail_errno(libc::EINVAL);
    }

    #[cfg(target_os = "macos")]
    if flags & DARWIN_AT_FDONLY != 0 {
        match virtual_descriptor_snapshot(dirfd) {
            Ok(Some(handle)) => {
                let stat = match opened_stat(&handle) {
                    Ok(stat) => stat,
                    Err(error) => return fail_errno(error),
                };
                return match fill_stat_checked(stat, handle.opened_inode, buf) {
                    Ok(()) => guard.ok(0),
                    Err(error) => fail_errno(error),
                };
            }
            Ok(None) => return real_fstatat(dirfd, path, buf, flags),
            Err(error) => return fail_errno(error),
        }
    }

    let empty = if at_empty_path_requested(flags) {
        EmptyAtPath::ResolveDescriptorIncludingNull
    } else {
        EmptyAtPath::Reject
    };
    let resolved_at = match resolve_at_path(dirfd, path, empty) {
        Ok(AtPathResolution::Resolved(resolved)) => resolved,
        Ok(AtPathResolution::VirtualDescriptor(handle)) => {
            let stat = match opened_stat(&handle) {
                Ok(stat) => stat,
                Err(error) => return fail_errno(error),
            };
            return match fill_stat_checked(stat, handle.opened_inode, buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            };
        }
        Ok(AtPathResolution::Passthrough) => {
            return real_fstatat(dirfd, path, buf, flags);
        }
        Err(error) => return fail_errno(error),
    };
    let beneath_base = match at_beneath_base(&resolved_at, at_beneath_requested(flags)) {
        Ok(base) => base,
        Err(error) => return fail_errno(error),
    };
    let resolved = resolved_at.path;
    let snapshot = resolved_at.snapshot;
    if !is_workspace_path(&resolved) {
        return real_fstatat(dirfd, path, buf, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_fstatat(dirfd, path, buf, flags),
    };

    let result = resolve_graph_at(
        &state.sock_path,
        &resolved,
        flags,
        beneath_base.as_deref(),
        snapshot,
    );

    match result {
        Ok((resolved, vstat)) => {
            match fill_stat_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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

    if !access_mode_is_valid(mode) {
        return fail_errno(libc::EINVAL);
    }

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
        Ok((_, stat)) if graph_mode_allows(&stat, mode, false) => guard.ok(0),
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

    if !access_mode_is_valid(mode) || !faccessat_flags_are_valid(flags) {
        return fail_errno(libc::EINVAL);
    }

    let empty = if at_empty_path_requested(flags) {
        EmptyAtPath::ResolveDescriptor
    } else {
        EmptyAtPath::Reject
    };
    let resolved_at = match resolve_at_path(dirfd, path, empty) {
        Ok(AtPathResolution::Resolved(resolved)) => resolved,
        Ok(AtPathResolution::VirtualDescriptor(handle)) => {
            let stat = match opened_stat(&handle) {
                Ok(stat) => stat,
                Err(error) => return fail_errno(error),
            };
            return if graph_mode_allows(stat, mode, flags & libc::AT_EACCESS != 0) {
                guard.ok(0)
            } else {
                fail_errno(libc::EACCES)
            };
        }
        Ok(AtPathResolution::Passthrough) => {
            return real_faccessat(dirfd, path, mode, flags);
        }
        Err(error) => return fail_errno(error),
    };
    let beneath_base = match at_beneath_base(&resolved_at, at_beneath_requested(flags)) {
        Ok(base) => base,
        Err(error) => return fail_errno(error),
    };
    let resolved = resolved_at.path;
    let snapshot = resolved_at.snapshot;
    if !is_workspace_path(&resolved) {
        return real_faccessat(dirfd, path, mode, flags);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_faccessat(dirfd, path, mode, flags),
    };

    let result = resolve_graph_at(
        &state.sock_path,
        &resolved,
        flags,
        beneath_base.as_deref(),
        snapshot,
    );

    match result {
        Ok((_, stat)) if graph_mode_allows(&stat, mode, flags & libc::AT_EACCESS != 0) => {
            guard.ok(0)
        }
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
        Some(h) if !h.io_permitted => {
            set_errno(libc::EBADF);
            return -1;
        }
        Some(h) if h.is_directory => h,
        Some(_) => {
            set_errno(libc::ENOTDIR);
            return -1;
        }
        None => {
            set_errno(libc::EBADF);
            return -1;
        }
    };

    let entries = match handle.dir_entries.as_ref() {
        Some(e) => e.clone(),
        None => return 0,
    };
    if handle.dir_offset >= entries.len() {
        return 0;
    }
    if buf_size == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    if buf.is_null() {
        set_errno(libc::EFAULT);
        return -1;
    }

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
        Some(h) if !h.io_permitted => {
            set_errno(libc::EBADF);
            return -1;
        }
        Some(h) if h.is_directory => h,
        Some(_) => {
            set_errno(libc::ENOTDIR);
            return -1;
        }
        None => {
            set_errno(libc::EBADF);
            return -1;
        }
    };

    let entries = match handle.dir_entries.as_ref() {
        Some(e) => e.clone(),
        None => return 0,
    };
    if handle.dir_offset >= entries.len() {
        return 0;
    }
    if buf_size == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    if buf.is_null() {
        set_errno(libc::EFAULT);
        return -1;
    }

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
            Some(h) if !h.io_permitted => {
                set_errno(libc::EBADF);
                return libc::MAP_FAILED;
            }
            Some(h) if !h.is_directory => h,
            _ => return real_mmap(addr, len, prot, flags, fd, offset),
        };

        if let Some(ref cached) = handle.cached_content {
            cached.clone()
        } else {
            let path = handle.path.clone();
            let identity = match opened_stat(handle) {
                Ok(stat) => stat.clone(),
                Err(error) => {
                    set_errno(error);
                    return libc::MAP_FAILED;
                }
            };
            drop(fd_table);
            match graph_read_opened_blob(&state.sock_path, &path, &identity, 0, 0) {
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if bufsiz == 0 {
        return fail_errno(libc::EINVAL) as libc::ssize_t;
    }

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

    match graph_stat_preserve_final(&state.sock_path, &path_bytes) {
        Ok((resolved, stat)) if stat.is_symlink => {
            let target = match graph_read_link(&state.sock_path, &resolved) {
                Some(target) => target,
                None => return fail_graph_authority_read(),
            };
            if buf.is_null() {
                return fail_errno(libc::EFAULT) as libc::ssize_t;
            }
            let copy_len = target.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len);
            guard.ok(copy_len as libc::ssize_t)
        }
        Ok(_) => {
            set_errno(libc::EINVAL);
            -1
        }
        Err(error) => fail_graph_path(error) as libc::ssize_t,
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if bufsiz == 0 {
        return fail_errno(libc::EINVAL) as libc::ssize_t;
    }

    if !path.is_null() && CStr::from_ptr(path).to_bytes().is_empty() {
        return match virtual_descriptor_snapshot(dirfd) {
            Ok(Some(handle)) => {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    let stat = match opened_stat(&handle) {
                        Ok(stat) => stat,
                        Err(error) => return fail_errno(error) as libc::ssize_t,
                    };
                    if !stat.is_symlink {
                        return fail_errno(libc::ENOENT) as libc::ssize_t;
                    }
                    let target = match handle.link_target.as_ref() {
                        Some(target) => target,
                        None => return fail_errno(libc::EIO) as libc::ssize_t,
                    };
                    if buf.is_null() {
                        return fail_errno(libc::EFAULT) as libc::ssize_t;
                    }
                    let copy_len = target.len().min(bufsiz);
                    std::ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len);
                    guard.ok(copy_len as libc::ssize_t)
                }
                #[cfg(target_os = "macos")]
                {
                    let _ = handle;
                    fail_errno(libc::ENOENT) as libc::ssize_t
                }
            }
            Ok(None) => real_readlinkat(dirfd, path, buf, bufsiz),
            Err(error) => fail_errno(error) as libc::ssize_t,
        };
    }

    let resolved_at = match resolve_at_path(dirfd, path, EmptyAtPath::Reject) {
        Ok(AtPathResolution::Resolved(resolved)) => resolved,
        Ok(AtPathResolution::VirtualDescriptor(_)) => {
            return fail_errno(libc::EINVAL) as libc::ssize_t;
        }
        Ok(AtPathResolution::Passthrough) => {
            return real_readlinkat(dirfd, path, buf, bufsiz);
        }
        Err(error) => {
            set_errno(error);
            return -1;
        }
    };
    let resolved = resolved_at.path;
    let snapshot = resolved_at.snapshot;

    if !is_workspace_path(&resolved) {
        return real_readlinkat(dirfd, path, buf, bufsiz);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real_readlinkat(dirfd, path, buf, bufsiz),
    };

    match graph_stat_preserve_final_in_snapshot(&state.sock_path, &resolved, snapshot) {
        Ok((resolved, stat)) if stat.is_symlink => {
            let target = match graph_read_link_in_snapshot(&state.sock_path, &resolved, snapshot) {
                Some(target) => target,
                None => return fail_graph_authority_read(),
            };
            if buf.is_null() {
                return fail_errno(libc::EFAULT) as libc::ssize_t;
            }
            let copy_len = target.len().min(bufsiz);
            std::ptr::copy_nonoverlapping(target.as_ptr().cast::<c_char>(), buf, copy_len);
            guard.ok(copy_len as libc::ssize_t)
        }
        Ok(_) => {
            set_errno(libc::EINVAL);
            -1
        }
        Err(error) => fail_graph_path(error) as libc::ssize_t,
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
            match fill_stat_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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

    match graph_stat_preserve_final(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            match fill_stat_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
        }
        Err(error) => fail_graph_path(error),
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

    let stat = match opened_stat(handle) {
        Ok(stat) => stat,
        Err(error) => return fail_errno(error),
    };
    match fill_stat_checked(stat, handle.opened_inode, buf) {
        Ok(()) => guard.ok(0),
        Err(error) => fail_errno(error),
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

    if !statx_flags_are_valid(flags) || mask & (libc::STATX__RESERVED as libc::c_uint) != 0 {
        return fail_errno(libc::EINVAL);
    }

    // AT_EMPTY_PATH acts on dirfd itself and, on Linux 6.11+, also permits a
    // NULL pathname. Without it, both empty and NULL retain their native
    // ENOENT/EFAULT behavior.
    let empty = if flags & libc::AT_EMPTY_PATH != 0 {
        EmptyAtPath::ResolveDescriptorIncludingNull
    } else {
        EmptyAtPath::Reject
    };
    let resolved_at = match resolve_at_path(dirfd, pathname, empty) {
        Ok(AtPathResolution::Resolved(resolved)) => resolved,
        Ok(AtPathResolution::VirtualDescriptor(handle)) => {
            let stat = match opened_stat(&handle) {
                Ok(stat) => stat,
                Err(error) => return fail_errno(error),
            };
            return match fill_statx_checked(stat, handle.opened_inode, statxbuf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            };
        }
        Ok(AtPathResolution::Passthrough) => {
            return real(dirfd, pathname, flags, mask, statxbuf);
        }
        Err(error) => return fail_errno(error),
    };
    let resolved = resolved_at.path;
    let snapshot = resolved_at.snapshot;

    if !is_workspace_path(&resolved) {
        return real(dirfd, pathname, flags, mask, statxbuf);
    }

    let state = match shim_state() {
        Some(s) => s,
        None => return real(dirfd, pathname, flags, mask, statxbuf),
    };

    let result = resolve_graph_at(&state.sock_path, &resolved, flags, None, snapshot);
    match result {
        Ok((resolved, vstat)) => {
            match fill_statx_checked(&vstat, stat_to_inode(&vstat, &resolved), statxbuf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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

/// Fortified 2-arg `open`. glibc aborts whenever `__OPEN_NEEDS_MODE` is true
/// (`O_CREAT` or the full `O_TMPFILE` compound); preserve that before routing
/// supported mode-free calls through KinVFS.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    if open_requires_mode(flags) {
        return get_real_open_2()(path, flags);
    }
    open(path, flags, 0)
}

/// Fortified 2-arg `open64` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    if open_requires_mode(flags) {
        return get_real_open64_2()(path, flags);
    }
    open(path, flags, 0)
}

/// Fortified 3-arg `openat`.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    if open_requires_mode(flags) {
        return get_real_openat_2()(dirfd, path, flags);
    }
    openat(dirfd, path, flags, 0)
}

/// Fortified 3-arg `openat64` (LFS).
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    if open_requires_mode(flags) {
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
            match fill_stat64_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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
    match graph_stat_preserve_final(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            match fill_stat64_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
        }
        Err(error) => fail_graph_path(error),
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
    let stat = match opened_stat(handle) {
        Ok(stat) => stat,
        Err(error) => return fail_errno(error),
    };
    match fill_stat64_checked(stat, handle.opened_inode, buf) {
        Ok(()) => guard.ok(0),
        Err(error) => fail_errno(error),
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
            match fill_stat64_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
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
    match graph_stat_preserve_final(&state.sock_path, &path_bytes) {
        Ok((resolved, vstat)) => {
            match fill_stat64_checked(&vstat, stat_to_inode(&vstat, &resolved), buf) {
                Ok(()) => guard.ok(0),
                Err(error) => fail_errno(error),
            }
        }
        Err(error) => fail_graph_path(error),
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
    let stat = match opened_stat(handle) {
        Ok(stat) => stat,
        Err(error) => return fail_errno(error),
    };
    match fill_stat64_checked(stat, handle.opened_inode, buf) {
        Ok(()) => guard.ok(0),
        Err(error) => fail_errno(error),
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

    #[test]
    fn directory_entry_inode_matches_stat_or_reports_unavailable() {
        let object_id = [0x5a; 32];
        let stat = kin_vfs_core::VirtualStat::directory(1).with_object_id(object_id);
        assert_eq!(
            directory_entry_inode(stat.object_id.as_ref()),
            stat_to_inode(&stat, b"renamed/path")
        );
        assert_eq!(
            directory_entry_inode(None),
            0,
            "a provider without listing identity must not invent a conflicting inode"
        );
    }

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

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_native_argument_masks_are_pinned() {
        assert!(open_flags_are_valid(libc::O_RDONLY));
        assert!(open_flags_are_valid(libc::O_CREAT | libc::O_WRONLY));
        assert!(!open_flags_are_valid(libc::O_ACCMODE));
        assert_eq!(
            graph_open_rejection_errno(libc::O_SYMLINK),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            graph_open_rejection_errno(libc::O_EXEC),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            graph_open_rejection_errno(libc::O_EVTONLY),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(graph_open_rejection_errno(libc::O_NOFOLLOW_ANY), None);
        assert_eq!(
            graph_open_rejection_errno(libc::O_NOFOLLOW_ANY | libc::O_RDWR),
            Some(libc::EOPNOTSUPP)
        );
        assert!(open_requires_mode(libc::O_CREAT));
        assert!(!open_requires_mode(libc::O_RDONLY));

        assert!(fstatat_flags_are_valid(0));
        assert!(fstatat_flags_are_valid(libc::AT_SYMLINK_NOFOLLOW));
        assert!(fstatat_flags_are_valid(
            DARWIN_AT_REALDEV
                | DARWIN_AT_FDONLY
                | DARWIN_AT_SYMLINK_NOFOLLOW_ANY
                | DARWIN_AT_RESOLVE_BENEATH
                | DARWIN_AT_UNIQUE
        ));
        assert!(!fstatat_flags_are_valid(libc::AT_EACCESS));
        assert!(!fstatat_flags_are_valid(0x1000)); // Linux-only AT_EMPTY_PATH

        assert!(faccessat_flags_are_valid(libc::AT_EACCESS));
        assert!(faccessat_flags_are_valid(libc::AT_SYMLINK_NOFOLLOW));
        assert!(faccessat_flags_are_valid(
            DARWIN_AT_SYMLINK_NOFOLLOW_ANY | DARWIN_AT_RESOLVE_BENEATH | DARWIN_AT_UNIQUE
        ));
        assert!(!faccessat_flags_are_valid(0x0100_0000));

        // Darwin masks permission checks to RWX rather than rejecting other
        // signed mode bits; the Apple-arm64 differential pins the resulting
        // success/EACCES behavior.
        assert!(access_mode_is_valid(0x08));
        assert!(access_mode_is_valid(-1));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_native_argument_masks_are_pinned() {
        assert!(open_requires_mode(libc::O_CREAT));
        assert!(open_requires_mode(libc::O_TMPFILE));
        assert!(!open_requires_mode(libc::O_RDONLY));
        assert_eq!(
            graph_open_rejection_errno(libc::O_TMPFILE | libc::O_RDWR),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            effective_graph_open_flags(libc::O_PATH | libc::O_TMPFILE),
            libc::O_PATH | libc::O_DIRECTORY
        );
        assert_eq!(
            graph_open_rejection_errno(libc::O_PATH | libc::O_TMPFILE),
            None
        );
        assert!(descriptor_check_only(libc::O_ACCMODE));
        assert!(!is_write_flags(libc::O_ACCMODE));
        assert!(descriptor_path_only(libc::O_PATH));
        assert!(!descriptor_check_only(libc::O_PATH | libc::O_ACCMODE));
        assert!(!descriptor_io_permitted(libc::O_PATH | libc::O_RDWR));
        assert!(!is_write_flags(
            libc::O_PATH | libc::O_CREAT | libc::O_TRUNC
        ));
        assert_eq!(
            graph_open_rejection_errno(libc::O_ACCMODE | libc::O_CREAT),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            graph_open_rejection_errno(libc::O_ACCMODE | libc::O_TRUNC),
            Some(libc::EOPNOTSUPP)
        );
        assert!(is_write_flags(libc::O_WRONLY));
        assert!(is_write_flags(libc::O_RDWR));

        assert!(fstatat_flags_are_valid(
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT
        ));
        assert!(!fstatat_flags_are_valid(libc::AT_EACCESS));

        assert!(faccessat_flags_are_valid(
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EACCESS
        ));
        assert!(!faccessat_flags_are_valid(libc::AT_NO_AUTOMOUNT));

        assert!(access_mode_is_valid(libc::R_OK | libc::W_OK | libc::X_OK));
        assert!(!access_mode_is_valid(0x08));
        assert!(!access_mode_is_valid(-1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_statx_flag_masks_are_pinned() {
        assert!(statx_flags_are_valid(
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_FORCE_SYNC
        ));
        assert!(statx_flags_are_valid(libc::AT_STATX_DONT_SYNC));
        assert!(!statx_flags_are_valid(libc::AT_STATX_SYNC_TYPE));
        assert!(!statx_flags_are_valid(0x0100_0000));
    }

    #[test]
    fn graph_component_stream_preserves_symlink_parent_order() {
        let components = graph_components(b"link/../file")
            .expect("valid component stream")
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            components,
            vec![b"link".to_vec(), b"..".to_vec(), b"file".to_vec()]
        );
        assert_eq!(
            graph_parent(b"/ws/deep/sub", b"/ws", true).unwrap(),
            b"/ws/deep"
        );
        assert!(matches!(
            graph_parent(b"/ws", b"/ws", true),
            Err(GraphPathError::BeneathEscape)
        ));
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
            graph_path_errno(&GraphPathError::MissingFinal(b"/ws/missing".to_vec()), true),
            libc::EIO
        );
        assert_eq!(
            graph_path_errno(
                &GraphPathError::MissingFinal(b"/ws/missing".to_vec()),
                false,
            ),
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
        assert_eq!(
            resolve(""),
            b"",
            "plain empty paths must remain empty rather than joining to cwd"
        );

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
