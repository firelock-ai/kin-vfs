// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-shim: cross-platform VFS interception layer.
//!
//! Routes file access to the VFS daemon, supporting three platform strategies:
//!
//! - **Linux**: LD_PRELOAD syscall interception via `dlsym(RTLD_NEXT)`
//! - **macOS**: DYLD_INSERT_LIBRARIES interception via a `__DATA,__interpose` table
//! - **Windows**: ProjFS (Projected File System) kernel callbacks
//!
//! # Environment variables
//!
//! - `KIN_VFS_WORKSPACE` — absolute path to the workspace root (required)
//! - `KIN_VFS_SOCK` — path to the daemon Unix socket (default: `$KIN_VFS_WORKSPACE/.kin/vfs.sock`)
//!   (Linux/macOS only)
//! - `KIN_VFS_PIPE` — named pipe path for daemon communication (default:
//!   `\\.\pipe\kin-vfs-{workspace-hash}`) (Windows only)
//! - `KIN_SESSION_ID` — optional session ID for session-scoped projections
//! - `KIN_VFS_DISABLE` — set to `1` to disable all interception (kill switch)
//! - `KIN_NO_VFS` — set to `1` to bypass VFS initialization entirely.
//!   Used by benchmarks and graph-building commands. Pattern matches
//!   `KIN_NO_DAEMON=1`.
//! - `KIN_VFS_STRICT` — set to `1` to make a *daemon-unreachable* miss on a
//!   graph-authority path (open/stat of a workspace file) fail loud with `EIO`
//!   instead of silently passing through to raw disk. Off by default, where the
//!   shim keeps its labeled compatibility pass-through (warned once). Proof and
//!   benchmark harnesses that must never let disk masquerade as graph truth
//!   should turn this on.
//!
//! # Architecture
//!
//! - **client.rs** — synchronous daemon client (Unix sockets on Linux/macOS,
//!   named pipes on Windows; thread-local, no tokio)
//! - **fd_table.rs** — virtual file descriptor table (fds >= 10000, Linux/macOS only)
//! - **intercept.rs** — `#[no_mangle]` syscall hooks via `dlsym(RTLD_NEXT)`
//!   (Linux/macOS only; Windows uses ProjFS instead)
//! - **platform/** — OS-specific helpers (stat structs on Unix, ProjFS provider on Windows)
//! - **protocol.rs** — wire-format types mirroring the daemon

#![allow(clippy::missing_safety_doc)]

pub mod client;
#[cfg(not(target_os = "windows"))]
pub mod fd_table;
#[cfg(not(target_os = "windows"))]
pub mod intercept;
pub mod platform;
pub mod protocol;
pub mod statfill;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[cfg(not(target_os = "windows"))]
use parking_lot::RwLock;

#[cfg(not(target_os = "windows"))]
use fd_table::FdTable;

// ── Global state ────────────────────────────────────────────────────────

/// Kill switch: when true, all hooks passthrough immediately.
///
/// Defaults to `true` and is cleared only once `STATE` is initialized in
/// [`shim_init`]. This matters on macOS: with the `__interpose` table active,
/// dyld can route libSystem calls through our hooks *before* the
/// `__mod_init_func` constructor has run — i.e. before `STATE` exists. Starting
/// disabled makes every hook pass straight through to real libc during that
/// pre-init window instead of dereferencing unset state and crashing the host.
static DISABLED: AtomicBool = AtomicBool::new(true);

/// Global shim state, initialized once on library load.
static STATE: OnceLock<ShimState> = OnceLock::new();

/// All mutable state for the shim.
///
/// On Linux/macOS, this holds the Unix socket path and virtual fd table.
/// On Windows, this holds the named pipe path and ProjFS provider handle.
pub struct ShimState {
    /// Absolute path to the workspace root.
    pub workspace_root: String,
    /// Optional session ID for session-scoped projections.
    /// Read from `KIN_SESSION_ID` environment variable during init.
    pub session_id: Option<String>,
    /// Normalized launch-time interposition canary token (from `KIN_VFS_CANARY`).
    /// When present, the shim announces it to the daemon on first contact so a
    /// launcher can confirm this process is graph-native rather than reading raw
    /// disk through stripped interposition. `None` when no token was injected.
    pub canary_token: Option<String>,
    /// Strict authority mode (from `KIN_VFS_STRICT=1`). When `true`, a
    /// daemon-*unreachable* miss on a graph-authority path fails loud (`EIO`)
    /// rather than silently falling through to raw disk. Default `false` keeps
    /// the labeled compatibility pass-through so adoption stays transparent.
    pub strict: bool,
    /// Path to the daemon Unix socket (Linux/macOS only).
    #[cfg(not(target_os = "windows"))]
    pub sock_path: PathBuf,
    /// Virtual file descriptor table (Linux/macOS only).
    #[cfg(not(target_os = "windows"))]
    pub fd_table: RwLock<FdTable>,
    /// Named pipe path for daemon communication (Windows only).
    /// e.g., `\\.\pipe\kin-vfs-{workspace-hash}`
    #[cfg(target_os = "windows")]
    pub pipe_name: String,
}

/// Returns `true` if the shim is disabled (kill switch or not initialized).
#[inline]
pub fn is_disabled() -> bool {
    DISABLED.load(Ordering::Relaxed)
}

/// Returns the global shim state, or `None` if not initialized.
#[inline]
pub fn shim_state() -> Option<&'static ShimState> {
    STATE.get()
}

/// Check if an absolute path falls within the workspace.
///
/// Excludes `.kin_tmp_` temp files from interception: `materialize_file()`
/// writes to `{path}.kin_tmp_{pid}` via `std::fs::write`, which calls the
/// hooked `open()`. Without this exclusion, `open()` would re-enter the
/// daemon with a roundtrip for a path that doesn't exist in the tree,
/// falling through to `real_open` anyway. This avoids the wasted overhead.
#[inline]
pub fn is_workspace_path(path: &str) -> bool {
    match STATE.get() {
        Some(state) => {
            // Exclude materialize temp files to prevent re-entrance overhead.
            if path.contains(".kin_tmp_") {
                return false;
            }

            // On Windows, paths use backslashes but we normalize to forward slashes
            // in daemon communication. Check with the OS-native separator.
            // Containment is the pure `path_within_root` seam in kin-vfs-core
            // (forward-slash semantics, prefix-with-separator-guard) so the
            // workspace boundary has one definition that is unit-tested AND
            // fuzzed there without linking these interposing hooks.
            #[cfg(target_os = "windows")]
            {
                let normalized = path.replace('\\', "/");
                let ws = state.workspace_root.replace('\\', "/");
                kin_vfs_core::pathmap::path_within_root(&normalized, &ws)
            }
            #[cfg(not(target_os = "windows"))]
            {
                kin_vfs_core::pathmap::path_within_root(path, &state.workspace_root)
            }
        }
        None => false,
    }
}

// ── Process skip policy ────────────────────────────────────────────────

/// Kin-family binaries own the graph/control plane directly and should never
/// be intercepted by VFS. The shim exists to make external tools graph-native,
/// not to interpose on Kin itself.
fn process_basename(argv0: &str) -> &str {
    argv0.rsplit(['/', '\\']).next().unwrap_or(argv0)
}

fn is_kin_family_process(argv0: &str) -> bool {
    let basename = process_basename(argv0).to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    basename == "kin" || basename == "kin-real" || basename.starts_with("kin-")
}

fn should_skip_vfs_for_process() -> bool {
    std::env::args()
        .next()
        .map(|argv0| is_kin_family_process(&argv0))
        .unwrap_or(false)
}

// ── Interposition canary ───────────────────────────────────────────────

/// Pure seam: given an environment getter, return the normalized interposition
/// canary token the shim should announce (and stamp into the in-process
/// sentinel), or `None` when no valid `KIN_VFS_CANARY` was injected.
///
/// Split out from `shim_init` so the announce decision is unit-testable without
/// touching the real process environment (or the shim's own hooked libc).
fn canary_announcement(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    kin_vfs_core::canary::normalize_token(get(kin_vfs_core::canary::CANARY_ENV).as_deref())
}

// ── Constructor: runs on library load ───────────────────────────────────

/// Initialize the shim (shared logic).
///
/// On Linux/macOS, called automatically when the shared library is loaded
/// via LD_PRELOAD or DYLD_INSERT_LIBRARIES.
///
/// On Windows, called from `shim_init_windows` which then sets up ProjFS.
fn shim_init() {
    // Kill switch (explicit disable).
    if std::env::var("KIN_VFS_DISABLE").as_deref() == Ok("1") {
        DISABLED.store(true, Ordering::Relaxed);
        return;
    }

    // Bypass switch: KIN_NO_VFS=1 skips all VFS initialization and execs
    // the real binary directly. Used by benchmarks and graph-building
    // commands that don't need file interception.
    if std::env::var("KIN_NO_VFS").as_deref() == Ok("1") {
        DISABLED.store(true, Ordering::Relaxed);
        return;
    }

    // Skip VFS for Kin-family control-plane processes entirely.
    // This keeps the overlay focused on external tools while avoiding preload
    // recursion or startup failures inside Kin binaries themselves.
    if should_skip_vfs_for_process() {
        DISABLED.store(true, Ordering::Relaxed);
        return;
    }

    // Workspace root (required).
    let workspace_root = match std::env::var("KIN_VFS_WORKSPACE") {
        Ok(w) if !w.is_empty() => w,
        _ => {
            // No workspace configured — disable silently.
            DISABLED.store(true, Ordering::Relaxed);
            return;
        }
    };

    // Read optional session ID for session-scoped projections.
    let session_id = std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty());

    // Resolve the interposition canary token (if a launcher injected one).
    let canary_token = canary_announcement(|k| std::env::var(k).ok());

    // Strict authority mode: a daemon-unreachable miss fails loud instead of
    // silently reading raw disk. Off unless explicitly requested.
    let strict = std::env::var("KIN_VFS_STRICT").as_deref() == Ok("1");

    // Platform-specific state initialization.
    #[cfg(not(target_os = "windows"))]
    {
        let sock_path = match std::env::var("KIN_VFS_SOCK") {
            Ok(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from(format!("{}/.kin/vfs.sock", &workspace_root)),
        };

        // Enable interception only once STATE is in place. `DISABLED` started
        // `true`, so until this store the hooks pass straight through — closing
        // the pre-constructor window where an interposed macOS call could hit
        // unset state. (If STATE is somehow already set, leave the shim enabled.)
        let sentinel = canary_token.clone();
        if STATE
            .set(ShimState {
                workspace_root,
                session_id,
                canary_token,
                strict,
                sock_path,
                fd_table: RwLock::new(FdTable::new()),
            })
            .is_ok()
        {
            DISABLED.store(false, Ordering::Relaxed);
            mark_interpose_active(sentinel.as_deref());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let pipe_name = match std::env::var("KIN_VFS_PIPE") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                // Derive pipe name from workspace path hash.
                let hash = simple_hash(&workspace_root);
                format!(r"\\.\pipe\kin-vfs-{:016x}", hash)
            }
        };

        // Enable interception only once STATE is in place (see the unix arm).
        let sentinel = canary_token.clone();
        if STATE
            .set(ShimState {
                workspace_root,
                session_id,
                canary_token,
                strict,
                pipe_name,
            })
            .is_ok()
        {
            DISABLED.store(false, Ordering::Relaxed);
            mark_interpose_active(sentinel.as_deref());
        }
    }
}

/// Stamp the in-process sentinel that proves the shim loaded. A launcher sets
/// `KIN_VFS_CANARY`; only a shim that actually loaded reaches this and exports
/// `KIN_VFS_INTERPOSE_ACTIVE`. Its absence in a child whose `KIN_VFS_CANARY` was
/// set is the local signal that interposition was stripped. Set to the canary
/// token when present (so it round-trips), else `"1"`.
fn mark_interpose_active(token: Option<&str>) {
    std::env::set_var(
        kin_vfs_core::canary::INTERPOSE_ACTIVE_ENV,
        token.unwrap_or("1"),
    );
}

/// Simple 64-bit hash for deriving named pipe names from workspace paths.
/// Not cryptographic — just needs to be deterministic and low-collision.
#[cfg(target_os = "windows")]
fn simple_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

// ── Windows ProjFS initialization ───────────────────────────────────────

/// Initialize and start the ProjFS virtualization provider on Windows.
///
/// This is the Windows entry point. It:
/// 1. Calls `shim_init()` to set up global state
/// 2. Creates a `ProjFsProvider` and starts virtualization
/// 3. Returns the provider for the caller to hold (dropping it stops ProjFS)
///
/// Typically called from the kin-vfs-daemon's Windows service entry point
/// or from a standalone helper process.
#[cfg(target_os = "windows")]
pub fn shim_init_windows() -> Result<platform::ProjFsProvider, String> {
    shim_init();

    if is_disabled() {
        return Err("shim disabled via KIN_VFS_DISABLE or missing KIN_VFS_WORKSPACE".into());
    }

    let state = shim_state().ok_or("failed to initialize shim state")?;
    let root_path = PathBuf::from(&state.workspace_root);
    let pipe_name = state.pipe_name.clone();

    let mut provider = platform::ProjFsProvider::new(root_path, pipe_name);
    provider.start().map_err(|e| format!("{e}"))?;

    Ok(provider)
}

// ── Platform-specific constructor registration ──────────────────────────

// On Linux, use .init_array to call shim_init on library load.
#[cfg(target_os = "linux")]
#[used]
#[link_section = ".init_array"]
static INIT: unsafe extern "C" fn() = {
    unsafe extern "C" fn init() {
        shim_init();
    }
    init
};

// On macOS, use __DATA,__mod_init_func.
#[cfg(target_os = "macos")]
#[used]
#[link_section = "__DATA,__mod_init_func"]
static INIT: unsafe extern "C" fn() = {
    unsafe extern "C" fn init() {
        shim_init();
    }
    init
};

// On Windows, no automatic constructor — ProjFS is started explicitly via
// `shim_init_windows()` from the daemon or helper process, because ProjFS
// requires an active process to service callbacks (unlike LD_PRELOAD which
// piggybacks on the host process).

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn is_workspace_path_basic() {
        // OnceLock can only be set once per process. If the link_section constructor
        // already initialized STATE (macOS/Linux), we can't override it for testing.
        if STATE.get().is_some() {
            eprintln!("STATE already initialized (link_section constructor), skipping test");
            return;
        }

        // Manually set up state for testing.
        let _ = STATE.set(ShimState {
            workspace_root: "/home/user/project".to_string(),
            session_id: None,
            canary_token: None,
            strict: false,
            sock_path: PathBuf::from("/home/user/project/.kin/vfs.sock"),
            fd_table: RwLock::new(FdTable::new()),
        });

        assert!(is_workspace_path("/home/user/project/src/main.rs"));
        assert!(is_workspace_path("/home/user/project/Cargo.toml"));
        assert!(is_workspace_path("/home/user/project"));

        // Must not match paths that merely share a prefix.
        assert!(!is_workspace_path("/home/user/project2/file.rs"));
        assert!(!is_workspace_path("/home/user/projectx"));

        // Outside workspace entirely.
        assert!(!is_workspace_path("/etc/passwd"));
        assert!(!is_workspace_path("/tmp/file"));
        assert!(!is_workspace_path("relative/path"));

        // .kin_tmp_ temp files must be excluded to prevent re-entrance
        // when materialize_file() writes via std::fs::write.
        assert!(!is_workspace_path(
            "/home/user/project/src/main.rs.kin_tmp_12345"
        ));
        assert!(!is_workspace_path(
            "/home/user/project/Cargo.toml.kin_tmp_99"
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn is_workspace_path_windows() {
        // Manually set up state for testing.
        let _ = STATE.set(ShimState {
            workspace_root: r"C:\Users\test\project".to_string(),
            session_id: None,
            canary_token: None,
            strict: false,
            pipe_name: r"\\.\pipe\kin-vfs-test".to_string(),
        });

        assert!(is_workspace_path(r"C:\Users\test\project\src\main.rs"));
        assert!(is_workspace_path(r"C:\Users\test\project\Cargo.toml"));
        assert!(is_workspace_path(r"C:\Users\test\project"));

        // Must not match paths that merely share a prefix.
        assert!(!is_workspace_path(r"C:\Users\test\project2\file.rs"));
        assert!(!is_workspace_path(r"C:\Users\test\projectx"));

        // Outside workspace entirely.
        assert!(!is_workspace_path(r"C:\Windows\System32\notepad.exe"));
        assert!(!is_workspace_path(r"D:\other\path"));
    }

    #[test]
    fn disabled_flag_default() {
        // In tests, DISABLED is whatever the env says. Just verify it's a bool.
        let _ = is_disabled();
    }

    #[test]
    fn kin_family_processes_skip_vfs() {
        assert!(is_kin_family_process("kin"));
        assert!(is_kin_family_process(r"C:\Users\test\kin.exe"));
        assert!(is_kin_family_process("/usr/local/bin/kin-real"));
        assert!(is_kin_family_process("/opt/bin/kin-daemon"));
        assert!(is_kin_family_process("/tmp/kin-bench-target"));
        assert!(is_kin_family_process(r"C:\Users\test\kin-mcp.exe"));
        assert!(is_kin_family_process("kin-vfs"));
    }

    #[test]
    fn non_kin_processes_do_not_skip_vfs() {
        assert!(!is_kin_family_process("cargo"));
        assert!(!is_kin_family_process("/usr/bin/python3"));
        assert!(!is_kin_family_process("kingpin"));
        assert!(!is_kin_family_process("akin-helper"));
    }

    #[test]
    fn canary_announcement_reads_and_normalizes_token() {
        // A valid token is trimmed and surfaced for announcement.
        let token = canary_announcement(|k| {
            (k == kin_vfs_core::canary::CANARY_ENV).then(|| "  launch-tok-9 ".to_string())
        });
        assert_eq!(token.as_deref(), Some("launch-tok-9"));

        // No token injected → nothing to announce.
        let none = canary_announcement(|_| None);
        assert_eq!(none, None);

        // A blank/malformed token must NOT register as expected (would otherwise
        // become a permanent false "stripped" alarm).
        let blank = canary_announcement(|k| {
            (k == kin_vfs_core::canary::CANARY_ENV).then(|| "   ".to_string())
        });
        assert_eq!(blank, None);
    }
}
