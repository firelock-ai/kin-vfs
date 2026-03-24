// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-shim: cross-platform VFS interception layer.
//!
//! Routes file access to the VFS daemon, supporting three platform strategies:
//!
//! - **Linux**: LD_PRELOAD syscall interception via `dlsym(RTLD_NEXT)`
//! - **macOS**: DYLD_INSERT_LIBRARIES syscall interception via `dlsym(RTLD_NEXT)`
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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[cfg(not(target_os = "windows"))]
use parking_lot::RwLock;

#[cfg(not(target_os = "windows"))]
use fd_table::FdTable;

// ── Global state ────────────────────────────────────────────────────────

/// Kill switch: when true, all hooks passthrough immediately.
static DISABLED: AtomicBool = AtomicBool::new(false);

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
#[inline]
pub fn is_workspace_path(path: &str) -> bool {
    match STATE.get() {
        Some(state) => {
            // On Windows, paths use backslashes but we normalize to forward slashes
            // in daemon communication. Check with the OS-native separator.
            #[cfg(target_os = "windows")]
            {
                let normalized = path.replace('\\', "/");
                let ws = state.workspace_root.replace('\\', "/");
                normalized.starts_with(&ws)
                    && (normalized.len() == ws.len()
                        || normalized.as_bytes().get(ws.len()) == Some(&b'/'))
            }
            #[cfg(not(target_os = "windows"))]
            {
                path.starts_with(&state.workspace_root)
                    && (path.len() == state.workspace_root.len()
                        || path.as_bytes().get(state.workspace_root.len()) == Some(&b'/'))
            }
        }
        None => false,
    }
}

// ── Constructor: runs on library load ───────────────────────────────────

/// Initialize the shim (shared logic).
///
/// On Linux/macOS, called automatically when the shared library is loaded
/// via LD_PRELOAD or DYLD_INSERT_LIBRARIES.
///
/// On Windows, called from `shim_init_windows` which then sets up ProjFS.
fn shim_init() {
    // Kill switch.
    if std::env::var("KIN_VFS_DISABLE").as_deref() == Ok("1") {
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

    // Platform-specific state initialization.
    #[cfg(not(target_os = "windows"))]
    {
        let sock_path = match std::env::var("KIN_VFS_SOCK") {
            Ok(s) if !s.is_empty() => PathBuf::from(s),
            _ => PathBuf::from(format!("{}/.kin/vfs.sock", &workspace_root)),
        };

        let _ = STATE.set(ShimState {
            workspace_root,
            session_id,
            sock_path,
            fd_table: RwLock::new(FdTable::new()),
        });
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

        let _ = STATE.set(ShimState {
            workspace_root,
            session_id,
            pipe_name,
        });
    }
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
        // Manually set up state for testing.
        let _ = STATE.set(ShimState {
            workspace_root: "/home/user/project".to_string(),
            session_id: None,
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
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn is_workspace_path_windows() {
        // Manually set up state for testing.
        let _ = STATE.set(ShimState {
            workspace_root: r"C:\Users\test\project".to_string(),
            session_id: None,
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
}
