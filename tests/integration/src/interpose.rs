// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empirical macOS interposition smoke test.
//!
//! Proves that a hooked `open()` actually routes through the shim on darwin:
//! the shim's `__DATA,__interpose` table must redirect libc calls in an
//! external process (loaded via `DYLD_INSERT_LIBRARIES`) into the shim, which
//! serves graph content. Without the interpose table the
//! child would read raw disk and the virtual-only file would not be found.
//!
//! The test is macOS-only and self-skips (with a logged reason, never a false
//! pass) when prerequisites can't be met in the sandbox.

#![cfg(all(test, target_os = "macos"))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use kin_vfs_core::{ContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
use kin_vfs_daemon::VfsDaemonServer;

// A minimal provider that serves exactly one virtual file by absolute path.
struct OneFileProvider {
    files: Mutex<HashMap<String, Vec<u8>>>,
    version: AtomicU64,
}

impl OneFileProvider {
    fn new(path: &str, content: &[u8]) -> Self {
        let mut files = HashMap::new();
        files.insert(path.to_string(), content.to_vec());
        Self {
            files: Mutex::new(files),
            version: AtomicU64::new(1),
        }
    }
}

impl ContentProvider for OneFileProvider {
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| VfsError::NotFound {
                path: path.to_string(),
            })
    }

    fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let data = self.read_file(path)?;
        let start = offset as usize;
        if start >= data.len() {
            return Ok(vec![]);
        }
        let end = std::cmp::min(start + len as usize, data.len());
        Ok(data[start..end].to_vec())
    }

    fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
        let files = self.files.lock().unwrap();
        match files.get(path) {
            Some(data) => Ok(VirtualStat::file(data.len() as u64, [0u8; 32], 1000)),
            None => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_dir(&self, _path: &str) -> VfsResult<Vec<DirEntry>> {
        Ok(vec![DirEntry {
            name: ".".to_string(),
            file_type: FileType::Directory,
        }])
    }

    fn exists(&self, path: &str) -> VfsResult<bool> {
        Ok(self.files.lock().unwrap().contains_key(path))
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }
}

/// Walk up from the test binary to the cargo target profile dir (e.g.
/// `target/debug`), where sibling artifacts (the shim cdylib, helper bins) live.
fn target_profile_dir() -> Option<PathBuf> {
    // current_exe is `<target>/<profile>/deps/<name>-<hash>`.
    let exe = std::env::current_exe().ok()?;
    // .../deps/<bin>  -> .../deps -> .../<profile>
    exe.parent()?.parent().map(Path::to_path_buf)
}

/// Find `libkin_vfs_shim.dylib` next to the test artifacts; build it if absent
/// so the test is self-sufficient rather than silently skipping.
fn locate_or_build_shim() -> Option<PathBuf> {
    let profile_dir = target_profile_dir()?;
    let candidates = [
        profile_dir.join("libkin_vfs_shim.dylib"),
        profile_dir.join("deps").join("libkin_vfs_shim.dylib"),
    ];
    for c in candidates.iter() {
        if c.exists() {
            return Some(c.clone());
        }
    }

    // Not built yet — build it once. (cargo serializes via the build lock.)
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest).parent()?.parent()?;
    let status = Command::new(env!("CARGO"))
        .current_dir(workspace_root)
        .args(["build", "-p", "kin-vfs-shim"])
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    candidates.iter().find(|c| c.exists()).cloned()
}

/// Locate (or build) one of this crate's helper binaries by name.
fn locate_or_build_bin(bin: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{bin}");
    if let Ok(path) = std::env::var(&env_key) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [profile_dir.join(bin), profile_dir.join("deps").join(bin)];
    for c in candidates.iter() {
        if c.exists() {
            return c.clone();
        }
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .expect("locate kin-vfs workspace root");
    let status = Command::new(env!("CARGO"))
        .current_dir(workspace_root)
        .args(["build", "-p", "kin-vfs-integration-tests", "--bin", bin])
        .status()
        .unwrap_or_else(|e| panic!("run cargo build for {bin}: {e}"));
    assert!(status.success(), "failed to build {bin} helper binary");

    candidates
        .iter()
        .find(|c| c.exists())
        .cloned()
        .unwrap_or_else(|| panic!("locate {bin} after cargo build"))
}

/// Run `provider` on a background tokio runtime serving `sock_path`, returning
/// the shutdown handle + join handle once the socket is bound.
fn start_daemon(
    provider: OneFileProvider,
    sock_path: &Path,
) -> (
    kin_vfs_daemon::server::ShutdownHandle,
    std::thread::JoinHandle<()>,
) {
    let sock_for_thread = sock_path.to_path_buf();
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");
    let server = VfsDaemonServer::new(provider, &sock_for_thread);
    let shutdown = server.shutdown_handle();
    let join = std::thread::spawn(move || {
        rt.block_on(async move {
            let _ = server.run().await;
        });
    });

    let mut waited = 0;
    while !sock_path.exists() && waited < 200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        waited += 10;
    }
    assert!(sock_path.exists(), "daemon socket never appeared");
    (shutdown, join)
}

#[test]
fn macos_interpose_routes_open_through_shim() {
    // Locate (or build) the shim cdylib.
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };

    // Workspace root for the child + a virtual file that does NOT exist on disk.
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path().to_path_buf();
    let virtual_path = workspace_root.join("graph_only.txt");
    let virtual_path_str = virtual_path.to_string_lossy().to_string();
    let expected = b"served-from-graph-not-disk\n";

    // Sanity: the file must be absent on disk, so a successful read can ONLY come
    // from the shim routing the open through the daemon.
    assert!(
        !virtual_path.exists(),
        "virtual file must not exist on disk for the test to be meaningful"
    );

    // Socket path inside the workspace's .kin dir (shim default).
    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");

    // Start a daemon serving the one virtual file.
    let provider = OneFileProvider::new(&virtual_path_str, expected);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    // Run the helper under DYLD_INSERT_LIBRARIES — this is the interposition.
    let output = Command::new(locate_or_build_bin("vfs_open_probe"))
        .arg(&virtual_path_str)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        // Keep the host clean: never let a real daemon on :4219 get notified.
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1") // unreachable; notify no-ops
        .output()
        .expect("spawn vfs_open_probe");

    shutdown.shutdown();
    let _ = server_thread.join();

    // If DYLD stripped the insert (SIP/hardened runtime) the read fails because
    // the file is virtual-only. Distinguish that from a genuine interpose failure
    // by checking we actually got the graph bytes.
    if !output.status.success() {
        panic!(
            "vfs_open_probe failed (status {:?}); stderr: {}\n\
             This means the shim did NOT intercept open() — interpose table broken \
             OR DYLD_INSERT_LIBRARIES was stripped for the helper.",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    assert_eq!(
        output.stdout, expected,
        "child read unexpected bytes; interposition did not route open() through the shim"
    );
}

/// Materialize-on-write must seed from GRAPH TRUTH, never trust a
/// stale on-disk copy. A child opens an existing-on-disk file for read-write
/// (no truncate). The disk holds stale bytes; the daemon (graph) holds the
/// authoritative bytes. The child must read graph truth — proving
/// `materialize_file` no longer short-circuits on disk existence.
#[test]
fn macos_materialize_prefers_graph_over_stale_disk() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path().to_path_buf();
    let path = workspace_root.join("doc.txt");
    let path_str = path.to_string_lossy().to_string();

    let graph_truth = b"GRAPH-TRUTH-authoritative\n";
    let stale_disk = b"STALE-DISK-must-not-win\n";

    // Pre-seed a STALE copy on disk. The old materialize_file would hand this
    // straight to the tool; the fix must overwrite it with graph truth.
    std::fs::write(&path, stale_disk).expect("write stale disk file");
    assert!(path.exists());

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");

    // Daemon serves the AUTHORITATIVE graph content for the same path.
    let provider = OneFileProvider::new(&path_str, graph_truth);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    // Child opens O_RDWR (read-modify-write) and dumps the bytes it sees.
    let output = Command::new(locate_or_build_bin("vfs_rmw_probe"))
        .arg(&path_str)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1") // unreachable; notify no-ops
        .output()
        .expect("spawn vfs_rmw_probe");

    shutdown.shutdown();
    let _ = server_thread.join();

    if !output.status.success() {
        panic!(
            "vfs_rmw_probe failed (status {:?}); stderr: {}\n\
             (DYLD may have been stripped, or the shim did not intercept open).",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    assert_ne!(
        output.stdout, stale_disk,
        "materialize handed the tool STALE DISK content — graph truth must win"
    );
    assert_eq!(
        output.stdout, graph_truth,
        "materialize must seed the file from graph truth"
    );
}
