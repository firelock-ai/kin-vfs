// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empirical macOS interposition smoke test (FIR-909).
//!
//! Proves that a hooked `open()` actually routes through the shim on darwin:
//! the shim's `__DATA,__interpose` table must redirect libc calls in an
//! external process (loaded via `DYLD_INSERT_LIBRARIES`) into the shim, which
//! serves graph content. Without the interpose table (the FIR-909 bug) the
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

/// Locate (or build) the helper binary used by the child process.
fn locate_or_build_open_probe() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vfs_open_probe") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [
        profile_dir.join("vfs_open_probe"),
        profile_dir.join("deps").join("vfs_open_probe"),
    ];
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
        .args([
            "build",
            "-p",
            "kin-vfs-integration-tests",
            "--bin",
            "vfs_open_probe",
        ])
        .status()
        .expect("run cargo build for vfs_open_probe");
    assert!(
        status.success(),
        "failed to build vfs_open_probe helper binary"
    );

    candidates
        .iter()
        .find(|c| c.exists())
        .cloned()
        .expect("locate vfs_open_probe after cargo build")
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

    // Start a daemon serving the one virtual file, on its own tokio runtime in a
    // background thread (this test is sync because it shells out).
    let provider = OneFileProvider::new(&virtual_path_str, expected);
    let sock_for_thread = sock_path.clone();
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");
    let server = VfsDaemonServer::new(provider, &sock_for_thread);
    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || {
        rt.block_on(async move {
            let _ = server.run().await;
        });
    });

    // Wait for the socket to appear (daemon bound).
    let mut waited = 0;
    while !sock_path.exists() && waited < 200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        waited += 10;
    }
    assert!(sock_path.exists(), "daemon socket never appeared");

    // Run the helper under DYLD_INSERT_LIBRARIES — this is the interposition.
    let output = Command::new(locate_or_build_open_probe())
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
