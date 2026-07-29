// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empirical Linux `LD_PRELOAD` passthrough regression.
//!
//! A loaded shim still has to preserve ordinary libc behavior for real file
//! descriptors and paths outside the workspace. In particular, glibc's legacy
//! `__xstat` ABI version differs by architecture; translating direct `stat` /
//! `fstat` calls through a hard-coded legacy version broke every AArch64 target
//! that inspected stdout before opening a workspace file.

#![cfg(all(test, target_os = "linux"))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use crate::native_parity::NativeParityProvider;
use kin_vfs_daemon::VfsDaemonServer;

fn target_profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.parent()?.parent().map(Path::to_path_buf)
}

/// Build the exact shim under test once, never silently reusing an old `.so`.
fn locate_or_build_shim() -> Option<PathBuf> {
    static SHIM_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    SHIM_PATH
        .get_or_init(|| {
            let profile_dir = target_profile_dir()?;
            let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
            let mut command = Command::new(env!("CARGO"));
            command
                .current_dir(workspace_root)
                .args(["build", "-p", "kin-vfs-shim"])
                .args(crate::nested_cargo_args());
            if profile_dir.file_name().and_then(|name| name.to_str()) == Some("release") {
                command.arg("--release");
            }
            if !command.status().ok()?.success() {
                return None;
            }

            [
                profile_dir.join("libkin_vfs_shim.so"),
                profile_dir.join("deps").join("libkin_vfs_shim.so"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        })
        .clone()
}

fn locate_or_build_probe(bin: &str) -> PathBuf {
    static PROBE_PATHS: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();

    let cargo_bin_var = format!("CARGO_BIN_EXE_{bin}");
    if let Ok(path) = std::env::var(&cargo_bin_var) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let paths = PROBE_PATHS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut paths = paths.lock().expect("probe path cache");
    if let Some(path) = paths.get(bin).filter(|path| path.exists()) {
        return path.clone();
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [profile_dir.join(bin), profile_dir.join("deps").join(bin)];

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("locate kin-vfs workspace root");
    let status = Command::new(env!("CARGO"))
        .current_dir(workspace_root)
        .args(["build", "-p", "kin-vfs-integration-tests", "--bin", bin])
        .args(crate::nested_cargo_args())
        .status()
        .unwrap_or_else(|error| panic!("build {bin}: {error}"));
    assert!(status.success(), "failed to build {bin}");

    let path = candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("locate {bin} after build"));
    paths.insert(bin.to_owned(), path.clone());
    path
}

fn start_native_parity_daemon(
    sock_path: &Path,
) -> (
    kin_vfs_daemon::server::ShutdownHandle,
    std::thread::JoinHandle<()>,
) {
    let sock_for_thread = sock_path.to_path_buf();
    let runtime = tokio::runtime::Runtime::new().expect("native parity tokio runtime");
    let server = VfsDaemonServer::new(NativeParityProvider, &sock_for_thread);
    let shutdown = server.shutdown_handle();
    let join = std::thread::spawn(move || {
        runtime.block_on(async move {
            let _ = server.run().await;
        });
    });

    let mut waited_ms = 0;
    while !sock_path.exists() && waited_ms < 200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        waited_ms += 10;
    }
    assert!(
        sock_path.exists(),
        "native parity daemon socket never appeared"
    );
    (shutdown, join)
}

#[test]
fn linux_preload_preserves_real_stat_family_passthrough() {
    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let missing_socket = workspace.path().join("missing-vfs.sock");
    let token = "kvfs-linux-stat-passthrough";

    let output = Command::new(locate_or_build_probe("vfs_passthrough_probe"))
        .arg("/dev/null")
        .env("LD_PRELOAD", &shim)
        .env("KIN_VFS_WORKSPACE", workspace.path())
        .env("KIN_VFS_SOCK", &missing_socket)
        .env("KIN_VFS_CANARY", token)
        .env("KIN_EXPECT_INTERPOSE_ACTIVE", token)
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .output()
        .expect("run preload passthrough probe");

    assert!(
        output.status.success(),
        "preloaded passthrough probe failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"passthrough-ok\n");
}

#[test]
fn linux_preload_matches_libc_at_argument_matrix() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let probe = locate_or_build_probe("vfs_at_parity_probe");
    let fixture = tempfile::tempdir().expect("native parity fixture");
    let fixture_root = std::fs::canonicalize(fixture.path()).expect("canonical parity fixture");
    let file = fixture_root.join("file.txt");
    std::fs::write(&file, b"parity\n").expect("write parity file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
        .expect("set parity permissions");
    symlink("file.txt", fixture_root.join("link.txt")).expect("create parity symlink");

    let native = Command::new(&probe)
        .arg(&fixture_root)
        .output()
        .expect("run native Linux *at probe");
    assert!(
        native.status.success(),
        "native Linux *at probe failed with {:?}: {}",
        native.status.code(),
        String::from_utf8_lossy(&native.stderr)
    );

    // Run the same calls against graph-backed virtual directory and file
    // descriptors, including Linux AT_EMPTY_PATH on the virtual file fd.
    let kin_dir = fixture_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir Linux parity .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let (shutdown, server_thread) = start_native_parity_daemon(&sock_path);
    let canary = "kin-vfs-at-parity-linux";
    let interposed = Command::new(&probe)
        .arg(&fixture_root)
        .env("LD_PRELOAD", &shim)
        .env("KIN_VFS_WORKSPACE", &fixture_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_VFS_CANARY", canary)
        .env("KIN_EXPECT_CANARY", canary)
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .output()
        .expect("run preloaded Linux *at probe");
    shutdown.shutdown();
    let _ = server_thread.join();
    assert!(
        interposed.status.success(),
        "preloaded Linux *at probe failed with {:?}: {}",
        interposed.status.code(),
        String::from_utf8_lossy(&interposed.stderr)
    );
    assert_eq!(
        interposed.stdout,
        native.stdout,
        "KinVFS Linux *at argument/errno behavior diverged from libc\n\
         native:\n{}\npreloaded:\n{}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interposed.stdout),
    );

    let baseline = String::from_utf8(native.stdout).expect("ASCII parity output");
    for required in [
        "openat-invalid-dirfd=err:9",
        "openat-file-dirfd=err:20",
        "openat-empty=err:2",
        "openat-null=err:14",
        "fstatat-at-empty-path=ok:100000",
        "fstatat-eaccess-is-invalid=err:22",
        "faccessat-extra-mode-bit=err:22",
        "faccessat-all-mode-bits=err:22",
        "faccessat-at-empty-path=ok",
    ] {
        assert!(
            baseline.lines().any(|line| line == required),
            "native baseline did not pin expected Linux behavior: {required}\n{baseline}"
        );
    }
}
