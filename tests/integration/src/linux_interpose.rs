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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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
                .args(["build", "-p", "kin-vfs-shim"]);
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

fn locate_or_build_probe() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vfs_passthrough_probe") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [
        profile_dir.join("vfs_passthrough_probe"),
        profile_dir.join("deps").join("vfs_passthrough_probe"),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
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
            "vfs_passthrough_probe",
        ])
        .status()
        .expect("build vfs_passthrough_probe");
    assert!(status.success(), "failed to build passthrough probe");

    candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .expect("locate vfs_passthrough_probe after build")
}

#[test]
fn linux_preload_preserves_real_stat_family_passthrough() {
    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let missing_socket = workspace.path().join("missing-vfs.sock");
    let token = "kvfs-linux-stat-passthrough";

    let output = Command::new(locate_or_build_probe())
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
