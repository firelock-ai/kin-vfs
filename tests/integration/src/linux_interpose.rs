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

fn locate_or_build_probe(name: &str) -> PathBuf {
    if let Ok(path) = std::env::var(format!("CARGO_BIN_EXE_{name}")) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [profile_dir.join(name), profile_dir.join("deps").join(name)];
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
        .args(["build", "-p", "kin-vfs-integration-tests", "--bin", name])
        .args(crate::nested_cargo_args())
        .status()
        .unwrap_or_else(|error| panic!("build {name}: {error}"));
    assert!(status.success(), "failed to build {name}");

    candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| panic!("locate {name} after build"))
}

/// Build a fixture directory the shim will admit as a projection root.
///
/// The shim requires `.kin/manifest.json`, not a bare `.kin` directory,
/// because the Kin managed toolchain home is exactly a bare `.kin` directory
/// and admitting it hands the shim the user's whole home (FIR-2552). A fixture
/// without the marker is a toolchain home to the shim, and every interception
/// assertion in this file would then pass with the shim disabled.
fn make_repository(root: &Path) {
    let kin_dir = root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    std::fs::write(
        kin_dir.join("manifest.json"),
        br#"{"repo_id":"linux-interpose-fixture","workspace_id":"linux-interpose-workspace"}"#,
    )
    .expect("seed repository identity marker");
}

/// Build the Kin managed toolchain home shape: a real `.kin` directory holding
/// binaries and configuration, and no repository identity anywhere in it. This
/// is what `$HOME` looks like after `kin setup`.
fn make_toolchain_home(root: &Path) {
    for directory in ["bin", "lib", "shell", "config"] {
        std::fs::create_dir_all(root.join(".kin").join(directory)).expect("mkdir toolchain dir");
    }
    std::fs::write(root.join(".kin").join("registry.toml"), b"").expect("seed registry.toml");
}

/// Run the stat-family probe over `paths` under a loaded shim bound to `root`,
/// with a socket that is deliberately absent. Returns one `<path> <verdict>`
/// line per path, in order.
fn stat_family_verdicts(shim: &Path, root: &Path, paths: &[&Path]) -> Vec<String> {
    let output = Command::new(locate_or_build_probe("vfs_stat_family_probe"))
        .args(paths)
        .env("LD_PRELOAD", shim)
        .env("KIN_VFS_WORKSPACE", root)
        .env("KIN_VFS_SOCK", root.join(".kin").join("absent-vfs.sock"))
        .env_remove("KIN_VFS_CANARY")
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .env_remove("KIN_VFS_STRICT")
        .output()
        .expect("run stat-family probe");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_ne!(
        output.status.code(),
        Some(4),
        "stat-family entry points disagreed: {stdout}"
    );
    assert!(
        output.status.success(),
        "stat-family probe failed with {:?}: {} / {}",
        output.status.code(),
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout.lines().map(str::to_owned).collect()
}

#[test]
fn linux_preload_preserves_real_stat_family_passthrough() {
    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    // The shim admits a root only when it carries the repository identity
    // marker, so without this the sentinel below is never stamped and the
    // probe reports a disabled shim rather than a passthrough one.
    make_repository(workspace.path());
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

/// FIR-2552. A root that is not a Kin repository must be left entirely alone.
///
/// `kin setup` installs a shell hook that binds a projection root by walking up
/// to the first `.kin` directory, and the Kin managed toolchain home is
/// `$HOME/.kin`, so every interactive shell exported `KIN_VFS_WORKSPACE=$HOME`.
/// The shim then owned the user's whole home while holding none of it: with no
/// store behind that root every path under it failed `EIO`, existing or not,
/// because a workspace path must never be answered from raw disk. `git` failed
/// 128 in every directory on the machine, Kin repository or not.
///
/// The verdicts asserted here are the stranger's own probe list on shipped
/// 0.5.45: the root itself, a real dotfile under it, the managed binary under
/// it, a missing path under it, and a missing path outside it.
#[test]
fn linux_preload_leaves_a_non_repository_root_alone() {
    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let home = tempfile::tempdir().expect("home tempdir");
    make_toolchain_home(home.path());
    std::fs::write(home.path().join(".bashrc"), b"# fixture\n").expect("seed .bashrc");
    std::fs::write(home.path().join(".kin/bin/kin"), b"#!/bin/sh\n").expect("seed managed binary");

    let outside = tempfile::tempdir().expect("outside tempdir");
    let missing_under_home = home.path().join("missing-dir/missing-file");
    let missing_outside = outside.path().join("missing-dir/missing-file");
    let bashrc = home.path().join(".bashrc");
    let managed_binary = home.path().join(".kin/bin/kin");

    let verdicts = stat_family_verdicts(
        &shim,
        home.path(),
        &[
            home.path(),
            &bashrc,
            &managed_binary,
            &missing_under_home,
            &missing_outside,
        ],
    );

    assert_eq!(
        verdicts,
        vec![
            format!("{} ok", home.path().display()),
            format!("{} ok", bashrc.display()),
            format!("{} ok", managed_binary.display()),
            format!("{} errno=2", missing_under_home.display()),
            format!("{} errno=2", missing_outside.display()),
        ],
        "a non-repository root must answer from the kernel, never errno=5"
    );
}

/// The positive control for the test above: a real repository root is still
/// projected, so the fix scoped interception rather than removing it.
///
/// The socket is deliberately absent, so a path the shim owns fails `EIO` (the
/// graph could not be reached and raw disk must not answer for a graph-owned
/// path) while a path outside the root still reaches the kernel. If admission
/// were widened back to any directory holding `.kin`, the previous test would
/// fail; if the shim stopped intercepting at all, this one would.
#[test]
fn linux_preload_still_owns_a_repository_root() {
    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let repo = tempfile::tempdir().expect("repo tempdir");
    make_repository(repo.path());
    std::fs::write(repo.path().join("tracked.txt"), b"on disk\n").expect("seed tracked file");

    let outside = tempfile::tempdir().expect("outside tempdir");
    let tracked = repo.path().join("tracked.txt");
    let missing_outside = outside.path().join("missing-dir/missing-file");

    let verdicts = stat_family_verdicts(&shim, repo.path(), &[&tracked, &missing_outside]);

    assert_eq!(
        verdicts,
        vec![
            format!("{} errno=5", tracked.display()),
            format!("{} errno=2", missing_outside.display()),
        ],
        "the shim must still own a repository root and still leave everything else alone"
    );
}

/// FIR-2572. Node must read what every libc caller reads.
///
/// libuv does not call a single libc stat entry point. `uv__fs_statx` issues
/// `syscall(SYS_statx, ...)` itself, so for a release `node` answered from raw
/// disk on the exact path where `python`, `git` and the coreutils got the
/// fail-closed `EIO`, inside a repository whose graph the daemon could not
/// answer for. Every editor, language server, bundler and agent runtime built
/// on Node was in that class, and Node is what Kin's own npm launcher runs on.
///
/// The bypass turned out to be interposable: libuv reaches the kernel through
/// glibc's `syscall(2)` wrapper, an ordinary exported symbol, not through the
/// instruction. `vfs_stat_family_probe` asserts the mechanism on every run by
/// calling that route the way libuv calls it. This test asserts the product
/// claim on the real runtime, because a probe agreeing with itself is not
/// evidence that Node agrees with it.
///
/// The socket is deliberately absent, so the graph-owned answer is `EIO`. A
/// Node that prints a size instead has read the working copy.
#[test]
fn linux_preload_projects_node_the_same_as_every_libc_caller() {
    let Some(node) = locate_node() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must run this test: node is the runtime FIR-2572 is about, and a silent skip \
             here is how the defect survived a release"
        );
        eprintln!("skipping: no `node` on PATH");
        return;
    };

    let shim = locate_or_build_shim().expect("build libkin_vfs_shim.so");
    let repo = tempfile::tempdir().expect("repo tempdir");
    make_repository(repo.path());
    let tracked = repo.path().join("tracked.txt");
    std::fs::write(&tracked, b"raw disk bytes that must never be served\n")
        .expect("seed tracked file");

    // Outside the projection, and outside the repository the shim was told to
    // own. Node must still read this normally, or the assertion above would
    // pass just as well with a shim that broke every path on the host.
    let outside = tempfile::tempdir().expect("outside tempdir");
    let plain = outside.path().join("plain.txt");
    std::fs::write(&plain, b"outside\n").expect("seed outside file");

    // The script lives outside the projection: Node resolves its own entry
    // point through the same hooks, so a script inside the repository fails to
    // load before any assertion here runs.
    let script = outside.path().join("probe.cjs");
    std::fs::write(
        &script,
        br#"const fs = require('fs');
const verdict = (path) => {
  try { return 'read-disk:' + fs.statSync(path).size; }
  catch (error) { return error.code; }
};
console.log(verdict(process.argv[2]));
console.log(verdict(process.argv[3]));
"#,
    )
    .expect("seed node probe");

    let output = std::process::Command::new(node)
        .arg(&script)
        .arg(&tracked)
        .arg(&plain)
        .env("LD_PRELOAD", &shim)
        .env("KIN_VFS_WORKSPACE", repo.path())
        .env("KIN_VFS_SOCK", repo.path().join(".kin").join("absent.sock"))
        .env_remove("KIN_VFS_CANARY")
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .env_remove("KIN_VFS_STRICT")
        .output()
        .expect("run node under the shim");

    assert!(
        output.status.success(),
        "node exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let verdicts: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        verdicts,
        vec!["EIO".to_string(), "read-disk:8".to_string()],
        "node must fail closed inside the projection and read normally outside it; a size on \
         the first line is FIR-2572 returning"
    );

    // The claim is that Node agrees with libc, so read libc's answer here
    // rather than assuming it: an `EIO` both sides would also be produced by a
    // shim that had started refusing everything.
    let libc_verdicts = stat_family_verdicts(&shim, repo.path(), &[&tracked, &plain]);
    assert_eq!(
        libc_verdicts,
        vec![
            format!("{} errno=5", tracked.display()),
            format!("{} ok", plain.display()),
        ],
        "the libc entry points must give node's answer, path for path"
    );
}

/// `node` as the host offers it, or `None`.
fn locate_node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("node"))
        .find(|candidate| candidate.is_file())
}
