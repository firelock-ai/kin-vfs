// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empirical proof that the shim's Kin-family exclusion survives the launch.
//!
//! Kin's own binaries must never run with the projection loaded, and the only
//! enforcement a user's machine had was a set of shell functions the setup hook
//! writes into `.zshrc`, `.bashrc` and `config.fish`. Functions do not reach a
//! `sh -c`, a Makefile, a launchd job or an agent harness, so the invariant
//! held in an interactive shell and nowhere else. The shim's own stand-down is
//! what makes it hold everywhere, and it decided from `argv[0]` alone, which is
//! a string the caller invents.
//!
//! These tests run one real binary under a real preloaded shim and vary only
//! the name it was launched under. They need no daemon: with a projection root
//! configured and no socket behind it, an intercepted `stat` fails `EIO`, and a
//! shim that stood down reads the file off disk. The two outcomes are opposite,
//! so neither direction can be satisfied by the shim doing nothing.
//!
//! Both directions are asserted in every run. Without the control, "Kin is
//! excluded" would also be satisfied by a shim that excluded everything.

#![cfg(all(test, any(target_os = "linux", target_os = "macos")))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;

use crate::nested_cargo_args;

/// The variable that injects a preloaded library on this platform.
const PRELOAD_ENV: &str = if cfg!(target_os = "macos") {
    "DYLD_INSERT_LIBRARIES"
} else {
    "LD_PRELOAD"
};

/// The shim cdylib's file name on this platform.
const SHIM_FILE: &str = if cfg!(target_os = "macos") {
    "libkin_vfs_shim.dylib"
} else {
    "libkin_vfs_shim.so"
};

/// Announced by the launcher and stamped back by a shim that actually loaded,
/// so the control asserts an exact value rather than mere truthiness.
const CANARY: &str = "kvfs-process-identity";

/// Walk up from the test binary to the cargo target profile dir, where the
/// shim cdylib and the helper bins land.
fn target_profile_dir() -> Option<PathBuf> {
    // current_exe is `<target>/<profile>/deps/<name>-<hash>`.
    let exe = std::env::current_exe().ok()?;
    exe.parent()?.parent().map(Path::to_path_buf)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("locate kin-vfs workspace root")
        .to_path_buf()
}

/// Build the shim in the active profile, then locate that exact artifact.
/// Rebuilding avoids injecting a stale dylib after the shim source changed,
/// which would prove the previous commit rather than this one.
fn locate_or_build_shim() -> Option<PathBuf> {
    static SHIM_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    SHIM_PATH
        .get_or_init(|| {
            let profile_dir = target_profile_dir()?;
            let mut command = Command::new(env!("CARGO"));
            command
                .current_dir(workspace_root())
                .args(["build", "-p", "kin-vfs-shim"])
                .args(nested_cargo_args());
            if profile_dir.file_name().and_then(|name| name.to_str()) == Some("release") {
                command.arg("--release");
            }
            if !command.status().ok()?.success() {
                eprintln!(
                    "kin-vfs tests: nested `cargo build -p kin-vfs-shim` failed; \
                     the process-identity proof cannot run"
                );
                return None;
            }

            [
                profile_dir.join(SHIM_FILE),
                profile_dir.join("deps").join(SHIM_FILE),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        })
        .clone()
}

/// Locate (or build) the neutral reporting probe.
fn locate_or_build_probe() -> PathBuf {
    const BIN: &str = "vfs_identity_probe";

    if let Ok(path) = std::env::var(format!("CARGO_BIN_EXE_{BIN}")) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [profile_dir.join(BIN), profile_dir.join("deps").join(BIN)];
    if let Some(found) = candidates.iter().find(|candidate| candidate.exists()) {
        return found.clone();
    }

    let status = Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args(["build", "-p", "kin-vfs-integration-tests", "--bin", BIN])
        .args(nested_cargo_args())
        .status()
        .unwrap_or_else(|error| panic!("run cargo build for {BIN}: {error}"));
    assert!(status.success(), "failed to build the {BIN} helper binary");

    candidates
        .iter()
        .find(|candidate| candidate.exists())
        .cloned()
        .unwrap_or_else(|| panic!("locate {BIN} after cargo build"))
}

/// A projection root the shim will accept: a real repository, proven by the
/// identity marker the daemon reads, holding one file that exists on disk.
struct Fixture {
    _root: tempfile::TempDir,
    root_path: PathBuf,
    on_disk: PathBuf,
    missing_socket: PathBuf,
    bin_dir: PathBuf,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("fixture tempdir");
    let root_path = root.path().to_path_buf();

    // Spelled literally rather than through a constant: the root the shim will
    // accept is a repository, and a repository is one that carries this file.
    // Writing it keeps the fixture a repository whether or not the shim of the
    // day checks, so what these tests vary stays the launch and nothing else.
    let marker = root_path.join(".kin").join("manifest.json");
    std::fs::create_dir_all(marker.parent().expect("marker has a parent"))
        .expect("create the repository marker directory");
    std::fs::write(&marker, br#"{"repo_id":"identity-fixture"}"#)
        .expect("write the repository marker");

    let on_disk = root_path.join("on-disk.txt");
    std::fs::write(&on_disk, b"read from disk\n").expect("write the on-disk fixture file");

    let bin_dir = root_path.join("launch-bin");
    std::fs::create_dir_all(&bin_dir).expect("create the fixture bin directory");

    Fixture {
        missing_socket: root_path.join("no-daemon.sock"),
        _root: root,
        root_path,
        on_disk,
        bin_dir,
    }
}

impl Fixture {
    /// Place the probe under `name`, which is what the executable image will
    /// report however the process is then launched.
    fn install_probe_as(&self, name: &str) -> PathBuf {
        let dest = self.bin_dir.join(name);
        std::fs::copy(locate_or_build_probe(), &dest)
            .unwrap_or_else(|error| panic!("copy the probe to {name}: {error}"));
        dest
    }

    /// Run `binary` under the shim, with `argv0` as the name it claims. Returns
    /// the probe's single report line.
    fn run_under_shim(&self, binary: &Path, argv0: &std::ffi::OsStr) -> String {
        let shim = locate_or_build_shim().expect("build the shim cdylib");

        let output = Command::new(binary)
            .arg0(argv0)
            .arg(&self.on_disk)
            .env(PRELOAD_ENV, &shim)
            .env("KIN_VFS_WORKSPACE", &self.root_path)
            .env("KIN_VFS_SOCK", &self.missing_socket)
            .env("KIN_VFS_CANARY", CANARY)
            .env_remove("KIN_VFS_DISABLE")
            .env_remove("KIN_NO_VFS")
            .env_remove(kin_vfs_core::canary::INTERPOSE_ACTIVE_ENV)
            .output()
            .expect("run the identity probe under the shim");

        assert!(
            output.status.success(),
            "the probe did not exit cleanly under the shim: status {:?}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string()
    }
}

fn os(name: &str) -> std::ffi::OsString {
    std::ffi::OsString::from(name)
}

/// The whole point: Kin's own binaries are left alone whatever name they were
/// launched under, because the executable image answers for the binary while
/// `argv[0]` only answers for the invocation.
#[test]
fn a_kin_binary_stands_the_shim_down_however_it_was_launched() {
    let fixture = fixture();
    let kin = fixture.install_probe_as("kin");
    let daemon = fixture.install_probe_as("kin-daemon");

    // How an ordinary `kin --version` arrives. This case already worked.
    let honest = fixture.run_under_shim(&kin, kin.as_os_str());

    // The cases the argv-only rule missed. A caller chooses `argv[0]` freely,
    // and `execve` accepts an empty `argv` that names nothing at all; both ran
    // Kin's own binary under a live projection, where every read of its own
    // configuration answers `EIO`.
    let renamed = fixture.run_under_shim(&kin, &os("mytool"));
    let nameless = fixture.run_under_shim(&kin, &os(""));
    let daemon_renamed = fixture.run_under_shim(&daemon, &os("mytool"));

    for (case, line) in [
        ("launched as itself", &honest),
        ("launched under another name", &renamed),
        ("launched with no name at all", &nameless),
        ("kin-daemon under another name", &daemon_renamed),
    ] {
        assert!(
            line.contains("\tinterpose=-\t"),
            "{case}: the shim engaged for a Kin binary, so the exclusion still \
             depends on how the process was launched: {line}"
        );
        assert!(
            line.ends_with("\tstat=ok"),
            "{case}: a Kin binary could not read a file in its own workspace, \
             which is what running Kin under the projection costs: {line}"
        );
    }
}

/// The control. A binary that is not Kin's keeps its projection under the same
/// shim, the same root and the same missing daemon, so the exclusion above is
/// scoped rather than a shim that quietly stopped working.
#[test]
fn a_non_kin_binary_under_the_same_shim_is_still_projected() {
    let fixture = fixture();
    let tool = fixture.install_probe_as("mytool");

    let line = fixture.run_under_shim(&tool, tool.as_os_str());

    assert!(
        line.contains(&format!("\tinterpose={CANARY}\t")),
        "the shim did not engage for an ordinary tool, so this run proves \
         nothing about the exclusion being scoped: {line}"
    );
    assert!(
        line.ends_with("\tstat=errno=5"),
        "a workspace path was answered from raw disk instead of failing closed \
         with no daemon behind the root: {line}"
    );
}

/// `argv[0]` is bytes, not text. Reading it as text inside a library
/// constructor aborts the host process on the first non-UTF-8 name, and an
/// `extern "C"` constructor cannot unwind, so the abort is the whole process
/// rather than a caught error.
#[test]
fn a_non_utf8_argv0_does_not_abort_the_host_process() {
    let fixture = fixture();
    let tool = fixture.install_probe_as("mytool");

    let argv0 = std::ffi::OsStr::from_bytes(b"\xff\xfe").to_os_string();
    let line = fixture.run_under_shim(&tool, &argv0);

    assert!(
        line.contains(&format!("\tinterpose={CANARY}\t")),
        "the shim did not engage, so this run cannot show that a non-UTF-8 \
         name was survived rather than avoided: {line}"
    );
}
