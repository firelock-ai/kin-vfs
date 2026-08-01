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
use std::sync::{Mutex, OnceLock};

use kin_vfs_core::{
    ContentProvider, DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
};

/// Build a validated byte-exact path for a fixture.
fn vpath(path: &str) -> VfsPath {
    VfsPath::from_utf8(path).expect("valid fixture path")
}

/// Build a validated byte-exact entry name for a fixture.
fn vname(name: &[u8]) -> VfsName {
    VfsName::from_bytes(name.to_vec()).expect("valid fixture name")
}
use kin_vfs_daemon::VfsDaemonServer;

// A minimal provider that serves exactly one virtual file by the same
// repo-relative key Kin's `/vfs/tree` and `/vfs/read/*path` endpoints use.
// Keeping this provider relative is intentional: if the shim ever serializes
// the intercepted host-absolute path, the real socket/protocol smoke fails.
struct OneFileProvider {
    files: Mutex<HashMap<VfsPath, Vec<u8>>>,
    version: AtomicU64,
}

impl OneFileProvider {
    fn new(path: &str, content: &[u8]) -> Self {
        let mut files = HashMap::new();
        files.insert(vpath(path), content.to_vec());
        Self {
            files: Mutex::new(files),
            version: AtomicU64::new(1),
        }
    }
}

impl ContentProvider for OneFileProvider {
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| VfsError::NotFound {
                path: path.to_string(),
            })
    }

    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let data = self.read_file(path)?;
        let start = offset as usize;
        if start >= data.len() {
            return Ok(vec![]);
        }
        let end = std::cmp::min(start + len as usize, data.len());
        Ok(data[start..end].to_vec())
    }

    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        let files = self.files.lock().unwrap();
        match files.get(path) {
            Some(data) => Ok(VirtualStat::regular_file(
                data.len() as u64,
                [0u8; 32],
                false,
                1000,
            )),
            None => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    /// List the entries this provider holds directly under `path`.
    ///
    /// This used to answer with a single `.` entry, which no test read and
    /// which `VfsName` rejects as a dot component — so the first caller that
    /// actually walked a listing panicked inside a daemon worker. A fixture
    /// that cannot survive being used is not a fixture.
    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        let prefix = match path.as_bytes() {
            b"" => Vec::new(),
            bytes => {
                let mut prefix = bytes.to_vec();
                prefix.push(b'/');
                prefix
            }
        };
        let files = self.files.lock().unwrap();
        let mut entries: Vec<DirEntry> = Vec::new();
        let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
        for key in files.keys() {
            let Some(relative) = key.as_bytes().strip_prefix(prefix.as_slice()) else {
                continue;
            };
            if relative.is_empty() {
                continue;
            }
            let (name, file_type) = match relative.iter().position(|byte| *byte == b'/') {
                Some(slash) => (&relative[..slash], FileType::Directory),
                None => (relative, FileType::File),
            };
            if seen.insert(name.to_vec()) {
                entries.push(DirEntry {
                    name: vname(name),
                    file_type,
                });
            }
        }
        Ok(entries)
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        Ok(self.files.lock().unwrap().contains_key(path))
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotFound {
            path: path.to_string(),
        })
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

use crate::nested_cargo_args;

/// Build `libkin_vfs_shim.dylib` once in the test's active profile, then locate
/// that exact artifact. Rebuilding avoids silently reusing a stale injected
/// dylib after shim source changed.
fn locate_or_build_shim() -> Option<PathBuf> {
    static SHIM_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    SHIM_PATH
        .get_or_init(|| {
            let profile_dir = target_profile_dir()?;
            let manifest = env!("CARGO_MANIFEST_DIR");
            let workspace_root = Path::new(manifest).parent()?.parent()?;
            let mut command = Command::new(env!("CARGO"));
            command
                .current_dir(workspace_root)
                .args(["build", "-p", "kin-vfs-shim"])
                .args(nested_cargo_args());
            if profile_dir.file_name().and_then(|name| name.to_str()) == Some("release") {
                command.arg("--release");
            }
            if !command.status().ok()?.success() {
                eprintln!(
                    "kin-vfs tests: nested `cargo build -p kin-vfs-shim` failed; \
                     interposition tests cannot run"
                );
                return None;
            }

            [
                profile_dir.join("libkin_vfs_shim.dylib"),
                profile_dir.join("deps").join("libkin_vfs_shim.dylib"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        })
        .clone()
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
        .args(nested_cargo_args())
        .status()
        .unwrap_or_else(|e| panic!("run cargo build for {bin}: {e}"));
    assert!(status.success(), "failed to build {bin} helper binary");

    candidates
        .iter()
        .find(|c| c.exists())
        .cloned()
        .unwrap_or_else(|| panic!("locate {bin} after cargo build"))
}

/// Refuse to run an interposition proof in a process that switched the shim
/// off.
///
/// The controls below self-skip when interposition is inactive, because a
/// sandbox can strip `DYLD_INSERT_LIBRARIES` (SIP, hardened runtime) and that
/// is not this repo's bug. An explicit `KIN_VFS_DISABLE=1` / `KIN_NO_VFS=1` is
/// a different thing: the shim loaded and disabled itself, every read went to
/// disk, and the skip would report that as a pass. Measured: with the kill
/// switch inherited from the environment, this suite reports several tests
/// green while proving nothing at all. Fail instead, and say which variable.
fn assert_interposition_not_disabled() {
    for key in ["KIN_VFS_DISABLE", "KIN_NO_VFS"] {
        assert!(
            std::env::var(key).as_deref() != Ok("1"),
            "{key}=1 disables the shim, so this run cannot prove interposition. \
             Clear it before running the macOS interposition suite."
        );
    }
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
    let shim = locate_or_build_shim()
        .expect("the baseline macOS interpose proof requires a freshly built shim");

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
    let provider = OneFileProvider::new("graph_only.txt", expected);
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

/// A child may name the same workspace through a lexical symlink while the VFS
/// daemon and launcher use its canonical root. The shim must translate either
/// spelling to the same repo-relative graph key without calling `canonicalize`
/// from inside an interposed hook.
#[test]
fn macos_interpose_maps_trusted_workspace_alias_to_graph_key() {
    use std::os::unix::fs::symlink;

    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let canonical_root = std::fs::canonicalize(workspace.path()).expect("canonical workspace");
    let aliases = tempfile::tempdir().expect("alias parent tempdir");
    let alias_root = aliases.path().join("project-link");
    symlink(&canonical_root, &alias_root).expect("workspace symlink alias");

    let virtual_path = alias_root.join("alias_only.txt");
    assert!(
        !virtual_path.exists(),
        "alias-only graph path must not exist on disk"
    );
    let expected = b"served-through-trusted-workspace-alias\n";

    let kin_dir = canonical_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir canonical .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let provider = OneFileProvider::new("alias_only.txt", expected);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    let alias_env = std::env::join_paths([&alias_root]).expect("encode alias path list");
    let output = Command::new(locate_or_build_bin("vfs_open_probe"))
        .arg(&virtual_path)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &canonical_root)
        .env("KIN_VFS_WORKSPACE_ALIASES", alias_env)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1")
        .output()
        .expect("spawn alias vfs_open_probe");

    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        output.status.success(),
        "alias probe failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, expected,
        "trusted alias and canonical root must resolve to the same graph key"
    );
}

/// A tool that names a workspace file relatively must get the same graph bytes
/// as one that names it absolutely.
///
/// Containment is decided on absolute bytes, so an unresolved relative argument
/// never matches the workspace root: the hook passes it through and the raw
/// filesystem answers for a graph-owned file. The virtual file does not exist on
/// disk, so only graph serving can make this child succeed.
#[test]
fn macos_interpose_serves_a_relative_path_like_its_absolute_twin() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = std::fs::canonicalize(workspace.path()).expect("canonical workspace");
    let expected = b"served-from-graph-through-a-relative-path\n";
    assert!(
        !workspace_root.join("graph_only.txt").exists(),
        "virtual file must not exist on disk for the test to be meaningful"
    );

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let provider = OneFileProvider::new("graph_only.txt", expected);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    let output = Command::new(locate_or_build_bin("vfs_open_probe"))
        .arg("graph_only.txt")
        .current_dir(&workspace_root)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1") // unreachable; notify no-ops
        .output()
        .expect("spawn relative vfs_open_probe");

    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        output.status.success(),
        "relative probe failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, expected,
        "a relative workspace path must resolve to the same graph key as its absolute twin"
    );
}

/// A relative spelling can begin outside the workspace and enter it through
/// `..`. Testing the unresolved bytes against the workspace prefix would miss
/// that destination and let raw disk answer. The resolved destination must be
/// routed to graph authority, whose strict miss is `EIO`, before libc sees it.
/// A normal component before `..` is more dangerous: it can be an outside
/// symlink into the workspace, so even default mode must fail closed.
#[test]
fn macos_interpose_refuses_outside_parent_traversal_into_workspace() {
    let shim = locate_or_build_shim()
        .expect("the parent-traversal regression requires a freshly built shim");

    let container = tempfile::tempdir().expect("container tempdir");
    let workspace = container.path().join("workspace");
    let outside = container.path().join("outside");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&outside).expect("outside cwd");
    let workspace_root = std::fs::canonicalize(workspace).expect("canonical workspace");
    let outside = std::fs::canonicalize(outside).expect("canonical outside cwd");
    std::fs::create_dir_all(workspace_root.join("subdir")).expect("workspace subdir");
    std::os::unix::fs::symlink(workspace_root.join("subdir"), outside.join("child"))
        .expect("outside symlink into workspace");
    let disk_only = b"RAW-DISK-MUST-NOT-ANSWER\n";
    std::fs::write(workspace_root.join("disk_only.txt"), disk_only).expect("disk-only fixture");

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let graph_truth = b"graph-control\n";
    let provider = OneFileProvider::new("graph_only.txt", graph_truth);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);
    let probe = locate_or_build_bin("vfs_open_probe");

    let control = Command::new(&probe)
        .arg(workspace_root.join("graph_only.txt"))
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_VFS_STRICT", "1")
        .output()
        .expect("spawn graph control");
    let traversal = Command::new(&probe)
        .arg("../workspace/disk_only.txt")
        .current_dir(&outside)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_VFS_STRICT", "1")
        .output()
        .expect("spawn traversal probe");
    let symlink_traversal = Command::new(&probe)
        .arg("child/../disk_only.txt")
        .current_dir(&outside)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env_remove("KIN_VFS_STRICT")
        .output()
        .expect("spawn default-mode symlink traversal probe");

    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        control.status.success() && control.stdout == graph_truth,
        "interposition control did not read graph truth (status {:?}); stderr: {}",
        control.status.code(),
        String::from_utf8_lossy(&control.stderr)
    );
    eprintln!("INTERPOSITION_ACTIVE: control read graph-only bytes");
    assert!(
        !traversal.status.success(),
        "outside parent traversal reached raw workspace disk"
    );
    assert!(
        traversal.stdout.is_empty(),
        "outside parent traversal leaked raw bytes: {:?}",
        traversal.stdout
    );
    assert!(
        String::from_utf8_lossy(&traversal.stderr).contains("os error 5"),
        "strict graph traversal must fail EIO, got: {}",
        String::from_utf8_lossy(&traversal.stderr)
    );
    assert!(
        !symlink_traversal.status.success(),
        "default-mode symlink parent traversal reached raw workspace disk"
    );
    assert!(
        symlink_traversal.stdout.is_empty(),
        "default-mode symlink traversal leaked raw bytes: {:?}",
        symlink_traversal.stdout
    );
    assert!(
        String::from_utf8_lossy(&symlink_traversal.stderr).contains("os error 5"),
        "default-mode ambiguous traversal must fail EIO, got: {}",
        String::from_utf8_lossy(&symlink_traversal.stderr)
    );
}

/// The other half of the traversal boundary: `..` after a normal component in a
/// path with no workspace relationship must still reach the host filesystem.
///
/// Embedded parents are how autotools, cmake, libtool, pkg-config and node
/// module resolution spell their own directories. Refusing them because the
/// shim cannot lexically prove where they land would leave a shim-enabled
/// process unable to open its own toolchain, which is the opposite of a
/// transparent projection. Refusal is scoped to traversals that can reach the
/// workspace, proven by the sibling test above.
#[test]
fn macos_interpose_passes_through_out_of_workspace_parent_traversal() {
    let shim = locate_or_build_shim()
        .expect("the toolchain-passthrough regression requires a freshly built shim");

    let container = tempfile::tempdir().expect("container tempdir");
    let workspace = container.path().join("workspace");
    let toolchain = container.path().join("toolchain");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(toolchain.join("bin")).expect("toolchain bin");
    std::fs::create_dir_all(toolchain.join("lib")).expect("toolchain lib");
    let workspace_root = std::fs::canonicalize(workspace).expect("canonical workspace");
    let toolchain = std::fs::canonicalize(toolchain).expect("canonical toolchain");
    let host_bytes = b"HOST-TOOLCHAIN-BYTES\n";
    std::fs::write(toolchain.join("lib").join("libfoo.dylib"), host_bytes).expect("host fixture");

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let graph_truth = b"graph-control\n";
    let provider = OneFileProvider::new("graph_only.txt", graph_truth);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);
    let probe = locate_or_build_bin("vfs_open_probe");

    let interposed = |arg: &str, cwd: &Path| {
        Command::new(&probe)
            .arg(arg)
            .current_dir(cwd)
            .env("DYLD_INSERT_LIBRARIES", &shim)
            .env("KIN_VFS_WORKSPACE", &workspace_root)
            .env("KIN_VFS_SOCK", &sock_path)
            .env("KIN_VFS_STRICT", "1")
            .output()
            .expect("spawn interposed probe")
    };

    // Control: interposition really is active in these children, so a
    // passthrough result below cannot be a silently stripped shim.
    let control = interposed(
        workspace_root
            .join("graph_only.txt")
            .to_str()
            .expect("utf8 fixture path"),
        &toolchain,
    );
    let absolute = interposed(
        toolchain
            .join("bin")
            .join("..")
            .join("lib")
            .join("libfoo.dylib")
            .to_str()
            .expect("utf8 fixture path"),
        &toolchain,
    );
    let relative = interposed("bin/../lib/libfoo.dylib", &toolchain);

    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        control.status.success() && control.stdout == graph_truth,
        "interposition control did not read graph truth (status {:?}); stderr: {}",
        control.status.code(),
        String::from_utf8_lossy(&control.stderr)
    );
    eprintln!("INTERPOSITION_ACTIVE: control read graph-only bytes");
    for (label, output) in [("absolute", &absolute), ("relative", &relative)] {
        assert!(
            output.status.success(),
            "{label} out-of-workspace traversal was refused (status {:?}); stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout, host_bytes,
            "{label} out-of-workspace traversal did not read the host file"
        );
    }
}

/// A path the graph does not hold is refused, never answered from raw disk —
/// and strict mode says so with the same EIO as unavailable authority.
///
/// The file is readable on disk on purpose: a raw-disk answer would be a
/// successful read with content on stdout, so the control cannot pass by
/// accident. Every spelling and mode must fail, and the exact errno is
/// load-bearing: EIO (5) is the strict refusal, ENOENT (2) the default absence.
#[test]
fn macos_interpose_refuses_a_graph_miss_in_both_modes() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = std::fs::canonicalize(workspace.path()).expect("canonical workspace");
    let graph_truth = b"held-by-the-graph\n";
    let disk_only = b"ON-DISK-ONLY-must-never-be-served\n";
    let miss_path = workspace_root.join("disk_only.txt");
    std::fs::write(&miss_path, disk_only).expect("write disk-only file");

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let provider = OneFileProvider::new("graph_only.txt", graph_truth);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    let probe = locate_or_build_bin("vfs_open_probe");
    let read = |arg: &str, strict: &str| {
        Command::new(&probe)
            .arg(arg)
            .current_dir(&workspace_root)
            .env("DYLD_INSERT_LIBRARIES", &shim)
            .env("KIN_VFS_WORKSPACE", &workspace_root)
            .env("KIN_VFS_SOCK", &sock_path)
            .env("KIN_VFS_STRICT", strict)
            .env("KIN_DAEMON_URL", "http://127.0.0.1:1")
            .output()
            .expect("spawn miss vfs_open_probe")
    };

    // Positive control: interposition is active here, so a later failure is the
    // refusal under test rather than a stripped DYLD_INSERT_LIBRARIES. It names
    // the file absolutely on purpose, so the control cannot fail for the
    // relative-resolution reason a miss case is meant to catch.
    let control = read(&workspace_root.join("graph_only.txt").to_string_lossy(), "");
    let control_served = control.status.success() && control.stdout == graph_truth;

    let miss_absolute = miss_path.to_string_lossy().to_string();
    let strict_absolute = read(&miss_absolute, "1");
    let strict_relative = read("disk_only.txt", "1");
    let default_absolute = read(&miss_absolute, "");
    let default_relative = read("disk_only.txt", "");

    shutdown.shutdown();
    let _ = server_thread.join();

    if !control_served {
        eprintln!(
            "SKIP: interposition not active in this environment \
             (control did not read graph truth; DYLD likely stripped)"
        );
        return;
    }

    for (label, output, errno) in [
        ("strict absolute", &strict_absolute, 5),
        ("strict relative", &strict_relative, 5),
        ("default absolute", &default_absolute, 2),
        ("default relative", &default_relative, 2),
    ] {
        assert!(
            !output.status.success(),
            "{label}: shim served a path the graph does not hold"
        );
        assert!(
            output.stdout.is_empty(),
            "{label}: miss leaked file content to stdout"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("os error {errno}")),
            "{label}: expected os error {errno}, got: {stderr}"
        );
    }
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
    assert_interposition_not_disabled();

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
    let provider = OneFileProvider::new("doc.txt", graph_truth);
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

/// Graph authority must fail loud when the daemon is unreachable rather than
/// silently serving the stale on-disk copy.
///
/// A positive control runs first with the daemon up, proving interposition is
/// active here; if that control does not
/// read graph bytes, the environment stripped `DYLD_INSERT_LIBRARIES` and the
/// test self-skips instead of false-failing. Then, with the daemon DOWN, the
/// same read must fail — never returning the stale disk bytes.
#[test]
fn macos_graph_authority_fails_loud_instead_of_reading_stale_disk() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path().to_path_buf();
    let path = workspace_root.join("doc.txt");
    let path_str = path.to_string_lossy().to_string();

    let graph_truth = b"GRAPH-TRUTH-authoritative\n";
    let stale_disk = b"STALE-DISK-must-not-win\n";

    // Stale copy on disk: the only content a non-interposed / fallthrough read
    // could ever return.
    std::fs::write(&path, stale_disk).expect("write stale disk file");

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");

    let probe = locate_or_build_bin("vfs_open_probe");

    // ── Positive control: daemon UP → must read GRAPH truth. ──
    let provider = OneFileProvider::new("doc.txt", graph_truth);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);
    let control = Command::new(&probe)
        .arg(&path_str)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1") // notify no-ops
        .output()
        .expect("spawn control vfs_open_probe");
    shutdown.shutdown();
    let _ = server_thread.join();

    if !control.status.success() || control.stdout != graph_truth {
        eprintln!(
            "SKIP: interposition not active in this environment \
             (control did not read graph truth; DYLD likely stripped)"
        );
        return;
    }

    // Wait for the socket to disappear / stop accepting so the next connect is
    // a genuine unreachable.
    for _ in 0..50 {
        if !sock_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // ── Assertion: daemon DOWN → fail loud, never stale disk. ──
    let output = Command::new(&probe)
        .arg(&path_str)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1")
        .output()
        .expect("spawn vfs_open_probe");

    assert!(
        !output.status.success(),
        "graph authority must fail the read when the daemon is unreachable, \
         not fall through to stale disk"
    );
    assert_ne!(
        output.stdout, stale_disk,
        "graph authority leaked stale disk content instead of failing loud"
    );
}

// ── Uninterposed-surface reporting ──────────────────────────────────────
//
// A launch canary that only records "the shim loaded" answers a question
// nobody asked. Interposition covers a fixed symbol roster, and a workspace
// file reached through a surface outside it is served from raw disk by a
// process whose shim loaded perfectly. These tests hold the canary to the
// claim it actually makes: this run's workspace reads were graph-native.

/// One request/response round trip to the VFS daemon, the way `kin-vfs exec`
/// talks to it. Kept here rather than reaching into the CLI so the test
/// exercises the same wire the launcher uses.
fn daemon_roundtrip(
    sock: &Path,
    request: &kin_vfs_daemon::VfsRequest,
) -> Option<kin_vfs_daemon::VfsResponse> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock).ok()?;
    let timeout = std::time::Duration::from_millis(2000);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = rmp_serde::to_vec(request).ok()?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .ok()?;
    stream.write_all(&payload).ok()?;
    stream.flush().ok()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    rmp_serde::from_slice(&buf).ok()
}

/// Register a launch canary with the daemon, as the launcher does before it
/// starts a child under interposition.
fn expect_canary(sock: &Path, token: &str) {
    let response = daemon_roundtrip(
        sock,
        &kin_vfs_daemon::VfsRequest::CanaryExpect {
            token: token.to_string(),
        },
    );
    assert!(
        matches!(response, Some(kin_vfs_daemon::VfsResponse::Announced)),
        "daemon did not accept the canary expectation: {response:?}"
    );
}

/// The verdict the launcher would read after the child exits.
fn canary_verdict(sock: &Path, token: &str) -> kin_vfs_core::InterposeStatus {
    match daemon_roundtrip(
        sock,
        &kin_vfs_daemon::VfsRequest::CanaryVerdict {
            token: token.to_string(),
        },
    ) {
        Some(kin_vfs_daemon::VfsResponse::CanaryStatus(status)) => status,
        other => panic!("daemon did not answer the verdict query: {other:?}"),
    }
}

/// The surfaces the launcher would name in its diagnostic.
fn canary_bypasses(sock: &Path, token: &str) -> Vec<String> {
    match daemon_roundtrip(
        sock,
        &kin_vfs_daemon::VfsRequest::CanaryBypassSurfaces {
            token: token.to_string(),
        },
    ) {
        Some(kin_vfs_daemon::VfsResponse::CanaryBypasses(surfaces)) => surfaces,
        other => panic!("daemon did not answer the bypass query: {other:?}"),
    }
}

/// Parse one `name<TAB>status<TAB>payload` line out of the surface probe.
fn probe_surface<'a>(stdout: &'a str, surface: &str) -> (&'a str, &'a str) {
    for line in stdout.lines() {
        let mut fields = line.splitn(3, '\t');
        let (Some(name), Some(status), Some(payload)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if name == surface {
            return (status, payload);
        }
    }
    panic!("surface {surface} missing from probe output:\n{stdout}");
}

/// Fixture: a workspace whose one file holds different bytes in the graph than
/// on disk, so every read can be attributed to exactly one authority.
struct DivergentFixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    sock: PathBuf,
}

const GRAPH_TRUTH: &[u8] = b"GRAPH-TRUTH-authoritative\n";
const STALE_DISK: &[u8] = b"STALE-DISK-must-not-win\n";

impl DivergentFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // The child resolves relative paths against its real cwd, which macOS
        // reports canonically (`/private/var/...`). Canonicalize the root so the
        // workspace the shim is told about is the one the child will name.
        let root = std::fs::canonicalize(dir.path()).expect("canonical workspace root");
        std::fs::write(root.join("doc.txt"), STALE_DISK).expect("seed stale disk copy");
        let kin_dir = root.join(".kin");
        std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
        let sock = kin_dir.join("vfs.sock");
        Self {
            _dir: dir,
            root,
            sock,
        }
    }

    /// Run the surface probe against `arg`, from inside the workspace, under a
    /// launch canary. Returns the probe's stdout and exit status.
    fn probe(&self, shim: &Path, arg: &str, token: &str, strict: bool) -> (String, Option<i32>) {
        let mut command = Command::new(locate_or_build_bin("vfs_surface_probe"));
        command
            .arg(arg)
            .arg(self.root.to_string_lossy().to_string())
            .current_dir(&self.root)
            .env("DYLD_INSERT_LIBRARIES", shim)
            .env("KIN_VFS_WORKSPACE", &self.root)
            .env("KIN_VFS_SOCK", &self.sock)
            .env(kin_vfs_core::canary::CANARY_ENV, token)
            // Keep the host clean: never let a real daemon on :4219 be notified.
            .env("KIN_DAEMON_URL", "http://127.0.0.1:1");
        if strict {
            command.env("KIN_VFS_STRICT", "1");
        }
        let output = command.output().expect("spawn vfs_surface_probe");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            output.status.code(),
        )
    }
}

/// The failure this test exists to catch: a tool reads a workspace file through
/// stdio, gets the disk copy, and the run is still certified graph-native.
///
/// The interposed syscall path is the control. It must serve graph truth in the
/// same process and the same run, so a red verdict cannot be explained by the
/// shim having failed to load — which is the other way this could go red, and
/// a different bug.
#[test]
fn macos_stdio_bypass_turns_the_canary_red() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let fixture = DivergentFixture::new();
    let provider = OneFileProvider::new("doc.txt", GRAPH_TRUTH);
    let (shutdown, server_thread) = start_daemon(provider, &fixture.sock);

    let token = "kvfs-stdio-bypass-token";
    expect_canary(&fixture.sock, token);
    let (stdout, status) = fixture.probe(&shim, "doc.txt", token, false);

    let (open_status, open_payload) = probe_surface(&stdout, "libc_open");
    if open_status != "ok" || open_payload.as_bytes() != &GRAPH_TRUTH[..GRAPH_TRUTH.len() - 1] {
        shutdown.shutdown();
        let _ = server_thread.join();
        eprintln!(
            "SKIP: interposition not active in this environment \
             (control read {open_status}/{open_payload:?}; DYLD likely stripped)"
        );
        return;
    }

    // The bypass itself: stdio reached the disk copy, and the process exited 0.
    let (fopen_status, fopen_payload) = probe_surface(&stdout, "fopen");
    assert_eq!(fopen_status, "ok", "probe output:\n{stdout}");
    assert_eq!(
        fopen_payload.as_bytes(),
        &STALE_DISK[..STALE_DISK.len() - 1],
        "this test is only meaningful while fopen still reaches raw disk"
    );
    assert_eq!(status, Some(0), "the bypassing run exited cleanly");

    // The verdict must contradict the clean exit. Before the shim reported
    // uninterposed surfaces this read Active: the shim had loaded, so the
    // launcher certified a run whose stdio reads were disk bytes.
    let verdict = canary_verdict(&fixture.sock, token);
    let surfaces = canary_bypasses(&fixture.sock, token);
    shutdown.shutdown();
    let _ = server_thread.join();

    assert_eq!(
        verdict,
        kin_vfs_core::InterposeStatus::Bypassed,
        "a run that served a workspace file from raw disk must not read as graph-native"
    );
    assert!(!verdict.is_graph_native());
    assert_eq!(
        surfaces,
        vec!["fopen"],
        "the launcher must be able to name the surface that served disk"
    );
}

/// Strict mode refuses rather than serving the disk copy, and a run with no
/// bypass keeps its clean verdict — so the red verdict above is caused by the
/// bypass and not by merely having a canary.
#[test]
fn macos_strict_refuses_the_stdio_surface_and_a_clean_run_stays_active() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let fixture = DivergentFixture::new();
    let provider = OneFileProvider::new("doc.txt", GRAPH_TRUTH);
    let (shutdown, server_thread) = start_daemon(provider, &fixture.sock);

    let strict_token = "kvfs-strict-token";
    expect_canary(&fixture.sock, strict_token);
    let (stdout, _) = fixture.probe(&shim, "doc.txt", strict_token, true);

    let (open_status, open_payload) = probe_surface(&stdout, "libc_open");
    if open_status != "ok" || open_payload.as_bytes() != &GRAPH_TRUTH[..GRAPH_TRUTH.len() - 1] {
        shutdown.shutdown();
        let _ = server_thread.join();
        eprintln!("SKIP: interposition not active in this environment");
        return;
    }

    // EIO, the same answer a graph-authority failure gives — never disk bytes.
    let (fopen_status, fopen_payload) = probe_surface(&stdout, "fopen");
    assert_eq!(
        (fopen_status, fopen_payload),
        ("err", "errno=5"),
        "strict mode must refuse the uninterposed surface, not serve disk:\n{stdout}"
    );
    assert_eq!(
        canary_verdict(&fixture.sock, strict_token),
        kin_vfs_core::InterposeStatus::Bypassed,
        "refusing the read does not make the run graph-native; it was still attempted"
    );

    // Control: the same fixture, read only through the interposed syscall path.
    let clean_token = "kvfs-clean-token";
    expect_canary(&fixture.sock, clean_token);
    let clean = Command::new(locate_or_build_bin("vfs_open_probe"))
        .arg("doc.txt")
        .current_dir(&fixture.root)
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &fixture.root)
        .env("KIN_VFS_SOCK", &fixture.sock)
        .env(kin_vfs_core::canary::CANARY_ENV, clean_token)
        .env("KIN_DAEMON_URL", "http://127.0.0.1:1")
        .output()
        .expect("spawn vfs_open_probe");
    let clean_verdict = canary_verdict(&fixture.sock, clean_token);

    shutdown.shutdown();
    let _ = server_thread.join();

    assert_eq!(clean.stdout, GRAPH_TRUTH, "control must read graph truth");
    assert_eq!(
        clean_verdict,
        kin_vfs_core::InterposeStatus::Active,
        "a run that reached the workspace only through interposed syscalls is graph-native"
    );
}

/// Every relative spelling of a workspace path must reach the same authority as
/// its absolute twin, on every surface — including the one that bypasses.
///
/// The original defect was spelling-dependent: `doc.txt` fell through to disk
/// while `/abs/doc.txt` was served from the graph. Resolution against the live
/// cwd fixed that for the interposed syscalls, and this pins it per spelling so
/// a regression cannot hide behind whichever spelling a test happened to use.
#[test]
fn macos_every_relative_spelling_reaches_the_same_authority() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    let fixture = DivergentFixture::new();
    let provider = OneFileProvider::new("doc.txt", GRAPH_TRUTH);
    let (shutdown, server_thread) = start_daemon(provider, &fixture.sock);

    let absolute = fixture.root.join("doc.txt").to_string_lossy().to_string();
    let spellings = [absolute.as_str(), "doc.txt", "./doc.txt"];
    let mut observed = Vec::new();
    for (index, spelling) in spellings.iter().enumerate() {
        let token = format!("kvfs-spelling-{index}");
        expect_canary(&fixture.sock, &token);
        let (stdout, _) = fixture.probe(&shim, spelling, &token, false);
        observed.push((
            *spelling,
            stdout.clone(),
            canary_verdict(&fixture.sock, &token),
        ));
    }

    shutdown.shutdown();
    let _ = server_thread.join();

    let control = probe_surface(&observed[0].1, "libc_open");
    if control.0 != "ok" || control.1.as_bytes() != &GRAPH_TRUTH[..GRAPH_TRUTH.len() - 1] {
        eprintln!("SKIP: interposition not active in this environment");
        return;
    }

    for (spelling, stdout, verdict) in &observed {
        for surface in ["std_fs_read", "libc_open"] {
            let (status, payload) = probe_surface(stdout, surface);
            assert_eq!(
                (status, payload.as_bytes()),
                ("ok", &GRAPH_TRUTH[..GRAPH_TRUTH.len() - 1]),
                "{surface} served {spelling} from the wrong authority:\n{stdout}"
            );
        }
        // The stat size distinguishes the two copies without reading them.
        let (stat_status, stat_payload) = probe_surface(stdout, "stat");
        assert_eq!(
            (stat_status, stat_payload),
            ("ok", format!("size={}", GRAPH_TRUTH.len()).as_str()),
            "stat reported the disk size for {spelling}:\n{stdout}"
        );
        // And the bypassing surface is reported for every spelling, so no
        // spelling quietly reads as graph-native.
        assert_eq!(
            *verdict,
            kin_vfs_core::InterposeStatus::Bypassed,
            "the stdio bypass went unreported for {spelling}"
        );
    }
}


/// A process that reads one file and exits immediately must still be verifiable.
///
/// The load announce used to be handed to a detached thread so it would not sit
/// on the caller's first read. Nothing joins that thread, so a short-lived
/// process races its own announce to the daemon and the launcher reads
/// `Stripped` for a run whose shim loaded and whose read came from the graph.
/// Under `KIN_VFS_STRICT=1` that makes `kin-vfs exec` refuse a good run.
///
/// Repeated, because a race that is usually won reads exactly like correctness
/// on a single sample. Every iteration is a fresh process with a fresh token, so
/// one lost race anywhere in the loop fails the test.
#[test]
fn macos_a_process_that_exits_immediately_still_reports_its_own_verdict() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    assert_interposition_not_disabled();

    const RUNS: usize = 48;

    let fixture = DivergentFixture::new();
    let provider = OneFileProvider::new("doc.txt", GRAPH_TRUTH);
    let (shutdown, server_thread) = start_daemon(provider, &fixture.sock);

    let mut verdicts = Vec::new();
    for run in 0..RUNS {
        let token = format!("kvfs-exit-race-{run}");
        expect_canary(&fixture.sock, &token);
        let output = Command::new(locate_or_build_bin("vfs_open_probe"))
            .arg("doc.txt")
            .current_dir(&fixture.root)
            .env("DYLD_INSERT_LIBRARIES", &shim)
            .env("KIN_VFS_WORKSPACE", &fixture.root)
            .env("KIN_VFS_SOCK", &fixture.sock)
            .env(kin_vfs_core::canary::CANARY_ENV, &token)
            .env("KIN_DAEMON_URL", "http://127.0.0.1:1")
            .output()
            .expect("spawn vfs_open_probe");
        verdicts.push((
            output.stdout.clone(),
            canary_verdict(&fixture.sock, &token),
        ));
    }

    shutdown.shutdown();
    let _ = server_thread.join();

    if verdicts[0].0 != GRAPH_TRUTH {
        eprintln!("SKIP: interposition not active in this environment");
        return;
    }

    for (run, (stdout, verdict)) in verdicts.iter().enumerate() {
        assert_eq!(stdout, GRAPH_TRUTH, "run {run} did not read graph truth");
        assert_eq!(
            *verdict,
            kin_vfs_core::InterposeStatus::Active,
            "run {run} read graph truth and was still not certified graph-native"
        );
    }
}
