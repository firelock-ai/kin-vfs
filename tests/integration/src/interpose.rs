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

use crate::native_parity::NativeParityProvider;
use kin_vfs_core::{
    ContentProvider, DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
};
use sha2::{Digest, Sha256};

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
                Sha256::digest(data).into(),
                false,
                1000,
            )),
            None => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_dir(&self, _path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        Ok(vec![DirEntry {
            name: vname(b"."),
            file_type: FileType::Directory,
            object_id: None,
        }])
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
    static BIN_PATHS: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();

    let env_key = format!("CARGO_BIN_EXE_{bin}");
    if let Ok(path) = std::env::var(&env_key) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }

    let paths = BIN_PATHS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut paths = paths.lock().expect("helper binary path cache");
    if let Some(path) = paths.get(bin).filter(|path| path.exists()) {
        return path.clone();
    }

    let profile_dir = target_profile_dir().expect("locate cargo target profile dir");
    let candidates = [profile_dir.join(bin), profile_dir.join("deps").join(bin)];

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

    let path = candidates
        .iter()
        .find(|c| c.exists())
        .cloned()
        .unwrap_or_else(|| panic!("locate {bin} after cargo build"));
    paths.insert(bin.to_owned(), path.clone());
    path
}

/// Run `provider` on a background tokio runtime serving `sock_path`, returning
/// the shutdown handle + join handle once the socket is bound.
fn start_daemon<P>(
    provider: P,
    sock_path: &Path,
) -> (
    kin_vfs_daemon::server::ShutdownHandle,
    std::thread::JoinHandle<()>,
)
where
    P: ContentProvider + Send + Sync + 'static,
{
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
    let provider = OneFileProvider::new("graph_only.txt", expected);
    let (shutdown, server_thread) = start_daemon(provider, &sock_path);

    // Run the helper under DYLD_INSERT_LIBRARIES — this is the interposition.
    let output = Command::new(locate_or_build_bin("vfs_open_probe"))
        .arg(&virtual_path_str)
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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

#[test]
fn macos_interpose_preserves_variadic_open_modes() {
    assert_eq!(
        std::env::consts::ARCH,
        "aarch64",
        "native Darwin variadic ABI proof must run on Apple arm64"
    );

    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    let probe = locate_or_build_bin("vfs_open_mode_probe");
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let native_dir = tempfile::tempdir().expect("native probe tempdir");
    let shim_dir = tempfile::tempdir().expect("shim probe tempdir");

    let native = Command::new(&probe)
        .arg(native_dir.path())
        .output()
        .expect("run native libSystem mode probe");
    assert!(
        native.status.success(),
        "native mode probe failed: {}",
        String::from_utf8_lossy(&native.stderr)
    );

    let canary = "kin-vfs-open-mode-arm64";
    let interposed = Command::new(&probe)
        .arg(shim_dir.path())
        // `kin-lane run` intentionally host-cleans child builds with the shim
        // disabled. This child is the explicit interposition proof and must
        // opt back in rather than inheriting that outer safety switch.
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", workspace.path())
        .env("KIN_VFS_CANARY", canary)
        .env("KIN_EXPECT_CANARY", canary)
        .output()
        .expect("run interposed mode probe");
    assert!(
        interposed.status.success(),
        "interposed mode probe failed: {}",
        String::from_utf8_lossy(&interposed.stderr)
    );

    // Darwin masks the sticky bit on regular-file creation, so the 01777
    // request establishes the native mode-mask behavior as 0777.
    let expected = b"open=600,751,777;openat=600,751,777;no-mode=ok\n";
    assert_eq!(native.stdout, expected, "unexpected native mode baseline");
    assert_eq!(
        interposed.stdout, native.stdout,
        "injected open/openat ABI or mode handling diverged from libSystem"
    );
}

#[test]
fn macos_interpose_matches_libsystem_at_argument_matrix() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    assert_eq!(
        std::env::consts::ARCH,
        "aarch64",
        "native *at differential proof must run on Apple arm64"
    );

    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    let probe = locate_or_build_bin("vfs_at_parity_probe");
    let workspace = tempfile::tempdir().expect("parity workspace");
    let workspace_root =
        std::fs::canonicalize(workspace.path()).expect("canonical parity workspace");
    let file = workspace_root.join("file.txt");
    std::fs::write(&file, b"disk-parity\n").expect("write disk-divergent native parity file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
        .expect("set parity permissions");
    symlink("file.txt", workspace_root.join("link.txt")).expect("create parity symlink");
    std::fs::create_dir(workspace_root.join("dir")).expect("create parity directory");
    std::fs::write(workspace_root.join("dir/nested.txt"), b"nested\n")
        .expect("write nested parity file");
    std::fs::create_dir_all(workspace_root.join("dir/deep/sub"))
        .expect("create ordered traversal directories");
    std::fs::write(workspace_root.join("dir/deep/file.txt"), b"ordered\n")
        .expect("write ordered traversal file");
    symlink("deep/sub", workspace_root.join("dir/order-link"))
        .expect("create ordered traversal symlink");
    symlink("../dir/nested.txt", workspace_root.join("dir/bounce-link"))
        .expect("create escaping/re-entering parity symlink");
    symlink("dir", workspace_root.join("dir-link")).expect("create intermediate parity symlink");
    std::fs::write(workspace_root.join("multi.txt"), b"multi\n")
        .expect("write multi-link parity file");
    std::fs::hard_link(
        workspace_root.join("multi.txt"),
        workspace_root.join("multi-alias.txt"),
    )
    .expect("create multi-link alias");
    for (name, mode) in [
        ("readonly.txt", 0o444),
        ("writeonly.txt", 0o222),
        ("noaccess.txt", 0o000),
    ] {
        let path = workspace_root.join(name);
        std::fs::write(&path, b"modes\n").expect("write mode parity file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set mode parity permissions");
    }
    std::fs::write(workspace_root.join("trigger.txt"), b"trigger\n")
        .expect("write state transition trigger");
    std::fs::write(
        workspace_root.join("stateful.bin"),
        vec![b'O'; 64 * 1024 + 1],
    )
    .expect("write stateful identity file");
    assert!(
        !workspace_root.join("graph-only.txt").exists(),
        "graph-only parity entry must not exist on disk"
    );

    let native = Command::new(&probe)
        .arg(&workspace_root)
        .output()
        .expect("run native *at probe");
    assert!(
        native.status.success(),
        "native *at probe failed: {}",
        String::from_utf8_lossy(&native.stderr)
    );

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let (shutdown, server_thread) = start_daemon(NativeParityProvider::default(), &sock_path);
    let canary = "kin-vfs-at-parity-arm64";
    let interposed = Command::new(&probe)
        .arg(&workspace_root)
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_VFS_CANARY", canary)
        .env("KIN_EXPECT_CANARY", canary)
        .env("KIN_EXPECT_GRAPH_OWNED", "1")
        .output()
        .expect("run interposed *at probe");
    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        interposed.status.success(),
        "interposed *at probe failed: {}",
        String::from_utf8_lossy(&interposed.stderr)
    );
    assert_eq!(
        interposed.stdout,
        native.stdout,
        "KinVFS *at path/dirfd/flag/mode/errno behavior diverged from libSystem\n\
         native:\n{}\ninterposed:\n{}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interposed.stdout),
    );
    assert_eq!(
        std::fs::read(&file).expect("read disk-divergent parity file"),
        b"disk-parity\n",
        "the graph-owned differential must not mutate the raw projection"
    );

    let baseline = String::from_utf8(native.stdout).expect("ASCII parity output");
    for required in [
        "openat-invalid-dirfd=err:9",
        "openat-file-dirfd=err:20",
        "openat-empty=err:2",
        "openat-null=err:14",
        "open-nofollow-intermediate=ok",
        "openat-nofollow-intermediate=ok",
        "fstatat-nofollow-intermediate=ok:100000",
        "faccessat-nofollow-intermediate=ok",
        "fstatat-invalid-dirfd-null-buffer=err:9",
        "fstatat-empty-null-buffer=err:2",
        "fstatat-valid-null-buffer=err:14",
        "read-valid-null-buffer=err:14",
        "pread-valid-null-buffer=err:14",
        "stat-valid-null-buffer=err:14",
        "getdirentries-valid-null-buffer=err:14",
        "fstatat-invalid-flag=err:22",
        "fstatat-realdev=ok:100000",
        "fstatat-fdonly=ok:100000",
        "beneath-symlink-parent-order-open=ok",
        "beneath-symlink-parent-order-stat=ok:100000",
        "beneath-symlink-parent-order-access=ok",
        "beneath-symlink-parent-order-plain-open=ok",
        "faccessat-extra-mode-bit=ok",
        "faccessat-all-mode-bits=err:13",
        "faccessat-x-ok=err:13",
    ] {
        assert!(
            baseline.lines().any(|line| line == required),
            "native baseline did not pin expected Darwin behavior: {required}\n{baseline}"
        );
    }
}

#[test]
fn macos_virtual_dirfd_write_fails_after_graph_directory_moves() {
    let Some(shim) = locate_or_build_shim() else {
        eprintln!("SKIP: could not locate or build libkin_vfs_shim.dylib");
        return;
    };
    let probe = locate_or_build_bin("vfs_virtual_dirfd_write_probe");
    let workspace = tempfile::tempdir().expect("virtual-dirfd write workspace");
    let workspace_root =
        std::fs::canonicalize(workspace.path()).expect("canonical write workspace");
    let old_directory = workspace_root.join("renamed-dir");
    let moved_directory = workspace_root.join("moved-dir");
    std::fs::create_dir_all(&old_directory).expect("mkdir old projection directory");
    std::fs::create_dir_all(&moved_directory).expect("mkdir moved projection directory");
    let old_file = old_directory.join("child.txt");
    let moved_file = moved_directory.join("child.txt");
    std::fs::write(&old_file, b"old-path-sentinel\n").expect("write old-path sentinel");
    std::fs::write(&moved_file, b"moved-path-sentinel\n").expect("write moved-path sentinel");

    let kin_dir = workspace_root.join(".kin");
    std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
    let sock_path = kin_dir.join("vfs.sock");
    let (shutdown, server_thread) = start_daemon(NativeParityProvider::default(), &sock_path);
    let canary = "kin-vfs-virtual-dirfd-write";
    let output = Command::new(&probe)
        .arg(&workspace_root)
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .env("DYLD_INSERT_LIBRARIES", &shim)
        .env("KIN_VFS_WORKSPACE", &workspace_root)
        .env("KIN_VFS_SOCK", &sock_path)
        .env("KIN_VFS_CANARY", canary)
        .env("KIN_EXPECT_CANARY", canary)
        .output()
        .expect("run virtual-dirfd write probe");
    shutdown.shutdown();
    let _ = server_thread.join();

    assert!(
        output.status.success(),
        "virtual-dirfd write probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        format!("virtual-dirfd-write=err:{}\n", libc::EOPNOTSUPP).as_bytes()
    );
    assert_eq!(
        std::fs::read(&old_file).expect("read old-path sentinel"),
        b"old-path-sentinel\n",
        "a rejected capability-bound write must not touch the former projection path"
    );
    assert_eq!(
        std::fs::read(&moved_file).expect("read moved-path sentinel"),
        b"moved-path-sentinel\n",
        "a rejected capability-bound write must not redirect into the moved directory"
    );
    assert!(
        [&workspace_root, &old_directory, &moved_directory]
            .into_iter()
            .flat_map(|directory| {
                std::fs::read_dir(directory)
                    .expect("read projection directory")
                    .collect::<Vec<_>>()
            })
            .all(|entry| !entry
                .expect("read entry")
                .file_name()
                .to_string_lossy()
                .contains(".kin_tmp_")),
        "rejection must happen before materialization creates a temp artifact"
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
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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
            .env_remove("KIN_VFS_DISABLE")
            .env_remove("KIN_NO_VFS")
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
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
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
