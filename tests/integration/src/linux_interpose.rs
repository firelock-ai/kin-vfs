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
    let server = VfsDaemonServer::new(NativeParityProvider::default(), &sock_for_thread);
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
    std::fs::write(&file, b"disk-parity\n").expect("write disk-divergent parity file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
        .expect("set parity permissions");
    symlink("file.txt", fixture_root.join("link.txt")).expect("create parity symlink");
    symlink("missing-target.txt", fixture_root.join("dangling-link.txt"))
        .expect("create dangling parity symlink");
    for name in ["racy-readlink.txt", "racy-at-cwd.txt", "racy-at-dirfd.txt"] {
        symlink("file.txt", fixture_root.join(name)).expect("create racy parity symlink");
    }
    std::fs::create_dir(fixture_root.join("dir")).expect("create parity directory");
    std::fs::write(fixture_root.join("dir/nested.txt"), b"nested\n")
        .expect("write nested parity file");
    std::fs::create_dir_all(fixture_root.join("dir/deep/sub"))
        .expect("create ordered traversal directories");
    std::fs::write(fixture_root.join("dir/deep/file.txt"), b"ordered\n")
        .expect("write ordered traversal file");
    symlink("deep/sub", fixture_root.join("dir/order-link"))
        .expect("create ordered traversal symlink");
    symlink("../dir/nested.txt", fixture_root.join("dir/bounce-link"))
        .expect("create escaping/re-entering parity symlink");
    symlink("dir", fixture_root.join("dir-link")).expect("create intermediate parity symlink");
    std::fs::create_dir(fixture_root.join("nosearch")).expect("create no-search directory");
    std::fs::write(fixture_root.join("nosearch/child.txt"), b"hidden\n")
        .expect("write no-search child");
    std::fs::set_permissions(
        fixture_root.join("nosearch"),
        std::fs::Permissions::from_mode(0o000),
    )
    .expect("remove directory search permission");
    for (name, mode) in [
        ("create-0555", 0o555),
        ("create-0333", 0o333),
        ("create-0000", 0o000),
    ] {
        let path = fixture_root.join(name);
        std::fs::create_dir(&path).expect("create parent-permission parity directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set parent-permission parity mode");
    }
    std::fs::write(fixture_root.join("multi.txt"), b"multi\n").expect("write multi-link file");
    std::fs::hard_link(
        fixture_root.join("multi.txt"),
        fixture_root.join("multi-alias.txt"),
    )
    .expect("create multi-link alias");
    for (name, mode) in [
        ("readonly.txt", 0o444),
        ("writeonly.txt", 0o222),
        ("noaccess.txt", 0o000),
    ] {
        let path = fixture_root.join(name);
        std::fs::write(&path, b"modes\n").expect("write mode parity file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set mode parity permissions");
    }
    std::fs::write(fixture_root.join("trigger.txt"), b"trigger\n")
        .expect("write state transition trigger");
    std::fs::write(fixture_root.join("stateful.bin"), vec![b'O'; 64 * 1024 + 1])
        .expect("write stateful identity file");
    let mut concurrent = vec![b'A'; 32 * 1024 + 1];
    concurrent.extend(std::iter::repeat_n(b'B', 32 * 1024 + 1));
    std::fs::write(fixture_root.join("concurrent.bin"), concurrent)
        .expect("write concurrent-read parity file");
    assert!(
        !fixture_root.join("graph-only.txt").exists(),
        "graph-only parity entry must not exist on disk"
    );

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
    // The interposed run gets permissive raw projection directories. Matching
    // the native 0555/0333/0000 result therefore requires graph-parent
    // W_OK|X_OK authority rather than a host-filesystem accident.
    for name in ["create-0555", "create-0333", "create-0000"] {
        std::fs::set_permissions(
            fixture_root.join(name),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("make raw create parent permissive before graph-owned run");
    }

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
        .env("KIN_EXPECT_GRAPH_OWNED", "1")
        .env_remove("KIN_VFS_DISABLE")
        .env_remove("KIN_NO_VFS")
        .output()
        .expect("run preloaded Linux *at probe");

    use std::os::unix::process::ExitStatusExt;
    for kind in ["open", "open64", "openat", "openat64"] {
        let fortified = Command::new(&probe)
            .arg(&fixture_root)
            .env("LD_PRELOAD", &shim)
            .env("KIN_VFS_WORKSPACE", &fixture_root)
            .env("KIN_VFS_SOCK", &sock_path)
            .env("KIN_VFS_CANARY", canary)
            .env("KIN_EXPECT_CANARY", canary)
            .env("KIN_FORTIFY_ABORT_KIND", kind)
            .env_remove("KIN_VFS_DISABLE")
            .env_remove("KIN_NO_VFS")
            .output()
            .unwrap_or_else(|error| panic!("run fortified {kind} probe: {error}"));
        assert_eq!(
            fortified.status.signal(),
            Some(libc::SIGABRT),
            "fortified {kind} must preserve glibc __OPEN_NEEDS_MODE abort for O_TMPFILE; \
             status={:?}, stderr={}",
            fortified.status,
            String::from_utf8_lossy(&fortified.stderr)
        );
    }

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
    assert_eq!(
        std::fs::read(&file).expect("read disk-divergent parity file after mode-3 open"),
        b"disk-parity\n",
        "Linux access-mode 3 must not materialize graph bytes onto disk"
    );
    assert!(
        std::fs::read_dir(&fixture_root)
            .expect("read parity fixture")
            .all(|entry| !entry
                .expect("parity entry")
                .file_name()
                .to_string_lossy()
                .contains(".kin_tmp_")),
        "Linux access-mode 3 must not leave a materialization temp artifact"
    );
    std::fs::set_permissions(
        fixture_root.join("nosearch"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("restore no-search directory for tempdir cleanup");
    for name in ["create-0555", "create-0333", "create-0000"] {
        std::fs::set_permissions(
            fixture_root.join(name),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("restore create parent for tempdir cleanup");
    }

    let baseline = String::from_utf8(native.stdout).expect("ASCII parity output");
    for required in [
        "readlink-snapshot-race=ok:file.txt",
        "readlinkat-cwd-snapshot-race=ok:file.txt",
        "readlinkat-real-dirfd-snapshot-race=ok:file.txt",
        "open-readonly-rdonly=ok",
        "open-readonly-wronly=err:13",
        "open-writeonly-rdonly=err:13",
        "open-writeonly-wronly=ok",
        "open-noaccess-rdonly=err:13",
        "openat-noaccess-rdwr=err:13",
        "open-directory-wronly=err:21",
        "openat-directory-rdwr=err:21",
        "open-no-search-child=err:13",
        "openat-no-search-child=err:13",
        "open-dangling-exclusive-symlink=err:17",
        "openat-dangling-exclusive-symlink-nofollow=err:17",
        "open-create-parent-0555=err:13",
        "open-create-parent-0333=ok",
        "open-create-parent-0000=err:13",
        "open-create-exclusive-parent-0555=err:13",
        "open-create-exclusive-parent-0333=ok",
        "open-create-exclusive-parent-0000=err:13",
        "openat-create-parent-0555=err:13",
        "openat-create-parent-0333=ok",
        "openat-create-parent-0000=err:13",
        "openat-create-exclusive-parent-0555=err:13",
        "openat-create-exclusive-parent-0333=ok",
        "openat-create-exclusive-parent-0000=err:13",
        "dup-shared-offset=ok",
        "lseek-cur-overflow-preserves-offset=ok",
        "lseek-end-overflow-preserves-offset=ok",
        "dup2-native-target=ok",
        "fcntl-low-getfl=ok",
        "fcntl-low-dupfd-graph-bytes=ok",
        "dup3-native-target=ok",
        "fcntl-getfl=ok",
        "fcntl-dupfd-shared-offset=ok",
        "fcntl-dupfd-cloexec=ok",
        "fork-low-fd-shared-offset=ok",
        "exec-low-fd-graph-bytes=ok",
        "concurrent-uncached-shared-offset=ok",
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
        "getdents64-valid-null-buffer=err:14",
        "readlink-valid-zero-size=err:22",
        "readlinkat-valid-zero-size=err:22",
        "mode3-readonly=err:13",
        "mode3-writeonly=err:13",
        "mode3-noaccess=err:13",
        "mode3-directory=err:21",
        "opath-file=ok",
        "opath-getfl=ok",
        "opath-fstat=ok:100000",
        "opath-read=err:9",
        "opath-pread=err:9",
        "opath-lseek=err:9",
        "opath-flock=err:9",
        "opath-mmap=err:9",
        "opath-trunc-ignored=ok",
        "opath-mode3-ignored=ok",
        "opath-create-ignored=err:2",
        "opath-tmpfile-open-directory=ok",
        "opath-tmpfile-open-file=err:20",
        "opath-tmpfile-open64-directory=ok",
        "opath-tmpfile-open64-file=err:20",
        "opath-tmpfile-openat-directory=ok",
        "opath-tmpfile-openat-file=err:20",
        "opath-tmpfile-openat64-directory=ok",
        "opath-tmpfile-openat64-file=err:20",
        "mode3-directory-readable=err:20",
        "mode3-directory-writeonly=err:20",
        "mode3-directory-noaccess=err:20",
        "mode3-directory-directory=err:21",
        "opath-directory=ok",
        "opath-getdents64=err:9",
        "opath-symlink=ok",
        "opath-readlinkat-empty=ok:8",
        "statx-nofollow-intermediate=ok:100000",
        "statx-invalid-dirfd-null-buffer=err:9",
        "statx-empty-null-buffer=err:2",
        "statx-valid-null-buffer=err:14",
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
