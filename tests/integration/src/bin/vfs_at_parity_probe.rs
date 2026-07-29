// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Differential probe for native `*at` path, dirfd, flag, mode, and errno
//! behavior. The parent runs the same binary against libc and against the
//! injected KinVFS shim, then compares the complete result stream.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

#[cfg(target_os = "linux")]
extern "C" {
    #[link_name = "__open_2"]
    fn fortified_open_2(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
    #[link_name = "__open64_2"]
    fn fortified_open64_2(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
    #[link_name = "__openat_2"]
    fn fortified_openat_2(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
    ) -> libc::c_int;
    #[link_name = "__openat64_2"]
    fn fortified_openat64_2(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
    ) -> libc::c_int;
}

const INVALID_DIRFD: libc::c_int = 0x3fff_ffff;
const INVALID_AT_FLAG: libc::c_int = 0x0100_0000;
const EXTRA_ACCESS_MODE_BIT: libc::c_int = 0x08;
const ALL_ACCESS_MODE_BITS: libc::c_int = -1;

#[cfg(target_os = "macos")]
const O_RESOLVE_BENEATH_VALUE: libc::c_int = 0x0000_1000;
#[cfg(target_os = "macos")]
const O_UNIQUE_VALUE: libc::c_int = 0x0000_2000;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW_ANY_VALUE: libc::c_int = 0x0800;
#[cfg(target_os = "macos")]
const AT_RESOLVE_BENEATH_VALUE: libc::c_int = 0x2000;
#[cfg(target_os = "macos")]
const AT_UNIQUE_VALUE: libc::c_int = 0x8000;

#[cfg(any(target_os = "linux", target_os = "android"))]
const AT_EMPTY_PATH_VALUE: libc::c_int = libc::AT_EMPTY_PATH;
// Darwin has no AT_EMPTY_PATH. This otherwise-unused bit must be rejected with
// the same EINVAL as libSystem.
#[cfg(target_os = "macos")]
const AT_EMPTY_PATH_VALUE: libc::c_int = 0x1000;

#[inline]
unsafe fn set_errno(value: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        *libc::__errno_location() = value;
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error() = value;
    }
}

#[inline]
unsafe fn errno() -> libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error()
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("probe path contains no NUL")
}

unsafe fn report_fd(label: &str, fd: libc::c_int) {
    if fd >= 0 {
        println!("{label}=ok");
        if libc::close(fd) != 0 {
            eprintln!("close after {label} failed: {}", errno());
            std::process::exit(3);
        }
    } else {
        println!("{label}=err:{}", errno());
    }
}

unsafe fn report_status(label: &str, result: libc::c_int) {
    if result == 0 {
        println!("{label}=ok");
    } else {
        println!("{label}=err:{}", errno());
    }
}

unsafe fn report_stat(label: &str, result: libc::c_int, stat: libc::stat) {
    if result == 0 {
        println!("{label}=ok:{:o}", stat.st_mode as u32 & libc::S_IFMT as u32);
    } else {
        println!("{label}=err:{}", errno());
    }
}

fn fail_extra(message: impl std::fmt::Display) -> ! {
    eprintln!("graph-owned parity assertion failed: {message}");
    std::process::exit(5);
}

unsafe fn expect_errno(label: &str, result: libc::c_int, expected: libc::c_int) {
    let actual = errno();
    if result != -1 || actual != expected {
        fail_extra(format!(
            "{label}: expected -1/{expected}, got {result}/{actual}"
        ));
    }
}

fn expected_vfd_base() -> libc::c_int {
    unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
            && limit.rlim_cur != libc::RLIM_INFINITY
        {
            return (limit.rlim_cur as libc::c_int)
                .saturating_add(1000)
                .max(10_000);
        }
    }
    100_000
}

unsafe fn run_fstatat(
    label: &str,
    dirfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) {
    let mut stat = std::mem::zeroed::<libc::stat>();
    set_errno(0);
    let result = libc::fstatat(dirfd, path, &mut stat, flags);
    report_stat(label, result, stat);
}

unsafe fn run_faccessat(
    label: &str,
    dirfd: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) {
    set_errno(0);
    let result = libc::faccessat(dirfd, path, mode, flags);
    report_status(label, result);
}

fn main() {
    let Some(root) = std::env::args_os().nth(1) else {
        eprintln!("usage: vfs_at_parity_probe <fixture-root>");
        std::process::exit(2);
    };
    let root = Path::new(&root);

    if let Ok(expected) = std::env::var("KIN_EXPECT_CANARY") {
        if std::env::var("KIN_VFS_INTERPOSE_ACTIVE").as_deref() != Ok(expected.as_str()) {
            eprintln!("shim did not stamp the expected interposition canary");
            std::process::exit(4);
        }
    }

    let root_c = c_path(root);

    #[cfg(target_os = "linux")]
    if let Ok(kind) = std::env::var("KIN_FORTIFY_ABORT_KIND") {
        let flags = libc::O_TMPFILE | libc::O_RDWR;
        unsafe {
            match kind.as_str() {
                "open" => {
                    fortified_open_2(root_c.as_ptr(), flags);
                }
                "open64" => {
                    fortified_open64_2(root_c.as_ptr(), flags);
                }
                "openat" => {
                    fortified_openat_2(libc::AT_FDCWD, root_c.as_ptr(), flags);
                }
                "openat64" => {
                    fortified_openat64_2(libc::AT_FDCWD, root_c.as_ptr(), flags);
                }
                _ => fail_extra(format!("unknown fortified abort kind {kind}")),
            }
        }
        fail_extra(format!(
            "fortified {kind} returned instead of enforcing __OPEN_NEEDS_MODE"
        ));
    }

    let file_absolute = c_path(&root.join("file.txt"));
    let nested_absolute = c_path(&root.join("dir-link").join("nested.txt"));
    let file_relative = CString::new("file.txt").expect("static file name");
    let nested_relative =
        CString::new("dir-link/nested.txt").expect("static intermediate-link path");
    let graph_only_relative = CString::new("graph-only.txt").expect("static graph-only name");
    #[cfg(target_os = "macos")]
    let multi_relative = CString::new("multi.txt").expect("static multi-link name");
    #[cfg(target_os = "macos")]
    let dir_relative = CString::new("dir").expect("static directory name");
    #[cfg(target_os = "macos")]
    let beneath_escape_relative =
        CString::new("../dir/nested.txt").expect("static beneath escape path");
    #[cfg(target_os = "macos")]
    let beneath_bounce_relative =
        CString::new("bounce-link").expect("static beneath bounce-link name");
    #[cfg(target_os = "macos")]
    let parent_relative = CString::new("../").expect("static parent path");
    let child_relative = CString::new("child").expect("static child name");
    let link_relative = CString::new("link.txt").expect("static link name");
    #[cfg(target_os = "linux")]
    let dot_relative = CString::new(".").expect("static dot path");
    let empty = CString::new("").expect("empty C string");

    unsafe {
        set_errno(0);
        let rootfd = libc::open(root_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if rootfd < 0 {
            eprintln!("open fixture root failed: {}", errno());
            std::process::exit(3);
        }

        set_errno(0);
        let filefd = libc::openat(rootfd, file_relative.as_ptr(), libc::O_RDONLY);
        if filefd < 0 {
            eprintln!("open fixture file failed: {}", errno());
            std::process::exit(3);
        }

        set_errno(0);
        report_fd("open-empty", libc::open(empty.as_ptr(), libc::O_RDONLY));
        let mut plain_stat = std::mem::zeroed::<libc::stat>();
        set_errno(0);
        report_stat(
            "stat-empty",
            libc::stat(empty.as_ptr(), &mut plain_stat),
            plain_stat,
        );
        plain_stat = std::mem::zeroed();
        set_errno(0);
        report_stat(
            "lstat-empty",
            libc::lstat(empty.as_ptr(), &mut plain_stat),
            plain_stat,
        );
        set_errno(0);
        report_status("access-empty", libc::access(empty.as_ptr(), libc::F_OK));
        let mut link_buf = [0u8; 64];
        set_errno(0);
        let readlink_empty = libc::readlink(
            empty.as_ptr(),
            link_buf.as_mut_ptr().cast::<libc::c_char>(),
            link_buf.len(),
        );
        if readlink_empty < 0 {
            println!("readlink-empty=err:{}", errno());
        } else {
            println!("readlink-empty=ok");
        }

        set_errno(0);
        report_fd(
            "open-nofollow-intermediate",
            libc::open(nested_absolute.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW),
        );
        set_errno(0);
        report_fd(
            "openat-relative",
            libc::openat(rootfd, file_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-nofollow-intermediate",
            libc::openat(
                rootfd,
                nested_relative.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW,
            ),
        );
        set_errno(0);
        report_fd(
            "openat-absolute-ignores-dirfd",
            libc::openat(INVALID_DIRFD, file_absolute.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-invalid-dirfd",
            libc::openat(INVALID_DIRFD, file_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-file-dirfd",
            libc::openat(filefd, child_relative.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-empty",
            libc::openat(rootfd, empty.as_ptr(), libc::O_RDONLY),
        );
        set_errno(0);
        report_fd(
            "openat-null",
            libc::openat(rootfd, ptr::null(), libc::O_RDONLY),
        );

        #[cfg(target_os = "macos")]
        {
            set_errno(0);
            report_fd(
                "openat-invalid-access-mode",
                libc::openat(rootfd, file_relative.as_ptr(), libc::O_ACCMODE),
            );
        }

        run_fstatat("fstatat-relative", rootfd, file_relative.as_ptr(), 0);
        run_fstatat(
            "fstatat-absolute-ignores-dirfd",
            INVALID_DIRFD,
            file_absolute.as_ptr(),
            0,
        );
        run_fstatat(
            "fstatat-invalid-dirfd",
            INVALID_DIRFD,
            file_relative.as_ptr(),
            0,
        );
        run_fstatat("fstatat-file-dirfd", filefd, child_relative.as_ptr(), 0);
        run_fstatat("fstatat-empty", rootfd, empty.as_ptr(), 0);
        run_fstatat("fstatat-null", rootfd, ptr::null(), 0);
        run_fstatat(
            "fstatat-invalid-flag",
            rootfd,
            file_relative.as_ptr(),
            INVALID_AT_FLAG,
        );
        run_fstatat(
            "fstatat-symlink-nofollow",
            rootfd,
            link_relative.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_fstatat(
            "fstatat-nofollow-intermediate",
            rootfd,
            nested_relative.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        );
        set_errno(0);
        report_status(
            "fstatat-invalid-dirfd-null-buffer",
            libc::fstatat(INVALID_DIRFD, file_relative.as_ptr(), ptr::null_mut(), 0),
        );
        set_errno(0);
        report_status(
            "fstatat-empty-null-buffer",
            libc::fstatat(rootfd, empty.as_ptr(), ptr::null_mut(), 0),
        );
        set_errno(0);
        report_status(
            "fstatat-valid-null-buffer",
            libc::fstatat(rootfd, file_relative.as_ptr(), ptr::null_mut(), 0),
        );
        run_fstatat(
            "fstatat-at-empty-path",
            filefd,
            empty.as_ptr(),
            AT_EMPTY_PATH_VALUE,
        );
        run_fstatat(
            "fstatat-eaccess-is-invalid",
            rootfd,
            file_relative.as_ptr(),
            libc::AT_EACCESS,
        );

        run_faccessat(
            "faccessat-f-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat(
            "faccessat-r-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::R_OK,
            0,
        );
        run_faccessat(
            "faccessat-w-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::W_OK,
            0,
        );
        run_faccessat(
            "faccessat-x-ok",
            rootfd,
            file_relative.as_ptr(),
            libc::X_OK,
            0,
        );
        run_faccessat(
            "faccessat-extra-mode-bit",
            rootfd,
            file_relative.as_ptr(),
            EXTRA_ACCESS_MODE_BIT,
            0,
        );
        run_faccessat(
            "faccessat-all-mode-bits",
            rootfd,
            file_relative.as_ptr(),
            ALL_ACCESS_MODE_BITS,
            0,
        );
        run_faccessat(
            "faccessat-invalid-dirfd",
            INVALID_DIRFD,
            file_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat(
            "faccessat-file-dirfd",
            filefd,
            child_relative.as_ptr(),
            libc::F_OK,
            0,
        );
        run_faccessat("faccessat-empty", rootfd, empty.as_ptr(), libc::F_OK, 0);
        run_faccessat("faccessat-null", rootfd, ptr::null(), libc::F_OK, 0);
        run_faccessat(
            "faccessat-invalid-flag",
            rootfd,
            file_relative.as_ptr(),
            libc::F_OK,
            INVALID_AT_FLAG,
        );
        run_faccessat(
            "faccessat-eaccess",
            rootfd,
            file_relative.as_ptr(),
            libc::R_OK | libc::W_OK,
            libc::AT_EACCESS,
        );
        run_faccessat(
            "faccessat-symlink-nofollow",
            rootfd,
            link_relative.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_faccessat(
            "faccessat-nofollow-intermediate",
            rootfd,
            nested_relative.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        );
        run_faccessat(
            "faccessat-at-empty-path",
            filefd,
            empty.as_ptr(),
            libc::R_OK,
            AT_EMPTY_PATH_VALUE,
        );

        #[cfg(target_os = "linux")]
        {
            let mut statx = std::mem::zeroed::<libc::statx>();
            set_errno(0);
            let result = libc::statx(
                rootfd,
                nested_relative.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS,
                &mut statx,
            );
            if result == 0 {
                println!(
                    "statx-nofollow-intermediate=ok:{:o}",
                    statx.stx_mode as u32 & libc::S_IFMT as u32
                );
            } else {
                println!("statx-nofollow-intermediate=err:{}", errno());
            }

            set_errno(0);
            report_status(
                "statx-invalid-dirfd-null-buffer",
                libc::statx(
                    INVALID_DIRFD,
                    file_relative.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
            set_errno(0);
            report_status(
                "statx-empty-null-buffer",
                libc::statx(
                    rootfd,
                    empty.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
            set_errno(0);
            report_status(
                "statx-valid-null-buffer",
                libc::statx(
                    rootfd,
                    file_relative.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    ptr::null_mut(),
                ),
            );
        }

        if std::env::var_os("KIN_EXPECT_GRAPH_OWNED").is_some() {
            let vfd_base = expected_vfd_base();
            if rootfd < vfd_base || filefd < vfd_base {
                fail_extra(format!(
                    "root/file descriptors must be virtual (base {vfd_base}), got {rootfd}/{filefd}"
                ));
            }

            let mut graph_bytes = [0u8; 32];
            set_errno(0);
            let read = libc::read(
                filefd,
                graph_bytes.as_mut_ptr().cast::<libc::c_void>(),
                graph_bytes.len(),
            );
            if read != b"graph-parity\n".len() as isize
                || &graph_bytes[..read.max(0) as usize] != b"graph-parity\n"
            {
                fail_extra(format!(
                    "disk-divergent file did not return graph bytes: read={read}, errno={}",
                    errno()
                ));
            }

            set_errno(0);
            let graph_only = libc::openat(rootfd, graph_only_relative.as_ptr(), libc::O_RDONLY);
            if graph_only < vfd_base {
                fail_extra(format!(
                    "graph-only path did not allocate a virtual fd: fd={graph_only}, errno={}",
                    errno()
                ));
            }
            let mut only_bytes = [0u8; 32];
            let only_read = libc::read(
                graph_only,
                only_bytes.as_mut_ptr().cast::<libc::c_void>(),
                only_bytes.len(),
            );
            if only_read != b"graph-only\n".len() as isize
                || &only_bytes[..only_read.max(0) as usize] != b"graph-only\n"
            {
                fail_extra("graph-only entry was not served by the provider");
            }
            if libc::close(graph_only) != 0 {
                fail_extra(format!("close graph-only fd: {}", errno()));
            }

            #[cfg(target_os = "linux")]
            {
                set_errno(0);
                let check_fd = libc::openat(rootfd, file_relative.as_ptr(), libc::O_ACCMODE);
                if check_fd < vfd_base {
                    fail_extra(format!(
                        "Linux mode-3 check descriptor was not virtual: fd={check_fd}, errno={}",
                        errno()
                    ));
                }
                let mut check_stat = std::mem::zeroed::<libc::stat>();
                if libc::fstat(check_fd, &mut check_stat) != 0 {
                    fail_extra(format!("mode-3 fstat failed: {}", errno()));
                }
                let mut byte = 0u8;
                set_errno(0);
                expect_errno(
                    "mode-3 read",
                    libc::read(check_fd, (&mut byte as *mut u8).cast(), 1) as libc::c_int,
                    libc::EBADF,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 write",
                    libc::write(check_fd, (&byte as *const u8).cast(), 1) as libc::c_int,
                    libc::EBADF,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 lseek",
                    libc::lseek(check_fd, 0, libc::SEEK_SET) as libc::c_int,
                    libc::EBADF,
                );
                if libc::close(check_fd) != 0 {
                    fail_extra(format!("close mode-3 fd: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "mode-3 truncate",
                    libc::openat(
                        rootfd,
                        file_relative.as_ptr(),
                        libc::O_ACCMODE | libc::O_TRUNC,
                    ),
                    libc::EOPNOTSUPP,
                );
                set_errno(0);
                expect_errno(
                    "mode-3 create",
                    libc::openat(
                        rootfd,
                        graph_only_relative.as_ptr(),
                        libc::O_ACCMODE | libc::O_CREAT,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );

                set_errno(0);
                expect_errno(
                    "open O_TMPFILE",
                    libc::open(
                        root_c.as_ptr(),
                        libc::O_TMPFILE | libc::O_RDWR,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );
                set_errno(0);
                expect_errno(
                    "openat O_TMPFILE",
                    libc::openat(
                        rootfd,
                        dot_relative.as_ptr(),
                        libc::O_TMPFILE | libc::O_RDWR,
                        0o600 as libc::mode_t,
                    ),
                    libc::EOPNOTSUPP,
                );
            }

            #[cfg(target_os = "macos")]
            {
                for (label, path, flags) in [
                    (
                        "O_SYMLINK",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_SYMLINK,
                    ),
                    (
                        "O_EXEC",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_EXEC,
                    ),
                    (
                        "O_EVTONLY",
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_EVTONLY,
                    ),
                    ("O_SEARCH", root_c.as_ptr(), libc::O_RDONLY | libc::O_SEARCH),
                ] {
                    set_errno(0);
                    expect_errno(label, libc::open(path, flags), libc::EOPNOTSUPP);
                }

                set_errno(0);
                let guarded = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW_ANY,
                );
                if guarded < vfd_base {
                    fail_extra(format!("O_NOFOLLOW_ANY regular open: {}", errno()));
                }
                libc::close(guarded);
                set_errno(0);
                expect_errno(
                    "O_NOFOLLOW_ANY intermediate",
                    libc::open(
                        nested_absolute.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW_ANY,
                    ),
                    libc::ELOOP,
                );

                set_errno(0);
                let beneath = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                );
                if beneath < vfd_base {
                    fail_extra(format!("O_RESOLVE_BENEATH relative open: {}", errno()));
                }
                libc::close(beneath);
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH absolute",
                    libc::openat(
                        rootfd,
                        file_absolute.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                if libc::chdir(root_c.as_ptr()) != 0 {
                    fail_extra(format!(
                        "chdir graph workspace for plain-open guards: {}",
                        errno()
                    ));
                }
                set_errno(0);
                let plain_beneath = libc::open(
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                );
                if plain_beneath < vfd_base {
                    fail_extra(format!(
                        "plain O_RESOLVE_BENEATH relative open: {}",
                        errno()
                    ));
                }
                libc::close(plain_beneath);
                set_errno(0);
                expect_errno(
                    "plain O_RESOLVE_BENEATH escape",
                    libc::open(
                        parent_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                set_errno(0);
                let dirfd = libc::openat(
                    rootfd,
                    dir_relative.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                );
                if dirfd < vfd_base {
                    fail_extra(format!(
                        "open graph directory for beneath checks: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH direct escape and re-entry",
                    libc::openat(
                        dirfd,
                        beneath_escape_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                set_errno(0);
                expect_errno(
                    "O_RESOLVE_BENEATH symlink escape and re-entry",
                    libc::openat(
                        dirfd,
                        beneath_bounce_relative.as_ptr(),
                        libc::O_RDONLY | O_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                if libc::close(dirfd) != 0 {
                    fail_extra(format!("close graph directory fd: {}", errno()));
                }

                set_errno(0);
                let unique = libc::openat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::O_RDONLY | O_UNIQUE_VALUE,
                );
                if unique < vfd_base {
                    fail_extra(format!("O_UNIQUE single-link open: {}", errno()));
                }
                libc::close(unique);
                set_errno(0);
                expect_errno(
                    "O_UNIQUE multi-link",
                    libc::openat(
                        rootfd,
                        multi_relative.as_ptr(),
                        libc::O_RDONLY | O_UNIQUE_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                set_errno(0);
                expect_errno(
                    "plain O_UNIQUE multi-link",
                    libc::open(multi_relative.as_ptr(), libc::O_RDONLY | O_UNIQUE_VALUE),
                    libc::ENOTCAPABLE,
                );

                let mut guarded_stat = std::mem::zeroed::<libc::stat>();
                if libc::fstatat(
                    rootfd,
                    link_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                ) != 0
                    || guarded_stat.st_mode & libc::S_IFMT != libc::S_IFLNK
                {
                    fail_extra(format!(
                        "AT_SYMLINK_NOFOLLOW_ANY final symlink: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "AT_SYMLINK_NOFOLLOW_ANY intermediate",
                    libc::fstatat(
                        rootfd,
                        nested_relative.as_ptr(),
                        &mut guarded_stat,
                        AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                    ),
                    libc::ELOOP,
                );
                if libc::fstatat(
                    rootfd,
                    file_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_RESOLVE_BENEATH_VALUE,
                ) != 0
                {
                    fail_extra(format!("AT_RESOLVE_BENEATH relative stat: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "AT_RESOLVE_BENEATH absolute",
                    libc::fstatat(
                        rootfd,
                        file_absolute.as_ptr(),
                        &mut guarded_stat,
                        AT_RESOLVE_BENEATH_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );
                if libc::fstatat(
                    rootfd,
                    file_relative.as_ptr(),
                    &mut guarded_stat,
                    AT_UNIQUE_VALUE,
                ) != 0
                {
                    fail_extra(format!("AT_UNIQUE single-link stat: {}", errno()));
                }
                set_errno(0);
                expect_errno(
                    "AT_UNIQUE multi-link",
                    libc::fstatat(
                        rootfd,
                        multi_relative.as_ptr(),
                        &mut guarded_stat,
                        AT_UNIQUE_VALUE,
                    ),
                    libc::ENOTCAPABLE,
                );

                if libc::faccessat(
                    rootfd,
                    link_relative.as_ptr(),
                    libc::F_OK,
                    AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                ) != 0
                {
                    fail_extra(format!(
                        "faccessat AT_SYMLINK_NOFOLLOW_ANY final: {}",
                        errno()
                    ));
                }
                set_errno(0);
                expect_errno(
                    "faccessat AT_SYMLINK_NOFOLLOW_ANY intermediate",
                    libc::faccessat(
                        rootfd,
                        nested_relative.as_ptr(),
                        libc::F_OK,
                        AT_SYMLINK_NOFOLLOW_ANY_VALUE,
                    ),
                    libc::ELOOP,
                );
                if libc::faccessat(
                    rootfd,
                    file_relative.as_ptr(),
                    libc::F_OK,
                    AT_RESOLVE_BENEATH_VALUE | AT_UNIQUE_VALUE,
                ) != 0
                {
                    fail_extra(format!(
                        "faccessat AT_RESOLVE_BENEATH|AT_UNIQUE: {}",
                        errno()
                    ));
                }
            }
        }

        if libc::close(filefd) != 0 || libc::close(rootfd) != 0 {
            eprintln!("closing fixture descriptors failed: {}", errno());
            std::process::exit(3);
        }
    }
}
