// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Differential probe for native `*at` path, dirfd, flag, mode, and errno
//! behavior. The parent runs the same binary against libc and against the
//! injected KinVFS shim, then compares the complete result stream.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

const INVALID_DIRFD: libc::c_int = 0x3fff_ffff;
const INVALID_AT_FLAG: libc::c_int = 0x0100_0000;
const EXTRA_ACCESS_MODE_BIT: libc::c_int = 0x08;
const ALL_ACCESS_MODE_BITS: libc::c_int = -1;

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
    let file_absolute = c_path(&root.join("file.txt"));
    let file_relative = CString::new("file.txt").expect("static file name");
    let child_relative = CString::new("child").expect("static child name");
    let link_relative = CString::new("link.txt").expect("static link name");
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
        report_fd(
            "openat-relative",
            libc::openat(rootfd, file_relative.as_ptr(), libc::O_RDONLY),
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
            "faccessat-at-empty-path",
            filefd,
            empty.as_ptr(),
            libc::R_OK,
            AT_EMPTY_PATH_VALUE,
        );

        if libc::close(filefd) != 0 || libc::close(rootfd) != 0 {
            eprintln!("closing fixture descriptors failed: {}", errno());
            std::process::exit(3);
        }
    }
}
