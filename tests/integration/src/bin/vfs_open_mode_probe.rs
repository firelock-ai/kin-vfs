// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Native `open`/`openat` ABI and creation-mode probe.
//!
//! The integration test runs this binary once against plain libSystem and once
//! with the KinVFS dylib injected. Calls without `O_CREAT` deliberately omit
//! the variadic mode argument; creation calls exercise several exact modes
//! under `umask(0)`.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn fail(operation: &str) -> ! {
    eprintln!("{operation} failed: {}", std::io::Error::last_os_error());
    std::process::exit(3);
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("probe path contains no NUL")
}

unsafe fn created_mode_with_open(path: &Path, requested: u32) -> u32 {
    let path = c_path(path);
    let fd = libc::open(
        path.as_ptr(),
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        requested as libc::c_uint,
    );
    if fd < 0 {
        fail("open(O_CREAT)");
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if libc::fstat(fd, stat.as_mut_ptr()) != 0 {
        fail("fstat(open)");
    }
    if libc::close(fd) != 0 {
        fail("close(open)");
    }
    stat.assume_init().st_mode as u32 & 0o7777
}

unsafe fn created_mode_with_openat(dirfd: libc::c_int, name: &str, requested: u32) -> u32 {
    let name = CString::new(name).expect("probe name contains no NUL");
    let fd = libc::openat(
        dirfd,
        name.as_ptr(),
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        requested as libc::c_uint,
    );
    if fd < 0 {
        fail("openat(O_CREAT)");
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if libc::fstat(fd, stat.as_mut_ptr()) != 0 {
        fail("fstat(openat)");
    }
    if libc::close(fd) != 0 {
        fail("close(openat)");
    }
    stat.assume_init().st_mode as u32 & 0o7777
}

fn main() {
    let Some(directory) = std::env::args_os().nth(1) else {
        eprintln!("usage: vfs_open_mode_probe <directory>");
        std::process::exit(2);
    };
    let directory = Path::new(&directory);

    if let Ok(expected) = std::env::var("KIN_EXPECT_CANARY") {
        if std::env::var("KIN_VFS_INTERPOSE_ACTIVE").as_deref() != Ok(expected.as_str()) {
            eprintln!("shim did not stamp the expected interposition canary");
            std::process::exit(4);
        }
    }

    let old_umask = unsafe { libc::umask(0) };

    let directory_c = c_path(directory);
    // No optional mode is supplied here. These calls are the arm64 ABI
    // regression controls for the non-O_CREAT case.
    let dirfd = unsafe { libc::open(directory_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if dirfd < 0 {
        fail("open(directory without mode)");
    }

    let seed = directory.join("seed.txt");
    std::fs::write(&seed, b"seed").expect("write seed");
    let seed_c = c_path(&seed);
    let read_fd = unsafe { libc::open(seed_c.as_ptr(), libc::O_RDONLY) };
    if read_fd < 0 {
        eprintln!(
            "probe directory={} workspace={:?}",
            directory.display(),
            std::env::var_os("KIN_VFS_WORKSPACE")
        );
        fail("open(file without mode)");
    }
    if unsafe { libc::close(read_fd) } != 0 {
        fail("close(read-only open)");
    }
    let seed_name = CString::new("seed.txt").expect("static name");
    let readat_fd = unsafe { libc::openat(dirfd, seed_name.as_ptr(), libc::O_RDONLY) };
    if readat_fd < 0 {
        fail("openat(file without mode)");
    }
    if unsafe { libc::close(readat_fd) } != 0 {
        fail("close(read-only openat)");
    }

    let requested = [0o600u32, 0o751, 0o1777];
    let open_modes = requested.map(|mode| unsafe {
        created_mode_with_open(&directory.join(format!("open-{mode:o}")), mode)
    });
    let openat_modes = requested
        .map(|mode| unsafe { created_mode_with_openat(dirfd, &format!("openat-{mode:o}"), mode) });

    if unsafe { libc::close(dirfd) } != 0 {
        fail("close(directory)");
    }
    unsafe {
        libc::umask(old_umask);
    }

    println!(
        "open={:o},{:o},{:o};openat={:o},{:o},{:o};no-mode=ok",
        open_modes[0],
        open_modes[1],
        open_modes[2],
        openat_modes[0],
        openat_modes[1],
        openat_modes[2],
    );
}
