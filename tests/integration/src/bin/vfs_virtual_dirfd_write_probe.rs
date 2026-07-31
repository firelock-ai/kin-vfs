// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Prove virtual-dirfd writes fail after the graph directory moves and before
//! path-only materialization.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("fixture path contains no NUL")
}

fn main() {
    let Some(root) = std::env::args_os().nth(1) else {
        eprintln!("usage: vfs_virtual_dirfd_write_probe <workspace>");
        std::process::exit(2);
    };
    let root = PathBuf::from(root);
    let directory = c_path(&root.join("renamed-dir"));
    let trigger = c_path(&root.join("trigger.txt"));
    let child = CString::new("child.txt").expect("static child name");

    unsafe {
        let dirfd = libc::open(directory.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if dirfd < 0 {
            eprintln!(
                "open virtual directory failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(3);
        }

        // Reading this graph fixture advances the provider from
        // `renamed-dir` to `moved-dir` while the old virtual descriptor stays
        // open. The write must be rejected before target lookup or staging.
        let trigger_fd = libc::open(trigger.as_ptr(), libc::O_RDONLY);
        if trigger_fd < 0 {
            eprintln!("open trigger failed: {}", std::io::Error::last_os_error());
            std::process::exit(4);
        }
        let mut byte = 0u8;
        if libc::read(trigger_fd, (&mut byte as *mut u8).cast(), 1) != 1 {
            eprintln!("read trigger failed: {}", std::io::Error::last_os_error());
            std::process::exit(5);
        }
        if libc::close(trigger_fd) != 0 {
            eprintln!("close trigger failed: {}", std::io::Error::last_os_error());
            std::process::exit(6);
        }

        let fd = libc::openat(dirfd, child.as_ptr(), libc::O_WRONLY);
        let error = std::io::Error::last_os_error().raw_os_error();
        let close_result = libc::close(dirfd);
        if fd >= 0 {
            libc::close(fd);
            eprintln!("virtual-dirfd write unexpectedly opened");
            std::process::exit(7);
        }
        if close_result != 0 {
            eprintln!(
                "close virtual directory failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(8);
        }
        if error != Some(libc::EOPNOTSUPP) {
            eprintln!("unexpected virtual-dirfd write errno: {error:?}");
            std::process::exit(9);
        }
    }

    println!("virtual-dirfd-write=err:{}", libc::EOPNOTSUPP);
}
