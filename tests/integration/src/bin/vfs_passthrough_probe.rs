// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Child process for the Linux `LD_PRELOAD` stat-family passthrough smoke.

use std::ffi::CString;

fn fail(operation: &str) -> ! {
    eprintln!("{operation} failed: {}", std::io::Error::last_os_error());
    std::process::exit(3);
}

fn main() {
    let expected = std::env::var("KIN_EXPECT_INTERPOSE_ACTIVE")
        .expect("KIN_EXPECT_INTERPOSE_ACTIVE must be set by the parent test");
    if std::env::var("KIN_VFS_INTERPOSE_ACTIVE").as_deref() != Ok(expected.as_str()) {
        eprintln!("shim constructor did not stamp the expected active sentinel");
        std::process::exit(2);
    }

    let path = std::env::args()
        .nth(1)
        .expect("usage: vfs_passthrough_probe <outside-workspace-path>");
    let path = CString::new(path).expect("path contains no NUL");
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();

    unsafe {
        if libc::fstat(libc::STDOUT_FILENO, stat_buf.as_mut_ptr()) != 0 {
            fail("fstat(stdout)");
        }
        if libc::stat(path.as_ptr(), stat_buf.as_mut_ptr()) != 0 {
            fail("stat(outside workspace)");
        }
        if libc::lstat(path.as_ptr(), stat_buf.as_mut_ptr()) != 0 {
            fail("lstat(outside workspace)");
        }
    }

    println!("passthrough-ok");
}
