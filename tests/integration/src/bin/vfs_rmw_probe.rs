// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Helper for the stale-disk materialize test (FIR-950).
//!
//! Opens `argv[1]` for READ-WRITE *without* truncation (the read-modify-write
//! pattern an editor or formatter uses), then reads the current bytes and
//! writes them to stdout. Under the shim this triggers materialize-on-write,
//! which must seed the file from graph truth — so a stale on-disk copy must NOT
//! be what comes back. Uses raw libc `open(O_RDWR)` so the materialize path
//! (not the read-only virtual path) is exercised.
//!
//! Exit codes: 0 ok, 2 bad args, 3 open failed, 4 read failed.

use std::ffi::CString;
use std::io::Write;
use std::os::raw::c_int;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: vfs_rmw_probe <path>");
        std::process::exit(2);
    };

    let c_path = CString::new(path.as_str()).expect("path has no NUL");

    // O_RDWR (no O_CREAT, no O_TRUNC): read-modify-write of an existing file.
    let fd: c_int = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        eprintln!("open failed for {path}");
        std::process::exit(3);
    }

    let mut buf = [0u8; 64 * 1024];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe {
        libc::close(fd);
    }
    if n < 0 {
        eprintln!("read failed for {path}");
        std::process::exit(4);
    }

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(&buf[..n as usize]);
    let _ = lock.flush();
}
