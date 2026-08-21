// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Child process for the process-identity exclusion smoke.
//!
//! Reports what the shim decided rather than asserting it, so one binary can
//! serve both directions: the test that proves Kin's own binaries are left
//! alone, and the control that proves everything else is still projected. A
//! probe that asserted its own expectation could only ever fail in one
//! direction, and the direction it could not fail in is the one that says the
//! feature was deleted rather than scoped.
//!
//! `argv[1]` is the path to stat. Output is one line:
//! `argv0=<name>\tinterpose=<sentinel|->\tstat=<ok|errno=N>`.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

fn main() {
    // `args_os`, not `args`: this probe is launched with a deliberately
    // non-UTF-8 `argv[0]` in one case, and `args` would panic on it here
    // instead of reporting what the shim did.
    let argv0 = std::env::args_os()
        .next()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string());

    let interpose = std::env::var(kin_vfs_core::canary::INTERPOSE_ACTIVE_ENV)
        .unwrap_or_else(|_| "-".to_string());

    let path = std::env::args_os()
        .nth(1)
        .expect("usage: vfs_identity_probe <path-to-stat>");
    let path = CString::new(path.as_os_str().as_bytes()).expect("path contains no NUL");

    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    let stat = unsafe {
        if libc::stat(path.as_ptr(), stat_buf.as_mut_ptr()) == 0 {
            "ok".to_string()
        } else {
            format!(
                "errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            )
        }
    };

    println!("argv0={argv0}\tinterpose={interpose}\tstat={stat}");
}
