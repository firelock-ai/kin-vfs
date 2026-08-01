// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reads one workspace file through several libc surfaces and reports what each
//! one returned.
//!
//! The interposition table covers a fixed symbol roster. A tool that reaches a
//! workspace file through a symbol outside that roster gets raw disk with no
//! error, which is the failure the canary exists to catch. This probe names each
//! surface it used so a test can tell graph bytes from disk bytes per surface
//! instead of concluding "interposition works" from one lucky entry point.
//!
//! `argv[1]` is the path to read, spelled exactly as the caller wants it tested
//! (relative spellings are resolved against the probe's working directory).
//! Every surface prints one `name<TAB>status<TAB>payload` line; the payload is
//! the bytes read, or the errno name, so no surface can fail silently.

use std::ffi::CString;
use std::io::Write;

/// Report one surface's outcome on stdout.
fn report(name: &str, status: &str, payload: &[u8]) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = write!(lock, "{name}\t{status}\t");
    let _ = lock.write_all(payload);
    let _ = writeln!(lock);
    let _ = lock.flush();
}

fn errno_payload() -> Vec<u8> {
    let errno = std::io::Error::last_os_error();
    format!("errno={}", errno.raw_os_error().unwrap_or(-1)).into_bytes()
}

/// `std::fs::read`, which lowers to the interposed `open`/`read`/`close`.
fn probe_std_fs(path: &str) {
    match std::fs::read(path) {
        Ok(bytes) => report("std_fs_read", "ok", &bytes),
        Err(error) => report(
            "std_fs_read",
            "err",
            format!("errno={}", error.raw_os_error().unwrap_or(-1)).as_bytes(),
        ),
    }
}

/// Raw `open` + `read`, the surface the interpose table names directly.
fn probe_libc_open(path: &CString) {
    // SAFETY: `path` is NUL terminated; the buffer is sized for the read.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            report("libc_open", "err", &errno_payload());
            return;
        }
        let mut buf = vec![0u8; 4096];
        let read = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        libc::close(fd);
        if read < 0 {
            report("libc_open", "err", &errno_payload());
            return;
        }
        buf.truncate(read as usize);
        report("libc_open", "ok", &buf);
    }
}

/// `fopen`, the stdio surface. libSystem resolves its own internal `open`, so a
/// caller that never names `open` itself can slip past a table keyed on it.
fn probe_fopen(path: &CString) {
    let mode = CString::new("rb").expect("mode literal has no NUL");
    // SAFETY: both pointers are NUL terminated; `fread` writes at most `buf`.
    unsafe {
        let handle = libc::fopen(path.as_ptr(), mode.as_ptr());
        if handle.is_null() {
            report("fopen", "err", &errno_payload());
            return;
        }
        let mut buf = vec![0u8; 4096];
        let read = libc::fread(buf.as_mut_ptr() as *mut libc::c_void, 1, buf.len(), handle);
        libc::fclose(handle);
        buf.truncate(read);
        report("fopen", "ok", &buf);
    }
}

/// `stat`, reported as the size the caller would size a buffer from.
fn probe_stat(path: &CString) {
    // SAFETY: `path` is NUL terminated and `stat` is sized for the write.
    unsafe {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if libc::stat(path.as_ptr(), stat.as_mut_ptr()) != 0 {
            report("stat", "err", &errno_payload());
            return;
        }
        let stat = stat.assume_init();
        report("stat", "ok", format!("size={}", stat.st_size).as_bytes());
    }
}

/// `realpath`, which resolves a path without the caller naming `open` at all.
fn probe_realpath(path: &CString) {
    // SAFETY: `path` is NUL terminated; `buf` is the PATH_MAX buffer realpath
    // requires.
    unsafe {
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let resolved = libc::realpath(path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char);
        if resolved.is_null() {
            report("realpath", "err", &errno_payload());
            return;
        }
        let resolved = std::ffi::CStr::from_ptr(resolved).to_bytes().to_vec();
        report("realpath", "ok", &resolved);
    }
}

/// `opendir`/`readdir` over the parent, listing the names a tool would walk.
fn probe_readdir(dir: &CString) {
    // SAFETY: `dir` is NUL terminated; each `readdir` result is read before the
    // next call and the stream is closed exactly once.
    unsafe {
        let handle = libc::opendir(dir.as_ptr());
        if handle.is_null() {
            report("readdir", "err", &errno_payload());
            return;
        }
        let mut names: Vec<u8> = Vec::new();
        loop {
            let entry = libc::readdir(handle);
            if entry.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if !names.is_empty() {
                names.push(b',');
            }
            names.extend_from_slice(name);
        }
        libc::closedir(handle);
        report("readdir", "ok", &names);
    }
}

fn main() {
    let mut args = std::env::args();
    let _argv0 = args.next();
    let Some(path) = args.next() else {
        eprintln!("usage: vfs_surface_probe <path> [dir]");
        std::process::exit(2);
    };
    let dir = args.next().unwrap_or_else(|| ".".to_string());

    let c_path = CString::new(path.clone()).expect("path argument has no interior NUL");
    let c_dir = CString::new(dir).expect("dir argument has no interior NUL");

    probe_std_fs(&path);
    probe_libc_open(&c_path);
    probe_fopen(&c_path);
    probe_stat(&c_path);
    probe_realpath(&c_path);
    probe_readdir(&c_dir);
}
