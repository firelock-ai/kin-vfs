// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Tiny helper for the macOS interposition smoke test.
//!
//! Reads the file named by `argv[1]` with plain `std::fs` (which lowers to the
//! libc `open`/`fstat`/`read`/`close` symbols the shim interposes) and writes
//! the raw bytes to stdout. The test launches this under
//! `DYLD_INSERT_LIBRARIES=<shim>` and asserts it receives graph content for a
//! path that does NOT exist on disk — which can only happen if the shim's
//! interpose table actually routed the libc calls through the daemon.
//!
//! Exit codes: 0 = read ok, 2 = bad args, 3 = read error (printed to stderr).

use std::io::Write;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: vfs_open_probe <path>");
        std::process::exit(2);
    };

    match std::fs::read(&path) {
        Ok(bytes) => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let _ = lock.write_all(&bytes);
            let _ = lock.flush();
        }
        Err(e) => {
            eprintln!("read error for {path}: {e}");
            std::process::exit(3);
        }
    }
}
