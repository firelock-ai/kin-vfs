// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Child process that reports one verdict per path across every stat-family
//! entry point the Linux shim interposes.
//!
//! Two properties are asserted here rather than in the parent, because only a
//! child running under `LD_PRELOAD` can observe them:
//!
//! 1. Every interposed entry point agrees about a path. `stat`, `lstat`,
//!    `stat64`, `lstat64`, `fstatat`, `statx` and `syscall(SYS_statx, ...)`
//!    must return the same verdict, or a tool's behavior depends on which one
//!    its runtime happens to call. Under FIR-2552 a Python `os.stat` failed
//!    `EIO` while the same path read fine from Node, and the libc entry points
//!    were in fact already unanimous: the split was Node issuing
//!    `syscall(SYS_statx, ...)`, the one route none of them covered (FIR-2572).
//!    That route is covered now, because libuv reaches it through glibc's
//!    `syscall` wrapper rather than through the instruction, so the shim
//!    interposes it like any other symbol. This probe is what keeps all seven
//!    unanimous, and it calls the raw route the way libuv does rather than
//!    trusting that hooking the `statx` symbol was enough.
//! 2. The verdict itself. `ok` for a path that exists, `errno=2` for one that
//!    does not. `errno=5` on either is the FIR-2552 signature: a projection
//!    root the shim owns but the graph cannot answer for.
//!
//! Output is one `<path> <verdict>` line per argument, in argument order.
//! Verdicts are `ok`, `errno=<n>`, or `disagree=<detail>`; a disagreement also
//! makes the process exit non-zero, so a parent cannot miss it by reading only
//! the status.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vfs_stat_family_probe exercises the Linux LD_PRELOAD stat family only");
    std::process::exit(64);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;

    /// What one entry point returned: success, or the errno it set.
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Verdict {
        Ok,
        Errno(i32),
    }

    impl std::fmt::Display for Verdict {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Verdict::Ok => write!(formatter, "ok"),
                Verdict::Errno(errno) => write!(formatter, "errno={errno}"),
            }
        }
    }

    /// Read `errno` for the calling thread.
    fn errno() -> i32 {
        // SAFETY: `__errno_location` returns a valid per-thread pointer.
        unsafe { *libc::__errno_location() }
    }

    /// Classify a raw libc return code into a verdict.
    fn classify(rc: libc::c_int) -> Verdict {
        if rc == 0 {
            Verdict::Ok
        } else {
            Verdict::Errno(errno())
        }
    }

    /// Evaluate every interposed stat-family entry point for one path.
    fn verdicts(path: &CString) -> Vec<(&'static str, Verdict)> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let mut stat64 = std::mem::MaybeUninit::<libc::stat64>::uninit();
        let mut results = Vec::new();

        // SAFETY: `path` is NUL terminated and every call writes only into the
        // buffer passed to it, which is sized for that call's struct.
        unsafe {
            results.push((
                "stat",
                classify(libc::stat(path.as_ptr(), stat.as_mut_ptr())),
            ));
            results.push((
                "lstat",
                classify(libc::lstat(path.as_ptr(), stat.as_mut_ptr())),
            ));
            results.push((
                "stat64",
                classify(libc::stat64(path.as_ptr(), stat64.as_mut_ptr())),
            ));
            results.push((
                "lstat64",
                classify(libc::lstat64(path.as_ptr(), stat64.as_mut_ptr())),
            ));
            results.push((
                "fstatat",
                classify(libc::fstatat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    stat.as_mut_ptr(),
                    0,
                )),
            ));
        }

        // glibc exports `statx` from 2.28. It is the entry point coreutils
        // `stat` uses, and the one whose name appeared in the FIR-2552 report,
        // so it is exercised by name rather than assumed to follow `stat`.
        #[cfg(target_env = "gnu")]
        {
            let mut statx_buf = std::mem::MaybeUninit::<libc::statx>::uninit();
            // SAFETY: same contract as the calls above.
            let rc = unsafe {
                libc::statx(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    statx_buf.as_mut_ptr(),
                )
            };
            results.push(("statx", classify(rc)));
        }

        // FIR-2572. The route Node takes, spelled the way libuv spells it:
        //
        //     syscall(SYS_statx, dirfd, path, flags, mask, statxbuf)
        //
        // Hooking the `statx` symbol above does not cover this one, and for a
        // release this entry point answered from raw disk while the six above
        // failed `EIO`. It is listed last so a regression reads as the raw
        // route disagreeing with the libc consensus, which is the shape the
        // defect actually had.
        #[cfg(target_env = "gnu")]
        {
            let mut statx_buf = std::mem::MaybeUninit::<libc::statx>::uninit();
            // SAFETY: same contract as the calls above. `libc::syscall` is
            // variadic; these are exactly the five arguments `SYS_statx` takes.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_statx,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0,
                    libc::STATX_BASIC_STATS,
                    statx_buf.as_mut_ptr(),
                )
            };
            results.push(("raw_statx", classify(rc as libc::c_int)));
        }

        results
    }

    pub fn run() -> i32 {
        let paths: Vec<String> = std::env::args().skip(1).collect();
        if paths.is_empty() {
            eprintln!("usage: vfs_stat_family_probe <path> [<path>...]");
            return 64;
        }

        let mut exit = 0;
        for path in paths {
            let Ok(c_path) = CString::new(path.clone()) else {
                eprintln!("{path} contains an interior NUL");
                return 64;
            };
            let results = verdicts(&c_path);
            let first = results[0].1;
            let disagreeing: Vec<String> = results
                .iter()
                .filter(|(_, verdict)| *verdict != first)
                .map(|(name, verdict)| format!("{name}={verdict}"))
                .collect();
            if disagreeing.is_empty() {
                println!("{path} {first}");
            } else {
                println!(
                    "{path} disagree={}={},{}",
                    results[0].0,
                    first,
                    disagreeing.join(",")
                );
                exit = 4;
            }
        }
        exit
    }
}
