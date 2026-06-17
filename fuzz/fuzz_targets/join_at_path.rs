// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the `openat`/`fstatat` path-join seam.
//!
//! `join_at_path` resolves a possibly-relative path against a base directory.
//! Invariants: an absolute `rel` is authoritative (returned verbatim); a
//! relative `rel` is appended under `base`. It must be total on arbitrary
//! strings (NUL-free is not assumed — these are Rust `String`s, not C strings).

#![no_main]

use kin_vfs_core::pathmap::join_at_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pair: (String, String)| {
    let (base, rel) = pair;
    let joined = join_at_path(&base, &rel);
    if rel.starts_with('/') {
        assert_eq!(joined, rel, "an absolute rel must be returned unchanged");
    } else {
        assert!(
            joined.starts_with(&base),
            "a relative join must start with the base directory"
        );
        assert!(
            joined.ends_with(&rel),
            "a relative join must preserve the rel suffix"
        );
    }
});
