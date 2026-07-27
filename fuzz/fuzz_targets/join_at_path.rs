// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the `openat`/`fstatat` path-join seam.
//!
//! `join_at_path` resolves a possibly-relative path against a base directory.
//! Invariants: an absolute `rel` is authoritative (returned verbatim); a
//! relative `rel` is appended under `base`. It must be total on arbitrary byte
//! sequences, which is the input domain that matters: Unix paths are bytes, and
//! restricting the fuzzer to UTF-8 would never generate the non-UTF8 names this
//! seam exists to carry.

#![no_main]

use kin_vfs_core::pathmap::join_at_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pair: (Vec<u8>, Vec<u8>)| {
    let (base, rel) = pair;
    let joined = join_at_path(&base, &rel);
    if rel.first() == Some(&b'/') {
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
