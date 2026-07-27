// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the synthetic-inode seam.
//!
//! `synthetic_inode` must be total (never panic on any input, including empty
//! and non-UTF8 byte sequences) and deterministic (the same path always hashes
//! to the same inode, because tools rely on a stable `st_ino`). Raw bytes reach
//! the hasher directly; a lossy UTF-8 decode here would collapse every distinct
//! invalid sequence onto U+FFFD and hide exactly the collisions worth finding.

#![no_main]

use kin_vfs_core::pathmap::synthetic_inode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = synthetic_inode(data);
    let second = synthetic_inode(data);
    assert_eq!(first, second, "synthetic_inode must be deterministic");
});
