// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the synthetic-inode seam.
//!
//! `synthetic_inode` must be total (never panic on any input, including empty
//! and multibyte strings) and deterministic (the same path always hashes to the
//! same inode — tools rely on a stable `st_ino`). Arbitrary bytes are decoded
//! with lossy UTF-8 so the full byte space reaches the hasher.

#![no_main]

use kin_vfs_core::pathmap::synthetic_inode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let first = synthetic_inode(&s);
    let second = synthetic_inode(&s);
    assert_eq!(first, second, "synthetic_inode must be deterministic");
});
