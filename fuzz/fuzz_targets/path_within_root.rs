// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the workspace-containment seam, the security boundary that decides
//! whether a path is eligible for graph-backed interception.
//!
//! The invariant under test is the one an attacker would try to break: if
//! `path_within_root` reports containment, the prefix-with-separator-guard
//! contract MUST actually hold (no sibling-prefix escape, no out-of-bounds
//! index on a multibyte boundary). Any future "optimization" that violates this
//! is a workspace-escape bug, and the fuzzer will trip the assert. Inputs are
//! raw bytes because that is what the boundary receives; a UTF-8-only fuzzer
//! could never reach the non-UTF8 names an escape attempt would use.

#![no_main]

use kin_vfs_core::pathmap::path_within_root;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pair: (Vec<u8>, Vec<u8>)| {
    let (path, root) = pair;
    if path_within_root(&path, &root) {
        // Containment must imply the documented contract.
        assert!(
            path.len() >= root.len(),
            "contained path cannot be shorter than its root"
        );
        assert!(
            path.starts_with(&root),
            "contained path must start with root"
        );
        assert!(
            path.len() == root.len() || path.get(root.len()) == Some(&b'/'),
            "containment must respect the `/` boundary (no sibling-prefix escape)"
        );
    }
});
