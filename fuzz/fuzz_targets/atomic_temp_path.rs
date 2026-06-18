// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fuzz the materialize-on-write temp-path seam.
//!
//! `atomic_temp_path` builds the `{target}.kin_tmp_{pid}` path the shim writes
//! graph truth into before a tool's write, renamed onto the target on close.
//! The safety-critical invariant: every path it produces MUST be recognized by
//! `is_interpose_temp_artifact`, because `is_workspace_path` uses that predicate
//! to exclude these temps from interception. If the two ever drift apart, a
//! materialize temp would be re-intercepted and the shim would re-enter the
//! daemon (the re-entrancy the exclusion exists to prevent).

#![no_main]

use kin_vfs_core::pathmap::{atomic_temp_path, is_interpose_temp_artifact};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pair: (String, i32)| {
    let (target, pid) = pair;
    let tmp = atomic_temp_path(&target, pid);
    assert!(
        is_interpose_temp_artifact(&tmp),
        "every atomic temp path must be excluded from interception"
    );
});
