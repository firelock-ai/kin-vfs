// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Build script for kin-vfs-shim.
//
// On macOS, compiles `src/macos_interpose.c` into the cdylib. That C TU carries
// the `__DATA,__interpose` table whose `replacee` entries must bind to the real
// libSystem symbols — something a pure-Rust table cannot express, because the
// shim defines the libc hook names itself (see intercept.rs `mod
// macos_interpose`). On every other platform this is a no-op.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "macos" {
        // Must match `macos_interpose::INTERPOSE_ENTRY_COUNT`; the C file
        // `_Static_assert`s its table length against this value so the two can
        // never silently drift.
        const EXPECTED_ENTRIES: usize = 23;

        println!("cargo:rerun-if-changed=src/macos_interpose.c");
        cc::Build::new()
            .file("src/macos_interpose.c")
            .define(
                "KIN_INTERPOSE_EXPECTED",
                EXPECTED_ENTRIES.to_string().as_str(),
            )
            .warnings(true)
            .compile("kin_macos_interpose");
    }
}
