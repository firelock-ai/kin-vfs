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
        // The expected number of interposed symbols. The C file derives its own
        // length with `sizeof` over the census array generated from
        // `KIN_INTERPOSE_LIST` and `_Static_assert`s it against this value, so
        // adding or dropping a hook without updating this number fails the
        // build rather than shipping a short table.
        // 25 before FIR-2631, plus the seven directory-listing producers
        // (opendir, fdopendir, scandir, glob, ftw, nftw, fts_open).
        const EXPECTED_ENTRIES: usize = 32;

        println!("cargo:rerun-if-changed=src/macos_interpose.c");
        cc::Build::new()
            .file("src/macos_interpose.c")
            // cc-rs enables per-symbol data sections by default. That is not
            // valid for dyld's ordered 16-byte interpose tuples: the Mach-O
            // linker can split and reorder their two pointer fixups.
            .flag("-fno-data-sections")
            .define(
                "KIN_INTERPOSE_EXPECTED",
                EXPECTED_ENTRIES.to_string().as_str(),
            )
            .warnings(true)
            .compile("kin_macos_interpose");
    }
}
