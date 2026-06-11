// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pure, platform-independent helpers shared by the stat-family fills and the
//! `_FORTIFY_SOURCE` hooks.
//!
//! These are factored out of the OS-gated `platform`/`intercept` modules so the
//! logic that *can* be exercised on any host (mode-bit composition, block
//! counting, the fortify bounds check) is unit-tested on the build host rather
//! than only under Linux CI. The OS-specific struct layouts (`libc::statx`,
//! `libc::stat64`) stay in `platform::linux` where they can only be
//! compile-checked cross-platform and run under Linux CI.

/// Whether a fortified read/readlink request of `requested` bytes fits the
/// caller's `buflen`-sized buffer.
///
/// glibc's `__*_chk` wrappers abort the process when the requested length
/// exceeds the compiler-known buffer length (a real buffer overflow). The shim
/// preserves that contract: when this returns `false`, the hook must delegate to
/// the real `__*_chk` so glibc's abort fires instead of overflowing.
#[inline]
pub fn fortify_within_bounds(requested: usize, buflen: usize) -> bool {
    requested <= buflen
}

/// Conventional 512-byte block count for a file of `size` bytes (rounded up),
/// for the `st_blocks` / `stx_blocks` fields.
#[cfg(not(target_os = "windows"))]
#[inline]
pub fn blocks_for(size: u64) -> u64 {
    size.div_ceil(512)
}

/// Compose the mode word (file-type bits | permission bits) a [`VirtualStat`]
/// should report. Shared by `stat`, `statx`, and the LFS `stat64` fills so they
/// never disagree on the file type. Returned as `u32` so each caller can narrow
/// to its struct's mode width (`mode_t` for stat/stat64, `u16` for statx).
///
/// [`VirtualStat`]: kin_vfs_core::VirtualStat
#[cfg(not(target_os = "windows"))]
#[inline]
// `libc::S_IF*` is `mode_t`, whose width is platform-dependent (u16 on macOS,
// u32 on Linux). The `as u32` widening is necessary on macOS but a no-op on
// Linux; allow the lint rather than fork the expression per platform.
#[allow(clippy::unnecessary_cast)]
pub fn vstat_mode_bits(vstat: &kin_vfs_core::VirtualStat) -> u32 {
    let type_bits: u32 = if vstat.is_file {
        libc::S_IFREG as u32
    } else if vstat.is_dir {
        libc::S_IFDIR as u32
    } else if vstat.is_symlink {
        libc::S_IFLNK as u32
    } else {
        0
    };
    type_bits | vstat.mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortify_bounds_allows_equal_and_smaller() {
        assert!(fortify_within_bounds(0, 0));
        assert!(fortify_within_bounds(10, 10));
        assert!(fortify_within_bounds(4, 8));
    }

    #[test]
    fn fortify_bounds_rejects_overflow() {
        assert!(!fortify_within_bounds(9, 8));
        assert!(!fortify_within_bounds(usize::MAX, 0));
    }

    #[cfg(not(target_os = "windows"))]
    // `libc::S_IF*` is `u16` on macOS (the `as u32` is needed) but `u32` on
    // Linux (where clippy flags it as unnecessary). Mirror the production
    // `vstat_mode_bits` allow rather than fork the asserts per platform.
    #[allow(clippy::unnecessary_cast)]
    mod unix {
        use super::*;
        use kin_vfs_core::VirtualStat;

        fn file_vstat() -> VirtualStat {
            VirtualStat {
                size: 1024,
                is_file: true,
                is_dir: false,
                is_symlink: false,
                mode: 0o644,
                mtime: 1700,
                ctime: 1600,
                nlink: 1,
                content_hash: Some([0u8; 32]),
            }
        }

        #[test]
        fn mode_bits_set_file_type_and_perms() {
            let bits = vstat_mode_bits(&file_vstat());
            assert_eq!(bits & libc::S_IFMT as u32, libc::S_IFREG as u32);
            assert_eq!(bits & 0o777, 0o644);
        }

        #[test]
        fn mode_bits_set_dir_type() {
            let mut v = file_vstat();
            v.is_file = false;
            v.is_dir = true;
            v.mode = 0o755;
            let bits = vstat_mode_bits(&v);
            assert_eq!(bits & libc::S_IFMT as u32, libc::S_IFDIR as u32);
            assert_eq!(bits & 0o777, 0o755);
        }

        #[test]
        fn mode_bits_set_symlink_type() {
            let mut v = file_vstat();
            v.is_file = false;
            v.is_symlink = true;
            let bits = vstat_mode_bits(&v);
            assert_eq!(bits & libc::S_IFMT as u32, libc::S_IFLNK as u32);
        }

        #[test]
        fn statx_mode_round_trips_through_u16() {
            // statx stores the mode in a u16 — ensure no type/perm bits are lost
            // when the fill narrows the value.
            let bits = vstat_mode_bits(&file_vstat());
            assert_eq!(bits as u16 as u32, bits, "mode must round-trip through u16");
        }

        #[test]
        fn blocks_round_up() {
            assert_eq!(blocks_for(0), 0);
            assert_eq!(blocks_for(1), 1);
            assert_eq!(blocks_for(512), 1);
            assert_eq!(blocks_for(513), 2);
        }
    }
}
