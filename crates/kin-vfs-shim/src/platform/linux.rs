// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Linux-specific stat helpers.
//!
//! On Linux, glibc uses versioned stat functions (`__xstat`, `__fxstat`,
//! `__lxstat`) with a `ver` parameter. We also handle the direct `stat`/
//! `fstat`/`lstat` symbols used by musl and newer glibc, the Large-File-Support
//! `stat64` family, and the modern `statx(2)` struct used by current coreutils.
//! Every stat-family fill shares [`vstat_mode_bits`](crate::statfill::vstat_mode_bits)
//! so they agree on the type/permission bits.

use kin_vfs_core::VirtualStat;

use crate::statfill::{blocks_for, vstat_mode_bits};

/// Synthetic inode/device markers shared by every stat-family fill. The shim
/// does not own real inodes; callers that key on inode identity get a stable,
/// obviously-synthetic value (per-path inodes are layered on at the call site).
const SYNTHETIC_INO: u64 = 0xBAD_F00D;
const SYNTHETIC_DEV: u64 = 0xFF;
const BLKSIZE: i64 = 4096;

/// Fill a libc `stat` struct from a `VirtualStat`.
///
/// # Safety
/// `buf` must point to a valid, writable `libc::stat` struct.
pub unsafe fn fill_stat_buf(vstat: &VirtualStat, buf: *mut libc::stat) {
    // Zero the struct first.
    std::ptr::write_bytes(buf, 0, 1);

    let s = &mut *buf;
    s.st_size = vstat.size as libc::off_t;
    s.st_nlink = vstat.nlink as libc::nlink_t;
    s.st_mode = vstat_mode_bits(vstat) as libc::mode_t;

    // Timestamps.
    s.st_mtime = vstat.mtime as libc::time_t;
    s.st_ctime = vstat.ctime as libc::time_t;
    s.st_atime = vstat.mtime as libc::time_t;

    // Block size and blocks (conventional values).
    s.st_blksize = BLKSIZE as libc::blksize_t;
    s.st_blocks = blocks_for(vstat.size) as libc::blkcnt_t;

    // Use a synthetic inode and device.
    s.st_ino = SYNTHETIC_INO;
    s.st_dev = SYNTHETIC_DEV;
    s.st_uid = libc::getuid();
    s.st_gid = libc::getgid();
}

/// Fill a libc `stat64` (Large File Support) struct from a `VirtualStat`.
///
/// Binaries compiled with `_FILE_OFFSET_BITS=64` (or that call `stat64`
/// directly) use this struct; without the hook they would silently see the real
/// disk. Mirrors [`fill_stat_buf`] field-for-field with the 64-bit offset types.
///
/// # Safety
/// `buf` must point to a valid, writable `libc::stat64` struct.
pub unsafe fn fill_stat64_buf(vstat: &VirtualStat, buf: *mut libc::stat64) {
    std::ptr::write_bytes(buf, 0, 1);

    let s = &mut *buf;
    s.st_size = vstat.size as libc::off64_t;
    s.st_nlink = vstat.nlink as libc::nlink_t;
    s.st_mode = vstat_mode_bits(vstat) as libc::mode_t;

    s.st_mtime = vstat.mtime as libc::time_t;
    s.st_ctime = vstat.ctime as libc::time_t;
    s.st_atime = vstat.mtime as libc::time_t;

    s.st_blksize = BLKSIZE as libc::blksize_t;
    s.st_blocks = blocks_for(vstat.size) as libc::blkcnt64_t;

    s.st_ino = SYNTHETIC_INO;
    s.st_dev = SYNTHETIC_DEV;
    s.st_uid = libc::getuid();
    s.st_gid = libc::getgid();
}

/// Fill a libc `statx` struct from a `VirtualStat`.
///
/// `statx(2)` is the syscall modern coreutils (`ls`, `stat`, `cp`, …) reach for
/// in place of `stat`/`lstat`/`fstat`; without this hook those tools bypass the
/// projection entirely. We advertise exactly the basic fields we populate via
/// `stx_mask` so callers know which fields are trustworthy — we never claim
/// fields (btime, mount id, dio alignment) we cannot derive.
///
/// # Safety
/// `buf` must point to a valid, writable `libc::statx` struct.
pub unsafe fn fill_statx_buf(vstat: &VirtualStat, buf: *mut libc::statx) {
    std::ptr::write_bytes(buf, 0, 1);

    let s = &mut *buf;
    // Only the STATX_BASIC_STATS set is populated; leave the extended bits clear.
    s.stx_mask = libc::STATX_BASIC_STATS;
    s.stx_blksize = BLKSIZE as u32;
    s.stx_nlink = vstat.nlink as u32;
    s.stx_uid = libc::getuid();
    s.stx_gid = libc::getgid();
    s.stx_mode = vstat_mode_bits(vstat) as u16;
    s.stx_ino = SYNTHETIC_INO;
    s.stx_size = vstat.size;
    s.stx_blocks = blocks_for(vstat.size);

    // Timestamps (nsec stays zero; the struct was zeroed above).
    s.stx_mtime.tv_sec = vstat.mtime as i64;
    s.stx_atime.tv_sec = vstat.mtime as i64;
    s.stx_ctime.tv_sec = vstat.ctime as i64;

    // Synthetic device numbers (split major/minor in the statx layout).
    s.stx_dev_major = 0;
    s.stx_dev_minor = SYNTHETIC_DEV as u32;
}
