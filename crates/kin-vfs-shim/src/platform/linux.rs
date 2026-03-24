// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Linux-specific stat helpers.
//!
//! On Linux, glibc uses versioned stat functions (`__xstat`, `__fxstat`,
//! `__lxstat`) with a `ver` parameter. We also handle the direct `stat`/
//! `fstat`/`lstat` symbols used by musl and newer glibc.

use kin_vfs_core::VirtualStat;

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

    // Mode: file type bits + permission bits.
    if vstat.is_file {
        s.st_mode = libc::S_IFREG | (vstat.mode as libc::mode_t);
    } else if vstat.is_dir {
        s.st_mode = libc::S_IFDIR | (vstat.mode as libc::mode_t);
    } else if vstat.is_symlink {
        s.st_mode = libc::S_IFLNK | (vstat.mode as libc::mode_t);
    }

    // Timestamps.
    s.st_mtime = vstat.mtime as libc::time_t;
    s.st_ctime = vstat.ctime as libc::time_t;
    s.st_atime = vstat.mtime as libc::time_t;

    // Block size and blocks (conventional values).
    s.st_blksize = 4096;
    s.st_blocks = ((vstat.size + 511) / 512) as libc::blkcnt_t;

    // Use a synthetic inode and device.
    s.st_ino = 0xBAD_F00D;
    s.st_dev = 0xFF;
    s.st_uid = unsafe { libc::getuid() };
    s.st_gid = unsafe { libc::getgid() };
}
