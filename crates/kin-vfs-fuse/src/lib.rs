// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-fuse: FUSE mount mode for kin-vfs.
//!
//! Presents a `ContentProvider`-backed virtual filesystem as a FUSE mount point.
//! Supports macFUSE (kernel extension) and FUSE-T (userspace) on macOS, and
//! libfuse on Linux. The mount is read-only — writes are rejected with EROFS.
//!
//! This is an alternative to the LD_PRELOAD/DYLD shim approach. While the shim
//! intercepts syscalls within individual processes, the FUSE mount presents a
//! real mount point visible to all processes on the system. Trade-offs:
//!
//! | | Shim (LD_PRELOAD/DYLD) | FUSE mount |
//! |---|---|---|
//! | Visibility | Per-process | System-wide |
//! | SIP issues | Yes (macOS) | No |
//! | Static binaries | No | Yes |
//! | Requires install | No | macFUSE or FUSE-T |
//! | Write-through | Yes | No (read-only) |

pub mod filesystem;
pub mod inode;
pub mod mount;

pub use filesystem::KinFuseFs;
pub use mount::{fuse_available, mount_blocking, unmount, FuseVariant, MountError, MountOptions};
