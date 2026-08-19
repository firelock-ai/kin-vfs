// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-fuse: FUSE mount mode for kin-vfs.
//!
//! Presents a `ContentProvider`-backed virtual filesystem as a FUSE mount point.
//! Supports macFUSE (kernel extension) and FUSE-T (userspace) on macOS, and
//! FUSE on Linux.
//!
//! Reads always come from the graph. A mount given a [`WorkspaceWriter`] also
//! accepts writes: saved bytes land on the workspace's real path and the kin
//! daemon must acknowledge the re-index before the operation reports success,
//! so a save the graph never took fails visibly rather than leaving the mount
//! and the graph disagreeing. Without a writer the mount is read-only and every
//! mutation returns EROFS.
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
//! | Requires install | No | fuse3 on Linux; macFUSE or FUSE-T on macOS |
//! | Write-through | Yes | Yes, when a workspace writer is supplied |

pub mod filesystem;
pub mod inode;
pub mod mount;
pub mod notify;
pub mod write;

pub use filesystem::KinFuseFs;
pub use mount::{
    auto_unmount_policy, fuse_available, mount_blocking, mount_blocking_with_writer, preflight,
    unmount, AutoUnmountPolicy, FuseVariant, MountError, MountOptions, MountPreflight,
};
pub use notify::{NotifyError, NotifyTarget};
pub use write::WorkspaceWriter;
