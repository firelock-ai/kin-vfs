// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OS-specific NFS mount/unmount helpers.
//!
//! Handles the platform-specific commands to mount the NFS share:
//! - macOS: `mount_nfs` (built-in)
//! - Linux: `mount -t nfs` (built-in)
//! - Windows: `mount` or `net use` (built-in NFS client)

// TODO: implement in task #5
