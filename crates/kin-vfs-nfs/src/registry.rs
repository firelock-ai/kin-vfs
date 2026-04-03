// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persistent workspace registry.
//!
//! Tracks which Kin workspaces are known on this machine. Persists to
//! `~/.kin/vfs-workspaces.json`. The NFS server reads this at startup
//! to know which workspaces to expose as top-level directories.

// TODO: implement in task #2
