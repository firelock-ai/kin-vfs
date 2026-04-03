// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! NFS server lifecycle.
//!
//! Manages the NFS TCP listener, port allocation, PID file, and
//! graceful shutdown. The server hosts the multi-workspace router
//! and serves all registered workspaces over a single NFS export.

// TODO: implement in task #5
