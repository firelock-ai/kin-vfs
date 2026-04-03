// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Multi-workspace NFS router.
//!
//! The NFS export root shows all registered workspaces as top-level
//! directories. Each workspace is backed by its own `ContentProvider`
//! (lazily created `KinDaemonProvider` pointing at the workspace's
//! kin-daemon instance).

// TODO: implement in task #4
