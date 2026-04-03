// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-nfs: NFS-backed virtual filesystem mount for Kin.
//!
//! Exposes all registered Kin workspaces as a single NFS mount at
//! `~/.kin/mnt/`. Each workspace appears as a top-level directory,
//! backed by the workspace's graph and blob store via kin-daemon.
//!
//! ```text
//! ~/.kin/mnt/
//! ├── my-project/          ← workspace 1 (graph-backed)
//! ├── company-monorepo/    ← workspace 2 (graph-backed)
//! └── kin-ecosystem/       ← workspace 3 (graph-backed)
//! ```
//!
//! # Architecture
//!
//! - **registry** — persistent workspace list (`~/.kin/vfs-workspaces.json`)
//! - **nfs_fs** — `nfsserve::vfs::NFSFileSystem` impl backed by `ContentProvider`
//! - **router** — multi-workspace path dispatch (root dir → per-workspace adapters)
//! - **server** — NFS server lifecycle (start, stop, port management)
//! - **automount** — OS-specific mount/unmount helpers (macOS, Linux, Windows)

pub mod automount;
pub mod nfs_fs;
pub mod registry;
pub mod router;
pub mod server;
