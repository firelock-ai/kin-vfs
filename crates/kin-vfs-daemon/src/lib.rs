// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-daemon: File-serving daemon over Unix socket.
//!
//! Serves file content from a `ContentProvider` to connected VFS shim clients.
//! Communicates via MessagePack over a length-prefixed Unix socket protocol.

pub mod async_kin_provider;
pub mod error;
pub mod framing;
pub mod kin_provider;
pub mod protocol;
pub mod server;

pub use async_kin_provider::AsyncKinDaemonProvider;
pub use error::DaemonError;
pub use framing::{read_frame, write_frame};
pub use kin_provider::KinDaemonProvider;
pub use protocol::{VfsRequest, VfsResponse};
pub use server::{ListenAddress, VfsDaemonServer};
