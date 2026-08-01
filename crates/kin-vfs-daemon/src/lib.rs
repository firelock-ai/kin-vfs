// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-daemon: File-serving daemon over Unix socket.
//!
//! Serves file content from a `ContentProvider` to connected VFS shim clients.
//! Communicates via MessagePack over a length-prefixed Unix socket protocol.

pub mod async_kin_provider;
mod auth;
mod endpoint;
pub mod error;
pub mod framing;
pub mod kin_provider;
mod lookup_log;
pub mod protocol;
mod routes;
pub mod server;
#[cfg(test)]
mod test_support;
mod tree_contract;

pub use async_kin_provider::AsyncKinDaemonProvider;
pub use error::DaemonError;
pub use framing::{read_frame, write_frame};
pub use kin_provider::KinDaemonProvider;
pub use protocol::{VfsRequest, VfsResponse};
pub use server::{ListenAddress, VfsDaemonServer};

/// The kin-daemon endpoint this repo currently advertises, or `None` when
/// nothing does.
///
/// Precedence matches what a provider dials: `KIN_DAEMON_URL` first, then
/// `<repo_root>/.kin/daemon.port`. There is deliberately no `:4219` default —
/// with no advertisement, that port may belong to a different repository's
/// daemon, so a caller reporting status must be able to say "not advertised"
/// rather than name an endpoint no request would use.
pub fn advertised_daemon_url(repo_root: &std::path::Path) -> Option<String> {
    endpoint::resolve_from(
        std::env::var(endpoint::DAEMON_URL_ENV).ok().as_deref(),
        endpoint::read_port_file(repo_root),
    )
}
