// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical kin-daemon HTTP route paths the VFS providers emit.
//!
//! These are the single source of truth for the provider↔daemon route contract:
//! both [`crate::kin_provider`] / [`crate::async_kin_provider`] request sites and
//! the offline contract test reference these constants, so renaming a route here
//! is the only way to change what the providers emit — and the contract test
//! pins the literal values, so silent route drift fails the build.
//!
//! All are served by the kin daemon (kin/crates/kin-daemon/src/api.rs):
//! `/health` is a public route (no bearer token); `/vfs/*` are non-public and
//! require `Authorization: Bearer <token>` once `KIN_DAEMON_REQUIRE_TOKEN` is on.
//! (`/vfs/write-notify` is emitted by the shim, not these providers.)
//!
//! There is deliberately **no** raw-path read route and **no** standalone
//! version route: freshness rides the conditional `ETag` handshake on
//! [`TREE`], and content is addressed only by the exact blob hash the tree
//! advertises — a path reuse or ref race can never return another artifact's
//! bytes.

/// Liveness probe. Public route — served without a bearer token.
pub(crate) const HEALTH: &str = "/health";

/// The strict versioned `WorkspaceTreeSnapshot`. Conditional: the provider
/// sends `If-None-Match: "<etag>"` and the daemon answers `304 Not Modified`
/// or a complete new snapshot whose quoted `ETag` header equals the document's
/// independently recomputed canonical identity.
pub(crate) const TREE: &str = "/vfs/tree";

/// Content-addressed blob bytes. The 64-char lowercase-hex SHA-256 from the
/// tree entry is appended: `/vfs/blob/<hash>`. Supports `Range`; a `206`
/// answer must echo `X-Kin-Blob-Hash` and an exact `Content-Range`.
pub(crate) const BLOB_PREFIX: &str = "/vfs/blob/";

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the literal route values. If a provider route changes, it must
    /// change here (the single source of truth), which trips this assertion —
    /// the guard against silent provider↔daemon route drift.
    #[test]
    fn route_paths_are_pinned() {
        assert_eq!(HEALTH, "/health");
        assert_eq!(TREE, "/vfs/tree");
        assert_eq!(BLOB_PREFIX, "/vfs/blob/");
    }
}
