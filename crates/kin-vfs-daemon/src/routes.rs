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
//! All four are served by the kin daemon (kin/crates/kin-daemon/src/api.rs):
//! `/health` is a public route (no bearer token); `/vfs/*` are non-public and
//! require `Authorization: Bearer <token>` once `KIN_DAEMON_REQUIRE_TOKEN` is on.
//! (`/vfs/write-notify` is emitted by the shim, not these providers.)

/// Liveness probe. Public route — served without a bearer token.
pub(crate) const HEALTH: &str = "/health";

/// Monotonic tree-version counter used for cache invalidation.
pub(crate) const VERSION: &str = "/vfs/version";

/// Full file tree (`path -> content hash`, plus timestamps).
pub(crate) const TREE: &str = "/vfs/tree";

/// Per-file content. The normalized path is appended: `/vfs/read/<path>`.
pub(crate) const READ_PREFIX: &str = "/vfs/read/";

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the literal route values. If a provider route changes, it must
    /// change here (the single source of truth), which trips this assertion —
    /// the guard against silent provider↔daemon route drift.
    #[test]
    fn route_paths_are_pinned() {
        assert_eq!(HEALTH, "/health");
        assert_eq!(VERSION, "/vfs/version");
        assert_eq!(TREE, "/vfs/tree");
        assert_eq!(READ_PREFIX, "/vfs/read/");
    }
}
