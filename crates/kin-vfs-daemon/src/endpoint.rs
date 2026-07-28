// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-daemon endpoint resolution for the HTTP providers.
//!
//! The kin daemon binds an **ephemeral** port and records it in
//! `<repo_root>/.kin/daemon.port`, deleting that file when it stops. A VFS
//! daemon outlives many kin-daemon lifetimes, so a base URL captured once at
//! construction goes stale the first time kin-daemon restarts: every later read
//! dials a dead port while the VFS daemon keeps answering, which degrades reads
//! silently instead of failing loud.
//!
//! [`DaemonEndpoint`] keeps the resolution inputs so the URL can be re-resolved
//! once after a transport failure, with the same precedence the CLI uses:
//! `KIN_DAEMON_URL` > `<repo_root>/.kin/daemon.port`. There is deliberately **no**
//! default fallback on re-resolution: with no port file and no override, the
//! `:4219` default could belong to a *different* repository's daemon, and
//! answering from another repo's graph is worse than reporting unreachable.

use std::path::{Path, PathBuf};

use parking_lot::RwLock;

/// Environment override for the kin-daemon base URL. The CLI reads the same
/// variable, so launcher and provider agree on which daemon is authoritative.
pub(crate) const DAEMON_URL_ENV: &str = "KIN_DAEMON_URL";

/// Serializes every test across the crate that reads or mutates
/// `KIN_DAEMON_URL`, so process-global env state cannot race between test
/// modules running in parallel.
#[cfg(test)]
pub(crate) static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Trim surrounding whitespace and discard an empty result.
fn trim_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// `<repo_root>/.kin/daemon.port` — the file the kin daemon writes on startup
/// and removes on shutdown.
pub(crate) fn port_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".kin").join("daemon.port")
}

/// Read the port the kin daemon currently advertises for this repo.
pub(crate) fn read_port_file(repo_root: &Path) -> Option<u16> {
    std::fs::read_to_string(port_file_path(repo_root))
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
}

/// Read the `KIN_DAEMON_URL` override from the environment.
fn env_url() -> Option<String> {
    std::env::var(DAEMON_URL_ENV)
        .ok()
        .as_deref()
        .and_then(trim_non_empty)
}

/// Pure precedence resolver. Each candidate source is passed explicitly so the
/// ordering can be unit-tested without touching the process environment or
/// filesystem. `None` means no live source claims a daemon; the caller keeps
/// whatever URL it already has rather than guessing.
pub(crate) fn resolve_from(env: Option<&str>, port_file: Option<u16>) -> Option<String> {
    env.and_then(trim_non_empty)
        .or_else(|| port_file.map(|port| format!("http://127.0.0.1:{port}")))
}

/// Resolve the effective base URL from the live sources, if any.
fn resolve_url(repo_root: Option<&Path>) -> Option<String> {
    resolve_from(env_url().as_deref(), repo_root.and_then(read_port_file))
}

/// Resolved endpoint state for a provider: the active base URL plus the inputs
/// needed to re-resolve it after a transport failure.
pub(crate) struct DaemonEndpoint {
    /// Served repo root used to locate `.kin/daemon.port`, if known.
    repo_root: Option<PathBuf>,
    /// Currently active base URL. Cached so every request need not read the
    /// port file; refreshed in place when a request cannot reach it.
    base_url: RwLock<String>,
}

impl DaemonEndpoint {
    /// Start from the URL the caller already resolved and capture the repo root
    /// so it can be re-resolved when that URL stops answering.
    pub(crate) fn new(base_url: String, repo_root: Option<PathBuf>) -> Self {
        Self {
            repo_root,
            base_url: RwLock::new(base_url),
        }
    }

    /// The base URL for the next request.
    pub(crate) fn base_url(&self) -> String {
        self.base_url.read().clone()
    }

    /// Re-resolve after a transport failure. Returns the fresh URL only when a
    /// live source names one that differs from the value already in use, so the
    /// caller retries exactly once and only when retrying could change the
    /// outcome. A missing port file (kin-daemon stopped) leaves the endpoint
    /// untouched and the failure stands as unreachable.
    pub(crate) fn refresh(&self) -> Option<String> {
        let resolved = resolve_url(self.repo_root.as_deref())?;
        let mut guard = self.base_url.write();
        if *guard == resolved {
            return None;
        }
        *guard = resolved.clone();
        Some(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `body` with no `KIN_DAEMON_URL` override, restoring the ambient value
    /// afterwards, so a port-file test measures the file and not the operator's
    /// environment.
    fn without_env_url<T>(body: impl FnOnce() -> T) -> T {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let saved = std::env::var(DAEMON_URL_ENV).ok();
        std::env::remove_var(DAEMON_URL_ENV);
        let result = body();
        if let Some(value) = saved {
            std::env::set_var(DAEMON_URL_ENV, value);
        }
        result
    }

    #[test]
    fn env_override_beats_the_port_file() {
        assert_eq!(
            resolve_from(Some("http://127.0.0.1:9999"), Some(5050)).as_deref(),
            Some("http://127.0.0.1:9999")
        );
    }

    #[test]
    fn port_file_builds_a_loopback_url() {
        assert_eq!(
            resolve_from(None, Some(5050)).as_deref(),
            Some("http://127.0.0.1:5050")
        );
    }

    #[test]
    fn no_live_source_resolves_to_nothing() {
        // Never a `:4219` guess: that port may belong to another repo's daemon.
        assert_eq!(resolve_from(None, None), None);
        assert_eq!(resolve_from(Some("  "), None), None);
    }

    #[test]
    fn port_file_path_is_under_dot_kin() {
        let path = port_file_path(Path::new("/repo"));
        assert_eq!(path, Path::new("/repo/.kin/daemon.port"));
    }

    #[test]
    fn read_port_file_trims_and_handles_missing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(read_port_file(root), None);

        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.port"), " 5150\n").unwrap();
        assert_eq!(read_port_file(root), Some(5150));

        std::fs::write(kin.join("daemon.port"), "not-a-port").unwrap();
        assert_eq!(read_port_file(root), None);
    }

    #[test]
    fn refresh_follows_a_restarted_daemon_to_its_new_port() {
        without_env_url(|| {
            let dir = tempfile::tempdir().unwrap();
            let kin = dir.path().join(".kin");
            std::fs::create_dir_all(&kin).unwrap();
            std::fs::write(kin.join("daemon.port"), "5150").unwrap();

            let endpoint = DaemonEndpoint::new(
                "http://127.0.0.1:5150".to_string(),
                Some(dir.path().to_path_buf()),
            );
            // Unchanged port file → no change, so no needless retry.
            assert_eq!(endpoint.refresh(), None);

            // kin-daemon restarted on a new ephemeral port.
            std::fs::write(kin.join("daemon.port"), "5151").unwrap();
            assert_eq!(endpoint.refresh().as_deref(), Some("http://127.0.0.1:5151"));
            assert_eq!(endpoint.base_url(), "http://127.0.0.1:5151");
        });
    }

    #[test]
    fn refresh_keeps_the_pinned_url_when_the_port_file_is_gone() {
        without_env_url(|| {
            let dir = tempfile::tempdir().unwrap();
            let endpoint = DaemonEndpoint::new(
                "http://127.0.0.1:5150".to_string(),
                Some(dir.path().to_path_buf()),
            );

            // kin-daemon stopped and removed its port file: there is nothing to
            // retry against, and the default port may be another repo's daemon.
            assert_eq!(endpoint.refresh(), None);
            assert_eq!(endpoint.base_url(), "http://127.0.0.1:5150");

            // Same answer with no repo root at all: nothing to re-resolve from.
            let rootless = DaemonEndpoint::new("http://127.0.0.1:4219".to_string(), None);
            assert_eq!(rootless.refresh(), None);
            assert_eq!(rootless.base_url(), "http://127.0.0.1:4219");
        });
    }
}
