// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bearer-token resolution for the kin-daemon HTTP providers.
//!
//! The kin-daemon auto-provisions a per-repo loopback bearer token at
//! `<repo_root>/.kin/daemon.token` (mode 0600) and, when
//! `KIN_DAEMON_REQUIRE_TOKEN` is enabled, requires every non-public request to
//! carry `Authorization: Bearer <token>`. The providers resolve the matching
//! token so reads keep working once enforcement is flipped on.
//!
//! Resolution precedence (first non-empty match wins):
//! 1. an explicit token passed to the provider constructor
//! 2. the `KIN_DAEMON_AUTH_TOKEN` environment variable
//! 3. `<repo_root>/.kin/daemon.token` (trimmed)
//! 4. none — no `Authorization` header is sent (the daemon accepts this while
//!    enforcement is off)
//!
//! The daemon reuses an existing `.kin/daemon.token` across restarts, so the
//! token is stable for the life of a repo's `.kin/` directory. To stay correct
//! if that file is ever regenerated (e.g. deleted and re-provisioned) while a
//! long-lived VFS daemon holds a stale value, [`DaemonAuth::refresh`] re-reads
//! the source once on a `401` response.

use std::path::{Path, PathBuf};

use parking_lot::RwLock;

/// Environment variable the kin-daemon reads for an explicit bearer token. The
/// providers read the same variable so client and server agree on the token.
pub(crate) const AUTH_TOKEN_ENV: &str = "KIN_DAEMON_AUTH_TOKEN";

/// Serializes every test across the crate that reads or mutates
/// `KIN_DAEMON_AUTH_TOKEN`, so process-global env state cannot race between the
/// `auth` and provider test modules running in parallel.
#[cfg(test)]
pub(crate) static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Trim surrounding whitespace and discard an empty result. The daemon trims
/// the token it parses out of the `Bearer ` header, so the client must send a
/// trimmed value to match.
fn trim_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// `<repo_root>/.kin/daemon.token` — the per-repo loopback token file the
/// kin-daemon provisions on startup.
pub(crate) fn token_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".kin").join("daemon.token")
}

/// Read and trim `<repo_root>/.kin/daemon.token`, if it exists and is non-empty.
pub(crate) fn read_token_file(repo_root: &Path) -> Option<String> {
    std::fs::read_to_string(token_file_path(repo_root))
        .ok()
        .as_deref()
        .and_then(trim_non_empty)
}

/// Read the `KIN_DAEMON_AUTH_TOKEN` override from the environment.
fn env_token() -> Option<String> {
    std::env::var(AUTH_TOKEN_ENV)
        .ok()
        .as_deref()
        .and_then(trim_non_empty)
}

/// Pure precedence resolver. Each candidate source is passed explicitly so the
/// ordering can be unit-tested without touching the process environment or
/// filesystem.
pub(crate) fn resolve_from(
    explicit: Option<&str>,
    env: Option<&str>,
    file: Option<&str>,
) -> Option<String> {
    explicit
        .and_then(trim_non_empty)
        .or_else(|| env.and_then(trim_non_empty))
        .or_else(|| file.and_then(trim_non_empty))
}

/// Resolve the effective bearer token, applying the documented precedence:
/// explicit > `KIN_DAEMON_AUTH_TOKEN` > `<repo_root>/.kin/daemon.token` > none.
pub(crate) fn resolve_token(explicit: Option<&str>, repo_root: Option<&Path>) -> Option<String> {
    let env = env_token();
    let file = repo_root.and_then(read_token_file);
    resolve_from(explicit, env.as_deref(), file.as_deref())
}

/// Resolved auth state for a provider: the active token plus the inputs needed
/// to re-resolve it once on a `401`.
pub(crate) struct DaemonAuth {
    /// Explicit token supplied at construction (highest precedence), if any.
    explicit: Option<String>,
    /// Served repo root used to locate `.kin/daemon.token`, if known.
    repo_root: Option<PathBuf>,
    /// Currently active token. Cached so every request need not re-read the
    /// file; refreshed in place on a `401`.
    token: RwLock<Option<String>>,
}

impl DaemonAuth {
    /// Resolve the token from the given inputs (explicit > env > file) and
    /// capture the inputs so it can be re-resolved on a `401`.
    pub(crate) fn new(explicit: Option<String>, repo_root: Option<PathBuf>) -> Self {
        let token = resolve_token(explicit.as_deref(), repo_root.as_deref());
        Self {
            explicit,
            repo_root,
            token: RwLock::new(token),
        }
    }

    /// The token to send on the next request, if any.
    pub(crate) fn token(&self) -> Option<String> {
        self.token.read().clone()
    }

    /// Re-resolve the token after a `401`. Returns the fresh token only when it
    /// differs from the value already in use (so the caller retries exactly
    /// once, and only when retrying could plausibly change the outcome).
    pub(crate) fn refresh(&self) -> Option<String> {
        let resolved = resolve_token(self.explicit.as_deref(), self.repo_root.as_deref());
        let mut guard = self.token.write();
        if *guard == resolved {
            return None;
        }
        *guard = resolved.clone();
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_explicit_wins() {
        assert_eq!(
            resolve_from(Some("explicit"), Some("env"), Some("file")).as_deref(),
            Some("explicit")
        );
    }

    #[test]
    fn precedence_env_beats_file() {
        assert_eq!(
            resolve_from(None, Some("env"), Some("file")).as_deref(),
            Some("env")
        );
    }

    #[test]
    fn precedence_file_is_last_resort() {
        assert_eq!(
            resolve_from(None, None, Some("file")).as_deref(),
            Some("file")
        );
    }

    #[test]
    fn precedence_none_when_all_absent() {
        assert_eq!(resolve_from(None, None, None), None);
    }

    #[test]
    fn blank_sources_are_skipped() {
        // Whitespace-only values are treated as absent, falling through.
        assert_eq!(
            resolve_from(Some("   "), Some("\n"), Some("file")).as_deref(),
            Some("file")
        );
        assert_eq!(resolve_from(Some(""), Some(""), Some("  ")), None);
    }

    #[test]
    fn resolved_token_is_trimmed() {
        assert_eq!(
            resolve_from(Some("  padded  "), None, None).as_deref(),
            Some("padded")
        );
    }

    #[test]
    fn token_file_path_is_under_dot_kin() {
        let path = token_file_path(Path::new("/repo"));
        assert!(path.ends_with(".kin/daemon.token"));
        assert_eq!(path, Path::new("/repo/.kin/daemon.token"));
    }

    #[test]
    fn read_token_file_trims_and_handles_missing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Missing file → None.
        assert_eq!(read_token_file(root), None);

        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.token"), "  abc123\n").unwrap();
        assert_eq!(read_token_file(root).as_deref(), Some("abc123"));

        // Empty file → None.
        std::fs::write(kin.join("daemon.token"), "   \n").unwrap();
        assert_eq!(read_token_file(root), None);
    }

    #[test]
    fn resolve_token_reads_file_when_no_explicit_or_env() {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved = std::env::var(AUTH_TOKEN_ENV).ok();
        std::env::remove_var(AUTH_TOKEN_ENV);

        let dir = tempfile::tempdir().unwrap();
        let kin = dir.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.token"), "file-token").unwrap();

        assert_eq!(
            resolve_token(None, Some(dir.path())).as_deref(),
            Some("file-token")
        );
        // Explicit arg still beats the file.
        assert_eq!(
            resolve_token(Some("explicit"), Some(dir.path())).as_deref(),
            Some("explicit")
        );

        match saved {
            Some(value) => std::env::set_var(AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(AUTH_TOKEN_ENV),
        }
    }

    #[test]
    fn resolve_token_env_beats_file() {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved = std::env::var(AUTH_TOKEN_ENV).ok();
        std::env::set_var(AUTH_TOKEN_ENV, "env-token");

        let dir = tempfile::tempdir().unwrap();
        let kin = dir.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.token"), "file-token").unwrap();

        assert_eq!(
            resolve_token(None, Some(dir.path())).as_deref(),
            Some("env-token")
        );

        match saved {
            Some(value) => std::env::set_var(AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(AUTH_TOKEN_ENV),
        }
    }

    #[test]
    fn refresh_picks_up_a_rotated_file_token() {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved = std::env::var(AUTH_TOKEN_ENV).ok();
        std::env::remove_var(AUTH_TOKEN_ENV);

        let dir = tempfile::tempdir().unwrap();
        let kin = dir.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.token"), "first").unwrap();

        let auth = DaemonAuth::new(None, Some(dir.path().to_path_buf()));
        assert_eq!(auth.token().as_deref(), Some("first"));

        // Unchanged file → refresh reports no change (so no needless retry).
        assert_eq!(auth.refresh(), None);

        // Rotated file → refresh surfaces the new token and updates the cache.
        std::fs::write(kin.join("daemon.token"), "second").unwrap();
        assert_eq!(auth.refresh().as_deref(), Some("second"));
        assert_eq!(auth.token().as_deref(), Some("second"));

        match saved {
            Some(value) => std::env::set_var(AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(AUTH_TOKEN_ENV),
        }
    }

    #[test]
    fn explicit_token_is_stable_across_refresh() {
        let auth = DaemonAuth::new(Some("explicit".to_string()), None);
        assert_eq!(auth.token().as_deref(), Some("explicit"));
        // Nothing to re-resolve for an explicit token.
        assert_eq!(auth.refresh(), None);
        assert_eq!(auth.token().as_deref(), Some("explicit"));
    }

    #[test]
    fn no_sources_sends_no_token() {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved = std::env::var(AUTH_TOKEN_ENV).ok();
        std::env::remove_var(AUTH_TOKEN_ENV);

        let auth = DaemonAuth::new(None, None);
        assert_eq!(auth.token(), None);
        assert_eq!(auth.refresh(), None);

        match saved {
            Some(value) => std::env::set_var(AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(AUTH_TOKEN_ENV),
        }
    }
}
