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
//! [`DaemonEndpoint`] keeps the resolution inputs so the URL is re-resolved
//! before every scoped request and once more after a transport race, with the
//! same precedence the CLI uses: `KIN_DAEMON_URL` >
//! `<repo_root>/.kin/daemon.port`. There is deliberately **no** default fallback
//! on re-resolution: with no port file and no override, the `:4219` default
//! could belong to a *different* repository's daemon. Before any scoped network
//! request, the local root and repository-v6 manifest must provide enough
//! identity to authenticate the response. Health and tree responses are then
//! bound back to that local identity before they are trusted.

use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::Deserialize;

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

#[derive(Debug, Deserialize)]
struct ManifestIdentity {
    repo_id: String,
    /// Repository-v6 manifests carry the workspace selector needed to bind a
    /// tree response. Older materializations deserialize so they can receive a
    /// precise migration error, but they are never network authority.
    #[serde(default)]
    workspace_id: Option<String>,
}

fn read_manifest_identity(repo_root: &Path) -> Result<ManifestIdentity, String> {
    // One spelling of the repository identity marker, shared with the shim's
    // projection-root admission and the CLI's discovery walk, so a rename
    // cannot leave one of the three reading a file the others do not.
    let path = repo_root.join(kin_vfs_core::pathmap::REPOSITORY_IDENTITY_MARKER);
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "cannot read repository identity {}: {error}",
            path.display()
        )
    })?;
    let identity: ManifestIdentity = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "cannot parse repository identity {}: {error}",
            path.display()
        )
    })?;
    if identity.repo_id.trim().is_empty() {
        return Err(format!(
            "repository identity {} has an empty repo_id",
            path.display()
        ));
    }
    if identity
        .workspace_id
        .as_deref()
        .is_some_and(|workspace_id| workspace_id.trim().is_empty())
    {
        return Err(format!(
            "repository identity {} has an empty workspace_id",
            path.display()
        ));
    }
    Ok(identity)
}

fn canonical_root_text(repo_root: &Path) -> Result<String, String> {
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            "local repository root is not valid UTF-8; daemon requests require a repository-v6 workspace identity"
                .to_string()
        })
}

fn required_workspace_id<'a>(
    repo_root: &Path,
    identity: &'a ManifestIdentity,
) -> Result<&'a str, String> {
    identity.workspace_id.as_deref().ok_or_else(|| {
        format!(
            "repository identity {} omits workspace_id; migrate this repository to repository-v6 before using Kin VFS",
            repo_root.join(".kin").join("manifest.json").display()
        )
    })
}

/// What a re-resolution changed relative to the endpoint already in use.
///
/// Separated from the logging so the "say it once" rule is a testable state
/// machine rather than something only a log-capturing harness could observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointTransition {
    /// Nothing the operator needs: same endpoint, or still-absent advertisement
    /// that was already reported.
    Quiet,
    /// kin-daemon restarted onto a different endpoint and is being followed.
    Moved,
    /// The advertisement disappeared; scoped requests now fail closed.
    Lost,
    /// An advertisement exists again after having been lost.
    Restored,
}

/// Resolved endpoint state for a provider: the active base URL plus the inputs
/// needed to re-resolve it after a transport failure.
pub(crate) struct DaemonEndpoint {
    /// Served repo root used to locate `.kin/daemon.port`, if known.
    repo_root: Option<PathBuf>,
    /// Currently active base URL. Cached so every request need not read the
    /// port file; refreshed in place when a request cannot reach it.
    base_url: RwLock<String>,
    /// Last advertisement state already announced to the operator. This is a
    /// single serialized value, not a Boolean separate from `base_url`: racing
    /// requests that both captured endpoint A can therefore claim A -> B only
    /// once. `None` means the lost-advertisement transition was announced.
    announced_endpoint: RwLock<Option<String>>,
}

impl DaemonEndpoint {
    /// Start from the URL the caller already resolved and capture the repo root
    /// so it can be re-resolved when that URL stops answering.
    pub(crate) fn new(base_url: String, repo_root: Option<PathBuf>) -> Self {
        Self {
            repo_root,
            announced_endpoint: RwLock::new(Some(base_url.clone())),
            base_url: RwLock::new(base_url),
        }
    }

    /// What one re-resolution changed, if anything worth telling the operator.
    fn classify_resolution(&self, resolved: Option<&str>, _previous: &str) -> EndpointTransition {
        // A rootless provider is an explicitly pinned client: it has no
        // advertisement to follow, so "not advertised" is its normal state and
        // saying so would be noise rather than news.
        if self.repo_root.is_none() {
            return EndpointTransition::Quiet;
        }
        let mut announced = self.announced_endpoint.write();
        match (resolved, announced.as_deref()) {
            (Some(resolved), Some(current)) if resolved == current => EndpointTransition::Quiet,
            (Some(resolved), Some(_)) => {
                *announced = Some(resolved.to_string());
                EndpointTransition::Moved
            }
            (Some(resolved), None) => {
                *announced = Some(resolved.to_string());
                EndpointTransition::Restored
            }
            (None, Some(_)) => {
                *announced = None;
                EndpointTransition::Lost
            }
            (None, None) => EndpointTransition::Quiet,
        }
    }

    /// Announce that the repo's advertised endpoint moved, vanished, or came
    /// back. A VFS daemon outlives many kin-daemon lifetimes and re-resolves
    /// silently, so without this the operator sees reads start failing (or
    /// start working again) with nothing naming the cause.
    ///
    /// Re-resolution runs before every request, so this speaks only on a state
    /// change. Logging each failure would emit one line per read for as long as
    /// kin-daemon stays down, which is how a real signal becomes noise nobody
    /// reads.
    fn note_resolution(&self, resolved: Option<&str>, previous: &str) {
        let repo_root = match self.repo_root.as_deref() {
            Some(repo_root) => repo_root.display().to_string(),
            None => return,
        };
        match self.classify_resolution(resolved, previous) {
            EndpointTransition::Quiet => {}
            EndpointTransition::Moved => tracing::warn!(
                repo_root,
                from = previous,
                to = resolved.unwrap_or_default(),
                "kin-daemon moved to a new endpoint; following the current advertisement"
            ),
            EndpointTransition::Lost => tracing::warn!(
                repo_root,
                pinned = previous,
                "kin-daemon is no longer advertised for this repo; scoped reads fail closed \
                 rather than dialing the stale endpoint"
            ),
            EndpointTransition::Restored => tracing::warn!(
                repo_root,
                endpoint = resolved.unwrap_or_default(),
                "kin-daemon is advertised again; reads resume against the current endpoint"
            ),
        }
    }

    /// The base URL for the next request.
    pub(crate) fn base_url(&self) -> String {
        self.base_url.read().clone()
    }

    /// Resolve and return the exact base URL one request must use.
    ///
    /// Returning the value captured while the cache is updated is
    /// load-bearing: callers must not prepare under one endpoint and then read
    /// the shared cache again after another request has moved it.
    pub(crate) fn prepared_base_url(&self) -> Result<String, String> {
        let Some(repo_root) = self.repo_root.as_deref() else {
            // A rootless provider is an explicitly pinned client. It has no
            // local repository identity or advertisement to revalidate.
            return Ok(self.base_url());
        };
        let previous = self.base_url();
        let resolved = resolve_url(Some(repo_root));
        self.note_resolution(resolved.as_deref(), &previous);
        let resolved = resolved.ok_or_else(|| {
            format!(
                "kin-daemon endpoint is not currently advertised for {}",
                repo_root.display()
            )
        })?;
        *self.base_url.write() = resolved.clone();
        Ok(resolved)
    }

    /// Re-resolve from the live advertisement before every request.
    ///
    /// A cached port is not authority: after the intended daemon exits, the OS
    /// may assign that port to a different repository's daemon. When a provider
    /// knows its repo root, the current `.kin/daemon.port` (or explicit
    /// `KIN_DAEMON_URL`) must still name an endpoint. A missing advertisement
    /// fails closed instead of dialing the stale cached URL.
    #[cfg(test)]
    pub(crate) fn prepare(&self) -> Result<bool, String> {
        let before = self.base_url();
        Ok(self.prepared_base_url()? != before)
    }

    /// Re-resolve after a transport failure. Returns the fresh URL only when a
    /// live source names one that differs from the value already in use, so the
    /// caller retries exactly once and only when retrying could change the
    /// outcome. A missing port file (kin-daemon stopped) leaves the endpoint
    /// untouched and the failure stands as unreachable.
    #[cfg(test)]
    pub(crate) fn refresh(&self) -> Option<String> {
        let resolved = resolve_url(self.repo_root.as_deref())?;
        let mut guard = self.base_url.write();
        if *guard == resolved {
            return None;
        }
        *guard = resolved.clone();
        Some(resolved)
    }

    /// Re-resolve after a request to `failed_base` could not complete.
    ///
    /// This differs from [`Self::refresh`] under concurrency: another request
    /// may already have updated the shared cache to the newly advertised URL.
    /// A retry is still warranted when that live URL differs from the endpoint
    /// this particular failed request actually used.
    pub(crate) fn refresh_after_failure(&self, failed_base: &str) -> Option<String> {
        let resolved = resolve_url(self.repo_root.as_deref());
        self.note_resolution(resolved.as_deref(), failed_base);
        let resolved = resolved?;
        *self.base_url.write() = resolved.clone();
        (resolved != failed_base).then_some(resolved)
    }

    /// Validate all local authority required by a scoped HTTP request.
    ///
    /// This must run before request construction or sending. A legacy manifest
    /// cannot bind a tree to one materialized workspace, and a non-UTF-8 root
    /// cannot be compared with the daemon's textual health identity. Both fail
    /// locally so no endpoint observes even a health request or bearer token.
    pub(crate) fn preflight_scoped_request(&self) -> Result<(), String> {
        let Some(repo_root) = self.repo_root.as_deref() else {
            // A rootless provider is an explicitly pinned client. It has no
            // local repository identity to enforce.
            return Ok(());
        };
        canonical_root_text(repo_root)?;
        let identity = read_manifest_identity(repo_root)?;
        required_workspace_id(repo_root, &identity)?;
        Ok(())
    }

    /// Validate the repository identity returned by `/health`.
    ///
    /// `repo_id` prevents one repository from impersonating another; the
    /// canonical root additionally distinguishes two local workspaces of the
    /// same repository. A scoped provider refuses an older/foreign health body
    /// that omits either identity.
    pub(crate) fn validate_health_identity(
        &self,
        observed_repo_id: Option<&str>,
        observed_repo_root: Option<&str>,
    ) -> Result<(), String> {
        let Some(repo_root) = self.repo_root.as_deref() else {
            return Ok(());
        };
        let expected_root = canonical_root_text(repo_root)?;
        let expected = read_manifest_identity(repo_root)?;
        required_workspace_id(repo_root, &expected)?;
        let observed_repo_id =
            observed_repo_id.ok_or_else(|| "daemon health omitted repo_id".to_string())?;
        if observed_repo_id != expected.repo_id {
            return Err(format!(
                "daemon repository mismatch: endpoint serves {observed_repo_id}, expected {}",
                expected.repo_id
            ));
        }

        let observed_repo_root =
            observed_repo_root.ok_or_else(|| "daemon health omitted repo_root".to_string())?;
        if observed_repo_root != expected_root {
            return Err(format!(
                "daemon workspace mismatch: endpoint serves {observed_repo_root}, expected {expected_root}"
            ));
        }
        Ok(())
    }

    /// Validate the immutable repository/workspace binding on the tree itself.
    ///
    /// Every data operation ensures the tree before fetching a blob, so this
    /// check prevents a stale/reused port from installing another repository's
    /// graph even if that process answers valid Kin HTTP.
    pub(crate) fn validate_tree_identity(
        &self,
        observed_repo_id: &str,
        observed_workspace_id: &str,
    ) -> Result<(), String> {
        let Some(repo_root) = self.repo_root.as_deref() else {
            return Ok(());
        };
        let expected = read_manifest_identity(repo_root)?;
        let expected_workspace_id = required_workspace_id(repo_root, &expected)?;
        if observed_repo_id != expected.repo_id {
            return Err(format!(
                "tree repository mismatch: endpoint serves {observed_repo_id}, expected {}",
                expected.repo_id
            ));
        }
        if observed_workspace_id != expected_workspace_id {
            return Err(format!(
                "tree workspace mismatch: endpoint serves {observed_workspace_id}, expected {expected_workspace_id}"
            ));
        }
        Ok(())
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
    fn a_restart_onto_a_new_port_is_announced_once_and_a_steady_endpoint_stays_quiet() {
        // Re-resolution runs before every request. Reporting each one would put
        // a line in the log per read, so the announcement has to key on the
        // transition. It also has to actually fire: a VFS daemon outlives many
        // kin-daemon lifetimes, and a silent move is how a whole run's reads
        // came back not-in-graph with nothing naming the cause.
        let endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:5150".to_string(),
            Some(std::path::PathBuf::from("/repo")),
        );

        assert_eq!(
            endpoint.classify_resolution(Some("http://127.0.0.1:5150"), "http://127.0.0.1:5150"),
            EndpointTransition::Quiet
        );
        assert_eq!(
            endpoint.classify_resolution(Some("http://127.0.0.1:5151"), "http://127.0.0.1:5150"),
            EndpointTransition::Moved
        );
        assert_eq!(
            endpoint.classify_resolution(Some("http://127.0.0.1:5151"), "http://127.0.0.1:5150"),
            EndpointTransition::Quiet,
            "the same transition must not be announced twice"
        );
    }

    #[test]
    fn concurrent_requests_announce_one_endpoint_move_once() {
        use std::sync::{Arc, Barrier};

        const CALLERS: usize = 16;
        let endpoint = Arc::new(DaemonEndpoint::new(
            "http://127.0.0.1:5150".to_string(),
            Some(std::path::PathBuf::from("/repo")),
        ));
        let start = Arc::new(Barrier::new(CALLERS));
        let callers: Vec<_> = (0..CALLERS)
            .map(|_| {
                let endpoint = Arc::clone(&endpoint);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    endpoint
                        .classify_resolution(Some("http://127.0.0.1:5151"), "http://127.0.0.1:5150")
                })
            })
            .collect();
        let transitions: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().expect("endpoint classifier thread"))
            .collect();
        assert_eq!(
            transitions
                .iter()
                .filter(|transition| **transition == EndpointTransition::Moved)
                .count(),
            1,
            "the serialized announced endpoint must admit one A -> B warning"
        );
        assert_eq!(
            transitions
                .iter()
                .filter(|transition| **transition == EndpointTransition::Quiet)
                .count(),
            CALLERS - 1
        );
    }

    #[test]
    fn a_lost_advertisement_is_announced_once_and_again_when_it_returns() {
        let endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:5150".to_string(),
            Some(std::path::PathBuf::from("/repo")),
        );
        let pinned = "http://127.0.0.1:5150";

        // kin-daemon stopped: say so once, then stop repeating it. Every read
        // re-resolves, so an unlatched warning would be one line per read for
        // as long as the daemon stays down.
        assert_eq!(
            endpoint.classify_resolution(None, pinned),
            EndpointTransition::Lost
        );
        for _ in 0..5 {
            assert_eq!(
                endpoint.classify_resolution(None, pinned),
                EndpointTransition::Quiet
            );
        }

        // It came back. This must speak again, or the operator is left with a
        // "reads fail closed" line and no record that they resumed.
        assert_eq!(
            endpoint.classify_resolution(Some("http://127.0.0.1:5151"), pinned),
            EndpointTransition::Restored
        );
        assert_eq!(
            endpoint.classify_resolution(Some("http://127.0.0.1:5151"), "http://127.0.0.1:5151"),
            EndpointTransition::Quiet
        );

        // And a second outage is announced again rather than swallowed by the
        // first one's latch.
        assert_eq!(
            endpoint.classify_resolution(None, "http://127.0.0.1:5151"),
            EndpointTransition::Lost
        );
    }

    #[test]
    fn an_explicitly_pinned_client_never_announces_a_transition() {
        // A rootless provider has no advertisement to follow, so "not
        // advertised" is its normal state and reporting it would be noise.
        let rootless = DaemonEndpoint::new("http://127.0.0.1:4219".to_string(), None);
        assert_eq!(
            rootless.classify_resolution(None, "http://127.0.0.1:4219"),
            EndpointTransition::Quiet
        );
        assert_eq!(
            rootless.classify_resolution(Some("http://127.0.0.1:9999"), "http://127.0.0.1:4219"),
            EndpointTransition::Quiet
        );
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
            assert!(
                endpoint.prepare().is_err(),
                "a scoped request must not dial the stale cached endpoint"
            );

            // Same answer with no repo root at all: nothing to re-resolve from.
            let rootless = DaemonEndpoint::new("http://127.0.0.1:4219".to_string(), None);
            assert_eq!(rootless.refresh(), None);
            assert_eq!(rootless.base_url(), "http://127.0.0.1:4219");
            assert_eq!(rootless.prepare(), Ok(false));
        });
    }

    #[test]
    fn identity_validation_rejects_another_repo_or_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(
            kin.join("manifest.json"),
            r#"{"repo_id":"repo-a","workspace_id":"00000000-0000-0000-0000-00000000000a"}"#,
        )
        .unwrap();
        let endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:5150".to_string(),
            Some(root.to_path_buf()),
        );
        let canonical = root.canonicalize().unwrap();
        let canonical = canonical.to_str().unwrap();

        assert!(endpoint
            .validate_health_identity(Some("repo-a"), Some(canonical))
            .is_ok());
        assert!(endpoint
            .validate_health_identity(Some("repo-b"), Some(canonical))
            .is_err());
        assert!(endpoint
            .validate_health_identity(Some("repo-a"), Some("/another/workspace"))
            .is_err());
        assert!(endpoint
            .validate_tree_identity("repo-a", "00000000-0000-0000-0000-00000000000a")
            .is_ok());
        assert!(endpoint
            .validate_tree_identity("repo-a", "00000000-0000-0000-0000-00000000000b")
            .is_err());
    }

    #[test]
    fn legacy_manifest_requires_repository_v6_migration() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(
            kin.join("manifest.json"),
            r#"{
                "kin_version":"0.2.1",
                "languages":[],
                "adapters":[],
                "repo_id":"legacy-repo",
                "created_at":"2026-01-01T00:00:00Z"
            }"#,
        )
        .unwrap();
        let endpoint = DaemonEndpoint::new(
            "http://127.0.0.1:5150".to_string(),
            Some(root.to_path_buf()),
        );
        let error = endpoint
            .preflight_scoped_request()
            .expect_err("a legacy manifest is not network authority");
        assert!(error.contains("omits workspace_id"), "{error}");
        assert!(error.contains("repository-v6"), "{error}");
        assert!(endpoint
            .validate_health_identity(Some("legacy-repo"), root.to_str())
            .is_err());
        assert!(endpoint
            .validate_tree_identity("legacy-repo", "00000000-0000-0000-0000-00000000000a")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn scoped_request_rejects_a_non_utf8_local_root() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir
            .path()
            .join(OsString::from_vec(b"legacy-workspace-\xff".to_vec()));
        let endpoint = DaemonEndpoint::new("http://127.0.0.1:5150".to_string(), Some(root));

        let error = endpoint
            .preflight_scoped_request()
            .expect_err("a text health field cannot authenticate a non-UTF8 local root");
        assert!(
            error.contains("not valid UTF-8"),
            "unexpected fail-closed reason: {error}"
        );
    }
}
