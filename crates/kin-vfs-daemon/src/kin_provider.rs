// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider backed by kin-daemon's HTTP API.
//!
//! Fetches the strict versioned tree snapshot and content-addressed blob
//! bytes from a running kin-daemon instance (default `http://127.0.0.1:4219`).
//!
//! Freshness is one conditional request: `GET /vfs/tree` with `If-None-Match`
//! either confirms the cached snapshot (`304`) or delivers a complete new one
//! bound to its `ETag` — there is no version-then-tree window. Content is
//! fetched only by the exact blob hash the validated tree advertises
//! (`GET /vfs/blob/<hash>`), and every body is verified against that hash and
//! the exact tree size before it is exposed or cached, so a path reuse or ref
//! race can never return bytes belonging to another artifact.

use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use kin_model::{ArtifactId, Hash256, TreeEntry, WorkspaceTreeSnapshot};
use kin_vfs_core::{ContentProvider, DirEntry, VfsError, VfsPath, VfsResult, VirtualStat};
use lru::LruCache;
use parking_lot::RwLock;
use serde::Deserialize;

use crate::auth::DaemonAuth;
use crate::endpoint::DaemonEndpoint;
use crate::routes;
use crate::tree_contract::{
    blob_identity, if_none_match_value, parse_etag_header, plan_succession, slice_verified_blob,
    verify_blob, verify_size, CachedTree, Succession,
};

/// Per-dispatch provenance for the synchronous provider. The VFS dispatcher
/// and every blocking provider call run on the same worker thread, so this
/// cannot be overwritten by a concurrent request on another thread. The
/// endpoint string is moved here from the actual transport attempt rather than
/// cloned back out of [`DaemonEndpoint`]'s shared mutable cache.
struct LookupEndpointCapture {
    active: bool,
    answered_by: Option<String>,
}

thread_local! {
    static LOOKUP_ENDPOINT_CAPTURE: RefCell<LookupEndpointCapture> = const {
        RefCell::new(LookupEndpointCapture {
            active: false,
            answered_by: None,
        })
    };
}

fn begin_lookup_endpoint_capture() {
    LOOKUP_ENDPOINT_CAPTURE.with(|capture| {
        let mut capture = capture.borrow_mut();
        capture.active = true;
        capture.answered_by = None;
    });
}

fn record_lookup_endpoint(endpoint: String) {
    LOOKUP_ENDPOINT_CAPTURE.with(|capture| {
        let mut capture = capture.borrow_mut();
        if capture.active {
            capture.answered_by = Some(endpoint);
        }
    });
}

fn finish_lookup_endpoint_capture() -> Option<String> {
    LOOKUP_ENDPOINT_CAPTURE.with(|capture| {
        let mut capture = capture.borrow_mut();
        capture.active = false;
        capture.answered_by.take()
    })
}

/// A `ContentProvider` that delegates to kin-daemon's `/vfs/*` HTTP endpoints.
pub struct KinDaemonProvider {
    /// Active kin-daemon base URL plus the inputs to re-resolve it when the
    /// daemon restarts on a new ephemeral port. See [`crate::endpoint`].
    endpoint: DaemonEndpoint,
    /// Optional session ID for session-scoped overlay projections.
    session_id: Option<String>,
    /// Bearer token resolved from explicit arg, `KIN_DAEMON_AUTH_TOKEN`, or the
    /// served repo's `.kin/daemon.token`. See [`crate::auth`].
    auth: DaemonAuth,
    /// Built on first use, never at construction.
    ///
    /// `reqwest::blocking::Client::new` starts a runtime on a background
    /// thread and waits for it. Constructing one from a tokio worker panics
    /// with "Cannot drop a runtime in a context where blocking is not
    /// allowed", and the NFS export builds its providers from an async
    /// handler. The panic kills the handler rather than the process, so the
    /// client never gets an answer and the read hangs in the kernel instead of
    /// failing. Every real use is already inside `spawn_blocking`, which is
    /// where this then gets built.
    client: std::sync::OnceLock<reqwest::blocking::Client>,
    tree: RwLock<Option<CachedTree>>,
    /// LRU cache of full verified blob bodies, keyed by content hash.
    /// Content-addressed, so entries stay valid across tree refreshes and a
    /// path remap can never alias stale bytes onto a new artifact.
    content_cache: RwLock<LruCache<Hash256, Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
struct EndpointHealth {
    status: String,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    repo_root: Option<String>,
}

impl KinDaemonProvider {
    /// Maximum number of blob bodies to cache for range reads.
    const CONTENT_CACHE_CAP: usize = 64;

    /// Create a new provider pointing at the given kin-daemon base URL.
    ///
    /// The bearer token is resolved from `KIN_DAEMON_AUTH_TOKEN` (no repo root
    /// is known here); use [`Self::with_auth`] to discover a served repo's
    /// `.kin/daemon.token`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_auth(base_url, None, None, None)
    }

    /// Create a new provider with an optional session ID.
    pub fn with_session(base_url: impl Into<String>, session_id: Option<String>) -> Self {
        Self::with_auth(base_url, session_id, None, None)
    }

    /// Create a provider with full control over auth resolution.
    ///
    /// The bearer token is resolved with precedence: `auth_token` (explicit) >
    /// `KIN_DAEMON_AUTH_TOKEN` env > `<repo_root>/.kin/daemon.token` > none.
    /// Pass the **served repo's** root as `repo_root` so a mount automatically
    /// adopts that repo's daemon token.
    pub fn with_auth(
        base_url: impl Into<String>,
        session_id: Option<String>,
        repo_root: Option<PathBuf>,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            endpoint: DaemonEndpoint::new(base_url.into(), repo_root.clone()),
            session_id,
            auth: DaemonAuth::new(auth_token, repo_root),
            client: std::sync::OnceLock::new(),
            tree: RwLock::new(None),
            content_cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(Self::CONTENT_CACHE_CAP).unwrap(),
            )),
        }
    }

    /// Default provider connecting to `http://127.0.0.1:4219`.
    pub fn default_local() -> Self {
        Self::new("http://127.0.0.1:4219")
    }

    /// The HTTP client, built on first use.
    fn client(&self) -> &reqwest::blocking::Client {
        self.client.get_or_init(reqwest::blocking::Client::new)
    }

    /// Attach the resolved bearer token to a request, if one is configured.
    fn authorized(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match self.auth.token() {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// Send a request with one independent retry budget for each mutable
    /// authority input:
    ///
    /// - `401` after re-reading the bearer token (`.kin/daemon.token` was
    ///   regenerated under a long-lived VFS daemon)
    /// - a transport failure after re-reading `.kin/daemon.port` (kin-daemon
    ///   restarted on a new ephemeral port; the pinned URL would otherwise stay
    ///   dead for the life of this process)
    ///
    /// `build` is called again to produce a fresh builder for the retry, since
    /// sending consumes the original and the retry must pick up the new URL.
    /// When no re-resolution is available the original failure stands, so an
    /// unreachable daemon is reported as unreachable rather than papered over.
    fn send_with_auth_retry<F>(&self, build: F) -> Result<reqwest::blocking::Response, String>
    where
        F: Fn(&str) -> reqwest::blocking::RequestBuilder,
    {
        let mut endpoint_retry_used = false;
        let mut auth_retry_used = false;
        loop {
            // Revalidate local authority for every network attempt. A
            // transport or auth retry may outlive a manifest downgrade, and
            // no endpoint may observe that retry (or its bearer token) after
            // repository-v6 workspace authority disappears.
            self.endpoint.preflight_scoped_request()?;
            // Re-read the repo's current advertisement before dialing. A
            // cached port can now belong to another repository after restart.
            let request_endpoint = self.endpoint.prepared_base_url()?;
            match self.authorized(build(&request_endpoint)).send() {
                Ok(response)
                    if response.status() == reqwest::StatusCode::UNAUTHORIZED
                        && !auth_retry_used =>
                {
                    auth_retry_used = true;
                    if self.auth.refresh().is_some() {
                        continue;
                    }
                    record_lookup_endpoint(request_endpoint);
                    return Ok(response);
                }
                Ok(response) => {
                    record_lookup_endpoint(request_endpoint);
                    return Ok(response);
                }
                Err(error) if !endpoint_retry_used => {
                    endpoint_retry_used = true;
                    if self
                        .endpoint
                        .refresh_after_failure(&request_endpoint)
                        .is_some()
                    {
                        continue;
                    }
                    record_lookup_endpoint(request_endpoint);
                    return Err(error.to_string());
                }
                Err(error) => {
                    record_lookup_endpoint(request_endpoint);
                    return Err(error.to_string());
                }
            }
        }
    }

    /// Build a URL with optional session_id query parameter.
    #[cfg(test)]
    fn url(&self, path: &str) -> String {
        self.url_at(&self.endpoint.base_url(), path)
    }

    /// Build a URL against the endpoint captured for this request.
    fn url_at(&self, endpoint: &str, path: &str) -> String {
        let base = format!("{endpoint}{path}");
        match &self.session_id {
            Some(sid) => format!("{}?session_id={}", base, sid),
            None => base,
        }
    }

    /// The `/health` route on the current endpoint. Not session-scoped.
    #[cfg(test)]
    fn health_url(&self) -> String {
        self.health_url_at(&self.endpoint.base_url())
    }

    fn health_url_at(&self, endpoint: &str) -> String {
        format!("{endpoint}{}", routes::HEALTH)
    }

    /// The content-addressed route for one blob hash.
    #[cfg(test)]
    fn blob_url(&self, hash: Hash256) -> String {
        self.blob_url_at(&self.endpoint.base_url(), hash)
    }

    fn blob_url_at(&self, endpoint: &str, hash: Hash256) -> String {
        self.url_at(endpoint, &format!("{}{hash}", routes::BLOB_PREFIX))
    }

    /// Check if the kin-daemon is reachable, following a restart onto a new
    /// port rather than reporting a stale URL as down.
    fn validate_endpoint_health(&self) -> Result<(), String> {
        // `/health` is a public route (no token required) but attaching the
        // bearer token is harmless and keeps every request uniform.
        let response = self.send_with_auth_retry(|endpoint| {
            self.client()
                .get(self.health_url_at(endpoint))
                .timeout(std::time::Duration::from_secs(2))
        })?;
        if !response.status().is_success() {
            return Err(format!("daemon health returned HTTP {}", response.status()));
        }
        let health = response
            .json::<EndpointHealth>()
            .map_err(|error| format!("invalid daemon health response: {error}"))?;
        if !matches!(health.status.as_str(), "ok" | "attention") {
            return Err(format!("daemon health is {}", health.status));
        }
        self.endpoint
            .validate_health_identity(health.repo_id.as_deref(), health.repo_root.as_deref())?;
        Ok(())
    }

    /// Check if the kin-daemon is reachable, following a restart onto a new
    /// port rather than reporting a stale URL as down.
    pub fn is_available(&self) -> bool {
        self.validate_endpoint_health().is_ok()
    }

    /// Invalidate the cached tree and content cache, forcing re-fetches.
    pub fn invalidate_tree(&self) {
        *self.tree.write() = None;
        self.content_cache.write().clear();
    }

    /// The stable graph identity of the artifact currently located at `path`.
    ///
    /// Paths are locations, identity is the artifact id. Callers that must
    /// distinguish "the same path" from "the same thing" across a refresh
    /// compare this rather than the path.
    pub fn artifact_id_at(&self, path: &VfsPath) -> VfsResult<ArtifactId> {
        self.with_tree(|tree| {
            tree.artifact_id_at(path).ok_or_else(|| {
                if tree.is_dir(path) {
                    VfsError::IsDirectory {
                        path: path.to_string(),
                    }
                } else {
                    VfsError::NotFound {
                        path: path.to_string(),
                    }
                }
            })
        })
    }

    /// Refresh the cached tree through the conditional ETag contract.
    ///
    /// Exactly one request: `If-None-Match` with the cached etag. A `304`
    /// confirms the cache; a `200` must carry a quoted `ETag` header equal to
    /// the document's independently recomputed canonical identity and a fully
    /// valid document, which is then installed atomically under
    /// [`plan_succession`]. Every failure leaves the prior snapshot untouched.
    fn ensure_tree(&self) -> Result<(), String> {
        let cached_etag = self.tree.read().as_ref().map(|tree| tree.etag.clone());

        let response = self
            .send_with_auth_retry(|endpoint| {
                let builder = self.client().get(self.url_at(endpoint, routes::TREE));
                match &cached_etag {
                    Some(etag) => {
                        builder.header(reqwest::header::IF_NONE_MATCH, if_none_match_value(etag))
                    }
                    None => builder,
                }
            })
            .map_err(|e| format!("tree request failed: {e}"))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let expected_etag = cached_etag
                .as_deref()
                .ok_or_else(|| "tree returned 304 without a cached snapshot".to_string())?;
            let (repository_id, workspace_id) = {
                let guard = self.tree.read();
                let cached = guard
                    .as_ref()
                    .ok_or_else(|| "tree returned 304 after cache invalidation".to_string())?;
                if cached.etag != expected_etag {
                    return Err("tree returned 304 for a superseded cached snapshot".to_string());
                }
                (
                    cached.binding.repository_id.as_str().to_owned(),
                    cached.binding.workspace_id.to_string(),
                )
            };
            self.endpoint
                .validate_tree_identity(&repository_id, &workspace_id)?;
            return Ok(());
        }
        if !response.status().is_success() {
            return Err(format!("tree returned status {}", response.status()));
        }

        let header_etag = parse_etag_header(response.headers())?;
        let snapshot: WorkspaceTreeSnapshot = response
            .json()
            .map_err(|e| format!("tree document parse failed: {e}"))?;
        let document_etag = snapshot
            .identity()
            .map_err(|error| format!("tree document validation failed: {error}"))?
            .to_string();
        if document_etag != header_etag {
            return Err(format!(
                "tree ETag header {header_etag:?} does not match document identity {document_etag:?}"
            ));
        }
        self.endpoint.validate_tree_identity(
            snapshot.binding.repository_id.as_str(),
            &snapshot.binding.workspace_id.to_string(),
        )?;
        let next = CachedTree::from_snapshot(snapshot)?;

        let mut guard = self.tree.write();
        match plan_succession(guard.as_ref(), &next)? {
            Succession::Install => {
                *guard = Some(next);
            }
            Succession::RetainCurrent => {}
        }
        Ok(())
    }

    /// Run `lookup` against the freshly ensured tree snapshot.
    fn with_tree<T>(&self, lookup: impl FnOnce(&CachedTree) -> VfsResult<T>) -> VfsResult<T> {
        self.ensure_tree().map_err(VfsError::Provider)?;
        let guard = self.tree.read();
        let cached = guard
            .as_ref()
            .ok_or_else(|| VfsError::Provider("no cached tree snapshot available".to_string()))?;
        lookup(cached)
    }

    /// Fetch one complete blob by content address and verify it against the
    /// exact hash and size the tree advertises before exposing or caching it.
    fn fetch_verified_blob(
        &self,
        hash: Hash256,
        expected_size: u64,
        path: &VfsPath,
    ) -> VfsResult<Vec<u8>> {
        if let Some(data) = self.content_cache.write().get(&hash) {
            return Ok(data.clone());
        }

        let response = self
            .send_with_auth_retry(|endpoint| self.client().get(self.blob_url_at(endpoint, hash)))
            .map_err(|e| VfsError::Provider(format!("blob request failed: {e}")))?;

        if response.status().as_u16() == 404 {
            // The validated tree references this blob; its absence is a graph
            // gap, never a path-not-found.
            return Err(VfsError::Provider(format!(
                "graph blob {hash} missing for {path}"
            )));
        }
        if !response.status().is_success() {
            return Err(VfsError::Provider(format!(
                "blob returned status {}",
                response.status()
            )));
        }

        let data = response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("blob body error: {e}")))?;
        verify_size(expected_size, data.len(), path)?;
        verify_blob(hash, &data, path)?;
        self.content_cache.write().put(hash, data.clone());
        Ok(data)
    }
}

impl ContentProvider for KinDaemonProvider {
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        let (entry, size) = self.with_tree(|tree| {
            let artifact = tree.require_artifact(path)?;
            Ok((artifact.entry, artifact.size))
        })?;
        let hash = blob_identity(entry, path)?;
        self.fetch_verified_blob(hash, size, path)
    }

    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let (entry, total_size) = self.with_tree(|tree| {
            let artifact = tree.require_artifact(path)?;
            Ok((artifact.entry, artifact.size))
        })?;
        let hash = blob_identity(entry, path)?;

        if len == 0 || offset >= total_size {
            return Ok(Vec::new());
        }
        let data = self.fetch_verified_blob(hash, total_size, path)?;
        slice_verified_blob(&data, offset, len, path)
    }

    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        self.with_tree(|tree| tree.stat_path(path))
    }

    /// Both facts leave the same snapshot under the same read guard, so the
    /// stamp names the tree that answered rather than whichever tree happened
    /// to be installed by the time a second call ran. It also costs no extra
    /// upstream request: `with_tree` already revalidates once.
    fn stat_at(&self, path: &VfsPath) -> (u64, VfsResult<VirtualStat>) {
        match self.with_tree(|tree| Ok((tree.version, tree.stat_path(path)))) {
            Ok((version, stat)) => (version, stat),
            // No snapshot answered at all. Zero is this provider's established
            // sentinel for absent authority, and it is never rememberable.
            Err(error) => (0, Err(error)),
        }
    }

    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        self.with_tree(|tree| tree.list_dir(path))
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        self.with_tree(|tree| Ok(tree.exists(path)))
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        let (entry, size) = self.with_tree(|tree| {
            match tree.require_artifact(path) {
                Ok(artifact) => Ok((artifact.entry, artifact.size)),
                // A directory has no link target; report the operation, not
                // the kind.
                Err(VfsError::IsDirectory { .. }) => Err(VfsError::InvalidInput {
                    path: path.to_string(),
                }),
                Err(error) => Err(error),
            }
        })?;
        match entry {
            TreeEntry::Symlink { target_blob } => self.fetch_verified_blob(target_blob, size, path),
            TreeEntry::Blob { .. } => Err(VfsError::InvalidInput {
                path: path.to_string(),
            }),
            TreeEntry::Gitlink { .. } => Err(VfsError::UnsupportedRepositoryBoundary {
                path: path.to_string(),
            }),
        }
    }

    fn version(&self) -> u64 {
        // A failed refresh must not make the cache clock regress to zero.
        // Keep advertising the last fully validated snapshot so the daemon's
        // version poller neither emits a false invalidation nor loses its
        // monotonic baseline. With no installed snapshot, zero remains the
        // sentinel for unavailable authority.
        let _ = self.ensure_tree();
        self.tree
            .read()
            .as_ref()
            .map(|tree| tree.version)
            .unwrap_or(0)
    }

    fn begin_lookup_endpoint(&self) {
        begin_lookup_endpoint_capture();
    }

    fn finish_lookup_endpoint(&self) -> Option<String> {
        finish_lookup_endpoint_capture()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_daemon_returns_false() {
        let provider = KinDaemonProvider::new("http://127.0.0.1:19999");
        assert!(!provider.is_available());
    }

    #[test]
    fn url_without_session() {
        let provider = KinDaemonProvider::new("http://127.0.0.1:4219");
        assert_eq!(provider.url("/vfs/tree"), "http://127.0.0.1:4219/vfs/tree");
    }

    #[test]
    fn url_with_session() {
        let provider =
            KinDaemonProvider::with_session("http://127.0.0.1:4219", Some("sess-42".into()));
        assert_eq!(
            provider.url("/vfs/tree"),
            "http://127.0.0.1:4219/vfs/tree?session_id=sess-42"
        );
        let hash = Hash256::from_bytes([0xab; 32]);
        assert_eq!(
            provider.blob_url(hash),
            format!("http://127.0.0.1:4219/vfs/blob/{hash}?session_id=sess-42")
        );
    }

    /// Header on a request built (not sent) through `authorized`.
    fn authorization_header(provider: &KinDaemonProvider) -> Option<String> {
        provider
            .authorized(provider.client().get(provider.url("/vfs/tree")))
            .build()
            .unwrap()
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    #[test]
    fn explicit_token_produces_bearer_header() {
        // An explicit token short-circuits env/file resolution, so this is
        // deterministic regardless of the ambient environment.
        let provider = KinDaemonProvider::with_auth(
            "http://127.0.0.1:4219",
            None,
            None,
            Some("secret-token".to_string()),
        );
        assert_eq!(
            authorization_header(&provider).as_deref(),
            Some("Bearer secret-token")
        );
    }

    #[test]
    fn no_token_means_no_authorization_header() {
        let _guard = crate::auth::ENV_GUARD.lock().unwrap();
        let saved = std::env::var(crate::auth::AUTH_TOKEN_ENV).ok();
        std::env::remove_var(crate::auth::AUTH_TOKEN_ENV);

        let provider = KinDaemonProvider::with_auth("http://127.0.0.1:4219", None, None, None);
        assert_eq!(authorization_header(&provider), None);

        match saved {
            Some(value) => std::env::set_var(crate::auth::AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(crate::auth::AUTH_TOKEN_ENV),
        }
    }

    #[test]
    fn repo_root_token_flows_into_header() {
        let _guard = crate::auth::ENV_GUARD.lock().unwrap();
        let saved = std::env::var(crate::auth::AUTH_TOKEN_ENV).ok();
        std::env::remove_var(crate::auth::AUTH_TOKEN_ENV);

        let dir = tempfile::tempdir().unwrap();
        let kin = dir.path().join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(kin.join("daemon.token"), "repo-token\n").unwrap();

        let provider = KinDaemonProvider::with_auth(
            "http://127.0.0.1:4219",
            None,
            Some(dir.path().to_path_buf()),
            None,
        );
        assert_eq!(
            authorization_header(&provider).as_deref(),
            Some("Bearer repo-token")
        );

        match saved {
            Some(value) => std::env::set_var(crate::auth::AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(crate::auth::AUTH_TOKEN_ENV),
        }
    }

    /// Offline provider↔daemon route contract: pins the exact (method, path)
    /// the provider emits and that each carries the bearer token. Drift in any
    /// route (via the `routes` constants) or the header shape fails here, before
    /// it can silently break against an enforcing daemon.
    #[test]
    fn contract_routes_emitted_with_bearer_token() {
        use reqwest::Method;
        let provider =
            KinDaemonProvider::with_auth("http://127.0.0.1:4219", None, None, Some("tok".into()));

        let assert_get_with_bearer = |req: reqwest::blocking::Request, path: &str| {
            assert_eq!(req.method(), Method::GET);
            assert_eq!(req.url().path(), path);
            assert_eq!(
                req.headers()
                    .get(reqwest::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
                Some("Bearer tok")
            );
        };

        // /health is built off the endpoint directly (not session-scoped).
        let health = provider
            .authorized(provider.client().get(provider.health_url()))
            .build()
            .unwrap();
        assert_get_with_bearer(health, "/health");

        let tree = provider
            .authorized(provider.client().get(provider.url(routes::TREE)))
            .build()
            .unwrap();
        assert_get_with_bearer(tree, "/vfs/tree");

        // /vfs/blob is content-addressed: the exact lowercase-hex hash.
        let hash = Hash256::from_bytes([0x5a; 32]);
        let blob = provider
            .authorized(provider.client().get(provider.blob_url(hash)))
            .build()
            .unwrap();
        assert_get_with_bearer(blob, &format!("/vfs/blob/{}", "5a".repeat(32)));
    }

    /// Live provider↔daemon contract. Ignored by default; the serialized runtime
    /// lane runs it explicitly against a real daemon (does NOT spawn one):
    ///   KIN_VFS_CONTRACT_DAEMON_URL=http://127.0.0.1:<port> \
    ///     cargo test -p kin-vfs-daemon -- --ignored live_contract
    /// Optionally set KIN_VFS_CONTRACT_REPO_ROOT so the token resolves from that
    /// repo's `.kin/daemon.token`.
    #[test]
    #[ignore = "requires a live kin-daemon; set KIN_VFS_CONTRACT_DAEMON_URL"]
    fn live_contract_against_real_daemon() {
        use kin_vfs_core::FileType;

        let url = std::env::var("KIN_VFS_CONTRACT_DAEMON_URL")
            .expect("set KIN_VFS_CONTRACT_DAEMON_URL to the running daemon's URL");
        let repo_root = std::env::var("KIN_VFS_CONTRACT_REPO_ROOT")
            .ok()
            .map(PathBuf::from);
        let provider = KinDaemonProvider::with_auth(url, None, repo_root, None);

        assert!(provider.is_available(), "/health should be reachable");
        // read_dir(root) forces the conditional /vfs/tree handshake.
        let entries = provider
            .read_dir(&VfsPath::root())
            .expect("root read_dir (/vfs/tree) should succeed");
        // Exercise /vfs/blob on the first regular file at the root, if any.
        if let Some(name) = entries
            .iter()
            .find(|e| e.file_type == FileType::File)
            .map(|e| e.name.clone())
        {
            provider
                .read_file(&VfsPath::root().join(&name))
                .expect("/vfs/blob should return content");
        }
    }
}

/// Hermetic provider↔daemon wire-contract tests over the strict versioned
/// tree document and content-addressed blob reads, including the adversarial
/// paths: malformed documents that must leave the cache untouched, stale and
/// conflicting snapshots, hash/size/range disagreement, gitlink refusal, and
/// byte-exact non-UTF8 lookup. Uses the in-process [`MockDaemon`]; no real
/// daemon is booted.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::test_support::{EndpointHandoff, MockDaemon};
    use crate::tree_contract::fixtures::{
        blob_artifact, content_artifact, gitlink_artifact, rebind, snapshot, symlink_artifact,
    };
    use kin_vfs_core::FileType;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const README: &[u8] = b"# Kin VFS\n";
    const MAIN_RS: &[u8] = b"fn main() {}\n";
    const COMPOSE_YAML: &[u8] = b"services:\n  api:\n    image: kin/example\n";
    const LOCKFILE: &[u8] = b"opaque-lock-v9\x00\x01binary-ish payload\n";
    const FORTRAN: &[u8] = b"      PROGRAM LEGACY\n      END\n";
    const RUN_SCRIPT: &[u8] = b"#!/bin/sh\nexec kin \"$@\"\n";
    const LOGO_BIN: &[u8] = &[0x00, 0xff, 0x89, b'K', b'I', b'N'];
    const LINK_TARGET: &[u8] = b"src/main.rs";
    const RAW_NAME_CONTENT: &[u8] = b"raw bytes win\n";
    const RANGED: &[u8] = &{
        let mut bytes = [0u8; 256];
        let mut index = 0;
        while index < 256 {
            bytes[index] = index as u8;
            index += 1;
        }
        bytes
    };

    /// Non-UTF8 repository path: `logs/x-<0xFF><0xFE>.log`.
    const RAW_NAME: &[u8] = b"logs/x-\xff\xfe.log";

    fn universal_snapshot() -> WorkspaceTreeSnapshot {
        snapshot(vec![
            content_artifact(1, b"README.md", README, false),
            content_artifact(2, b"src/main.rs", MAIN_RS, false),
            content_artifact(3, b"compose.yaml", COMPOSE_YAML, false),
            content_artifact(4, b"vendor.lock", LOCKFILE, false),
            content_artifact(5, b"legacy/model.f90", FORTRAN, false),
            content_artifact(6, b"scripts/run-kin", RUN_SCRIPT, true),
            content_artifact(7, b"assets/logo.bin", LOGO_BIN, false),
            symlink_artifact(8, b"current", LINK_TARGET),
            content_artifact(9, RAW_NAME, RAW_NAME_CONTENT, false),
            gitlink_artifact(10, b"vendor/dep"),
            content_artifact(11, b"data/ranged.bin", RANGED, false),
        ])
    }

    fn spawn_universal() -> (MockDaemon, KinDaemonProvider) {
        let daemon = MockDaemon::spawn(universal_snapshot());
        for content in [
            README,
            MAIN_RS,
            COMPOSE_YAML,
            LOCKFILE,
            FORTRAN,
            RUN_SCRIPT,
            LOGO_BIN,
            LINK_TARGET,
            RAW_NAME_CONTENT,
            RANGED,
        ] {
            daemon.state.insert_blob(content);
        }
        let provider = KinDaemonProvider::new(daemon.base_url());
        (daemon, provider)
    }

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    fn without_daemon_overrides<T>(body: impl FnOnce() -> T) -> T {
        let _endpoint_guard = crate::endpoint::ENV_GUARD
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _auth_guard = crate::auth::ENV_GUARD
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let saved_url = std::env::var(crate::endpoint::DAEMON_URL_ENV).ok();
        let saved_token = std::env::var(crate::auth::AUTH_TOKEN_ENV).ok();
        std::env::remove_var(crate::endpoint::DAEMON_URL_ENV);
        std::env::remove_var(crate::auth::AUTH_TOKEN_ENV);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        match saved_url {
            Some(value) => std::env::set_var(crate::endpoint::DAEMON_URL_ENV, value),
            None => std::env::remove_var(crate::endpoint::DAEMON_URL_ENV),
        }
        match saved_token {
            Some(value) => std::env::set_var(crate::auth::AUTH_TOKEN_ENV, value),
            None => std::env::remove_var(crate::auth::AUTH_TOKEN_ENV),
        }
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn write_repo_authority(root: &std::path::Path, snapshot: &WorkspaceTreeSnapshot) {
        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(
            kin.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "repo_id": snapshot.binding.repository_id.as_str(),
                "workspace_id": snapshot.binding.workspace_id.to_string(),
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn write_legacy_repo_authority(root: &std::path::Path, snapshot: &WorkspaceTreeSnapshot) {
        let kin = root.join(".kin");
        std::fs::create_dir_all(&kin).unwrap();
        std::fs::write(
            kin.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "kin_version": "0.2.1",
                "languages": [],
                "adapters": [],
                "repo_id": snapshot.binding.repository_id.as_str(),
                "created_at": "2026-01-01T00:00:00Z",
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn transport_handoff_then_rotated_token_uses_two_bounded_retries() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_repo_authority(repo.path(), &authority);

            let fresh = MockDaemon::spawn(authority);
            fresh.state.insert_blob(README);
            fresh.state.require_token("new-token");
            fresh.state.set_health_root(
                repo.path()
                    .canonicalize()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
            );

            let kin = repo.path().join(".kin");
            let handoff = EndpointHandoff::spawn(
                kin.join("daemon.port"),
                kin.join("daemon.token"),
                fresh.port(),
                "new-token",
            );
            std::fs::write(kin.join("daemon.port"), handoff.port().to_string()).unwrap();
            std::fs::write(kin.join("daemon.token"), "old-token").unwrap();
            let provider = KinDaemonProvider::with_auth(
                handoff.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                None,
            );

            assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
            assert_eq!(
                handoff.request_count(),
                1,
                "one transport failure must consume the endpoint retry budget"
            );
            assert_eq!(
                fresh.state.unauthorized_requests.load(Ordering::Relaxed),
                1,
                "the first request on the fresh endpoint uses the stale token exactly once"
            );
            assert_eq!(
                fresh.state.tree_bodies_served.load(Ordering::Relaxed),
                1,
                "the auth retry must install one exact tree, not loop"
            );
            assert_eq!(
                fresh.state.blob_requests.load(Ordering::Relaxed),
                1,
                "the verified tree must drive one content-addressed blob read"
            );
        });
    }

    #[test]
    fn manifest_downgrade_between_transport_attempts_prevents_retry() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_repo_authority(repo.path(), &authority);
            let replacement_manifest = serde_json::to_vec(&serde_json::json!({
                "kin_version": "0.2.1",
                "languages": [],
                "adapters": [],
                "repo_id": authority.binding.repository_id.as_str(),
                "created_at": "2026-01-01T00:00:00Z",
            }))
            .unwrap();

            let fresh = MockDaemon::spawn(authority);
            fresh.state.require_token("new-token");
            let kin = repo.path().join(".kin");
            let handoff = EndpointHandoff::spawn_with_manifest_rewrite(
                kin.join("daemon.port"),
                kin.join("daemon.token"),
                fresh.port(),
                "new-token",
                kin.join("manifest.json"),
                replacement_manifest,
            );
            std::fs::write(kin.join("daemon.port"), handoff.port().to_string()).unwrap();
            std::fs::write(kin.join("daemon.token"), "old-token").unwrap();
            let provider = KinDaemonProvider::with_auth(
                handoff.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                None,
            );

            assert!(matches!(
                provider.stat(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("omits workspace_id")
                        && message.contains("repository-v6")
            ));
            assert_eq!(
                handoff.request_count(),
                1,
                "the first attempt must reach only the handoff endpoint"
            );
            assert_eq!(
                fresh.state.requests.load(Ordering::Relaxed),
                0,
                "a manifest downgrade must prevent the transport retry and bearer token from reaching the replacement endpoint"
            );
            assert_eq!(fresh.state.unauthorized_requests.load(Ordering::Relaxed), 0);
            assert_eq!(fresh.state.tree_bodies_served.load(Ordering::Relaxed), 0);
            assert_eq!(fresh.state.blob_requests.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn not_modified_revalidates_cached_tree_against_current_manifest() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_repo_authority(repo.path(), &authority);
            let daemon = MockDaemon::spawn(authority.clone());
            std::fs::write(
                repo.path().join(".kin").join("daemon.port"),
                daemon.port().to_string(),
            )
            .unwrap();
            let provider = KinDaemonProvider::with_auth(
                daemon.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                None,
            );

            assert!(
                provider.stat(&path("README.md")).is_ok(),
                "the first response must install the workspace-A cache"
            );
            let mut replacement_authority = authority;
            replacement_authority.binding.workspace_id =
                kin_model::WorkspaceId::from_uuid(uuid::Uuid::from_u128(0xcafe));
            write_repo_authority(repo.path(), &replacement_authority);

            assert!(matches!(
                provider.stat(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("tree workspace mismatch")
            ));
            assert_eq!(
                daemon.state.tree_bodies_served.load(Ordering::Relaxed),
                1,
                "the second tree response is a 304 and must not silently authorize the workspace-A cache under workspace B"
            );
            assert_eq!(daemon.state.blob_requests.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn reused_port_serving_another_repo_cannot_install_or_serve_data() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_repo_authority(repo.path(), &authority);

            let mut foreign = universal_snapshot();
            foreign.binding.repository_id =
                kin_model::RepositoryId::new("foreign-repository").unwrap();
            let foreign = MockDaemon::spawn(foreign);
            foreign.state.insert_blob(README);
            foreign.state.set_health_root(
                repo.path()
                    .canonicalize()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
            std::fs::write(
                repo.path().join(".kin").join("daemon.port"),
                foreign.port().to_string(),
            )
            .unwrap();

            let provider = KinDaemonProvider::with_auth(
                foreign.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                None,
            );
            assert!(
                !provider.is_available(),
                "health from another repository must not satisfy availability"
            );
            assert!(matches!(
                provider.read_file(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("tree repository mismatch")
            ));
            assert_eq!(
                foreign.state.blob_requests.load(Ordering::Relaxed),
                0,
                "a foreign tree binding must fail before any blob can be fetched"
            );
        });
    }

    #[test]
    fn manifest_without_workspace_id_never_sends_a_request() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_legacy_repo_authority(repo.path(), &authority);

            let daemon = MockDaemon::spawn(authority);
            daemon.state.require_token("must-not-leave-process");
            let port_file = repo.path().join(".kin").join("daemon.port");
            std::fs::write(&port_file, daemon.port().to_string()).unwrap();
            let provider = KinDaemonProvider::with_auth(
                daemon.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                Some("must-not-leave-process".to_string()),
            );

            assert!(
                !provider.is_available(),
                "legacy availability must fail from local authority alone"
            );
            assert!(matches!(
                provider.read_file(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("omits workspace_id")
                        && message.contains("repository-v6")
            ));
            assert_eq!(
                daemon.state.requests.load(Ordering::Relaxed),
                0,
                "a manifest without workspace_id must fail before health, tree, blob, or token disclosure"
            );
            assert_eq!(
                daemon.state.unauthorized_requests.load(Ordering::Relaxed),
                0,
                "the daemon must not observe even a stale-token attempt"
            );
            assert_eq!(daemon.state.tree_bodies_served.load(Ordering::Relaxed), 0);
            assert_eq!(daemon.state.blob_requests.load(Ordering::Relaxed), 0);
        });
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_scoped_root_never_sends_a_request() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            let non_utf8_root = repo
                .path()
                .join(OsString::from_vec(b"workspace-\xff".to_vec()));
            let daemon = MockDaemon::spawn(authority);
            daemon.state.require_token("must-not-leave-process");
            let provider = KinDaemonProvider::with_auth(
                daemon.base_url(),
                None,
                Some(non_utf8_root),
                Some("must-not-leave-process".to_string()),
            );

            assert!(
                !provider.is_available(),
                "non-UTF8 scoped availability must fail locally"
            );
            assert!(matches!(
                provider.read_file(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("not valid UTF-8")
            ));
            assert_eq!(
                daemon.state.requests.load(Ordering::Relaxed),
                0,
                "a non-UTF8 scoped root must fail before any request or token disclosure"
            );
            assert_eq!(
                daemon.state.unauthorized_requests.load(Ordering::Relaxed),
                0
            );
        });
    }

    #[test]
    fn concurrent_endpoint_move_preserves_current_workspace_tree_identity() {
        without_daemon_overrides(|| {
            let authority = universal_snapshot();
            let repo = tempfile::tempdir().unwrap();
            write_repo_authority(repo.path(), &authority);

            let mut wrong_workspace_authority = authority.clone();
            wrong_workspace_authority.binding.workspace_id =
                kin_model::WorkspaceId::from_uuid(uuid::Uuid::from_u128(0xbeef));

            let endpoint_a = MockDaemon::spawn(authority.clone());
            endpoint_a.state.insert_blob(README);
            let endpoint_b = MockDaemon::spawn(wrong_workspace_authority);
            let canonical_root = repo
                .path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            endpoint_a.state.set_health_root(canonical_root.clone());
            endpoint_b.state.set_health_root(canonical_root);

            let port_file = repo.path().join(".kin").join("daemon.port");
            std::fs::write(&port_file, endpoint_a.port().to_string()).unwrap();
            let provider = Arc::new(KinDaemonProvider::with_auth(
                endpoint_a.base_url(),
                None,
                Some(repo.path().to_path_buf()),
                None,
            ));
            let (tree_arrived, release_tree) = endpoint_a.state.gate_next_tree_response();

            let reader = {
                let provider = Arc::clone(&provider);
                std::thread::spawn(move || {
                    provider.begin_lookup_endpoint();
                    let result = provider.stat(&path("README.md"));
                    let answered_by = provider.finish_lookup_endpoint();
                    (result, answered_by)
                })
            };
            tree_arrived
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("endpoint A tree response did not reach the gate");

            // Move a second request to B while A's workspace-bound tree response
            // is in flight. The shared endpoint cache now names B, but the
            // captured A response must retain its own identity.
            std::fs::write(&port_file, endpoint_b.port().to_string()).unwrap();
            let endpoint_b_available = provider.is_available();
            release_tree
                .send(())
                .expect("release endpoint A tree response");
            let (stat, answered_by) = reader
                .join()
                .expect("join concurrent current-workspace stat");
            let stat = stat.expect("endpoint A tree remains valid after the concurrent move");

            assert!(
                endpoint_b_available,
                "health alone cannot distinguish B's wrong tree workspace"
            );
            assert!(stat.is_file);
            assert_eq!(
                answered_by.as_deref(),
                Some(endpoint_a.base_url()),
                "request A must retain the endpoint that answered it even after the shared cache moved to B"
            );
            assert_eq!(
                endpoint_a.state.tree_bodies_served.load(Ordering::Relaxed),
                1
            );
            assert!(matches!(
                provider.stat(&path("README.md")),
                Err(VfsError::Provider(message))
                    if message.contains("tree workspace mismatch")
            ));
            assert_eq!(
                endpoint_b.state.tree_bodies_served.load(Ordering::Relaxed),
                1,
                "the next request must validate B's tree against the local workspace"
            );
            assert_eq!(
                endpoint_b.state.blob_requests.load(Ordering::Relaxed),
                0,
                "a wrong-workspace tree must fail before content"
            );

            std::fs::write(&port_file, endpoint_a.port().to_string()).unwrap();
            assert!(
                provider.stat(&path("README.md")).is_ok(),
                "the provider must recover when the current workspace endpoint returns"
            );
        });
    }

    #[test]
    fn universal_entries_serve_exact_bytes() {
        let (_daemon, provider) = spawn_universal();

        // Language-agnostic coverage: docs, source, Compose config, an opaque
        // lockfile, unsupported-language source, an executable, and raw binary
        // all serve byte-exact content through the same contract.
        for (name, expected) in [
            ("README.md", README),
            ("src/main.rs", MAIN_RS),
            ("compose.yaml", COMPOSE_YAML),
            ("vendor.lock", LOCKFILE),
            ("legacy/model.f90", FORTRAN),
            ("scripts/run-kin", RUN_SCRIPT),
            ("assets/logo.bin", LOGO_BIN),
        ] {
            assert_eq!(
                provider.read_file(&path(name)).unwrap(),
                expected,
                "{name} bytes must round-trip exactly"
            );
        }

        let executable = provider.stat(&path("scripts/run-kin")).unwrap();
        assert!(executable.is_file);
        assert_eq!(executable.mode, 0o755, "executable bit preserved");
        assert_eq!(executable.mtime, 1_006);

        let config = provider.stat(&path("compose.yaml")).unwrap();
        assert_eq!(config.mode, 0o644);
        assert_eq!(config.size, COMPOSE_YAML.len() as u64);
        assert_eq!(
            config.content_hash,
            Some(Sha256::digest(COMPOSE_YAML).into())
        );
    }

    #[test]
    fn symlink_target_bytes_are_content_addressed() {
        let (_daemon, provider) = spawn_universal();
        let link = path("current");

        let stat = provider.stat(&link).unwrap();
        assert!(stat.is_symlink);
        assert_eq!(stat.size, LINK_TARGET.len() as u64);
        assert_eq!(provider.read_link(&link).unwrap(), LINK_TARGET);

        assert!(matches!(
            provider.read_link(&path("README.md")),
            Err(VfsError::InvalidInput { .. })
        ));
        assert!(matches!(
            provider.read_link(&path("src")),
            Err(VfsError::InvalidInput { .. })
        ));
    }

    #[test]
    fn non_utf8_paths_resolve_byte_exactly() {
        let (_daemon, provider) = spawn_universal();
        let raw = VfsPath::from_bytes(RAW_NAME.to_vec()).unwrap();

        assert_eq!(provider.read_file(&raw).unwrap(), RAW_NAME_CONTENT);
        assert!(provider.exists(&raw).unwrap());

        // One byte different in the same position is a different identity.
        let near_miss = VfsPath::from_bytes(b"logs/x-\xff\xfd.log".to_vec()).unwrap();
        assert!(matches!(
            provider.read_file(&near_miss),
            Err(VfsError::NotFound { .. })
        ));

        // The listing carries the raw name bytes unmodified.
        let names: Vec<Vec<u8>> = provider
            .read_dir(&path("logs"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.into_bytes())
            .collect();
        assert_eq!(names, vec![b"x-\xff\xfe.log".to_vec()]);
    }

    #[test]
    fn read_dir_carries_gitlinks_and_kinds() {
        let (_daemon, provider) = spawn_universal();
        let got: Vec<(Vec<u8>, FileType)> = provider
            .read_dir(&VfsPath::root())
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.into_bytes(), entry.file_type))
            .collect();
        assert_eq!(
            got,
            vec![
                (b"README.md".to_vec(), FileType::File),
                (b"assets".to_vec(), FileType::Directory),
                (b"compose.yaml".to_vec(), FileType::File),
                (b"current".to_vec(), FileType::Symlink),
                (b"data".to_vec(), FileType::Directory),
                (b"legacy".to_vec(), FileType::Directory),
                (b"logs".to_vec(), FileType::Directory),
                (b"scripts".to_vec(), FileType::Directory),
                (b"src".to_vec(), FileType::Directory),
                (b"vendor".to_vec(), FileType::Directory),
                (b"vendor.lock".to_vec(), FileType::File),
            ],
            "root listing is sorted and preserves every entry kind"
        );

        let vendor: Vec<(Vec<u8>, FileType)> = provider
            .read_dir(&path("vendor"))
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.into_bytes(), entry.file_type))
            .collect();
        assert_eq!(vendor, vec![(b"dep".to_vec(), FileType::Gitlink)]);
    }

    #[test]
    fn gitlink_paths_fail_with_typed_boundary_error() {
        let (_daemon, provider) = spawn_universal();
        let dep = path("vendor/dep");

        assert!(matches!(
            provider.stat(&dep),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        assert!(matches!(
            provider.read_file(&dep),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        assert!(matches!(
            provider.read_range(&dep, 0, 1),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        assert!(matches!(
            provider.read_link(&dep),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        // The path itself exists in the tree — it is a boundary, not a hole.
        assert!(provider.exists(&dep).unwrap());
    }

    #[test]
    fn conditional_refresh_uses_etag_not_a_second_probe() {
        let (daemon, provider) = spawn_universal();

        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
        assert_eq!(provider.read_file(&path("src/main.rs")).unwrap(), MAIN_RS);
        assert_eq!(
            daemon.state.tree_bodies_served.load(Ordering::Relaxed),
            1,
            "second operation must revalidate with If-None-Match (304), not refetch"
        );
        assert_eq!(provider.version(), 7);
    }

    #[test]
    fn refresh_installs_new_snapshot_and_rebinds_content() {
        let (daemon, provider) = spawn_universal();
        let readme = path("README.md");
        assert_eq!(provider.read_file(&readme).unwrap(), README);

        // The path is reused for entirely different content at a new head.
        let replacement = b"# Rewritten\n";
        daemon.state.insert_blob(replacement);
        let mut next = universal_snapshot();
        next.artifacts[0] = content_artifact(1, b"README.md", replacement, false);
        rebind(&mut next);
        next.binding.roots.generation = 8;
        next.binding.workspace_generation = 4;
        daemon.state.set_snapshot(next);

        assert_eq!(
            provider.read_file(&readme).unwrap(),
            replacement,
            "reads after refresh must bind to the new artifact's exact hash"
        );
        assert_eq!(provider.version(), 8);
        assert_eq!(
            provider.artifact_id_at(&readme).unwrap(),
            crate::tree_contract::fixtures::artifact_id(1),
            "the path still resolves to its stable graph identity"
        );

        // The same path now hosts a DIFFERENT artifact identity. Content must
        // follow the new artifact, never the previously cached bytes.
        let moved_in = b"# Different artifact entirely\n";
        daemon.state.insert_blob(moved_in);
        let mut swapped = universal_snapshot();
        swapped.artifacts[0] = content_artifact(999, b"README.md", moved_in, false);
        rebind(&mut swapped);
        swapped.binding.roots.generation = 9;
        swapped.binding.workspace_generation = 5;
        daemon.state.set_snapshot(swapped);

        assert_eq!(
            provider.artifact_id_at(&readme).unwrap(),
            crate::tree_contract::fixtures::artifact_id(999),
            "path reuse must report the new artifact identity"
        );
        assert_eq!(
            provider.read_file(&readme).unwrap(),
            moved_in,
            "a path reuse must never return the prior artifact's bytes"
        );
    }

    #[test]
    fn directory_stat_listing_and_cache_version_advance_from_one_snapshot() {
        let initial = snapshot(vec![
            blob_artifact(1, b"left/older.bin", 1, false, 1),
            blob_artifact(99, b"left/newest.bin", 2, false, 1),
            blob_artifact(2, b"right/keep.bin", 3, false, 1),
            content_artifact(3, b"compose.yaml", COMPOSE_YAML, false),
            symlink_artifact(4, b"right/current", b"keep.bin"),
            gitlink_artifact(5, b"right/vendor"),
        ]);
        let daemon = MockDaemon::spawn(initial.clone());
        let provider = KinDaemonProvider::new(daemon.base_url());
        let left = path("left");
        let root = VfsPath::root();

        assert_eq!(provider.stat(&left).unwrap().mtime, 7);
        assert_eq!(provider.version(), 7);
        assert_eq!(
            provider
                .read_dir(&left)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name.into_bytes())
                .collect::<Vec<_>>(),
            vec![b"newest.bin".to_vec(), b"older.bin".to_vec()]
        );

        let mut next = initial;
        next.artifacts
            .retain(|artifact| artifact.path.as_bytes() != b"left/newest.bin");
        rebind(&mut next);
        next.binding.roots.generation = 8;
        next.binding.workspace_generation = 4;
        daemon.state.set_snapshot(next);

        assert_eq!(
            provider
                .read_dir(&left)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name.into_bytes())
                .collect::<Vec<_>>(),
            vec![b"older.bin".to_vec()],
            "readdir must install and use the same exact successor snapshot"
        );
        assert_eq!(provider.stat(&left).unwrap().mtime, 8);
        assert_eq!(provider.stat(&root).unwrap().mtime, 8);
        assert_eq!(provider.version(), 8);

        *daemon.state.tree_body_override.lock().unwrap() = Some(b"not json".to_vec());
        *daemon.state.etag_header_override.lock().unwrap() = Some("\"tree-9\"".to_string());
        assert_eq!(
            provider.version(),
            8,
            "a refresh fault must retain the installed cache version, never regress to zero"
        );
    }

    #[test]
    fn malformed_refresh_retains_prior_snapshot_unchanged() {
        let (daemon, provider) = spawn_universal();
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);

        let malformed: Vec<(&str, Vec<u8>)> = vec![
            ("garbage", b"not json".to_vec()),
            (
                "unknown field",
                serde_json::to_vec(&{
                    let mut value = serde_json::to_value(universal_snapshot()).unwrap();
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("surprise".to_string(), serde_json::json!(1));
                    value
                })
                .unwrap(),
            ),
            (
                "unsupported schema",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot.schema = 99;
                    snapshot.binding.roots.generation = 9;
                    snapshot
                })
                .unwrap(),
            ),
            (
                "duplicate artifact id",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot
                        .artifacts
                        .push(blob_artifact(1, b"dup.txt", 9, false, 1));
                    snapshot.binding.roots.generation = 9;
                    snapshot
                })
                .unwrap(),
            ),
            (
                "prefix collision",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot
                        .artifacts
                        .push(blob_artifact(90, b"src", 9, false, 1));
                    snapshot.binding.roots.generation = 9;
                    snapshot
                })
                .unwrap(),
            ),
        ];

        for (label, body) in malformed {
            *daemon.state.tree_body_override.lock().unwrap() = Some(body);
            *daemon.state.etag_header_override.lock().unwrap() = Some("\"tree-9\"".to_string());
            assert!(
                matches!(
                    provider.read_file(&path("README.md")),
                    Err(VfsError::Provider(_))
                ),
                "{label}: malformed refresh must fail loud"
            );

            // Clearing the fault shows the prior snapshot was retained intact:
            // the cached etag still revalidates and content still serves.
            *daemon.state.tree_body_override.lock().unwrap() = None;
            *daemon.state.etag_header_override.lock().unwrap() = None;
            assert_eq!(
                provider.read_file(&path("README.md")).unwrap(),
                README,
                "{label}: prior snapshot must remain fully usable"
            );
            assert_eq!(provider.version(), 7, "{label}: version must be unchanged");
        }
    }

    #[test]
    fn etag_header_and_document_must_agree() {
        let (daemon, provider) = spawn_universal();
        // Fresh provider, first fetch: header says one thing, body another.
        *daemon.state.etag_header_override.lock().unwrap() = Some("\"other\"".to_string());
        assert!(matches!(
            provider.read_file(&path("README.md")),
            Err(VfsError::Provider(_))
        ));

        *daemon.state.etag_header_override.lock().unwrap() = None;
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
    }

    #[test]
    fn stale_and_conflicting_snapshots_never_install() {
        let (daemon, provider) = spawn_universal();
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
        assert_eq!(provider.version(), 7);

        // Regressed version: the stale snapshot is refused; the newer cached
        // one keeps serving.
        let mut stale = universal_snapshot();
        stale.binding.roots.generation = 6;
        daemon.state.set_snapshot(stale);
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
        assert_eq!(provider.version(), 7, "stale snapshot must not install");

        // Same version, different etag: a ref race fails loud and retains the
        // prior snapshot.
        let mut race = universal_snapshot();
        race.artifacts[0].mtime += 1;
        daemon.state.set_snapshot(race);
        assert!(matches!(
            provider.read_file(&path("README.md")),
            Err(VfsError::Provider(_))
        ));
        daemon.state.set_snapshot(universal_snapshot());
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
    }

    #[test]
    fn blob_hash_and_size_disagreement_fail_loud() {
        let daemon = MockDaemon::spawn(snapshot(vec![
            content_artifact(1, b"bad-size.bin", b"integrity", false),
            blob_artifact(2, b"bad-hash.bin", 0x44, false, 9),
        ]));
        // bad-size.bin: tree advertises the hash of "integrity" but a body of
        // a different length is served under that hash.
        daemon.state.insert_blob_at(
            &hex::encode(Sha256::digest(b"integrity")),
            b"integrity-plus-extra",
        );
        // bad-hash.bin: tree advertises 0x44…44 (size 9); the daemon serves
        // "integrity" (correct size, wrong bytes).
        daemon.state.insert_blob_at(&"44".repeat(32), b"integrity");
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert!(matches!(
            provider.read_file(&path("bad-size.bin")),
            Err(VfsError::Provider(_))
        ));
        assert!(matches!(
            provider.read_file(&path("bad-hash.bin")),
            Err(VfsError::Provider(_))
        ));
    }

    #[test]
    fn missing_blob_is_a_graph_gap_not_path_not_found() {
        let daemon = MockDaemon::spawn(snapshot(vec![content_artifact(
            1,
            b"present.txt",
            b"tracked",
            false,
        )]));
        // Deliberately do NOT insert the blob.
        let provider = KinDaemonProvider::new(daemon.base_url());
        match provider.read_file(&path("present.txt")) {
            Err(VfsError::Provider(message)) => {
                assert!(message.contains("missing"), "{message}");
            }
            other => panic!("expected loud graph gap, got {other:?}"),
        }
    }

    #[test]
    fn ranged_reads_verify_the_whole_blob_before_slicing_and_cache_it() {
        let (daemon, provider) = spawn_universal();
        let ranged = path("data/ranged.bin");

        let before = daemon.state.blob_requests.load(Ordering::Relaxed);
        let slice = provider.read_range(&ranged, 246, 10).unwrap();
        assert_eq!(slice, (246..=255).map(|b| b as u8).collect::<Vec<u8>>());

        // The verified full body was cached; the second slice is local.
        let cached = provider.read_range(&ranged, 0, 3).unwrap();
        assert_eq!(cached, vec![0, 1, 2]);
        assert_eq!(
            daemon.state.blob_requests.load(Ordering::Relaxed),
            before + 1,
            "second range must be served from the verified content cache"
        );

        // A same-length corrupt body served under the expected address must
        // fail before any partial bytes escape.
        let mut corrupt = RANGED.to_vec();
        corrupt[255] ^= 0xff;
        daemon
            .state
            .insert_blob_at(&hex::encode(Sha256::digest(RANGED)), &corrupt);
        provider.invalidate_tree();
        assert!(matches!(
            provider.read_range(&ranged, 246, 10),
            Err(VfsError::Provider(_))
        ));
    }

    #[test]
    fn empty_and_out_of_bounds_ranges_are_empty() {
        let (_daemon, provider) = spawn_universal();
        let ranged = path("data/ranged.bin");
        assert!(provider.read_range(&ranged, 0, 0).unwrap().is_empty());
        assert!(provider
            .read_range(&ranged, RANGED.len() as u64, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn symlink_targets_may_be_non_utf8_bytes() {
        // A symlink target is opaque bytes, not text. The provider must serve
        // it byte-exactly; anything else would resolve to a different path.
        let target: &[u8] = b"logs/x-\xff\xfe.log";
        let daemon = MockDaemon::spawn(snapshot(vec![symlink_artifact(1, b"raw-link", target)]));
        daemon.state.insert_blob(target);
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert_eq!(provider.read_link(&path("raw-link")).unwrap(), target);
        assert_eq!(
            provider.stat(&path("raw-link")).unwrap().size,
            target.len() as u64
        );
    }

    #[test]
    fn empty_tree_serves_only_the_root() {
        let daemon = MockDaemon::spawn(snapshot(vec![]));
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert!(provider.read_dir(&VfsPath::root()).unwrap().is_empty());
        assert!(provider.stat(&VfsPath::root()).unwrap().is_dir);
        assert!(provider.exists(&VfsPath::root()).unwrap());
        assert!(matches!(
            provider.stat(&path("anything")),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn zero_length_blob_is_verified_not_skipped() {
        // An empty file still has an exact content address; serving it must
        // verify that hash rather than short-circuiting on the length.
        let daemon = MockDaemon::spawn(snapshot(vec![content_artifact(1, b"empty", b"", false)]));
        daemon.state.insert_blob(b"");
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert_eq!(provider.read_file(&path("empty")).unwrap(), b"");
        assert_eq!(provider.stat(&path("empty")).unwrap().size, 0);
    }

    #[test]
    fn directory_kind_errors_are_precise() {
        let (_daemon, provider) = spawn_universal();
        assert!(matches!(
            provider.read_file(&path("scripts")),
            Err(VfsError::IsDirectory { .. })
        ));
        assert!(matches!(
            provider.read_range(&path("scripts"), 0, 1),
            Err(VfsError::IsDirectory { .. })
        ));
        assert!(matches!(
            provider.read_dir(&path("README.md")),
            Err(VfsError::NotDirectory { .. })
        ));
        assert!(matches!(
            provider.stat(&path("ghost.rs")),
            Err(VfsError::NotFound { .. })
        ));
        let root = provider.stat(&VfsPath::root()).unwrap();
        assert!(root.is_dir);
    }
}
