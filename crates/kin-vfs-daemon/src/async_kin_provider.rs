// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Async `ContentProvider` backed by kin-daemon's HTTP API.
//!
//! Uses `reqwest::Client` (async) so it can be driven directly from the
//! tokio-based daemon server without `spawn_blocking`. Speaks exactly the same
//! contract as [`super::KinDaemonProvider`]: one conditional `If-None-Match`
//! tree request (no version-then-tree window) and content-addressed
//! `/vfs/blob/<hash>` reads verified against the exact hash and size the
//! validated tree advertises.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use kin_model::{Hash256, TreeEntry, WorkspaceTreeSnapshot};
use kin_vfs_core::{AsyncContentProvider, DirEntry, VfsError, VfsPath, VfsResult, VirtualStat};
use lru::LruCache;
use tokio::sync::RwLock;

use crate::auth::DaemonAuth;
use crate::routes;
use crate::tree_contract::{
    blob_identity, if_none_match_value, parse_etag_header, plan_succession, slice_verified_blob,
    verify_blob, verify_size, CachedTree, Succession,
};

/// An async `ContentProvider` that delegates to kin-daemon's `/vfs/*` HTTP
/// endpoints using `reqwest::Client`.
///
/// Designed for use inside the tokio-based VFS daemon server. For sync
/// contexts (e.g. the shim), use [`super::KinDaemonProvider`] instead.
pub struct AsyncKinDaemonProvider {
    base_url: String,
    session_id: Option<String>,
    /// Bearer token resolved from explicit arg, `KIN_DAEMON_AUTH_TOKEN`, or the
    /// served repo's `.kin/daemon.token`. See [`crate::auth`].
    auth: DaemonAuth,
    client: reqwest::Client,
    tree: RwLock<Option<CachedTree>>,
    /// LRU cache of full verified blob bodies, keyed by content hash.
    content_cache: RwLock<LruCache<Hash256, Vec<u8>>>,
}

impl AsyncKinDaemonProvider {
    const CONTENT_CACHE_CAP: usize = 64;

    /// Create a new async provider pointing at the given kin-daemon base URL.
    ///
    /// The bearer token is resolved from `KIN_DAEMON_AUTH_TOKEN` (no repo root
    /// is known here); use [`Self::with_auth`] to discover a served repo's
    /// `.kin/daemon.token`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_auth(base_url, None, None, None)
    }

    /// Create a new async provider with an optional session ID.
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
            base_url: base_url.into(),
            session_id,
            auth: DaemonAuth::new(auth_token, repo_root),
            client: reqwest::Client::new(),
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

    /// Attach the resolved bearer token to a request, if one is configured.
    fn authorized(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth.token() {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// Send a request with the bearer token attached, retrying once with a
    /// freshly re-resolved token if the daemon answers `401` (covers the rare
    /// case where `.kin/daemon.token` was regenerated under a long-lived VFS
    /// daemon). `build` is called again to produce a fresh builder for the
    /// retry since sending consumes the original.
    async fn send_with_auth_retry<F>(&self, build: F) -> reqwest::Result<reqwest::Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let response = self.authorized(build()).send().await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && self.auth.refresh().is_some() {
            return self.authorized(build()).send().await;
        }
        Ok(response)
    }

    /// Check if the kin-daemon is reachable.
    pub async fn is_available(&self) -> bool {
        // `/health` is a public route (no token required) but attaching the
        // bearer token is harmless and keeps every request uniform.
        self.authorized(
            self.client
                .get(format!("{}{}", self.base_url, routes::HEALTH))
                .timeout(std::time::Duration::from_secs(2)),
        )
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
    }

    /// Invalidate the cached tree and content cache.
    pub async fn invalidate_tree(&self) {
        *self.tree.write().await = None;
        self.content_cache.write().await.clear();
    }

    fn url(&self, path: &str) -> String {
        let base = format!("{}{}", self.base_url, path);
        match &self.session_id {
            Some(sid) => format!("{}?session_id={}", base, sid),
            None => base,
        }
    }

    /// The content-addressed route for one blob hash.
    fn blob_url(&self, hash: Hash256) -> String {
        self.url(&format!("{}{hash}", routes::BLOB_PREFIX))
    }

    /// Refresh the cached tree through the conditional ETag contract.
    ///
    /// Exactly one request. A `304` confirms the cache; a `200` must carry a
    /// quoted `ETag` header equal to the document's independently recomputed
    /// canonical identity and a fully valid document, installed atomically
    /// under [`plan_succession`]. Every failure leaves the prior snapshot
    /// untouched.
    async fn ensure_tree(&self) -> Result<(), String> {
        let cached_etag = self
            .tree
            .read()
            .await
            .as_ref()
            .map(|tree| tree.etag.clone());

        let response = self
            .send_with_auth_retry(|| {
                let builder = self.client.get(self.url(routes::TREE));
                match &cached_etag {
                    Some(etag) => {
                        builder.header(reqwest::header::IF_NONE_MATCH, if_none_match_value(etag))
                    }
                    None => builder,
                }
            })
            .await
            .map_err(|e| format!("tree request failed: {e}"))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cached_etag.is_some() {
                return Ok(());
            }
            return Err("tree returned 304 without a cached snapshot".to_string());
        }
        if !response.status().is_success() {
            return Err(format!("tree returned status {}", response.status()));
        }

        let header_etag = parse_etag_header(response.headers())?;
        let snapshot: WorkspaceTreeSnapshot = response
            .json()
            .await
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
        let next = CachedTree::from_snapshot(snapshot)?;

        let mut guard = self.tree.write().await;
        match plan_succession(guard.as_ref(), &next)? {
            Succession::Install => {
                *guard = Some(next);
            }
            Succession::RetainCurrent => {}
        }
        Ok(())
    }

    /// Run `lookup` against the freshly ensured tree snapshot.
    async fn with_tree<T>(&self, lookup: impl FnOnce(&CachedTree) -> VfsResult<T>) -> VfsResult<T> {
        self.ensure_tree().await.map_err(VfsError::Provider)?;
        let guard = self.tree.read().await;
        let cached = guard
            .as_ref()
            .ok_or_else(|| VfsError::Provider("no cached tree snapshot available".to_string()))?;
        lookup(cached)
    }

    /// Fetch one complete blob by content address and verify it against the
    /// exact hash and size the tree advertises before exposing or caching it.
    async fn fetch_verified_blob(
        &self,
        hash: Hash256,
        expected_size: u64,
        path: &VfsPath,
    ) -> VfsResult<Vec<u8>> {
        if let Some(data) = self.content_cache.write().await.get(&hash) {
            return Ok(data.clone());
        }

        let response = self
            .send_with_auth_retry(|| self.client.get(self.blob_url(hash)))
            .await
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
            .await
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("blob body error: {e}")))?;
        verify_size(expected_size, data.len(), path)?;
        verify_blob(hash, &data, path)?;
        self.content_cache.write().await.put(hash, data.clone());
        Ok(data)
    }
}

impl AsyncContentProvider for AsyncKinDaemonProvider {
    async fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        let (entry, size) = self
            .with_tree(|tree| {
                let artifact = tree.require_artifact(path)?;
                Ok((artifact.entry, artifact.size))
            })
            .await?;
        let hash = blob_identity(entry, path)?;
        self.fetch_verified_blob(hash, size, path).await
    }

    async fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let (entry, total_size) = self
            .with_tree(|tree| {
                let artifact = tree.require_artifact(path)?;
                Ok((artifact.entry, artifact.size))
            })
            .await?;
        let hash = blob_identity(entry, path)?;

        if len == 0 || offset >= total_size {
            return Ok(Vec::new());
        }
        let data = self.fetch_verified_blob(hash, total_size, path).await?;
        slice_verified_blob(&data, offset, len, path)
    }

    async fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        self.with_tree(|tree| tree.stat_path(path)).await
    }

    async fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        self.with_tree(|tree| tree.list_dir(path)).await
    }

    async fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        self.with_tree(|tree| Ok(tree.exists(path))).await
    }

    async fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        let (entry, size) = self
            .with_tree(|tree| match tree.require_artifact(path) {
                Ok(artifact) => Ok((artifact.entry, artifact.size)),
                // A directory has no link target; report the operation, not
                // the kind.
                Err(VfsError::IsDirectory { .. }) => Err(VfsError::InvalidInput {
                    path: path.to_string(),
                }),
                Err(error) => Err(error),
            })
            .await?;
        match entry {
            TreeEntry::Symlink { target_blob } => {
                self.fetch_verified_blob(target_blob, size, path).await
            }
            TreeEntry::Blob { .. } => Err(VfsError::InvalidInput {
                path: path.to_string(),
            }),
            TreeEntry::Gitlink { .. } => Err(VfsError::UnsupportedRepositoryBoundary {
                path: path.to_string(),
            }),
        }
    }

    async fn version(&self) -> u64 {
        if self.ensure_tree().await.is_err() {
            return 0;
        }
        self.tree
            .read()
            .await
            .as_ref()
            .map(|tree| tree.version)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_daemon_returns_false() {
        let provider = AsyncKinDaemonProvider::new("http://127.0.0.1:19999");
        assert!(!provider.is_available().await);
    }

    #[test]
    fn url_without_session() {
        let provider = AsyncKinDaemonProvider::new("http://127.0.0.1:4219");
        assert_eq!(provider.url("/vfs/tree"), "http://127.0.0.1:4219/vfs/tree");
    }

    #[test]
    fn url_with_session() {
        let provider =
            AsyncKinDaemonProvider::with_session("http://127.0.0.1:4219", Some("sess-42".into()));
        assert_eq!(
            provider.url("/vfs/tree"),
            "http://127.0.0.1:4219/vfs/tree?session_id=sess-42"
        );
    }

    /// Header on a request built (not sent) through `authorized`.
    fn authorization_header(provider: &AsyncKinDaemonProvider) -> Option<String> {
        provider
            .authorized(provider.client.get(provider.url("/vfs/tree")))
            .build()
            .unwrap()
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    #[test]
    fn explicit_token_produces_bearer_header() {
        let provider = AsyncKinDaemonProvider::with_auth(
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

        let provider = AsyncKinDaemonProvider::with_auth("http://127.0.0.1:4219", None, None, None);
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

        let provider = AsyncKinDaemonProvider::with_auth(
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

    /// Offline provider↔daemon route contract (async): pins the exact
    /// (method, path) emitted and the bearer-header shape, same as the sync
    /// provider, so both stay aligned with the daemon.
    #[test]
    fn contract_routes_emitted_with_bearer_token() {
        use reqwest::Method;
        let provider = AsyncKinDaemonProvider::with_auth(
            "http://127.0.0.1:4219",
            None,
            None,
            Some("tok".into()),
        );

        let assert_get_with_bearer = |req: reqwest::Request, path: &str| {
            assert_eq!(req.method(), Method::GET);
            assert_eq!(req.url().path(), path);
            assert_eq!(
                req.headers()
                    .get(reqwest::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
                Some("Bearer tok")
            );
        };

        let health = provider
            .authorized(
                provider
                    .client
                    .get(format!("{}{}", provider.base_url, routes::HEALTH)),
            )
            .build()
            .unwrap();
        assert_get_with_bearer(health, "/health");

        let tree = provider
            .authorized(provider.client.get(provider.url(routes::TREE)))
            .build()
            .unwrap();
        assert_get_with_bearer(tree, "/vfs/tree");

        let hash = Hash256::from_bytes([0x5a; 32]);
        let blob = provider
            .authorized(provider.client.get(provider.blob_url(hash)))
            .build()
            .unwrap();
        assert_get_with_bearer(blob, &format!("/vfs/blob/{}", "5a".repeat(32)));
    }

    /// Live provider↔daemon contract (async). Ignored by default; the serialized
    /// runtime lane runs it explicitly (does NOT spawn a daemon):
    ///   KIN_VFS_CONTRACT_DAEMON_URL=http://127.0.0.1:<port> \
    ///     cargo test -p kin-vfs-daemon -- --ignored live_contract
    #[tokio::test]
    #[ignore = "requires a live kin-daemon; set KIN_VFS_CONTRACT_DAEMON_URL"]
    async fn live_contract_against_real_daemon() {
        use kin_vfs_core::FileType;

        let url = std::env::var("KIN_VFS_CONTRACT_DAEMON_URL")
            .expect("set KIN_VFS_CONTRACT_DAEMON_URL to the running daemon's URL");
        let repo_root = std::env::var("KIN_VFS_CONTRACT_REPO_ROOT")
            .ok()
            .map(PathBuf::from);
        let provider = AsyncKinDaemonProvider::with_auth(url, None, repo_root, None);

        assert!(provider.is_available().await, "/health should be reachable");
        let entries = provider
            .read_dir(&VfsPath::root())
            .await
            .expect("root read_dir (/vfs/tree) should succeed");
        if let Some(name) = entries
            .iter()
            .find(|e| e.file_type == FileType::File)
            .map(|e| e.name.clone())
        {
            provider
                .read_file(&VfsPath::root().join(&name))
                .await
                .expect("/vfs/blob should return content");
        }
    }
}

/// Hermetic async-provider wire tests. The async provider must enforce the
/// identical contract as the sync one — same conditional refresh, same
/// content-addressed verification, same typed gitlink refusal, same byte-exact
/// paths — so a mount served through tokio is never weaker than the shim path.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::test_support::MockDaemon;
    use crate::tree_contract::fixtures::{
        content_artifact, gitlink_artifact, snapshot as build_snapshot, symlink_artifact,
    };
    use kin_vfs_core::FileType;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;

    const COMPOSE_YAML: &[u8] = b"services:\n  api:\n    image: kin/example\n";
    const LOCKFILE: &[u8] = b"opaque-lock-v9\x00\x01binary-ish payload\n";
    const RUN_SCRIPT: &[u8] = b"#!/bin/sh\nexec kin \"$@\"\n";
    const LOGO_BIN: &[u8] = &[0x00, 0xff, 0x89, b'K', b'I', b'N'];
    const LINK_TARGET: &[u8] = b"compose.yaml";
    const RAW_NAME: &[u8] = b"logs/x-\xff\xfe.log";
    const RAW_CONTENT: &[u8] = b"raw bytes win\n";

    fn snapshot() -> WorkspaceTreeSnapshot {
        build_snapshot(vec![
            content_artifact(1, b"compose.yaml", COMPOSE_YAML, false),
            content_artifact(2, b"vendor.lock", LOCKFILE, false),
            content_artifact(3, b"scripts/run-kin", RUN_SCRIPT, true),
            content_artifact(4, b"assets/logo.bin", LOGO_BIN, false),
            symlink_artifact(5, b"current", LINK_TARGET),
            content_artifact(6, RAW_NAME, RAW_CONTENT, false),
            gitlink_artifact(7, b"vendor/dep"),
        ])
    }

    fn spawn() -> (MockDaemon, AsyncKinDaemonProvider) {
        let daemon = MockDaemon::spawn(snapshot());
        for content in [
            COMPOSE_YAML,
            LOCKFILE,
            RUN_SCRIPT,
            LOGO_BIN,
            LINK_TARGET,
            RAW_CONTENT,
        ] {
            daemon.state.insert_blob(content);
        }
        let provider = AsyncKinDaemonProvider::new(daemon.base_url());
        (daemon, provider)
    }

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    #[tokio::test]
    async fn universal_kinds_serve_exact_bytes_and_modes() {
        let (_daemon, provider) = spawn();

        assert_eq!(
            provider.read_file(&path("compose.yaml")).await.unwrap(),
            COMPOSE_YAML
        );
        assert_eq!(
            provider.read_file(&path("vendor.lock")).await.unwrap(),
            LOCKFILE
        );
        assert_eq!(
            provider.read_file(&path("assets/logo.bin")).await.unwrap(),
            LOGO_BIN
        );

        let executable = provider.stat(&path("scripts/run-kin")).await.unwrap();
        assert!(executable.is_file);
        assert_eq!(executable.mode, 0o755);

        let link = provider.stat(&path("current")).await.unwrap();
        assert!(link.is_symlink);
        assert_eq!(
            provider.read_link(&path("current")).await.unwrap(),
            LINK_TARGET
        );
        assert!(matches!(
            provider.read_link(&path("compose.yaml")).await,
            Err(VfsError::InvalidInput { .. })
        ));
    }

    #[tokio::test]
    async fn non_utf8_paths_and_listings_are_byte_exact() {
        let (_daemon, provider) = spawn();
        let raw = VfsPath::from_bytes(RAW_NAME.to_vec()).unwrap();
        assert_eq!(provider.read_file(&raw).await.unwrap(), RAW_CONTENT);

        let names: Vec<Vec<u8>> = provider
            .read_dir(&path("logs"))
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.into_bytes())
            .collect();
        assert_eq!(names, vec![b"x-\xff\xfe.log".to_vec()]);
    }

    #[tokio::test]
    async fn gitlink_is_listed_but_refused_per_path() {
        let (_daemon, provider) = spawn();
        let dep = path("vendor/dep");

        let vendor = provider.read_dir(&path("vendor")).await.unwrap();
        assert_eq!(vendor.len(), 1);
        assert_eq!(vendor[0].file_type, FileType::Gitlink);

        assert!(matches!(
            provider.stat(&dep).await,
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        assert!(matches!(
            provider.read_file(&dep).await,
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        assert!(matches!(
            provider.read_link(&dep).await,
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
    }

    #[tokio::test]
    async fn conditional_refresh_revalidates_without_refetching() {
        let (daemon, provider) = spawn();
        assert_eq!(
            provider.read_file(&path("compose.yaml")).await.unwrap(),
            COMPOSE_YAML
        );
        assert_eq!(provider.version().await, 7);
        assert_eq!(
            daemon.state.tree_bodies_served.load(Ordering::Relaxed),
            1,
            "revalidation must ride If-None-Match, not a refetch"
        );
    }

    #[tokio::test]
    async fn malformed_refresh_retains_prior_snapshot() {
        let (daemon, provider) = spawn();
        assert_eq!(
            provider.read_file(&path("compose.yaml")).await.unwrap(),
            COMPOSE_YAML
        );

        *daemon.state.tree_body_override.lock().unwrap() = Some(b"not json".to_vec());
        *daemon.state.etag_header_override.lock().unwrap() = Some("\"tree-9\"".to_string());
        assert!(matches!(
            provider.read_file(&path("compose.yaml")).await,
            Err(VfsError::Provider(_))
        ));

        *daemon.state.tree_body_override.lock().unwrap() = None;
        *daemon.state.etag_header_override.lock().unwrap() = None;
        assert_eq!(
            provider.read_file(&path("compose.yaml")).await.unwrap(),
            COMPOSE_YAML,
            "prior snapshot must remain fully usable"
        );
        assert_eq!(provider.version().await, 7);
    }

    #[tokio::test]
    async fn stale_and_conflicting_snapshots_never_install() {
        let (daemon, provider) = spawn();
        assert_eq!(provider.version().await, 7);

        let mut stale = snapshot();
        stale.binding.roots.generation = 6;
        daemon.state.set_snapshot(stale);
        assert_eq!(
            provider.version().await,
            7,
            "a regressed snapshot must not install"
        );

        let mut race = snapshot();
        race.artifacts[0].mtime += 1;
        daemon.state.set_snapshot(race);
        assert!(matches!(
            provider.read_file(&path("compose.yaml")).await,
            Err(VfsError::Provider(_))
        ));
    }

    #[tokio::test]
    async fn ranged_reads_verify_the_whole_blob_before_slicing() {
        let (daemon, provider) = spawn();
        let lock = path("vendor.lock");

        let slice = provider.read_range(&lock, 0, 6).await.unwrap();
        assert_eq!(slice, &LOCKFILE[..6]);

        let mut corrupt = LOCKFILE.to_vec();
        corrupt[0] ^= 0xff;
        daemon
            .state
            .insert_blob_at(&hex::encode(Sha256::digest(LOCKFILE)), &corrupt);
        provider.invalidate_tree().await;
        assert!(matches!(
            provider.read_range(&lock, 8, 4).await,
            Err(VfsError::Provider(_))
        ));
    }

    #[tokio::test]
    async fn blob_hash_mismatch_fails_loud() {
        let daemon = MockDaemon::spawn(build_snapshot(vec![content_artifact(
            1,
            b"tampered.bin",
            b"expected",
            false,
        )]));
        // Serve different bytes under the advertised content address.
        daemon
            .state
            .insert_blob_at(&hex::encode(Sha256::digest(b"expected")), b"tampered");
        let provider = AsyncKinDaemonProvider::new(daemon.base_url());
        assert!(matches!(
            provider.read_file(&path("tampered.bin")).await,
            Err(VfsError::Provider(_))
        ));
    }
}
