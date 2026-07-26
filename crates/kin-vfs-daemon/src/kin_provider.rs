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

use std::num::NonZeroUsize;
use std::path::PathBuf;

use kin_model::{Hash256, TreeEntry};
use kin_vfs_core::{ContentProvider, DirEntry, VfsError, VfsPath, VfsResult, VirtualStat};
use lru::LruCache;
use parking_lot::RwLock;

use crate::auth::DaemonAuth;
use crate::routes;
use crate::tree_contract::{
    blob_identity, if_none_match_value, parse_etag_header, plan_succession, verify_blob,
    verify_range_headers, verify_size, CachedTree, Succession, TreeSnapshotDto,
};

/// A `ContentProvider` that delegates to kin-daemon's `/vfs/*` HTTP endpoints.
pub struct KinDaemonProvider {
    base_url: String,
    /// Optional session ID for session-scoped overlay projections.
    session_id: Option<String>,
    /// Bearer token resolved from explicit arg, `KIN_DAEMON_AUTH_TOKEN`, or the
    /// served repo's `.kin/daemon.token`. See [`crate::auth`].
    auth: DaemonAuth,
    client: reqwest::blocking::Client,
    tree: RwLock<Option<CachedTree>>,
    /// LRU cache of full verified blob bodies, keyed by content hash.
    /// Content-addressed, so entries stay valid across tree refreshes and a
    /// path remap can never alias stale bytes onto a new artifact.
    content_cache: RwLock<LruCache<Hash256, Vec<u8>>>,
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
            base_url: base_url.into(),
            session_id,
            auth: DaemonAuth::new(auth_token, repo_root),
            client: reqwest::blocking::Client::new(),
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
    fn authorized(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
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
    fn send_with_auth_retry<F>(&self, build: F) -> reqwest::Result<reqwest::blocking::Response>
    where
        F: Fn() -> reqwest::blocking::RequestBuilder,
    {
        let response = self.authorized(build()).send()?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && self.auth.refresh().is_some() {
            return self.authorized(build()).send();
        }
        Ok(response)
    }

    /// Build a URL with optional session_id query parameter.
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

    /// Check if the kin-daemon is reachable.
    pub fn is_available(&self) -> bool {
        // `/health` is a public route (no token required) but attaching the
        // bearer token is harmless and keeps every request uniform.
        self.authorized(
            self.client
                .get(format!("{}{}", self.base_url, routes::HEALTH)) // health is not session-scoped
                .timeout(std::time::Duration::from_secs(2)),
        )
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
    }

    /// Invalidate the cached tree and content cache, forcing re-fetches.
    pub fn invalidate_tree(&self) {
        *self.tree.write() = None;
        self.content_cache.write().clear();
    }

    /// Refresh the cached tree through the conditional ETag contract.
    ///
    /// Exactly one request: `If-None-Match` with the cached etag. A `304`
    /// confirms the cache; a `200` must carry a quoted `ETag` header equal to
    /// the document's `etag` field and a fully valid document, which is then
    /// installed atomically under [`plan_succession`]. Every failure leaves
    /// the prior snapshot untouched.
    fn ensure_tree(&self) -> Result<(), String> {
        let cached_etag = self.tree.read().as_ref().map(|tree| tree.etag.clone());

        let response = self
            .send_with_auth_retry(|| {
                let builder = self.client.get(self.url(routes::TREE));
                match &cached_etag {
                    Some(etag) => builder.header(
                        reqwest::header::IF_NONE_MATCH,
                        if_none_match_value(etag),
                    ),
                    None => builder,
                }
            })
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
        let dto: TreeSnapshotDto = response
            .json()
            .map_err(|e| format!("tree document parse failed: {e}"))?;
        if dto.etag != header_etag {
            return Err(format!(
                "tree ETag header {header_etag:?} does not match document etag {:?}",
                dto.etag
            ));
        }
        let next = CachedTree::from_dto(dto)?;

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
            .send_with_auth_retry(|| self.client.get(self.blob_url(hash)))
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

        // A cached verified body serves any range locally.
        if let Some(data) = self.content_cache.write().get(&hash) {
            let start = usize::try_from(offset)
                .map_err(|_| VfsError::Provider("range offset exceeds usize".to_string()))?;
            let requested_end = offset.saturating_add(len).min(total_size);
            let end = usize::try_from(requested_end)
                .map_err(|_| VfsError::Provider("range end exceeds usize".to_string()))?;
            return Ok(data[start..end].to_vec());
        }

        let expected_end = offset.saturating_add(len - 1).min(total_size - 1);
        let response = self
            .send_with_auth_retry(|| {
                self.client
                    .get(self.blob_url(hash))
                    .header("Range", format!("bytes={offset}-{expected_end}"))
            })
            .map_err(|e| VfsError::Provider(format!("range blob request failed: {e}")))?;

        if response.status().as_u16() == 404 {
            return Err(VfsError::Provider(format!(
                "graph blob {hash} missing for {path}"
            )));
        }

        if response.status().as_u16() == 206 {
            verify_range_headers(
                hash,
                offset,
                expected_end,
                total_size,
                response.headers(),
                path,
            )?;
            let data = response
                .bytes()
                .map(|bytes| bytes.to_vec())
                .map_err(|e| VfsError::Provider(format!("range blob body error: {e}")))?;
            let expected_len = usize::try_from(expected_end - offset + 1)
                .map_err(|_| VfsError::Provider("range length exceeds usize".to_string()))?;
            if data.len() != expected_len {
                return Err(VfsError::Provider(format!(
                    "ranged graph read body length mismatch for {path}: expected {expected_len}, got {}",
                    data.len()
                )));
            }
            return Ok(data);
        }

        if !response.status().is_success() {
            return Err(VfsError::Provider(format!(
                "range blob returned status {}",
                response.status()
            )));
        }

        // A server may legally ignore Range and return the complete blob. In
        // that case verify the full body against the exact hash and size
        // before caching it and slicing the requested window.
        let data = response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|e| VfsError::Provider(format!("blob body error: {e}")))?;
        verify_size(total_size, data.len(), path)?;
        verify_blob(hash, &data, path)?;
        let start = usize::try_from(offset)
            .map_err(|_| VfsError::Provider("range offset exceeds usize".to_string()))?;
        let end = usize::try_from(offset.saturating_add(len).min(total_size))
            .map_err(|_| VfsError::Provider("range end exceeds usize".to_string()))?;
        let result = data[start..end].to_vec();

        self.content_cache.write().put(hash, data);
        Ok(result)
    }

    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        self.with_tree(|tree| tree.stat_path(path))
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
            TreeEntry::Symlink { target_blob } => {
                self.fetch_verified_blob(target_blob, size, path)
            }
            TreeEntry::Blob { .. } => Err(VfsError::InvalidInput {
                path: path.to_string(),
            }),
            TreeEntry::Gitlink { .. } => Err(VfsError::UnsupportedRepositoryBoundary {
                path: path.to_string(),
            }),
        }
    }

    fn version(&self) -> u64 {
        if self.ensure_tree().is_err() {
            return 0;
        }
        self.tree.read().as_ref().map(|tree| tree.version).unwrap_or(0)
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

        // /health is built off base_url directly (not session-scoped).
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

        // /vfs/blob is content-addressed: the exact lowercase-hex hash.
        let hash = Hash256::from_bytes([0x5a; 32]);
        let blob = provider
            .authorized(provider.client.get(provider.blob_url(hash)))
            .build()
            .unwrap();
        assert_get_with_bearer(
            blob,
            &format!("/vfs/blob/{}", "5a".repeat(32)),
        );
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
    use crate::test_support::MockDaemon;
    use crate::tree_contract::fixtures::{
        blob_artifact, content_artifact, dto, gitlink_artifact, symlink_artifact,
    };
    use crate::tree_contract::TreeSnapshotDto;
    use kin_vfs_core::FileType;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;

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

    fn universal_snapshot() -> TreeSnapshotDto {
        dto(vec![
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
            README, MAIN_RS, COMPOSE_YAML, LOCKFILE, FORTRAN, RUN_SCRIPT, LOGO_BIN, LINK_TARGET,
            RAW_NAME_CONTENT, RANGED,
        ] {
            daemon.state.insert_blob(content);
        }
        let provider = KinDaemonProvider::new(daemon.base_url());
        (daemon, provider)
    }

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
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
                (b"src".to_vec(), FileType::File),
                (b"vendor".to_vec(), FileType::Directory),
                (b"vendor.lock".to_vec(), FileType::File),
            ]
            .into_iter()
            .map(|(name, file_type)| (name, file_type))
            .collect::<Vec<_>>()
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
        next.version = 8;
        next.etag = "tree-8".to_string();
        daemon.state.set_snapshot(next);

        assert_eq!(
            provider.read_file(&readme).unwrap(),
            replacement,
            "reads after refresh must bind to the new artifact's exact hash"
        );
        assert_eq!(provider.version(), 8);
    }

    #[test]
    fn malformed_refresh_retains_prior_snapshot_unchanged() {
        let (daemon, provider) = spawn_universal();
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);

        let malformed: Vec<(&str, Vec<u8>)> = vec![
            ("garbage", b"not json".to_vec()),
            (
                "unknown field",
                serde_json::to_vec(&serde_json::json!({
                    "schema": 1,
                    "head": {"branch": "main", "change": [0xcd; 32]},
                    "version": 9,
                    "etag": "tree-9",
                    "artifacts": [],
                    "surprise": 1,
                }))
                .unwrap(),
            ),
            (
                "unsupported schema",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot.schema = 99;
                    snapshot.version = 9;
                    snapshot.etag = "tree-9".to_string();
                    snapshot
                })
                .unwrap(),
            ),
            (
                "duplicate artifact id",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot.artifacts.push(blob_artifact(1, b"dup.txt", 9, false, 1));
                    snapshot.version = 9;
                    snapshot.etag = "tree-9".to_string();
                    snapshot
                })
                .unwrap(),
            ),
            (
                "prefix collision",
                serde_json::to_vec(&{
                    let mut snapshot = universal_snapshot();
                    snapshot.artifacts.push(blob_artifact(90, b"src", 9, false, 1));
                    snapshot.version = 9;
                    snapshot.etag = "tree-9".to_string();
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
        stale.version = 6;
        stale.etag = "tree-6".to_string();
        daemon.state.set_snapshot(stale);
        assert_eq!(provider.read_file(&path("README.md")).unwrap(), README);
        assert_eq!(provider.version(), 7, "stale snapshot must not install");

        // Same version, different etag: a ref race fails loud and retains the
        // prior snapshot.
        let mut race = universal_snapshot();
        race.etag = "tree-7-forked".to_string();
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
        let daemon = MockDaemon::spawn(dto(vec![
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
        let daemon = MockDaemon::spawn(dto(vec![content_artifact(
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
    fn ranged_reads_bind_hash_and_total_size() {
        let (daemon, provider) = spawn_universal();
        let ranged = path("data/ranged.bin");

        let slice = provider.read_range(&ranged, 246, 10).unwrap();
        assert_eq!(slice, (246..=255).map(|b| b as u8).collect::<Vec<u8>>());

        // Wrong X-Kin-Blob-Hash on the 206 answer.
        *daemon.state.range_hash_override.lock().unwrap() = Some("55".repeat(32));
        assert!(matches!(
            provider.read_range(&ranged, 0, 4),
            Err(VfsError::Provider(_))
        ));
        *daemon.state.range_hash_override.lock().unwrap() = None;

        // Wrong Content-Range total on the 206 answer.
        *daemon.state.range_total_override.lock().unwrap() = Some(RANGED.len() as u64 + 1);
        assert!(matches!(
            provider.read_range(&ranged, 0, 4),
            Err(VfsError::Provider(_))
        ));
        *daemon.state.range_total_override.lock().unwrap() = None;
    }

    #[test]
    fn full_body_range_fallback_is_verified_and_cached() {
        let (daemon, provider) = spawn_universal();
        let ranged = path("data/ranged.bin");
        daemon.state.ignore_range.store(true, Ordering::Relaxed);

        let before = daemon.state.blob_requests.load(Ordering::Relaxed);
        let slice = provider.read_range(&ranged, 10, 5).unwrap();
        assert_eq!(slice, vec![10, 11, 12, 13, 14]);
        // The verified full body was cached; the second slice is local.
        let cached = provider.read_range(&ranged, 0, 3).unwrap();
        assert_eq!(cached, vec![0, 1, 2]);
        assert_eq!(
            daemon.state.blob_requests.load(Ordering::Relaxed),
            before + 1,
            "second range must be served from the verified content cache"
        );
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
