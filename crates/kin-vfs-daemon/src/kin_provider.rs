// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider backed by kin-daemon's HTTP API.
//!
//! Fetches file tree and blob content from a running kin-daemon instance
//! (default `http://127.0.0.1:4219`).

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use kin_model::TreeEntryKind;
use kin_vfs_core::{ContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
use lru::LruCache;
use parking_lot::RwLock;

use crate::auth::DaemonAuth;
use crate::routes;
use crate::tree_contract::{
    file_type, stat_for_entry, verify_blob, verify_range_headers, verify_size, CachedTree,
    TreeSnapshot,
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
    /// LRU cache of full file contents, keyed by normalized path.
    /// Avoids re-fetching for repeated `read_range` calls on the same file.
    content_cache: RwLock<LruCache<String, Vec<u8>>>,
}

impl KinDaemonProvider {
    /// Maximum number of file contents to cache for range reads.
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

    /// Ensure the cached tree is up-to-date. Returns an error string on failure.
    fn ensure_tree(&self) -> Result<(), String> {
        // Check remote version.
        let remote_version = self.fetch_version()?;

        {
            let guard = self.tree.read();
            if let Some(ref cached) = *guard {
                if cached.version == remote_version {
                    return Ok(());
                }
            }
        }

        // Version changed (or no cache) — refresh.
        // Clear content cache since file contents may have changed.
        self.content_cache.write().clear();
        let snapshot = self.fetch_tree()?;
        let cached = CachedTree::from_snapshot(snapshot, remote_version)?;

        *self.tree.write() = Some(cached);
        Ok(())
    }

    fn fetch_version(&self) -> Result<u64, String> {
        let resp = self
            .send_with_auth_retry(|| self.client.get(self.url(routes::VERSION)))
            .map_err(|e| format!("version request failed: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .map_err(|e| format!("version parse failed: {e}"))?;

        json["version"]
            .as_u64()
            .ok_or_else(|| "version field missing or not a number".to_string())
    }

    fn fetch_tree(&self) -> Result<TreeSnapshot, String> {
        let resp = self
            .send_with_auth_retry(|| self.client.get(self.url(routes::TREE)))
            .map_err(|e| format!("tree request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("tree returned status {}", resp.status()));
        }

        resp.json()
            .map_err(|e| format!("exact tree response parse failed: {e}"))
    }

    /// Normalize a path: strip leading "/" if present, handle "." and empty.
    fn normalize_path(path: &str) -> &str {
        let p = path.strip_prefix('/').unwrap_or(path);
        if p == "." {
            ""
        } else {
            p
        }
    }
}

impl ContentProvider for KinDaemonProvider {
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path);

        // Verify the file exists in the tree first.
        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let (entry, expected_size) = {
            let guard = self.tree.read();
            let cached = guard
                .as_ref()
                .ok_or_else(|| VfsError::Provider("no cached exact tree available".to_string()))?;
            cached.entry_and_size(norm, path)?
        };

        // Fetch content from kin-daemon.
        let resp = self
            .send_with_auth_retry(|| {
                self.client
                    .get(self.url(&format!("{}{}", routes::READ_PREFIX, norm)))
            })
            .map_err(|e| VfsError::Provider(format!("read request failed: {e}")))?;

        if resp.status().as_u16() == 404 {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        if !resp.status().is_success() {
            return Err(VfsError::Provider(format!(
                "read returned status {}",
                resp.status()
            )));
        }

        let data = resp
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("read body error: {e}")))?;

        verify_size(norm, expected_size, data.len())?;
        verify_blob(norm, entry, &data)?;
        Ok(data)
    }

    fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path).to_string();

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let (entry, total_size) = {
            let guard = self.tree.read();
            let cached = guard
                .as_ref()
                .ok_or_else(|| VfsError::Provider("no cached exact tree available".to_string()))?;
            cached.entry_and_size(&norm, path)?
        };

        if len == 0 || offset >= total_size {
            return Ok(Vec::new());
        }

        // Try the content cache first to avoid re-fetching the full file.
        {
            let mut cache = self.content_cache.write();
            if let Some(data) = cache.get(&norm) {
                let start = usize::try_from(offset)
                    .map_err(|_| VfsError::Provider("range offset exceeds usize".to_string()))?;
                let requested_end = offset.saturating_add(len).min(total_size);
                let end = usize::try_from(requested_end)
                    .map_err(|_| VfsError::Provider("range end exceeds usize".to_string()))?;
                return Ok(data[start..end].to_vec());
            }
        }

        let expected_end = offset.saturating_add(len - 1).min(total_size - 1);
        let resp = self
            .send_with_auth_retry(|| {
                self.client
                    .get(self.url(&format!("{}{}", routes::READ_PREFIX, norm)))
                    .header("Range", format!("bytes={offset}-{expected_end}"))
            })
            .map_err(|e| VfsError::Provider(format!("range read request failed: {e}")))?;

        if resp.status().as_u16() == 404 {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        if resp.status().as_u16() == 206 {
            verify_range_headers(
                &norm,
                entry,
                offset,
                expected_end,
                total_size,
                resp.headers(),
            )?;
            let data = resp
                .bytes()
                .map(|bytes| bytes.to_vec())
                .map_err(|e| VfsError::Provider(format!("range read body error: {e}")))?;
            let expected_len = usize::try_from(expected_end - offset + 1)
                .map_err(|_| VfsError::Provider("range length exceeds usize".to_string()))?;
            if data.len() != expected_len {
                return Err(VfsError::Provider(format!(
                    "ranged graph read body length mismatch for {norm}: expected {expected_len}, got {}",
                    data.len()
                )));
            }
            return Ok(data);
        }

        if !resp.status().is_success() {
            return Err(VfsError::Provider(format!(
                "range read returned status {}",
                resp.status()
            )));
        }

        // A server may legally ignore Range and return the complete blob. In
        // that case validate both exact metadata fields before caching it.
        let data = resp
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|e| VfsError::Provider(format!("read body error: {e}")))?;
        verify_size(&norm, total_size, data.len())?;
        verify_blob(&norm, entry, &data)?;
        let start = usize::try_from(offset)
            .map_err(|_| VfsError::Provider("range offset exceeds usize".to_string()))?;
        let end = usize::try_from(offset.saturating_add(len).min(total_size))
            .map_err(|_| VfsError::Provider("range end exceeds usize".to_string()))?;
        let result = data[start..end].to_vec();

        self.content_cache.write().put(norm, data);
        Ok(result)
    }

    fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let (entry, size, mtime) = {
            let guard = self.tree.read();
            let cached = guard
                .as_ref()
                .ok_or_else(|| VfsError::Provider("no cached tree available".to_string()))?;

            if let Some(entry) = cached.entries.get(norm) {
                let size = cached.sizes.get(norm).copied().ok_or_else(|| {
                    VfsError::Provider(format!("exact tree size missing for {norm}"))
                })?;
                let mtime = cached.timestamps.get(norm).copied().unwrap_or(0);
                (*entry, size, mtime)
            } else if norm.is_empty() || cached.dirs.contains(norm) {
                let dir_mtime = cached
                    .timestamps
                    .iter()
                    .filter(|(k, _)| {
                        if norm.is_empty() {
                            true
                        } else {
                            k.starts_with(&format!("{}/", norm))
                        }
                    })
                    .map(|(_, &t)| t)
                    .max()
                    .unwrap_or(0);
                return Ok(VirtualStat::directory(dir_mtime));
            } else {
                return Err(VfsError::NotFound {
                    path: path.to_string(),
                });
            }
        };

        Ok(stat_for_entry(entry, size, mtime))
    }

    fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read();
        let cached = guard
            .as_ref()
            .ok_or_else(|| VfsError::Provider("no cached tree available".to_string()))?;

        // Verify this is a directory.
        if !norm.is_empty() && !cached.dirs.contains(norm) {
            // Could be a file.
            if cached.entries.contains_key(norm) {
                return Err(VfsError::NotDirectory {
                    path: path.to_string(),
                });
            }
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        let prefix = if norm.is_empty() {
            String::new()
        } else {
            format!("{}/", norm)
        };

        let mut seen = HashSet::new();
        let mut entries = Vec::new();

        for (file_path, entry) in &cached.entries {
            let rest = if prefix.is_empty() {
                file_path.as_str()
            } else if let Some(r) = file_path.strip_prefix(&prefix) {
                r
            } else {
                continue;
            };

            let child_name = if let Some(slash_pos) = rest.find('/') {
                &rest[..slash_pos]
            } else {
                rest
            };

            if child_name.is_empty() {
                continue;
            }

            if seen.insert(child_name.to_string()) {
                let is_dir = rest.contains('/');
                entries.push(DirEntry {
                    name: child_name.to_string(),
                    file_type: if is_dir {
                        FileType::Directory
                    } else {
                        file_type(*entry)
                    },
                });
            }
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn exists(&self, path: &str) -> VfsResult<bool> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read();
        let cached = guard
            .as_ref()
            .ok_or_else(|| VfsError::Provider("no cached tree available".to_string()))?;

        Ok(norm.is_empty() || cached.entries.contains_key(norm) || cached.dirs.contains(norm))
    }

    fn read_link(&self, path: &str) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path);
        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let entry = {
            let guard = self.tree.read();
            let cached = guard
                .as_ref()
                .ok_or_else(|| VfsError::Provider("no cached exact tree available".to_string()))?;
            match cached.entry_and_size(norm, path) {
                Ok((entry, _)) => entry,
                Err(VfsError::IsDirectory { .. }) => {
                    return Err(VfsError::InvalidInput {
                        path: path.to_string(),
                    });
                }
                Err(error) => return Err(error),
            }
        };
        if entry.kind != TreeEntryKind::Symlink {
            return Err(VfsError::InvalidInput {
                path: path.to_string(),
            });
        }
        self.read_file(path)
    }

    fn version(&self) -> u64 {
        self.fetch_version().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn normalize_paths() {
        assert_eq!(
            KinDaemonProvider::normalize_path("/src/main.rs"),
            "src/main.rs"
        );
        assert_eq!(
            KinDaemonProvider::normalize_path("src/main.rs"),
            "src/main.rs"
        );
        assert_eq!(KinDaemonProvider::normalize_path("."), "");
        assert_eq!(KinDaemonProvider::normalize_path("/"), "");
        assert_eq!(KinDaemonProvider::normalize_path(""), "");
    }

    #[test]
    fn unavailable_daemon_returns_false() {
        let provider = KinDaemonProvider::new("http://127.0.0.1:19999");
        assert!(!provider.is_available());
    }

    #[test]
    fn url_without_session() {
        let provider = KinDaemonProvider::new("http://127.0.0.1:4219");
        assert_eq!(
            provider.url("/vfs/version"),
            "http://127.0.0.1:4219/vfs/version"
        );
    }

    #[test]
    fn url_with_session() {
        let provider =
            KinDaemonProvider::with_session("http://127.0.0.1:4219", Some("sess-42".into()));
        assert_eq!(
            provider.url("/vfs/version"),
            "http://127.0.0.1:4219/vfs/version?session_id=sess-42"
        );
        assert_eq!(
            provider.url("/vfs/read/src/main.rs"),
            "http://127.0.0.1:4219/vfs/read/src/main.rs?session_id=sess-42"
        );
    }

    #[test]
    fn invalidate_tree_clears_cache() {
        let provider = KinDaemonProvider::new("http://127.0.0.1:19999");
        // Cache should be empty initially.
        assert!(provider.tree.read().is_none());
        // Manually set a cache entry.
        *provider.tree.write() = Some(CachedTree {
            entries: HashMap::new(),
            dirs: std::collections::HashSet::new(),
            sizes: HashMap::new(),
            timestamps: HashMap::new(),
            version: 1,
        });
        assert!(provider.tree.read().is_some());
        // Invalidate.
        provider.invalidate_tree();
        assert!(provider.tree.read().is_none());
    }

    /// Header on a request built (not sent) through `authorized`.
    fn authorization_header(provider: &KinDaemonProvider) -> Option<String> {
        provider
            .authorized(provider.client.get(provider.url("/vfs/version")))
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

        for (route, expected) in [
            (routes::VERSION, "/vfs/version"),
            (routes::TREE, "/vfs/tree"),
        ] {
            let req = provider
                .authorized(provider.client.get(provider.url(route)))
                .build()
                .unwrap();
            assert_get_with_bearer(req, expected);
        }

        // /vfs/read appends the normalized path.
        let read = provider
            .authorized(provider.client.get(provider.url(&format!(
                "{}{}",
                routes::READ_PREFIX,
                "src/main.rs"
            ))))
            .build()
            .unwrap();
        assert_get_with_bearer(read, "/vfs/read/src/main.rs");
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
        let url = std::env::var("KIN_VFS_CONTRACT_DAEMON_URL")
            .expect("set KIN_VFS_CONTRACT_DAEMON_URL to the running daemon's URL");
        let repo_root = std::env::var("KIN_VFS_CONTRACT_REPO_ROOT")
            .ok()
            .map(PathBuf::from);
        let provider = KinDaemonProvider::with_auth(url, None, repo_root, None);

        assert!(provider.is_available(), "/health should be reachable");
        // read_dir(".") forces ensure_tree → exercises /vfs/version + /vfs/tree.
        let entries = provider
            .read_dir(".")
            .expect("root read_dir (/vfs/version + /vfs/tree) should succeed");
        // Exercise /vfs/read on the first regular file at the root, if any.
        if let Some(name) = entries
            .iter()
            .find(|e| e.file_type == FileType::File)
            .map(|e| e.name.clone())
        {
            provider
                .read_file(&name)
                .expect("/vfs/read should return content");
        }
    }
}

/// AC4 authority tests against a mock kin daemon (no real daemon process): a
/// stat whose content read fails must fail loud rather than report a misleading
/// zero-byte file, and large reads must return the exact slice without
/// truncation. Uses an in-test HTTP mock, not a daemon boot.
#[cfg(test)]
mod authority_tests {
    use super::*;
    use kin_model::{Hash256, TreeEntry};
    use kin_vfs_core::ContentProvider;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    const BIG_LEN: usize = 200_000;

    /// Minimal HTTP mock of the kin daemon: serves `/vfs/version`, `/vfs/tree`,
    /// and `/vfs/read/<path>`. `broken.txt` returns 500 (content-read failure).
    /// Every response sets `Connection: close`, so reqwest uses a fresh
    /// connection per request and each accepted socket carries one request.
    fn request_range(request: &str) -> Option<(usize, usize)> {
        let line = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("range: bytes="))?;
        let range = line.split_once('=').map(|(_, value)| value)?;
        let (start, end) = range.split_once('-')?;
        Some((start.parse().ok()?, end.trim().parse().ok()?))
    }

    fn spawn_mock_daemon() -> (
        String,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{addr}");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let big_reads = Arc::new(AtomicUsize::new(0));
        let big_reads_thread = big_reads.clone();

        let handle = thread::spawn(move || {
            let big_hash = Hash256::from_bytes(Sha256::digest(vec![b'k'; BIG_LEN]).into());
            let tree = serde_json::to_vec(&serde_json::json!({
                "entries": {
                    "big.bin": TreeEntry::regular(big_hash, false),
                    "broken.txt": TreeEntry::regular(Hash256::from_bytes([0xaa; 32]), false),
                },
                "sizes": {
                    "big.bin": BIG_LEN,
                    "broken.txt": 4,
                }
            }))
            .expect("serialize exact tree");
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ =
                            stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                        let mut buf = [0u8; 1024];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("")
                            .split('?')
                            .next()
                            .unwrap_or("");

                        let (status, extra_headers, body): (&str, String, Vec<u8>) = match path {
                            "/vfs/version" => {
                                ("200 OK", String::new(), b"{\"version\":1}".to_vec())
                            }
                            "/vfs/tree" => ("200 OK", String::new(), tree.clone()),
                            "/vfs/read/big.bin" => {
                                big_reads_thread.fetch_add(1, Ordering::Relaxed);
                                if let Some((start, end)) = request_range(&req) {
                                    (
                                        "206 Partial Content",
                                        format!(
                                            "Content-Range: bytes {start}-{end}/{BIG_LEN}\r\nX-Kin-Blob-Hash: {big_hash}\r\n"
                                        ),
                                        vec![b'k'; end - start + 1],
                                    )
                                } else {
                                    ("200 OK", String::new(), vec![b'k'; BIG_LEN])
                                }
                            }
                            "/vfs/read/broken.txt" => {
                                ("500 Internal Server Error", String::new(), b"boom".to_vec())
                            }
                            _ => ("404 Not Found", String::new(), Vec::new()),
                        };
                        let header = format!(
                            "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&body);
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (base, stop, big_reads, handle)
    }

    #[test]
    fn large_binary_stat_is_metadata_only_and_read_errors_fail_loud() {
        let (base, stop, big_reads, handle) = spawn_mock_daemon();
        let provider = KinDaemonProvider::new(base);

        // Large file: stat reports the TRUE content length, never 0.
        let st = provider.stat("big.bin").expect("stat big.bin");
        assert_eq!(
            st.size, BIG_LEN as u64,
            "stat must report the real size, not a truncated/zero value"
        );
        assert_eq!(
            big_reads.load(Ordering::Relaxed),
            0,
            "stat must use exact tree metadata without fetching the large blob"
        );

        // A range read returns exactly the requested slice (no truncation, no
        // whole-file corruption) even though the file is large.
        let part = provider
            .read_range("big.bin", (BIG_LEN as u64) - 10, 10)
            .expect("range read");
        assert_eq!(part.len(), 10, "range read must return exactly the slice");
        assert!(
            part.iter().all(|&b| b == b'k'),
            "range bytes must be intact"
        );
        assert_eq!(
            big_reads.load(Ordering::Relaxed),
            1,
            "a bounded range read must not issue a stat-time full-body fetch"
        );

        // Metadata remains independently available, but the broken blob read
        // itself fails loud.
        assert_eq!(provider.stat("broken.txt").unwrap().size, 4);
        assert!(provider.read_file("broken.txt").is_err());

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}

/// Hermetic provider↔daemon wire-contract tests. A minimal in-process HTTP mock
/// of kin-daemon (no real daemon, no GPU) serves `/health`, `/vfs/version`,
/// `/vfs/tree`, and `/vfs/read/<path>` so the FULL `KinDaemonProvider` surface is
/// exercised over the real wire format: `read_dir` deriving directories from
/// exact universal tree entries, metadata-only file and directory `stat`,
/// `read_file` (happy path + not-found), range reads bound to blob hash and total
/// size (`206` partial + verified `200` full response), `exists`, and
/// `version`/`is_available`. Complements `authority_tests` (fail-loud on a read
/// error) and the offline route-pinning test; together they close the historical
/// "conformance tests never speak the wire protocol" gap without booting a daemon.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use kin_model::{Hash256, TreeEntry};
    use kin_vfs_core::{ContentProvider, FileType};
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    const README: &[u8] = b"# Kin VFS\n";
    const MAIN_RS: &[u8] = b"fn main() {}\n";
    const LIB_RS: &[u8] = b"pub mod util;\n";
    const HELPERS_RS: &[u8] = b"pub fn help() {}\n";
    const COMPOSE_YAML: &[u8] = b"services:\n  api:\n    image: kin/example\n";
    const RUN_SCRIPT: &[u8] = b"#!/bin/sh\nexec kin \"$@\"\n";
    const LOGO_BIN: &[u8] = &[0x00, 0xff, 0x89, b'K', b'I', b'N'];
    const LINK_TARGET: &[u8] = b"src/main.rs";
    const INTEGRITY_BYTES: &[u8] = b"integrity";
    const PLAIN_LEN: usize = 100;

    /// `data/ranged.bin` content: bytes `0,1,…,255`. Range reads slice into this.
    fn ranged_body() -> Vec<u8> {
        (0..=255u8).collect()
    }

    fn parse_range(request: &str) -> Option<(usize, usize)> {
        let line = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("range: bytes="))?;
        let range = line.split_once('=').map(|(_, value)| value)?;
        let (start, end) = range.split_once('-')?;
        Some((start.parse().ok()?, end.trim().parse().ok()?))
    }

    /// Content served for each `/vfs/read/<path>` route (`None` → 404).
    fn read_body(path: &str) -> Option<Vec<u8>> {
        match path {
            "/vfs/read/README.md" => Some(README.to_vec()),
            "/vfs/read/src/main.rs" => Some(MAIN_RS.to_vec()),
            "/vfs/read/src/lib.rs" => Some(LIB_RS.to_vec()),
            "/vfs/read/src/util/helpers.rs" => Some(HELPERS_RS.to_vec()),
            "/vfs/read/compose.yaml" => Some(COMPOSE_YAML.to_vec()),
            "/vfs/read/scripts/run-kin" => Some(RUN_SCRIPT.to_vec()),
            "/vfs/read/assets/logo.bin" => Some(LOGO_BIN.to_vec()),
            "/vfs/read/current" => Some(LINK_TARGET.to_vec()),
            "/vfs/read/data/plain.bin" => Some(vec![b'p'; PLAIN_LEN]),
            "/vfs/read/data/ranged.bin" => Some(ranged_body()),
            "/vfs/read/data/bad-size.bin"
            | "/vfs/read/data/bad-hash.bin"
            | "/vfs/read/data/bad-range-hash.bin"
            | "/vfs/read/data/bad-range-total.bin" => Some(INTEGRITY_BYTES.to_vec()),
            _ => None,
        }
    }

    fn hash(data: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(data).into())
    }

    /// The `/vfs/tree` snapshot contains the exact entry contract for code,
    /// configuration, binary, executable, and symbolic-link paths alike.
    fn tree_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "entries": {
                "README.md": TreeEntry::regular(hash(README), false),
                "src/main.rs": TreeEntry::regular(hash(MAIN_RS), false),
                "src/lib.rs": TreeEntry::regular(hash(LIB_RS), false),
                "src/util/helpers.rs": TreeEntry::regular(hash(HELPERS_RS), false),
                "compose.yaml": TreeEntry::regular(hash(COMPOSE_YAML), false),
                "scripts/run-kin": TreeEntry::regular(hash(RUN_SCRIPT), true),
                "assets/logo.bin": TreeEntry::regular(hash(LOGO_BIN), false),
                "current": TreeEntry::symlink(hash(LINK_TARGET)),
                "data/plain.bin": TreeEntry::regular(hash(&vec![b'p'; PLAIN_LEN]), false),
                "data/ranged.bin": TreeEntry::regular(hash(&ranged_body()), false),
                "data/bad-size.bin": TreeEntry::regular(hash(INTEGRITY_BYTES), false),
                "data/bad-hash.bin": TreeEntry::regular(Hash256::from_bytes([0x44; 32]), false),
                "data/bad-range-hash.bin": TreeEntry::regular(hash(INTEGRITY_BYTES), false),
                "data/bad-range-total.bin": TreeEntry::regular(hash(INTEGRITY_BYTES), false),
            },
            "sizes": {
                "README.md": README.len(),
                "src/main.rs": MAIN_RS.len(),
                "src/lib.rs": LIB_RS.len(),
                "src/util/helpers.rs": HELPERS_RS.len(),
                "compose.yaml": COMPOSE_YAML.len(),
                "scripts/run-kin": RUN_SCRIPT.len(),
                "assets/logo.bin": LOGO_BIN.len(),
                "current": LINK_TARGET.len(),
                "data/plain.bin": PLAIN_LEN,
                "data/ranged.bin": ranged_body().len(),
                "data/bad-size.bin": INTEGRITY_BYTES.len() + 1,
                "data/bad-hash.bin": INTEGRITY_BYTES.len(),
                "data/bad-range-hash.bin": INTEGRITY_BYTES.len(),
                "data/bad-range-total.bin": INTEGRITY_BYTES.len(),
            },
            "timestamps": {
                "README.md": 1000,
                "src/main.rs": 2000,
                "src/lib.rs": 1500,
                "src/util/helpers.rs": 3000,
                "compose.yaml": 4000,
                "scripts/run-kin": 5000,
                "assets/logo.bin": 6000,
                "current": 7000,
            }
        }))
        .expect("serialize exact tree")
    }

    /// RAII in-process HTTP mock of kin-daemon. Stops and joins its accept thread
    /// on drop, so each test releases its ephemeral port deterministically.
    struct MockDaemon {
        base: String,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockDaemon {
        fn spawn() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            let addr = listener.local_addr().expect("addr");
            let base = format!("http://{addr}");
            let stop = Arc::new(AtomicBool::new(false));
            let stop_thread = stop.clone();

            let handle = thread::spawn(move || {
                while !stop_thread.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream
                                .set_read_timeout(Some(std::time::Duration::from_millis(500)));
                            let mut buf = [0u8; 1024];
                            let n = stream.read(&mut buf).unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let path = req
                                .lines()
                                .next()
                                .and_then(|l| l.split_whitespace().nth(1))
                                .unwrap_or("")
                                .split('?')
                                .next()
                                .unwrap_or("");

                            let (status, extra_headers, body): (&str, String, Vec<u8>) = if path
                                == "/health"
                            {
                                ("200 OK", String::new(), b"{\"status\":\"ok\"}".to_vec())
                            } else if path == "/vfs/version" {
                                ("200 OK", String::new(), b"{\"version\":1}".to_vec())
                            } else if path == "/vfs/tree" {
                                ("200 OK", String::new(), tree_json().into_bytes())
                            } else if path == "/vfs/read/data/ranged.bin" {
                                let full = ranged_body();
                                let (start, end) = parse_range(&req).expect("range header");
                                (
                                    "206 Partial Content",
                                    format!(
                                        "Content-Range: bytes {start}-{end}/{}\r\nX-Kin-Blob-Hash: {}\r\n",
                                        full.len(),
                                        hash(&full)
                                    ),
                                    full[start..=end].to_vec(),
                                )
                            } else if path == "/vfs/read/data/bad-range-hash.bin"
                                || path == "/vfs/read/data/bad-range-total.bin"
                            {
                                let (start, end) = parse_range(&req).expect("range header");
                                let response_hash = if path.ends_with("bad-range-hash.bin") {
                                    Hash256::from_bytes([0x55; 32]).to_string()
                                } else {
                                    hash(INTEGRITY_BYTES).to_string()
                                };
                                let total = if path.ends_with("bad-range-total.bin") {
                                    INTEGRITY_BYTES.len() + 1
                                } else {
                                    INTEGRITY_BYTES.len()
                                };
                                (
                                    "206 Partial Content",
                                    format!(
                                        "Content-Range: bytes {start}-{end}/{total}\r\nX-Kin-Blob-Hash: {response_hash}\r\n"
                                    ),
                                    INTEGRITY_BYTES[start..=end].to_vec(),
                                )
                            } else if let Some(body) = read_body(path) {
                                ("200 OK", String::new(), body)
                            } else {
                                ("404 Not Found", String::new(), Vec::new())
                            };

                            let header = format!(
                                "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(&body);
                            let _ = stream.flush();
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                base,
                stop,
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> &str {
            &self.base
        }
    }

    impl Drop for MockDaemon {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn health_and_version_over_the_wire() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert!(provider.is_available(), "/health must report available");
        assert_eq!(provider.version(), 1, "/vfs/version must parse the counter");
    }

    #[test]
    fn read_dir_root_derives_files_and_dirs() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        let got: Vec<(String, FileType)> = provider
            .read_dir(".")
            .expect("root read_dir")
            .into_iter()
            .map(|e| (e.name, e.file_type))
            .collect();
        assert_eq!(
            got,
            vec![
                ("README.md".to_string(), FileType::File),
                ("assets".to_string(), FileType::Directory),
                ("compose.yaml".to_string(), FileType::File),
                ("current".to_string(), FileType::Symlink),
                ("data".to_string(), FileType::Directory),
                ("scripts".to_string(), FileType::Directory),
                ("src".to_string(), FileType::Directory),
            ],
            "root listing must preserve regular, directory, and symlink kinds, sorted"
        );
    }

    #[test]
    fn read_dir_nested_lists_children() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        let got: Vec<(String, FileType)> = provider
            .read_dir("src")
            .expect("src read_dir")
            .into_iter()
            .map(|e| (e.name, e.file_type))
            .collect();
        assert_eq!(
            got,
            vec![
                ("lib.rs".to_string(), FileType::File),
                ("main.rs".to_string(), FileType::File),
                ("util".to_string(), FileType::Directory),
            ],
            "nested listing must include both files and the util subdirectory, sorted"
        );
    }

    #[test]
    fn stat_file_reports_size_and_mtime() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        let st = provider.stat("README.md").expect("stat file");
        assert!(st.is_file, "README.md must stat as a file");
        assert_eq!(
            st.size,
            README.len() as u64,
            "size comes from exact tree metadata"
        );
        assert_eq!(st.mtime, 1000, "mtime comes from the tree timestamps");
        assert_eq!(st.mode, 0o644, "non-executable mode comes from TreeEntry");
    }

    #[test]
    fn stat_preserves_executable_and_symlink_kinds() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());

        let executable = provider.stat("scripts/run-kin").expect("stat executable");
        assert!(executable.is_file);
        assert!(!executable.is_symlink);
        assert_eq!(executable.mode, 0o755);

        let symlink = provider.stat("current").expect("stat symlink");
        assert!(!symlink.is_file);
        assert!(symlink.is_symlink);
        assert_eq!(symlink.mode, 0o777);
        assert_eq!(symlink.size, LINK_TARGET.len() as u64);
        assert_eq!(provider.read_link("current").unwrap(), LINK_TARGET);
        assert!(matches!(
            provider.read_link("README.md"),
            Err(VfsError::InvalidInput { .. })
        ));
        assert!(matches!(
            provider.read_link("src"),
            Err(VfsError::InvalidInput { .. })
        ));
    }

    #[test]
    fn content_reads_preserve_directory_kind_errors() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert!(matches!(
            provider.read_file("src"),
            Err(VfsError::IsDirectory { .. })
        ));
        assert!(matches!(
            provider.read_range("src", 0, 1),
            Err(VfsError::IsDirectory { .. })
        ));
    }

    #[test]
    fn stat_directory_uses_max_child_mtime() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        let st = provider.stat("src").expect("stat dir");
        assert!(!st.is_file, "src must stat as a directory");
        assert_eq!(st.mtime, 3000, "dir mtime is the max child timestamp");
    }

    #[test]
    fn stat_missing_path_is_not_found() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert!(matches!(
            provider.stat("nope.txt"),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn read_file_returns_exact_bytes() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert_eq!(
            provider.read_file("src/main.rs").expect("read_file"),
            MAIN_RS
        );
    }

    #[test]
    fn non_language_config_and_binary_bytes_are_first_class() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());

        assert_eq!(provider.read_file("compose.yaml").unwrap(), COMPOSE_YAML);
        assert_eq!(provider.read_file("assets/logo.bin").unwrap(), LOGO_BIN);
        assert_eq!(
            provider.stat("assets/logo.bin").unwrap().content_hash,
            Some(*hash(LOGO_BIN).as_bytes())
        );
    }

    #[test]
    fn size_hash_and_range_metadata_disagreement_fail_loud() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());

        for path in ["data/bad-size.bin", "data/bad-hash.bin"] {
            assert!(
                matches!(provider.read_file(path), Err(VfsError::Provider(_))),
                "{path} must reject full-body metadata disagreement"
            );
        }
        for path in ["data/bad-range-hash.bin", "data/bad-range-total.bin"] {
            assert!(
                matches!(provider.read_range(path, 0, 4), Err(VfsError::Provider(_))),
                "{path} must reject ranged metadata disagreement"
            );
        }
    }

    #[test]
    fn read_file_absent_path_is_not_found() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert!(matches!(
            provider.read_file("ghost.rs"),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn read_range_is_bound_to_tree_hash_and_total_size() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        // ranged.bin is 0,1,…,255; the daemon binds [246, 256) to the exact
        // tree blob hash and total length before the provider exposes it.
        let part = provider
            .read_range("data/ranged.bin", 246, 10)
            .expect("range read");
        assert_eq!(part, (246..=255u8).collect::<Vec<u8>>());
    }

    #[test]
    fn read_range_reuses_verified_full_blob() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        // The provider caches the verified full body; the second slice is local.
        let part = provider
            .read_range("data/plain.bin", 10, 5)
            .expect("range read");
        assert_eq!(part, vec![b'p'; 5]);
        let cached = provider
            .read_range("data/plain.bin", 0, 3)
            .expect("cached range read");
        assert_eq!(cached, vec![b'p'; 3]);
    }

    #[test]
    fn exists_reflects_tree_membership() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert!(provider.exists("README.md").unwrap(), "file must exist");
        assert!(provider.exists("src").unwrap(), "directory must exist");
        assert!(
            !provider.exists("missing").unwrap(),
            "absent path must not exist"
        );
    }
}
