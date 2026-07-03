// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider backed by kin-daemon's HTTP API.
//!
//! Fetches file tree and blob content from a running kin-daemon instance
//! (default `http://127.0.0.1:4219`).

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::PathBuf;

use kin_vfs_core::{ContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
use lru::LruCache;
use parking_lot::RwLock;

use crate::auth::DaemonAuth;
use crate::routes;

/// Result of fetching the file tree: `path -> content hash` plus
/// `path -> last-modified epoch seconds`.
type TreeSnapshot = (HashMap<String, String>, HashMap<String, u64>);

/// Cached snapshot of the file tree from kin-daemon.
struct CachedTree {
    /// path -> hex content hash
    files: HashMap<String, String>,
    /// set of directory paths (derived from file paths)
    dirs: HashSet<String>,
    /// path -> file size in bytes (populated lazily on stat)
    sizes: HashMap<String, u64>,
    /// path -> last-modified epoch seconds (from graph change timestamps)
    timestamps: HashMap<String, u64>,
    /// monotonic version counter from kin-daemon
    version: u64,
}

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
        let (new_tree, new_timestamps) = self.fetch_tree()?;

        // Derive directory set from file paths.
        let mut dirs = HashSet::new();
        dirs.insert(String::new()); // root
        for path in new_tree.keys() {
            let mut current = String::new();
            for component in path.split('/') {
                if !current.is_empty() {
                    current.push('/');
                }
                current.push_str(component);
                // Every prefix except the full path is a directory.
            }
            // Add all parent directories.
            if let Some(last_slash) = path.rfind('/') {
                let mut prefix = String::new();
                for component in path[..last_slash].split('/') {
                    if !prefix.is_empty() {
                        prefix.push('/');
                    }
                    prefix.push_str(component);
                    dirs.insert(prefix.clone());
                }
            }
        }

        let cached = CachedTree {
            files: new_tree,
            dirs,
            sizes: HashMap::new(),
            timestamps: new_timestamps,
            version: remote_version,
        };

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

        let json: serde_json::Value = resp.json().map_err(|e| format!("tree parse failed: {e}"))?;

        let files_obj = json["files"]
            .as_object()
            .ok_or_else(|| "tree response missing 'files' object".to_string())?;

        let mut files = HashMap::with_capacity(files_obj.len());
        for (k, v) in files_obj {
            if let Some(hash) = v.as_str() {
                files.insert(k.clone(), hash.to_string());
            }
        }

        let mut timestamps = HashMap::new();
        if let Some(ts_obj) = json["timestamps"].as_object() {
            for (k, v) in ts_obj {
                if let Some(epoch) = v.as_u64() {
                    timestamps.insert(k.clone(), epoch);
                }
            }
        }

        Ok((files, timestamps))
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

        {
            let guard = self.tree.read();
            if let Some(ref cached) = *guard {
                if !cached.files.contains_key(norm) {
                    return Err(VfsError::NotFound {
                        path: path.to_string(),
                    });
                }
                if cached.dirs.contains(norm) && !cached.files.contains_key(norm) {
                    return Err(VfsError::IsDirectory {
                        path: path.to_string(),
                    });
                }
            }
        }

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

        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("read body error: {e}")))
    }

    fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path).to_string();

        // Try the content cache first to avoid re-fetching the full file.
        {
            let mut cache = self.content_cache.write();
            if let Some(data) = cache.get(&norm) {
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(vec![]);
                }
                let end = std::cmp::min(start + len as usize, data.len());
                return Ok(data[start..end].to_vec());
            }
        }

        // Cache miss — attempt a range-only fetch via HTTP Range header.
        // If the daemon supports it we avoid downloading the entire file.
        // If it doesn't (returns 200 instead of 206), we fall back to
        // caching the full response and slicing locally.
        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let range_end = offset.saturating_add(len).saturating_sub(1);
        let resp = self
            .send_with_auth_retry(|| {
                self.client
                    .get(self.url(&format!("{}{}", routes::READ_PREFIX, norm)))
                    .header("Range", format!("bytes={}-{}", offset, range_end))
            })
            .map_err(|e| VfsError::Provider(format!("range read request failed: {e}")))?;

        if resp.status().as_u16() == 404 {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        if resp.status().as_u16() == 206 {
            // Server honored the Range request — return partial content directly.
            return resp
                .bytes()
                .map(|b| b.to_vec())
                .map_err(|e| VfsError::Provider(format!("range read body error: {e}")));
        }

        // Server returned the full file (Range not supported).
        // Cache it and slice the requested range.
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

        let start = offset as usize;
        let result = if start >= data.len() {
            vec![]
        } else {
            let end = std::cmp::min(start + len as usize, data.len());
            data[start..end].to_vec()
        };

        self.content_cache.write().put(norm, data);
        Ok(result)
    }

    fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        // First check under read lock whether we have the file and a cached size.
        let (is_file, hash_hex, cached_size, mtime) = {
            let guard = self.tree.read();
            let cached = guard
                .as_ref()
                .ok_or_else(|| VfsError::Provider("no cached tree available".to_string()))?;

            if let Some(hash_hex) = cached.files.get(norm) {
                let size = cached.sizes.get(norm).copied();
                let mtime = cached.timestamps.get(norm).copied().unwrap_or(0);
                (true, Some(hash_hex.clone()), size, mtime)
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

        if !is_file {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        let hash_hex = hash_hex.unwrap();
        let mut content_hash = [0u8; 32];
        if let Ok(bytes) = hex::decode(&hash_hex) {
            if bytes.len() == 32 {
                content_hash.copy_from_slice(&bytes);
            }
        }

        // If we already have a cached size, return it.
        if let Some(size) = cached_size {
            return Ok(VirtualStat::file(size, content_hash, mtime));
        }

        // Derive size from content: the kin daemon's tree endpoint carries only
        // path→hash, not sizes. A read failure here must NOT be masked as a
        // zero-byte file — the shim would then serve an empty file, silently
        // truncating real content and reporting misleading metadata. Surface the
        // error so the caller sees a clean miss instead of a false empty stat.
        let data = self.read_file(path)?;
        let size = data.len() as u64;
        // Cache the size for future stat calls.
        if let Some(ref mut cached) = *self.tree.write() {
            cached.sizes.insert(norm.to_string(), size);
        }

        Ok(VirtualStat::file(size, content_hash, mtime))
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
            if cached.files.contains_key(norm) {
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

        for file_path in cached.files.keys() {
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
                        FileType::File
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

        Ok(norm.is_empty() || cached.files.contains_key(norm) || cached.dirs.contains(norm))
    }

    fn version(&self) -> u64 {
        self.fetch_version().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            files: HashMap::new(),
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
    use kin_vfs_core::ContentProvider;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    const BIG_LEN: usize = 200_000;

    /// Minimal HTTP mock of the kin daemon: serves `/vfs/version`, `/vfs/tree`,
    /// and `/vfs/read/<path>`. `broken.txt` returns 500 (content-read failure).
    /// Every response sets `Connection: close`, so reqwest uses a fresh
    /// connection per request and each accepted socket carries one request.
    fn spawn_mock_daemon() -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{addr}");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();

        let handle = thread::spawn(move || {
            let hash = "aa".repeat(32); // 64 hex chars → 32 bytes
            let tree =
                format!("{{\"files\":{{\"big.bin\":\"{hash}\",\"broken.txt\":\"{hash}\"}}}}");
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

                        let (status, body): (&str, Vec<u8>) = match path {
                            "/vfs/version" => ("200 OK", b"{\"version\":1}".to_vec()),
                            "/vfs/tree" => ("200 OK", tree.clone().into_bytes()),
                            "/vfs/read/big.bin" => ("200 OK", vec![b'k'; BIG_LEN]),
                            "/vfs/read/broken.txt" => {
                                ("500 Internal Server Error", b"boom".to_vec())
                            }
                            _ => ("404 Not Found", Vec::new()),
                        };
                        let header = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

        (base, stop, handle)
    }

    #[test]
    fn stat_reports_real_size_and_fails_loud_on_read_error() {
        let (base, stop, handle) = spawn_mock_daemon();
        let provider = KinDaemonProvider::new(base);

        // Large file: stat reports the TRUE content length, never 0.
        let st = provider.stat("big.bin").expect("stat big.bin");
        assert_eq!(
            st.size, BIG_LEN as u64,
            "stat must report the real size, not a truncated/zero value"
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

        // broken.txt: content read 500s. stat must FAIL LOUD (Err) rather than
        // silently report a misleading zero-byte file (which the shim would then
        // serve as empty — silent truncation of real content).
        assert!(
            provider.stat("broken.txt").is_err(),
            "a failed content read must surface an error, never become size 0"
        );

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}

/// Hermetic provider↔daemon wire-contract tests. A minimal in-process HTTP mock
/// of kin-daemon (no real daemon, no GPU) serves `/health`, `/vfs/version`,
/// `/vfs/tree`, and `/vfs/read/<path>` so the FULL `KinDaemonProvider` surface is
/// exercised over the real wire format: `read_dir` deriving directories from the
/// flat `path→hash` tree, file and directory `stat` (size from content, mtime from
/// the max child timestamp), `read_file` (happy path + not-found), range reads
/// (server `206` partial + `200` full-fetch fallback), `exists`, and
/// `version`/`is_available`. Complements `authority_tests` (fail-loud on a read
/// error) and the offline route-pinning test; together they close the historical
/// "conformance tests never speak the wire protocol" gap without booting a daemon.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use kin_vfs_core::{ContentProvider, FileType};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    const README: &[u8] = b"# Kin VFS\n";
    const MAIN_RS: &[u8] = b"fn main() {}\n";
    const LIB_RS: &[u8] = b"pub mod util;\n";
    const HELPERS_RS: &[u8] = b"pub fn help() {}\n";
    const PLAIN_LEN: usize = 100;

    /// `data/ranged.bin` content: bytes `0,1,…,255`. Range reads slice into this.
    fn ranged_body() -> Vec<u8> {
        (0..=255u8).collect()
    }

    /// Content served for each `/vfs/read/<path>` route (`None` → 404).
    fn read_body(path: &str) -> Option<Vec<u8>> {
        match path {
            "/vfs/read/README.md" => Some(README.to_vec()),
            "/vfs/read/src/main.rs" => Some(MAIN_RS.to_vec()),
            "/vfs/read/src/lib.rs" => Some(LIB_RS.to_vec()),
            "/vfs/read/src/util/helpers.rs" => Some(HELPERS_RS.to_vec()),
            "/vfs/read/data/plain.bin" => Some(vec![b'p'; PLAIN_LEN]),
            "/vfs/read/data/ranged.bin" => Some(ranged_body()),
            _ => None,
        }
    }

    /// The `/vfs/tree` snapshot: a flat `path→hash` map plus per-file timestamps.
    /// The hash value is unused by these assertions but must be 64 hex chars so
    /// the provider's `hex::decode` into a 32-byte content hash succeeds.
    fn tree_json() -> String {
        let h = "ab".repeat(32);
        format!(
            "{{\"files\":{{\
                \"README.md\":\"{h}\",\
                \"src/main.rs\":\"{h}\",\
                \"src/lib.rs\":\"{h}\",\
                \"src/util/helpers.rs\":\"{h}\",\
                \"data/plain.bin\":\"{h}\",\
                \"data/ranged.bin\":\"{h}\"\
            }},\"timestamps\":{{\
                \"README.md\":1000,\
                \"src/main.rs\":2000,\
                \"src/lib.rs\":1500,\
                \"src/util/helpers.rs\":3000\
            }}}}"
        )
    }

    /// Parse an HTTP byte range (`Range: bytes=A-B`) from a raw request. Matches on
    /// the `bytes=` value so it is insensitive to header-name casing on the wire.
    fn parse_range(req: &str) -> Option<(usize, usize)> {
        let spec = req.split("bytes=").nth(1)?;
        let spec = spec.split(['\r', '\n']).next()?;
        let (a, b) = spec.split_once('-')?;
        Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
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

                            let (status, body): (&str, Vec<u8>) = if path == "/health" {
                                ("200 OK", b"{\"status\":\"ok\"}".to_vec())
                            } else if path == "/vfs/version" {
                                ("200 OK", b"{\"version\":1}".to_vec())
                            } else if path == "/vfs/tree" {
                                ("200 OK", tree_json().into_bytes())
                            } else if path == "/vfs/read/data/ranged.bin" {
                                // Honor Range for this file only → 206 partial;
                                // otherwise the full body (still a valid 200).
                                let full = ranged_body();
                                match parse_range(&req) {
                                    Some((a, b)) if a <= b && b < full.len() => {
                                        ("206 Partial Content", full[a..=b].to_vec())
                                    }
                                    _ => ("200 OK", full),
                                }
                            } else if let Some(body) = read_body(path) {
                                // Every other file ignores Range and returns 200 full,
                                // exercising the provider's full-fetch-then-slice path.
                                ("200 OK", body)
                            } else {
                                ("404 Not Found", Vec::new())
                            };

                            let header = format!(
                                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
                ("data".to_string(), FileType::Directory),
                ("src".to_string(), FileType::Directory),
            ],
            "root listing must derive the top-level file and the two directories, sorted"
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
            "size is derived from the fetched content, never a stale zero"
        );
        assert_eq!(st.mtime, 1000, "mtime comes from the tree timestamps");
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
    fn read_file_absent_path_is_not_found() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        assert!(matches!(
            provider.read_file("ghost.rs"),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn read_range_honors_server_partial_content() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        // ranged.bin is 0,1,…,255; [246, 256) is the last 10 bytes, served as 206.
        let part = provider
            .read_range("data/ranged.bin", 246, 10)
            .expect("range read");
        assert_eq!(part, (246..=255u8).collect::<Vec<u8>>());
    }

    #[test]
    fn read_range_falls_back_to_full_fetch_and_slices() {
        let daemon = MockDaemon::spawn();
        let provider = KinDaemonProvider::new(daemon.base_url());
        // plain.bin returns 200 (Range ignored) → the provider caches the full body
        // and slices locally, and a second read is served from that cache.
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
