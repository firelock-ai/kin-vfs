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
    fn send_with_auth_retry<F>(
        &self,
        build: F,
    ) -> reqwest::Result<reqwest::blocking::Response>
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
                .get(format!("{}/health", self.base_url)) // health is not session-scoped
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
            .send_with_auth_retry(|| self.client.get(self.url("/vfs/version")))
            .map_err(|e| format!("version request failed: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .map_err(|e| format!("version parse failed: {e}"))?;

        json["version"]
            .as_u64()
            .ok_or_else(|| "version field missing or not a number".to_string())
    }

    fn fetch_tree(&self) -> Result<(HashMap<String, String>, HashMap<String, u64>), String> {
        let resp = self
            .send_with_auth_retry(|| self.client.get(self.url("/vfs/tree")))
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
            .send_with_auth_retry(|| self.client.get(self.url(&format!("/vfs/read/{}", norm))))
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
                    .get(self.url(&format!("/vfs/read/{}", norm)))
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

        // Fetch file content to determine size, then cache it.
        let size = match self.read_file(path) {
            Ok(data) => {
                let len = data.len() as u64;
                // Cache the size for future stat calls.
                if let Some(ref mut cached) = *self.tree.write() {
                    cached.sizes.insert(norm.to_string(), len);
                }
                len
            }
            Err(_) => 0,
        };

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
}
