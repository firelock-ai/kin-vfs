// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Async `ContentProvider` backed by kin-daemon's HTTP API.
//!
//! Uses `reqwest::Client` (async) so it can be driven directly from the
//! tokio-based daemon server without `spawn_blocking`.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;

use kin_vfs_core::{AsyncContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
use lru::LruCache;
use tokio::sync::RwLock;

/// Cached snapshot of the file tree from kin-daemon.
struct CachedTree {
    /// path -> hex content hash
    files: HashMap<String, String>,
    /// set of directory paths (derived from file paths)
    dirs: HashSet<String>,
    /// path -> file size in bytes (populated lazily on stat)
    sizes: HashMap<String, u64>,
    /// monotonic version counter from kin-daemon
    version: u64,
}

/// An async `ContentProvider` that delegates to kin-daemon's `/vfs/*` HTTP
/// endpoints using `reqwest::Client`.
///
/// Designed for use inside the tokio-based VFS daemon server. For sync
/// contexts (e.g. the shim), use [`super::KinDaemonProvider`] instead.
pub struct AsyncKinDaemonProvider {
    base_url: String,
    session_id: Option<String>,
    client: reqwest::Client,
    tree: RwLock<Option<CachedTree>>,
    content_cache: RwLock<LruCache<String, Vec<u8>>>,
}

impl AsyncKinDaemonProvider {
    const CONTENT_CACHE_CAP: usize = 64;

    /// Create a new async provider pointing at the given kin-daemon base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            session_id: None,
            client: reqwest::Client::new(),
            tree: RwLock::new(None),
            content_cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(Self::CONTENT_CACHE_CAP).unwrap(),
            )),
        }
    }

    /// Create a new async provider with an optional session ID.
    pub fn with_session(base_url: impl Into<String>, session_id: Option<String>) -> Self {
        Self {
            base_url: base_url.into(),
            session_id,
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

    /// Check if the kin-daemon is reachable.
    pub async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url))
            .timeout(std::time::Duration::from_secs(2))
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

    fn normalize_path(path: &str) -> &str {
        let p = path.strip_prefix('/').unwrap_or(path);
        if p == "." { "" } else { p }
    }

    async fn ensure_tree(&self) -> Result<(), String> {
        let remote_version = self.fetch_version().await?;

        {
            let guard = self.tree.read().await;
            if let Some(ref cached) = *guard {
                if cached.version == remote_version {
                    return Ok(());
                }
            }
        }

        self.content_cache.write().await.clear();
        let new_tree = self.fetch_tree().await?;

        let mut dirs = HashSet::new();
        dirs.insert(String::new());
        for path in new_tree.keys() {
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
            version: remote_version,
        };

        *self.tree.write().await = Some(cached);
        Ok(())
    }

    async fn fetch_version(&self) -> Result<u64, String> {
        let resp = self
            .client
            .get(self.url("/vfs/version"))
            .send()
            .await
            .map_err(|e| format!("version request failed: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("version parse failed: {e}"))?;

        json["version"]
            .as_u64()
            .ok_or_else(|| "version field missing or not a number".to_string())
    }

    async fn fetch_tree(&self) -> Result<HashMap<String, String>, String> {
        let resp = self
            .client
            .get(self.url("/vfs/tree"))
            .send()
            .await
            .map_err(|e| format!("tree request failed: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("tree parse failed: {e}"))?;

        let files_obj = json["files"]
            .as_object()
            .ok_or_else(|| "tree response missing 'files' object".to_string())?;

        let mut files = HashMap::with_capacity(files_obj.len());
        for (k, v) in files_obj {
            if let Some(hash) = v.as_str() {
                files.insert(k.clone(), hash.to_string());
            }
        }

        Ok(files)
    }
}

impl AsyncContentProvider for AsyncKinDaemonProvider {
    async fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .await
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        {
            let guard = self.tree.read().await;
            if let Some(ref cached) = *guard {
                if !cached.files.contains_key(norm) {
                    return Err(VfsError::NotFound {
                        path: path.to_string(),
                    });
                }
            }
        }

        let resp = self
            .client
            .get(self.url(&format!("/vfs/read/{}", norm)))
            .send()
            .await
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
            .await
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("read body error: {e}")))
    }

    async fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let norm = Self::normalize_path(path).to_string();

        {
            let mut cache = self.content_cache.write().await;
            if let Some(data) = cache.get(&norm) {
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(vec![]);
                }
                let end = std::cmp::min(start + len as usize, data.len());
                return Ok(data[start..end].to_vec());
            }
        }

        self.ensure_tree()
            .await
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let range_end = offset.saturating_add(len).saturating_sub(1);
        let resp = self
            .client
            .get(self.url(&format!("/vfs/read/{}", norm)))
            .header("Range", format!("bytes={}-{}", offset, range_end))
            .send()
            .await
            .map_err(|e| VfsError::Provider(format!("range read request failed: {e}")))?;

        if resp.status().as_u16() == 404 {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }

        if resp.status().as_u16() == 206 {
            return resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| VfsError::Provider(format!("range read body error: {e}")));
        }

        if !resp.status().is_success() {
            return Err(VfsError::Provider(format!(
                "read returned status {}",
                resp.status()
            )));
        }

        let data = resp
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| VfsError::Provider(format!("read body error: {e}")))?;

        let start = offset as usize;
        let result = if start >= data.len() {
            vec![]
        } else {
            let end = std::cmp::min(start + len as usize, data.len());
            data[start..end].to_vec()
        };

        self.content_cache.write().await.put(norm, data);
        Ok(result)
    }

    async fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .await
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let (is_file, hash_hex, cached_size) = {
            let guard = self.tree.read().await;
            let cached = guard.as_ref().ok_or_else(|| {
                VfsError::Provider("no cached tree available".to_string())
            })?;

            if let Some(hash_hex) = cached.files.get(norm) {
                let size = cached.sizes.get(norm).copied();
                (true, Some(hash_hex.clone()), size)
            } else if norm.is_empty() || cached.dirs.contains(norm) {
                return Ok(VirtualStat::directory(0));
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

        if let Some(size) = cached_size {
            return Ok(VirtualStat::file(size, content_hash, 0));
        }

        let size = match self.read_file(path).await {
            Ok(data) => {
                let len = data.len() as u64;
                if let Some(ref mut cached) = *self.tree.write().await {
                    cached.sizes.insert(norm.to_string(), len);
                }
                len
            }
            Err(_) => 0,
        };

        Ok(VirtualStat::file(size, content_hash, 0))
    }

    async fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .await
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read().await;
        let cached = guard.as_ref().ok_or_else(|| {
            VfsError::Provider("no cached tree available".to_string())
        })?;

        if !norm.is_empty() && !cached.dirs.contains(norm) {
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

    async fn exists(&self, path: &str) -> VfsResult<bool> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .await
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read().await;
        let cached = guard.as_ref().ok_or_else(|| {
            VfsError::Provider("no cached tree available".to_string())
        })?;

        Ok(norm.is_empty()
            || cached.files.contains_key(norm)
            || cached.dirs.contains(norm))
    }

    async fn version(&self) -> u64 {
        self.fetch_version().await.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_paths() {
        assert_eq!(AsyncKinDaemonProvider::normalize_path("/src/main.rs"), "src/main.rs");
        assert_eq!(AsyncKinDaemonProvider::normalize_path("src/main.rs"), "src/main.rs");
        assert_eq!(AsyncKinDaemonProvider::normalize_path("."), "");
        assert_eq!(AsyncKinDaemonProvider::normalize_path("/"), "");
        assert_eq!(AsyncKinDaemonProvider::normalize_path(""), "");
    }

    #[tokio::test]
    async fn unavailable_daemon_returns_false() {
        let provider = AsyncKinDaemonProvider::new("http://127.0.0.1:19999");
        assert!(!provider.is_available().await);
    }

    #[test]
    fn url_without_session() {
        let provider = AsyncKinDaemonProvider::new("http://127.0.0.1:4219");
        assert_eq!(
            provider.url("/vfs/version"),
            "http://127.0.0.1:4219/vfs/version"
        );
    }

    #[test]
    fn url_with_session() {
        let provider =
            AsyncKinDaemonProvider::with_session("http://127.0.0.1:4219", Some("sess-42".into()));
        assert_eq!(
            provider.url("/vfs/version"),
            "http://127.0.0.1:4219/vfs/version?session_id=sess-42"
        );
    }
}
