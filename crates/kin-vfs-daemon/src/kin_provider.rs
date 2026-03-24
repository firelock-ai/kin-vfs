// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider backed by kin-daemon's HTTP API.
//!
//! Fetches file tree and blob content from a running kin-daemon instance
//! (default `http://127.0.0.1:4219`).

use std::collections::{HashMap, HashSet};

use kin_vfs_core::{ContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
use parking_lot::RwLock;

/// Cached snapshot of the file tree from kin-daemon.
struct CachedTree {
    /// path -> hex content hash
    files: HashMap<String, String>,
    /// set of directory paths (derived from file paths)
    dirs: HashSet<String>,
    /// monotonic version counter from kin-daemon
    version: u64,
}

/// A `ContentProvider` that delegates to kin-daemon's `/vfs/*` HTTP endpoints.
pub struct KinDaemonProvider {
    base_url: String,
    /// Optional session ID for session-scoped overlay projections.
    session_id: Option<String>,
    client: reqwest::blocking::Client,
    tree: RwLock<Option<CachedTree>>,
}

impl KinDaemonProvider {
    /// Create a new provider pointing at the given kin-daemon base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            session_id: None,
            client: reqwest::blocking::Client::new(),
            tree: RwLock::new(None),
        }
    }

    /// Create a new provider with an optional session ID.
    pub fn with_session(base_url: impl Into<String>, session_id: Option<String>) -> Self {
        Self {
            base_url: base_url.into(),
            session_id,
            client: reqwest::blocking::Client::new(),
            tree: RwLock::new(None),
        }
    }

    /// Default provider connecting to `http://127.0.0.1:4219`.
    pub fn default_local() -> Self {
        Self::new("http://127.0.0.1:4219")
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
        self.client
            .get(format!("{}/health", self.base_url))  // health is not session-scoped
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Invalidate the cached tree, forcing a re-fetch on the next operation.
    pub fn invalidate_tree(&self) {
        *self.tree.write() = None;
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
        let new_tree = self.fetch_tree()?;

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
            version: remote_version,
        };

        *self.tree.write() = Some(cached);
        Ok(())
    }

    fn fetch_version(&self) -> Result<u64, String> {
        let resp = self
            .client
            .get(self.url("/vfs/version"))
            .send()
            .map_err(|e| format!("version request failed: {e}"))?;

        let json: serde_json::Value = resp
            .json()
            .map_err(|e| format!("version parse failed: {e}"))?;

        json["version"]
            .as_u64()
            .ok_or_else(|| "version field missing or not a number".to_string())
    }

    fn fetch_tree(&self) -> Result<HashMap<String, String>, String> {
        let resp = self
            .client
            .get(self.url("/vfs/tree"))
            .send()
            .map_err(|e| format!("tree request failed: {e}"))?;

        let json: serde_json::Value =
            resp.json().map_err(|e| format!("tree parse failed: {e}"))?;

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
            .client
            .get(self.url(&format!("/vfs/read/{}", norm)))
            .send()
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
        // Simple implementation: read the full file and slice.
        let data = self.read_file(path)?;
        let start = offset as usize;
        let end = std::cmp::min(start + len as usize, data.len());
        if start >= data.len() {
            return Ok(vec![]);
        }
        Ok(data[start..end].to_vec())
    }

    fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read();
        let cached = guard.as_ref().ok_or_else(|| VfsError::Provider(
            "no cached tree available".to_string(),
        ))?;

        // Check if it's a file.
        if let Some(hash_hex) = cached.files.get(norm) {
            let mut content_hash = [0u8; 32];
            if let Ok(bytes) = hex::decode(hash_hex) {
                if bytes.len() == 32 {
                    content_hash.copy_from_slice(&bytes);
                }
            }
            // We don't know the size without fetching; report 0 and let
            // the caller read the file if needed.
            return Ok(VirtualStat::file(0, content_hash, 0));
        }

        // Check if it's a directory.
        if norm.is_empty() || cached.dirs.contains(norm) {
            return Ok(VirtualStat::directory(0));
        }

        Err(VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
        let norm = Self::normalize_path(path);

        self.ensure_tree()
            .map_err(|e| VfsError::Provider(e.to_string()))?;

        let guard = self.tree.read();
        let cached = guard.as_ref().ok_or_else(|| VfsError::Provider(
            "no cached tree available".to_string(),
        ))?;

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
        let cached = guard.as_ref().ok_or_else(|| VfsError::Provider(
            "no cached tree available".to_string(),
        ))?;

        Ok(norm.is_empty()
            || cached.files.contains_key(norm)
            || cached.dirs.contains(norm))
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
        assert_eq!(KinDaemonProvider::normalize_path("/src/main.rs"), "src/main.rs");
        assert_eq!(KinDaemonProvider::normalize_path("src/main.rs"), "src/main.rs");
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
            version: 1,
        });
        assert!(provider.tree.read().is_some());
        // Invalidate.
        provider.invalidate_tree();
        assert!(provider.tree.read().is_none());
    }
}
