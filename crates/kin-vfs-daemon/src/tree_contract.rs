// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};

use kin_model::{TreeEntry, TreeEntryKind};
use kin_vfs_core::{FileType, VfsError, VfsResult, VirtualStat};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Exact effective repository tree returned by kin-daemon.
///
/// Every tracked path is present whether or not Kin can parse its contents.
/// The entry identifies both the graph-owned blob and its Git-relevant kind.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreeSnapshot {
    pub(crate) entries: HashMap<String, TreeEntry>,
    pub(crate) sizes: HashMap<String, u64>,
    #[serde(default)]
    pub(crate) timestamps: HashMap<String, u64>,
}

pub(crate) struct CachedTree {
    pub(crate) entries: HashMap<String, TreeEntry>,
    pub(crate) dirs: HashSet<String>,
    pub(crate) sizes: HashMap<String, u64>,
    pub(crate) timestamps: HashMap<String, u64>,
    pub(crate) version: u64,
}

impl CachedTree {
    pub(crate) fn from_snapshot(snapshot: TreeSnapshot, version: u64) -> Result<Self, String> {
        if snapshot.entries.len() != snapshot.sizes.len()
            || snapshot
                .entries
                .keys()
                .any(|path| !snapshot.sizes.contains_key(path))
        {
            return Err(
                "exact tree response must contain one size for every tree entry and no extras"
                    .to_string(),
            );
        }

        for path in snapshot.entries.keys() {
            let mut components = path.split('/');
            if path.is_empty()
                || path.starts_with('/')
                || path.ends_with('/')
                || components
                    .any(|component| component.is_empty() || component == "." || component == "..")
            {
                return Err(format!(
                    "exact tree response contains non-canonical path {path:?}"
                ));
            }

            let mut ancestor = String::new();
            for component in path.split('/').take(path.split('/').count() - 1) {
                if !ancestor.is_empty() {
                    ancestor.push('/');
                }
                ancestor.push_str(component);
                if snapshot.entries.contains_key(&ancestor) {
                    return Err(format!(
                        "exact tree response contains file/directory collision at {ancestor:?}"
                    ));
                }
            }
        }

        let mut dirs = HashSet::new();
        dirs.insert(String::new());
        for path in snapshot.entries.keys() {
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

        Ok(Self {
            entries: snapshot.entries,
            dirs,
            sizes: snapshot.sizes,
            timestamps: snapshot.timestamps,
            version,
        })
    }

    pub(crate) fn entry_and_size(
        &self,
        normalized_path: &str,
        requested_path: &str,
    ) -> VfsResult<(TreeEntry, u64)> {
        if let Some(entry) = self.entries.get(normalized_path).copied() {
            let size = self.sizes.get(normalized_path).copied().ok_or_else(|| {
                VfsError::Provider(format!("exact tree size missing for {normalized_path}"))
            })?;
            Ok((entry, size))
        } else if normalized_path.is_empty() || self.dirs.contains(normalized_path) {
            Err(VfsError::IsDirectory {
                path: requested_path.to_string(),
            })
        } else {
            Err(VfsError::NotFound {
                path: requested_path.to_string(),
            })
        }
    }
}

pub(crate) fn stat_for_entry(entry: TreeEntry, size: u64, mtime: u64) -> VirtualStat {
    let hash = *entry.blob_hash.as_bytes();
    match entry.kind {
        TreeEntryKind::Regular { executable } => {
            VirtualStat::regular_file(size, hash, executable, mtime)
        }
        TreeEntryKind::Symlink => VirtualStat::symlink(size, hash, mtime),
    }
}

pub(crate) fn file_type(entry: TreeEntry) -> FileType {
    match entry.kind {
        TreeEntryKind::Regular { .. } => FileType::File,
        TreeEntryKind::Symlink => FileType::Symlink,
    }
}

pub(crate) fn verify_blob(path: &str, entry: TreeEntry, data: &[u8]) -> VfsResult<()> {
    let actual: [u8; 32] = Sha256::digest(data).into();
    let expected = *entry.blob_hash.as_bytes();
    if actual == expected {
        Ok(())
    } else {
        Err(VfsError::Provider(format!(
            "graph blob hash mismatch for {path}: expected {}, got {}",
            entry.blob_hash,
            hex::encode(actual)
        )))
    }
}

pub(crate) fn verify_size(path: &str, expected: u64, actual: usize) -> VfsResult<()> {
    if usize::try_from(expected).ok() == Some(actual) {
        Ok(())
    } else {
        Err(VfsError::Provider(format!(
            "graph blob size mismatch for {path}: expected {expected}, got {actual}"
        )))
    }
}

pub(crate) fn verify_range_headers(
    path: &str,
    entry: TreeEntry,
    expected_start: u64,
    expected_end: u64,
    expected_total: u64,
    headers: &HeaderMap,
) -> VfsResult<()> {
    let response_hash = headers
        .get("x-kin-blob-hash")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            VfsError::Provider(format!(
                "ranged graph read for {path} missing X-Kin-Blob-Hash"
            ))
        })?;
    if response_hash != entry.blob_hash.to_string() {
        return Err(VfsError::Provider(format!(
            "ranged graph read hash mismatch for {path}: expected {}, got {response_hash}",
            entry.blob_hash
        )));
    }

    let content_range = headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            VfsError::Provider(format!(
                "ranged graph read for {path} missing Content-Range"
            ))
        })?;
    let expected = format!("bytes {expected_start}-{expected_end}/{expected_total}");
    if content_range != expected {
        return Err(VfsError::Provider(format!(
            "ranged graph read metadata mismatch for {path}: expected {expected}, got {content_range}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::Hash256;

    fn regular(byte: u8) -> TreeEntry {
        TreeEntry::regular(Hash256::from_bytes([byte; 32]), false)
    }

    fn snapshot(
        entries: impl IntoIterator<Item = (&'static str, TreeEntry)>,
        sizes: impl IntoIterator<Item = (&'static str, u64)>,
    ) -> TreeSnapshot {
        TreeSnapshot {
            entries: entries
                .into_iter()
                .map(|(path, entry)| (path.to_string(), entry))
                .collect(),
            sizes: sizes
                .into_iter()
                .map(|(path, size)| (path.to_string(), size))
                .collect(),
            timestamps: HashMap::new(),
        }
    }

    #[test]
    fn exact_tree_requires_one_size_per_entry_and_no_extras() {
        let missing = snapshot([("compose.yaml", regular(1))], []);
        assert!(CachedTree::from_snapshot(missing, 1).is_err());

        let extra = snapshot(
            [("compose.yaml", regular(1))],
            [("compose.yaml", 10), ("ghost.bin", 4)],
        );
        assert!(CachedTree::from_snapshot(extra, 1).is_err());
    }

    #[test]
    fn exact_tree_rejects_noncanonical_and_colliding_paths() {
        for invalid in [
            "",
            "/absolute",
            "dir/",
            "dir//file",
            "dir/./file",
            "../file",
        ] {
            let tree = snapshot([(invalid, regular(1))], [(invalid, 1)]);
            assert!(
                CachedTree::from_snapshot(tree, 1).is_err(),
                "{invalid:?} must be rejected"
            );
        }

        let collision = snapshot(
            [("tools", regular(1)), ("tools/run", regular(2))],
            [("tools", 1), ("tools/run", 1)],
        );
        assert!(CachedTree::from_snapshot(collision, 1).is_err());
    }

    #[test]
    fn exact_tree_derives_only_real_ancestor_directories() {
        let tree = snapshot(
            [
                ("compose.yaml", regular(1)),
                (
                    "scripts/run",
                    TreeEntry::regular(Hash256::from_bytes([2; 32]), true),
                ),
                (
                    "assets/current",
                    TreeEntry::symlink(Hash256::from_bytes([3; 32])),
                ),
            ],
            [
                ("compose.yaml", 10),
                ("scripts/run", 20),
                ("assets/current", 7),
            ],
        );
        let cached = CachedTree::from_snapshot(tree, 7).expect("valid exact tree");
        assert_eq!(cached.version, 7);
        assert_eq!(
            cached.dirs,
            HashSet::from([String::new(), "assets".to_string(), "scripts".to_string()])
        );
    }
}
