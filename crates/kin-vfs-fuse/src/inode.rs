// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Inode table: bidirectional mapping between filesystem paths and FUSE inodes.
//!
//! FUSE identifies every file and directory by a 64-bit inode number. This
//! module maintains the mapping from inodes to paths and back, allocating new
//! inodes on demand as the filesystem is traversed.

use std::collections::HashMap;

/// Root directory inode (FUSE convention).
pub const ROOT_INO: u64 = 1;

/// Bidirectional mapping between paths and inode numbers.
///
/// Inodes are allocated lazily as paths are looked up. The root directory
/// is pre-allocated as inode 1.
pub struct InodeTable {
    /// inode → normalized path (no leading slash, "" = root)
    ino_to_path: HashMap<u64, String>,
    /// normalized path → inode
    path_to_ino: HashMap<String, u64>,
    /// Next inode number to allocate.
    next_ino: u64,
}

impl InodeTable {
    pub fn new() -> Self {
        let mut table = Self {
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            next_ino: 2, // 1 is reserved for root
        };
        table.ino_to_path.insert(ROOT_INO, String::new());
        table.path_to_ino.insert(String::new(), ROOT_INO);
        table
    }

    /// Get the path for an inode, if it exists.
    pub fn get_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(|s| s.as_str())
    }

    /// Get the inode for a path, if it has been allocated.
    pub fn get_ino(&self, path: &str) -> Option<u64> {
        self.path_to_ino.get(path).copied()
    }

    /// Get or allocate an inode for the given path.
    pub fn get_or_insert(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }

    /// Resolve a child name under a parent inode to a full path.
    /// Returns the normalized path (e.g., "src/main.rs").
    pub fn child_path(&self, parent_ino: u64, name: &str) -> Option<String> {
        let parent_path = self.get_path(parent_ino)?;
        if parent_path.is_empty() {
            Some(name.to_string())
        } else {
            Some(format!("{}/{}", parent_path, name))
        }
    }

    /// Invalidate all cached inodes (except root). Call when the provider
    /// version changes and the file tree may have been restructured.
    pub fn clear(&mut self) {
        self.ino_to_path.clear();
        self.path_to_ino.clear();
        self.next_ino = 2;
        self.ino_to_path.insert(ROOT_INO, String::new());
        self.path_to_ino.insert(String::new(), ROOT_INO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_preallocated() {
        let table = InodeTable::new();
        assert_eq!(table.get_path(ROOT_INO), Some(""));
        assert_eq!(table.get_ino(""), Some(ROOT_INO));
    }

    #[test]
    fn allocate_and_lookup() {
        let mut table = InodeTable::new();
        let ino = table.get_or_insert("src/main.rs");
        assert_eq!(ino, 2);
        assert_eq!(table.get_path(ino), Some("src/main.rs"));
        assert_eq!(table.get_ino("src/main.rs"), Some(ino));

        // Second call returns same inode.
        assert_eq!(table.get_or_insert("src/main.rs"), ino);
    }

    #[test]
    fn child_path_from_root() {
        let table = InodeTable::new();
        assert_eq!(table.child_path(ROOT_INO, "Cargo.toml"), Some("Cargo.toml".into()));
    }

    #[test]
    fn child_path_nested() {
        let mut table = InodeTable::new();
        let src_ino = table.get_or_insert("src");
        assert_eq!(table.child_path(src_ino, "main.rs"), Some("src/main.rs".into()));
    }

    #[test]
    fn clear_resets() {
        let mut table = InodeTable::new();
        table.get_or_insert("src/main.rs");
        table.get_or_insert("Cargo.toml");
        table.clear();
        assert_eq!(table.get_path(ROOT_INO), Some(""));
        assert_eq!(table.get_ino("src/main.rs"), None);
        assert_eq!(table.get_or_insert("src/main.rs"), 2); // re-allocated from 2
    }
}
