// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Inode table: bidirectional mapping between filesystem paths and FUSE inodes.
//!
//! FUSE identifies every file and directory by a 64-bit inode number. This
//! module maintains the mapping from inodes to paths and back, allocating new
//! inodes on demand as the filesystem is traversed.

use std::collections::HashMap;

use kin_vfs_core::{VfsName, VfsPath};

/// Root directory inode (FUSE convention).
pub const ROOT_INO: u64 = 1;

/// Bidirectional mapping between paths and inode numbers.
///
/// Inodes are allocated lazily as paths are looked up. The root directory
/// is pre-allocated as inode 1.
pub struct InodeTable {
    /// inode → byte-exact graph path (empty = root)
    ino_to_path: HashMap<u64, VfsPath>,
    /// byte-exact graph path → inode
    path_to_ino: HashMap<VfsPath, u64>,
    /// Next inode number to allocate.
    next_ino: u64,
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable {
    pub fn new() -> Self {
        let mut table = Self {
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            next_ino: 2, // 1 is reserved for root
        };
        table.ino_to_path.insert(ROOT_INO, VfsPath::root());
        table.path_to_ino.insert(VfsPath::root(), ROOT_INO);
        table
    }

    /// Get the path for an inode, if it exists.
    pub fn get_path(&self, ino: u64) -> Option<&VfsPath> {
        self.ino_to_path.get(&ino)
    }

    /// Get the inode for a path, if it has been allocated.
    pub fn get_ino(&self, path: &VfsPath) -> Option<u64> {
        self.path_to_ino.get(path).copied()
    }

    /// Get or allocate an inode for the given path.
    pub fn get_or_insert(&mut self, path: &VfsPath) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.clone());
        self.path_to_ino.insert(path.clone(), ino);
        ino
    }

    /// Resolve a child name under a parent inode to a full byte-exact path.
    ///
    /// The name arrives from the kernel as raw `OsStr` bytes and is validated,
    /// never lossily decoded: a mount must address the artifact the caller
    /// actually named.
    pub fn child_path(&self, parent_ino: u64, name: &VfsName) -> Option<VfsPath> {
        Some(self.get_path(parent_ino)?.join(name))
    }

    /// Invalidate all cached inodes (except root). Call when the provider
    /// version changes and the file tree may have been restructured.
    pub fn clear(&mut self) {
        self.ino_to_path.clear();
        self.path_to_ino.clear();
        self.next_ino = 2;
        self.ino_to_path.insert(ROOT_INO, VfsPath::root());
        self.path_to_ino.insert(VfsPath::root(), ROOT_INO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid test path")
    }

    fn vname(name: &[u8]) -> VfsName {
        VfsName::from_bytes(name.to_vec()).expect("valid test name")
    }

    #[test]
    fn root_is_preallocated() {
        let table = InodeTable::new();
        assert_eq!(table.get_path(ROOT_INO), Some(&VfsPath::root()));
        assert_eq!(table.get_ino(&VfsPath::root()), Some(ROOT_INO));
    }

    #[test]
    fn allocate_and_lookup() {
        let mut table = InodeTable::new();
        let ino = table.get_or_insert(&vpath("src/main.rs"));
        assert_eq!(ino, 2);
        assert_eq!(table.get_path(ino), Some(&vpath("src/main.rs")));
        assert_eq!(table.get_ino(&vpath("src/main.rs")), Some(ino));

        // Second call returns same inode.
        assert_eq!(table.get_or_insert(&vpath("src/main.rs")), ino);
    }

    #[test]
    fn non_utf8_paths_get_distinct_inodes() {
        let mut table = InodeTable::new();
        let raw = VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).unwrap();
        let near = VfsPath::from_bytes(b"logs/x-\xff\xfd.log".to_vec()).unwrap();
        let raw_ino = table.get_or_insert(&raw);
        let near_ino = table.get_or_insert(&near);
        assert_ne!(
            raw_ino, near_ino,
            "names differing by one byte are distinct artifacts"
        );
        assert_eq!(table.get_path(raw_ino), Some(&raw));
    }

    #[test]
    fn child_path_from_root() {
        let table = InodeTable::new();
        assert_eq!(
            table.child_path(ROOT_INO, &vname(b"Cargo.toml")),
            Some(vpath("Cargo.toml"))
        );
    }

    #[test]
    fn child_path_nested() {
        let mut table = InodeTable::new();
        let src_ino = table.get_or_insert(&vpath("src"));
        assert_eq!(
            table.child_path(src_ino, &vname(b"main.rs")),
            Some(vpath("src/main.rs"))
        );
    }

    #[test]
    fn clear_resets() {
        let mut table = InodeTable::new();
        table.get_or_insert(&vpath("src/main.rs"));
        table.get_or_insert(&vpath("Cargo.toml"));
        table.clear();
        assert_eq!(table.get_path(ROOT_INO), Some(&VfsPath::root()));
        assert_eq!(table.get_ino(&vpath("src/main.rs")), None);
        assert_eq!(table.get_or_insert(&vpath("src/main.rs")), 2); // re-allocated from 2
    }
}
