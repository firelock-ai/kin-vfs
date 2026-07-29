// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared graph fixture for the Linux and macOS native `*at` differentials.

use kin_vfs_core::{
    ContentProvider, DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
};

fn vname(name: &[u8]) -> VfsName {
    VfsName::from_bytes(name.to_vec()).expect("valid native-parity entry name")
}

/// Mirrors the raw directory, file, and symlink created for
/// `vfs_at_parity_probe`, allowing each platform to compare native libc with
/// graph-backed virtual descriptors from the same probe binary.
pub(crate) struct NativeParityProvider;

impl ContentProvider for NativeParityProvider {
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        if path.as_bytes() == b"file.txt" {
            Ok(b"parity\n".to_vec())
        } else {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }
    }

    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let data = self.read_file(path)?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let requested = usize::try_from(len).unwrap_or(usize::MAX);
        let end = start.saturating_add(requested).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        match path.as_bytes() {
            b"" => Ok(VirtualStat::directory(1)),
            b"file.txt" => Ok(VirtualStat::regular_file(7, [7u8; 32], false, 1)),
            b"link.txt" => Ok(VirtualStat::symlink(8, [8u8; 32], 1)),
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        if !path.is_root() {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }
        Ok(vec![
            DirEntry {
                name: vname(b"file.txt"),
                file_type: FileType::File,
            },
            DirEntry {
                name: vname(b"link.txt"),
                file_type: FileType::Symlink,
            },
        ])
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        Ok(matches!(path.as_bytes(), b"" | b"file.txt" | b"link.txt"))
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        if path.as_bytes() == b"link.txt" {
            Ok(b"file.txt".to_vec())
        } else {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }
    }

    fn version(&self) -> u64 {
        1
    }
}
