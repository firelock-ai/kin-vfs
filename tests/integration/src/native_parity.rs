// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared graph fixture for the Linux and macOS native `*at` differentials.

use kin_vfs_core::{
    ContentProvider, DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
};

fn vname(name: &[u8]) -> VfsName {
    VfsName::from_bytes(name.to_vec()).expect("valid native-parity entry name")
}

/// Mirrors the raw directory, file, and symlink shape created for
/// `vfs_at_parity_probe`, while deliberately diverging on file bytes and
/// carrying one graph-only entry. The parity subprocess therefore has to use
/// graph-owned virtual descriptors; raw-disk passthrough cannot satisfy the
/// graph-activity assertions.
pub(crate) struct NativeParityProvider;

impl ContentProvider for NativeParityProvider {
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match path.as_bytes() {
            b"file.txt" => Ok(b"graph-parity\n".to_vec()),
            b"graph-only.txt" => Ok(b"graph-only\n".to_vec()),
            b"dir/nested.txt" => Ok(b"nested\n".to_vec()),
            b"multi.txt" => Ok(b"multi\n".to_vec()),
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
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
            b"file.txt" => Ok(VirtualStat::regular_file(13, [7u8; 32], false, 1)),
            b"link.txt" => Ok(VirtualStat::symlink(8, [8u8; 32], 1)),
            b"graph-only.txt" => Ok(VirtualStat::regular_file(11, [9u8; 32], false, 1)),
            b"dir" => Ok(VirtualStat::directory(1)),
            b"dir/nested.txt" => Ok(VirtualStat::regular_file(7, [10u8; 32], false, 1)),
            b"dir/bounce-link" => Ok(VirtualStat::symlink(17, [13u8; 32], 1)),
            b"dir-link" => Ok(VirtualStat::symlink(3, [11u8; 32], 1)),
            b"multi.txt" => {
                let mut stat = VirtualStat::regular_file(6, [12u8; 32], false, 1);
                stat.nlink = 2;
                Ok(stat)
            }
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        match path.as_bytes() {
            b"" => Ok(vec![
                DirEntry {
                    name: vname(b"file.txt"),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: vname(b"link.txt"),
                    file_type: FileType::Symlink,
                },
                DirEntry {
                    name: vname(b"graph-only.txt"),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: vname(b"dir"),
                    file_type: FileType::Directory,
                },
                DirEntry {
                    name: vname(b"dir-link"),
                    file_type: FileType::Symlink,
                },
                DirEntry {
                    name: vname(b"multi.txt"),
                    file_type: FileType::File,
                },
            ]),
            b"dir" => Ok(vec![
                DirEntry {
                    name: vname(b"nested.txt"),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: vname(b"bounce-link"),
                    file_type: FileType::Symlink,
                },
            ]),
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        Ok(matches!(
            path.as_bytes(),
            b"" | b"file.txt"
                | b"link.txt"
                | b"graph-only.txt"
                | b"dir"
                | b"dir/nested.txt"
                | b"dir/bounce-link"
                | b"dir-link"
                | b"multi.txt"
        ))
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match path.as_bytes() {
            b"link.txt" => Ok(b"file.txt".to_vec()),
            b"dir-link" => Ok(b"dir".to_vec()),
            b"dir/bounce-link" => Ok(b"../dir/nested.txt".to_vec()),
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn version(&self) -> u64 {
        1
    }
}
