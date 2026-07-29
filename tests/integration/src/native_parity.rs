// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared graph fixture for the Linux and macOS native `*at` differentials.

use kin_vfs_core::{
    ContentProvider, DirEntry, FileType, SnapshotToken, VfsError, VfsName, VfsPath, VfsResult,
    VirtualStat,
};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

const STATEFUL_LEN: usize = 64 * 1024 + 1;
const CONCURRENT_CHUNK: usize = 32 * 1024 + 1;
const CONCURRENT_LEN: usize = CONCURRENT_CHUNK * 2;
const STATEFUL_OLD_HASH: [u8; 32] = [20; 32];
const STATEFUL_NEW_HASH: [u8; 32] = [21; 32];
const ROOT_OBJECT_ID: [u8; 32] = [30; 32];
const STATEFUL_OLD_OBJECT_ID: [u8; 32] = [31; 32];
const STATEFUL_NEW_OBJECT_ID: [u8; 32] = [32; 32];
const UNLINKED_OBJECT_ID: [u8; 32] = [33; 32];
const RENAMED_OBJECT_ID: [u8; 32] = [34; 32];
const RENAMED_DIRECTORY_OBJECT_ID: [u8; 32] = [35; 32];
const RENAMED_DIRECTORY_CHILD_OBJECT_ID: [u8; 32] = [36; 32];
const DIR_OBJECT_ID: [u8; 32] = [37; 32];
const DEEP_DIRECTORY_OBJECT_ID: [u8; 32] = [38; 32];
const SUB_DIRECTORY_OBJECT_ID: [u8; 32] = [39; 32];
const FILE_OBJECT_ID: [u8; 32] = [40; 32];
const DEEP_FILE_OBJECT_ID: [u8; 32] = [41; 32];
const CREATE_0555_OBJECT_ID: [u8; 32] = [42; 32];
const CREATE_0333_OBJECT_ID: [u8; 32] = [43; 32];
const CREATE_0000_OBJECT_ID: [u8; 32] = [44; 32];

fn vname(name: &[u8]) -> VfsName {
    VfsName::from_bytes(name.to_vec()).expect("valid native-parity entry name")
}

/// Mirrors the raw directory, file, and symlink shape created for
/// `vfs_at_parity_probe`, while deliberately diverging on file bytes and
/// carrying one graph-only entry. The parity subprocess therefore has to use
/// graph-owned virtual descriptors; raw-disk passthrough cannot satisfy the
/// graph-activity assertions.
#[derive(Default)]
pub(crate) struct NativeParityProvider {
    stateful_generation: AtomicU8,
    raced_symlinks: AtomicU8,
}

impl NativeParityProvider {
    fn current_snapshot_token(&self) -> SnapshotToken {
        let stateful = self.stateful_generation.load(Ordering::SeqCst) << 4;
        let symlinks = self.raced_symlinks.load(Ordering::SeqCst) & 0b111;
        [stateful | (symlinks << 1) | 1; 32]
    }

    fn require_snapshot(&self, snapshot: SnapshotToken) -> VfsResult<()> {
        if snapshot == self.current_snapshot_token() {
            Ok(())
        } else {
            Err(VfsError::Provider(
                "native-parity descriptor snapshot changed".to_string(),
            ))
        }
    }

    fn racy_symlink_bit(path: &VfsPath) -> Option<u8> {
        match path.as_bytes() {
            b"racy-readlink.txt" => Some(0b001),
            b"racy-at-cwd.txt" => Some(0b010),
            b"racy-at-dirfd.txt" => Some(0b100),
            _ => None,
        }
    }

    fn racy_link_target_for_mask(bit: u8, mask: u8) -> Vec<u8> {
        if mask & bit == 0 {
            b"file.txt".to_vec()
        } else {
            b"graph-only.txt".to_vec()
        }
    }
}

impl ContentProvider for NativeParityProvider {
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match path.as_bytes() {
            b"file.txt" => Ok(b"graph-parity\n".to_vec()),
            b"graph-only.txt" => Ok(b"graph-only\n".to_vec()),
            b"dir/nested.txt" => Ok(b"nested\n".to_vec()),
            b"dir/deep/file.txt" => Ok(b"ordered\n".to_vec()),
            b"nosearch/child.txt" => Ok(b"hidden\n".to_vec()),
            b"multi.txt" => Ok(b"multi\n".to_vec()),
            b"readonly.txt" | b"writeonly.txt" | b"noaccess.txt" => Ok(b"modes\n".to_vec()),
            b"concurrent.bin" => {
                let mut data = vec![b'A'; CONCURRENT_CHUNK];
                data.extend(std::iter::repeat_n(b'B', CONCURRENT_CHUNK));
                Ok(data)
            }
            b"trigger.txt" => {
                self.stateful_generation.store(1, Ordering::SeqCst);
                Ok(b"trigger\n".to_vec())
            }
            b"stateful.bin" => Ok(vec![
                if self.stateful_generation.load(Ordering::SeqCst) == 0 {
                    b'O'
                } else {
                    b'N'
                };
                STATEFUL_LEN
            ]),
            b"unlinked.bin" | b"renamed.bin"
                if self.stateful_generation.load(Ordering::SeqCst) == 0 =>
            {
                Ok(vec![b'O'; STATEFUL_LEN])
            }
            b"moved.bin" if self.stateful_generation.load(Ordering::SeqCst) != 0 => {
                Ok(vec![b'O'; STATEFUL_LEN])
            }
            b"renamed-dir/child.txt" if self.stateful_generation.load(Ordering::SeqCst) == 0 => {
                Ok(b"dir-child\n".to_vec())
            }
            b"moved-dir/child.txt" if self.stateful_generation.load(Ordering::SeqCst) != 0 => {
                Ok(b"dir-child\n".to_vec())
            }
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        if path.as_bytes() == b"concurrent.bin" {
            // Make the pre-fix same-description race deterministic enough for
            // the native differential: both callers can enter the provider
            // before either response advances the shim offset. The fixed shim
            // serializes before this boundary.
            std::thread::sleep(Duration::from_millis(100));
        }
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
            b"" => Ok(VirtualStat::directory(1).with_object_id(ROOT_OBJECT_ID)),
            b"file.txt" => {
                Ok(VirtualStat::regular_file(13, [7u8; 32], false, 1)
                    .with_object_id(FILE_OBJECT_ID))
            }
            b"link.txt" => Ok(VirtualStat::symlink(8, [8u8; 32], 1)),
            b"dangling-link.txt" => Ok(VirtualStat::symlink(18, [23u8; 32], 1)),
            b"racy-readlink.txt" | b"racy-at-cwd.txt" | b"racy-at-dirfd.txt" => {
                let bit = Self::racy_symlink_bit(path).expect("matched racy link");
                let mask = self.raced_symlinks.load(Ordering::SeqCst);
                let target = Self::racy_link_target_for_mask(bit, mask);
                Ok(VirtualStat::symlink(
                    target.len() as u64,
                    [24u8.wrapping_add(bit); 32],
                    1,
                ))
            }
            b"graph-only.txt" => Ok(VirtualStat::regular_file(11, [9u8; 32], false, 1)),
            b"dir" => Ok(VirtualStat::directory(1).with_object_id(DIR_OBJECT_ID)),
            b"dir/nested.txt" => Ok(VirtualStat::regular_file(7, [10u8; 32], false, 1)),
            b"dir/deep" => Ok(VirtualStat::directory(1).with_object_id(DEEP_DIRECTORY_OBJECT_ID)),
            b"dir/deep/sub" => {
                Ok(VirtualStat::directory(1).with_object_id(SUB_DIRECTORY_OBJECT_ID))
            }
            b"dir/deep/file.txt" => Ok(VirtualStat::regular_file(8, [14u8; 32], false, 1)
                .with_object_id(DEEP_FILE_OBJECT_ID)),
            b"nosearch" => {
                let mut stat = VirtualStat::directory(1);
                stat.mode = 0;
                Ok(stat)
            }
            b"nosearch/child.txt" => Ok(VirtualStat::regular_file(7, [29; 32], false, 1)),
            b"create-0555" | b"create-0333" | b"create-0000" => {
                let mut stat = VirtualStat::directory(1).with_object_id(match path.as_bytes() {
                    b"create-0555" => CREATE_0555_OBJECT_ID,
                    b"create-0333" => CREATE_0333_OBJECT_ID,
                    _ => CREATE_0000_OBJECT_ID,
                });
                stat.mode = match path.as_bytes() {
                    b"create-0555" => 0o555,
                    b"create-0333" => 0o333,
                    _ => 0o000,
                };
                Ok(stat)
            }
            b"dir/order-link" => Ok(VirtualStat::symlink(8, [15u8; 32], 1)),
            b"dir/bounce-link" => Ok(VirtualStat::symlink(17, [13u8; 32], 1)),
            b"dir-link" => Ok(VirtualStat::symlink(3, [11u8; 32], 1)),
            b"readonly.txt" => {
                let mut stat = VirtualStat::regular_file(6, [16; 32], false, 1);
                stat.mode = 0o444;
                Ok(stat)
            }
            b"writeonly.txt" => {
                let mut stat = VirtualStat::regular_file(6, [17; 32], false, 1);
                stat.mode = 0o222;
                Ok(stat)
            }
            b"noaccess.txt" => {
                let mut stat = VirtualStat::regular_file(6, [18; 32], false, 1);
                stat.mode = 0;
                Ok(stat)
            }
            b"concurrent.bin" => Ok(VirtualStat::regular_file(
                CONCURRENT_LEN as u64,
                [28; 32],
                false,
                1,
            )),
            b"trigger.txt" => Ok(VirtualStat::regular_file(8, [19; 32], false, 1)),
            b"stateful.bin" => {
                let replaced = self.stateful_generation.load(Ordering::SeqCst) != 0;
                Ok(VirtualStat::regular_file(
                    STATEFUL_LEN as u64,
                    if replaced {
                        STATEFUL_NEW_HASH
                    } else {
                        STATEFUL_OLD_HASH
                    },
                    false,
                    if replaced { 2 } else { 1 },
                )
                .with_object_id(if replaced {
                    STATEFUL_NEW_OBJECT_ID
                } else {
                    STATEFUL_OLD_OBJECT_ID
                }))
            }
            b"unlinked.bin" if self.stateful_generation.load(Ordering::SeqCst) == 0 => Ok(
                VirtualStat::regular_file(STATEFUL_LEN as u64, STATEFUL_OLD_HASH, false, 1)
                    .with_object_id(UNLINKED_OBJECT_ID),
            ),
            b"renamed.bin" if self.stateful_generation.load(Ordering::SeqCst) == 0 => Ok(
                VirtualStat::regular_file(STATEFUL_LEN as u64, STATEFUL_OLD_HASH, false, 1)
                    .with_object_id(RENAMED_OBJECT_ID),
            ),
            b"moved.bin" if self.stateful_generation.load(Ordering::SeqCst) != 0 => Ok(
                VirtualStat::regular_file(STATEFUL_LEN as u64, STATEFUL_OLD_HASH, false, 1)
                    .with_object_id(RENAMED_OBJECT_ID),
            ),
            b"renamed-dir" if self.stateful_generation.load(Ordering::SeqCst) == 0 => {
                Ok(VirtualStat::directory(1).with_object_id(RENAMED_DIRECTORY_OBJECT_ID))
            }
            b"moved-dir" if self.stateful_generation.load(Ordering::SeqCst) != 0 => {
                Ok(VirtualStat::directory(2).with_object_id(RENAMED_DIRECTORY_OBJECT_ID))
            }
            b"renamed-dir/child.txt" if self.stateful_generation.load(Ordering::SeqCst) == 0 => {
                Ok(VirtualStat::regular_file(10, [22; 32], false, 1)
                    .with_object_id(RENAMED_DIRECTORY_CHILD_OBJECT_ID))
            }
            b"moved-dir/child.txt" if self.stateful_generation.load(Ordering::SeqCst) != 0 => {
                Ok(VirtualStat::regular_file(10, [22; 32], false, 1)
                    .with_object_id(RENAMED_DIRECTORY_CHILD_OBJECT_ID))
            }
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

    fn stat_with_snapshot(
        &self,
        path: &VfsPath,
    ) -> VfsResult<(VirtualStat, Option<SnapshotToken>)> {
        self.stat(path)
            .map(|stat| (stat, Some(self.current_snapshot_token())))
    }

    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        match path.as_bytes() {
            b"" => {
                let mut entries = vec![
                    DirEntry {
                        name: vname(b"file.txt"),
                        file_type: FileType::File,
                        object_id: Some(FILE_OBJECT_ID),
                    },
                    DirEntry {
                        name: vname(b"link.txt"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"dangling-link.txt"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"racy-readlink.txt"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"racy-at-cwd.txt"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"racy-at-dirfd.txt"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"graph-only.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"dir"),
                        file_type: FileType::Directory,
                        object_id: Some(DIR_OBJECT_ID),
                    },
                    DirEntry {
                        name: vname(b"nosearch"),
                        file_type: FileType::Directory,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"create-0555"),
                        file_type: FileType::Directory,
                        object_id: Some(CREATE_0555_OBJECT_ID),
                    },
                    DirEntry {
                        name: vname(b"create-0333"),
                        file_type: FileType::Directory,
                        object_id: Some(CREATE_0333_OBJECT_ID),
                    },
                    DirEntry {
                        name: vname(b"create-0000"),
                        file_type: FileType::Directory,
                        object_id: Some(CREATE_0000_OBJECT_ID),
                    },
                    DirEntry {
                        name: vname(b"dir-link"),
                        file_type: FileType::Symlink,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"multi.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"readonly.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"writeonly.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"noaccess.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"concurrent.bin"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"trigger.txt"),
                        file_type: FileType::File,
                        object_id: None,
                    },
                    DirEntry {
                        name: vname(b"stateful.bin"),
                        file_type: FileType::File,
                        object_id: Some(if self.stateful_generation.load(Ordering::SeqCst) == 0 {
                            STATEFUL_OLD_OBJECT_ID
                        } else {
                            STATEFUL_NEW_OBJECT_ID
                        }),
                    },
                ];
                if self.stateful_generation.load(Ordering::SeqCst) == 0 {
                    entries.extend([
                        DirEntry {
                            name: vname(b"unlinked.bin"),
                            file_type: FileType::File,
                            object_id: Some(UNLINKED_OBJECT_ID),
                        },
                        DirEntry {
                            name: vname(b"renamed.bin"),
                            file_type: FileType::File,
                            object_id: Some(RENAMED_OBJECT_ID),
                        },
                        DirEntry {
                            name: vname(b"renamed-dir"),
                            file_type: FileType::Directory,
                            object_id: Some(RENAMED_DIRECTORY_OBJECT_ID),
                        },
                    ]);
                } else {
                    entries.extend([
                        DirEntry {
                            name: vname(b"moved.bin"),
                            file_type: FileType::File,
                            object_id: Some(RENAMED_OBJECT_ID),
                        },
                        DirEntry {
                            name: vname(b"moved-dir"),
                            file_type: FileType::Directory,
                            object_id: Some(RENAMED_DIRECTORY_OBJECT_ID),
                        },
                    ]);
                }
                Ok(entries)
            }
            b"dir" => Ok(vec![
                DirEntry {
                    name: vname(b"nested.txt"),
                    file_type: FileType::File,
                    object_id: None,
                },
                DirEntry {
                    name: vname(b"bounce-link"),
                    file_type: FileType::Symlink,
                    object_id: None,
                },
                DirEntry {
                    name: vname(b"deep"),
                    file_type: FileType::Directory,
                    object_id: Some(DEEP_DIRECTORY_OBJECT_ID),
                },
                DirEntry {
                    name: vname(b"order-link"),
                    file_type: FileType::Symlink,
                    object_id: None,
                },
            ]),
            b"dir/deep" => Ok(vec![
                DirEntry {
                    name: vname(b"file.txt"),
                    file_type: FileType::File,
                    object_id: Some(DEEP_FILE_OBJECT_ID),
                },
                DirEntry {
                    name: vname(b"sub"),
                    file_type: FileType::Directory,
                    object_id: Some(SUB_DIRECTORY_OBJECT_ID),
                },
            ]),
            b"dir/deep/sub" => Ok(Vec::new()),
            b"create-0555" | b"create-0333" | b"create-0000" => Ok(Vec::new()),
            b"nosearch" => Ok(vec![DirEntry {
                name: vname(b"child.txt"),
                file_type: FileType::File,
                object_id: None,
            }]),
            b"renamed-dir" if self.stateful_generation.load(Ordering::SeqCst) == 0 => {
                Ok(vec![DirEntry {
                    name: vname(b"child.txt"),
                    file_type: FileType::File,
                    object_id: Some(RENAMED_DIRECTORY_CHILD_OBJECT_ID),
                }])
            }
            b"moved-dir" if self.stateful_generation.load(Ordering::SeqCst) != 0 => {
                Ok(vec![DirEntry {
                    name: vname(b"child.txt"),
                    file_type: FileType::File,
                    object_id: Some(RENAMED_DIRECTORY_CHILD_OBJECT_ID),
                }])
            }
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        let generation = self.stateful_generation.load(Ordering::SeqCst);
        Ok(matches!(
            path.as_bytes(),
            b"" | b"file.txt"
                | b"link.txt"
                | b"dangling-link.txt"
                | b"racy-readlink.txt"
                | b"racy-at-cwd.txt"
                | b"racy-at-dirfd.txt"
                | b"graph-only.txt"
                | b"dir"
                | b"dir/nested.txt"
                | b"dir/deep"
                | b"dir/deep/sub"
                | b"dir/deep/file.txt"
                | b"nosearch"
                | b"nosearch/child.txt"
                | b"create-0555"
                | b"create-0333"
                | b"create-0000"
                | b"dir/order-link"
                | b"dir/bounce-link"
                | b"dir-link"
                | b"readonly.txt"
                | b"writeonly.txt"
                | b"noaccess.txt"
                | b"concurrent.bin"
                | b"trigger.txt"
                | b"stateful.bin"
                | b"multi.txt"
        ) || (generation == 0 && matches!(path.as_bytes(), b"unlinked.bin" | b"renamed.bin"))
            || (generation != 0 && path.as_bytes() == b"moved.bin")
            || (generation == 0
                && matches!(path.as_bytes(), b"renamed-dir" | b"renamed-dir/child.txt"))
            || (generation != 0
                && matches!(path.as_bytes(), b"moved-dir" | b"moved-dir/child.txt")))
    }

    fn resolve_directory(&self, object_id: [u8; 32]) -> VfsResult<(VfsPath, SnapshotToken)> {
        let snapshot = self.current_snapshot_token();
        if object_id == ROOT_OBJECT_ID {
            return Ok((VfsPath::root(), snapshot));
        }
        let fixed = match object_id {
            DIR_OBJECT_ID => Some("dir"),
            DEEP_DIRECTORY_OBJECT_ID => Some("dir/deep"),
            SUB_DIRECTORY_OBJECT_ID => Some("dir/deep/sub"),
            CREATE_0555_OBJECT_ID => Some("create-0555"),
            CREATE_0333_OBJECT_ID => Some("create-0333"),
            CREATE_0000_OBJECT_ID => Some("create-0000"),
            _ => None,
        };
        if let Some(path) = fixed {
            return VfsPath::from_utf8(path)
                .map(|path| (path, snapshot))
                .map_err(|error| VfsError::Provider(error.to_string()));
        }
        if object_id == RENAMED_DIRECTORY_OBJECT_ID {
            return VfsPath::from_utf8(if self.stateful_generation.load(Ordering::SeqCst) == 0 {
                "renamed-dir"
            } else {
                "moved-dir"
            })
            .map(|path| (path, snapshot))
            .map_err(|error| VfsError::Provider(error.to_string()));
        }
        Err(VfsError::Provider(
            "unknown native-parity directory capability".to_string(),
        ))
    }

    fn stat_at_snapshot(&self, snapshot: SnapshotToken, path: &VfsPath) -> VfsResult<VirtualStat> {
        self.require_snapshot(snapshot)?;
        let stat = self.stat(path)?;
        if let Some(bit) = Self::racy_symlink_bit(path) {
            // Replace the link immediately after returning metadata. A caller
            // that discards `snapshot` will read the replacement target.
            self.raced_symlinks.fetch_or(bit, Ordering::SeqCst);
        }
        Ok(stat)
    }

    fn read_dir_at_snapshot(
        &self,
        snapshot: SnapshotToken,
        path: &VfsPath,
    ) -> VfsResult<Vec<DirEntry>> {
        self.require_snapshot(snapshot)?;
        self.read_dir(path)
    }

    fn exists_at_snapshot(&self, snapshot: SnapshotToken, path: &VfsPath) -> VfsResult<bool> {
        self.require_snapshot(snapshot)?;
        self.exists(path)
    }

    fn read_link_at_snapshot(&self, snapshot: SnapshotToken, path: &VfsPath) -> VfsResult<Vec<u8>> {
        if let Some(bit) = Self::racy_symlink_bit(path) {
            return Ok(Self::racy_link_target_for_mask(bit, snapshot[0] >> 1));
        }
        self.require_snapshot(snapshot)?;
        self.read_link(path)
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match path.as_bytes() {
            b"link.txt" => Ok(b"file.txt".to_vec()),
            b"dangling-link.txt" => Ok(b"missing-target.txt".to_vec()),
            b"racy-readlink.txt" | b"racy-at-cwd.txt" | b"racy-at-dirfd.txt" => {
                let bit = Self::racy_symlink_bit(path).expect("matched racy link");
                Ok(Self::racy_link_target_for_mask(
                    bit,
                    self.raced_symlinks.load(Ordering::SeqCst),
                ))
            }
            b"dir-link" => Ok(b"dir".to_vec()),
            b"dir/bounce-link" => Ok(b"../dir/nested.txt".to_vec()),
            b"dir/order-link" => Ok(b"deep/sub".to_vec()),
            _ => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn read_blob(
        &self,
        content_hash: [u8; 32],
        total_size: u64,
        path_hint: &VfsPath,
        offset: u64,
        len: u64,
    ) -> VfsResult<Vec<u8>> {
        let data = match content_hash {
            STATEFUL_OLD_HASH => vec![b'O'; STATEFUL_LEN],
            STATEFUL_NEW_HASH => vec![b'N'; STATEFUL_LEN],
            _ => {
                let stat = self.stat(path_hint)?;
                if stat.content_hash != Some(content_hash) || stat.size != total_size {
                    return Err(VfsError::Provider(
                        "native-parity descriptor identity changed".into(),
                    ));
                }
                return if offset == 0 && len == 0 {
                    self.read_file(path_hint)
                } else {
                    self.read_range(path_hint, offset, len)
                };
            }
        };
        if total_size != data.len() as u64 {
            return Err(VfsError::Provider("stateful blob size mismatch".into()));
        }
        if offset == 0 && len == 0 {
            return Ok(data);
        }
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = start
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            .min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn version(&self) -> u64 {
        1
    }
}
