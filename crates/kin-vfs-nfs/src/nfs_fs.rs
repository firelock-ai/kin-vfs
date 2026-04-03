// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! NFS filesystem adapter.
//!
//! Implements `nfsserve::vfs::NFSFileSystem` backed by a single
//! `ContentProvider`. Translates NFS operations (GETATTR, LOOKUP,
//! READ, READDIR, etc.) into ContentProvider calls.
//!
//! Phase 1 is read-only: all write operations return `NFS3ERR_ROFS`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use nfsserve::nfs::*;
use nfsserve::vfs::{DirEntry as NfsDirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use parking_lot::RwLock;
use tracing::{debug, warn};

use kin_vfs_core::{ContentProvider, VfsError, VirtualStat};

/// Bidirectional inode table mapping file paths to NFS file IDs.
struct InodeTable {
    path_to_id: HashMap<String, fileid3>,
    id_to_path: HashMap<fileid3, String>,
    next_id: fileid3,
}

impl InodeTable {
    fn new() -> Self {
        let mut table = Self {
            path_to_id: HashMap::new(),
            id_to_path: HashMap::new(),
            next_id: 2, // 0 is reserved by NFS, 1 is root
        };
        // Root directory = inode 1, path ""
        table.path_to_id.insert(String::new(), 1);
        table.id_to_path.insert(1, String::new());
        table
    }

    fn get_or_assign(&mut self, path: &str) -> fileid3 {
        if let Some(&id) = self.path_to_id.get(path) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.path_to_id.insert(path.to_string(), id);
        self.id_to_path.insert(id, path.to_string());
        id
    }

    fn get_path(&self, id: fileid3) -> Option<&str> {
        self.id_to_path.get(&id).map(String::as_str)
    }
}

/// NFS filesystem backed by a single kin workspace's `ContentProvider`.
///
/// Each instance serves one workspace. The router (see `router.rs`) dispatches
/// per-workspace by path prefix, but this struct only needs to know about a
/// single flat `ContentProvider` namespace.
pub struct KinNfsFs<P: ContentProvider> {
    provider: Arc<P>,
    inodes: RwLock<InodeTable>,
    uid: u32,
    gid: u32,
}

impl<P: ContentProvider + 'static> KinNfsFs<P> {
    pub fn new(provider: Arc<P>) -> Self {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            provider,
            inodes: RwLock::new(InodeTable::new()),
            uid,
            gid,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl<P: ContentProvider + 'static> KinNfsFs<P> {
    /// Resolve an inode to its path, or return NFS3ERR_STALE.
    fn id_to_path(&self, id: fileid3) -> Result<String, nfsstat3> {
        self.inodes
            .read()
            .get_path(id)
            .map(String::from)
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }

    /// Build child path from parent path + name component.
    fn child_path(parent: &str, name: &[u8]) -> String {
        let name = String::from_utf8_lossy(name);
        if parent.is_empty() {
            name.into_owned()
        } else {
            format!("{parent}/{name}")
        }
    }

    /// Convert a `VirtualStat` to an NFS `fattr3`.
    fn stat_to_fattr(&self, st: &VirtualStat, id: fileid3) -> fattr3 {
        let ftype = if st.is_symlink {
            ftype3::NF3LNK
        } else if st.is_dir {
            ftype3::NF3DIR
        } else {
            ftype3::NF3REG
        };

        let time = |secs: u64| nfstime3 {
            seconds: secs as u32,
            nseconds: 0,
        };

        fattr3 {
            ftype,
            mode: st.mode,
            nlink: st.nlink as u32,
            uid: self.uid,
            gid: self.gid,
            size: st.size,
            used: st.size,
            rdev: specdata3::default(),
            fsid: 1,
            fileid: id,
            atime: time(st.mtime),
            mtime: time(st.mtime),
            ctime: time(st.ctime),
        }
    }

    /// Map `VfsError` to the appropriate NFS status code.
    fn map_err(e: &VfsError) -> nfsstat3 {
        match e {
            VfsError::NotFound { .. } => nfsstat3::NFS3ERR_NOENT,
            VfsError::IsDirectory { .. } => nfsstat3::NFS3ERR_ISDIR,
            VfsError::NotDirectory { .. } => nfsstat3::NFS3ERR_NOTDIR,
            VfsError::PermissionDenied { .. } => nfsstat3::NFS3ERR_ACCES,
            VfsError::Io(_) | VfsError::Provider(_) => nfsstat3::NFS3ERR_IO,
        }
    }
}

// ---------------------------------------------------------------------------
// NFSFileSystem implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<P: ContentProvider + 'static> NFSFileSystem for KinNfsFs<P> {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    fn root_dir(&self) -> fileid3 {
        1
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let parent_path = self.id_to_path(dirid)?;
        let name_bytes: &[u8] = filename.as_ref();

        // Handle "." and ".."
        if name_bytes == b"." {
            return Ok(dirid);
        }
        if name_bytes == b".." {
            // Walk up: strip last component, or stay at root.
            if parent_path.is_empty() {
                return Ok(1);
            }
            let parent = match parent_path.rfind('/') {
                Some(pos) => &parent_path[..pos],
                None => "",
            };
            let id = self.inodes.write().get_or_assign(parent);
            return Ok(id);
        }

        let child = Self::child_path(&parent_path, name_bytes);

        // Verify the child exists via the provider (blocking I/O).
        let provider = Arc::clone(&self.provider);
        let child_clone = child.clone();
        let exists = tokio::task::spawn_blocking(move || provider.exists(&child_clone))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;

        if !exists {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        let id = self.inodes.write().get_or_assign(&child);
        debug!(parent = %parent_path, name = %String::from_utf8_lossy(name_bytes), id, "lookup");
        Ok(id)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let path = self.id_to_path(id)?;
        let provider = Arc::clone(&self.provider);
        let st = tokio::task::spawn_blocking(move || provider.stat(&path))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        Ok(self.stat_to_fattr(&st, id))
    }

    async fn setattr(&self, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let path = self.id_to_path(id)?;
        let provider = Arc::clone(&self.provider);
        let len = count as u64;
        let data = tokio::task::spawn_blocking(move || provider.read_range(&path, offset, len))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        let eof = (data.len() as u64) < len;
        Ok((data, eof))
    }

    async fn write(
        &self,
        _id: fileid3,
        _offset: u64,
        _data: &[u8],
    ) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create(
        &self,
        _dirid: fileid3,
        _filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create_exclusive(
        &self,
        _dirid: fileid3,
        _filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn mkdir(
        &self,
        _dirid: fileid3,
        _dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn remove(&self, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn rename(
        &self,
        _from_dirid: fileid3,
        _from_filename: &filename3,
        _to_dirid: fileid3,
        _to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let dir_path = self.id_to_path(dirid)?;
        let provider = Arc::clone(&self.provider);
        let dir_path_clone = dir_path.clone();
        let entries = tokio::task::spawn_blocking(move || provider.read_dir(&dir_path_clone))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;

        let mut result_entries: Vec<NfsDirEntry> = Vec::new();
        let mut skipping = start_after != 0;

        // Synthesize "." and ".."
        let dot_id = dirid;
        let dotdot_id = {
            if dir_path.is_empty() {
                1
            } else {
                let parent = match dir_path.rfind('/') {
                    Some(pos) => &dir_path[..pos],
                    None => "",
                };
                self.inodes.write().get_or_assign(parent)
            }
        };

        // Build the full ordered list: ".", "..", then directory contents.
        let mut all_entries: Vec<(fileid3, Vec<u8>, Option<VirtualStat>)> = Vec::new();
        all_entries.push((dot_id, b".".to_vec(), None));
        all_entries.push((dotdot_id, b"..".to_vec(), None));

        for entry in &entries {
            let child = Self::child_path(&dir_path, entry.name.as_bytes());
            let child_id = self.inodes.write().get_or_assign(&child);
            all_entries.push((child_id, entry.name.as_bytes().to_vec(), None));
        }

        // Skip entries until we pass start_after, then collect up to max_entries.
        for (eid, name, _) in &all_entries {
            if skipping {
                if *eid == start_after {
                    skipping = false;
                }
                continue;
            }
            if result_entries.len() >= max_entries {
                break;
            }

            // Fetch attrs for this entry.
            let entry_path = if name == b"." {
                dir_path.clone()
            } else if name == b".." {
                if dir_path.is_empty() {
                    String::new()
                } else {
                    match dir_path.rfind('/') {
                        Some(pos) => dir_path[..pos].to_string(),
                        None => String::new(),
                    }
                }
            } else {
                Self::child_path(&dir_path, name)
            };

            let provider = Arc::clone(&self.provider);
            let attr = match tokio::task::spawn_blocking(move || provider.stat(&entry_path))
                .await
                .map_err(|_| nfsstat3::NFS3ERR_IO)?
            {
                Ok(st) => self.stat_to_fattr(&st, *eid),
                Err(e) => {
                    warn!(path = %String::from_utf8_lossy(name), error = %e, "readdir: stat failed, skipping entry");
                    continue;
                }
            };

            result_entries.push(NfsDirEntry {
                fileid: *eid,
                name: name.clone().into(),
                attr,
            });
        }

        let end = result_entries.len() < max_entries || {
            // We collected max_entries; check if there are more.
            let collected = if start_after == 0 {
                result_entries.len()
            } else {
                // Count skipped + collected
                let skip_count = all_entries
                    .iter()
                    .position(|(eid, _, _)| *eid == start_after)
                    .map(|p| p + 1)
                    .unwrap_or(0);
                skip_count + result_entries.len()
            };
            collected >= all_entries.len()
        };

        Ok(ReadDirResult {
            entries: result_entries,
            end,
        })
    }

    async fn symlink(
        &self,
        _dirid: fileid3,
        _linkname: &filename3,
        _symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let path = self.id_to_path(id)?;
        let provider = Arc::clone(&self.provider);
        let target = tokio::task::spawn_blocking(move || provider.read_link(&path))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        Ok(target.into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_vfs_core::{DirEntry as VfsDirEntry, FileType, VfsResult};

    /// Minimal in-memory provider for testing.
    struct MemProvider {
        files: HashMap<String, Vec<u8>>,
    }

    impl MemProvider {
        fn new() -> Self {
            let mut files = HashMap::new();
            files.insert("hello.txt".to_string(), b"Hello, NFS!".to_vec());
            files.insert("src".to_string(), Vec::new()); // directory marker
            files.insert("src/main.rs".to_string(), b"fn main() {}".to_vec());
            Self { files }
        }
    }

    impl ContentProvider for MemProvider {
        fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = (offset as usize).min(data.len());
            let end = (start + len as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
            if path.is_empty() {
                return Ok(VirtualStat::directory(1000));
            }
            if !self.files.contains_key(path) {
                return Err(VfsError::NotFound {
                    path: path.to_string(),
                });
            }
            // "src" is a directory
            if path == "src" {
                return Ok(VirtualStat::directory(1000));
            }
            let data = &self.files[path];
            Ok(VirtualStat::file(
                data.len() as u64,
                [0u8; 32],
                1000,
            ))
        }

        fn read_dir(&self, path: &str) -> VfsResult<Vec<VfsDirEntry>> {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{path}/")
            };
            let mut entries = Vec::new();
            for key in self.files.keys() {
                let relative = if prefix.is_empty() {
                    key.as_str()
                } else if let Some(rest) = key.strip_prefix(&prefix) {
                    rest
                } else {
                    continue;
                };
                // Only direct children (no deeper slashes).
                if !relative.is_empty() && !relative.contains('/') {
                    let ft = if self.files[key].is_empty() && !key.contains('.') {
                        FileType::Directory
                    } else {
                        FileType::File
                    };
                    entries.push(VfsDirEntry {
                        name: relative.to_string(),
                        file_type: ft,
                    });
                }
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        }

        fn exists(&self, path: &str) -> VfsResult<bool> {
            if path.is_empty() {
                return Ok(true);
            }
            Ok(self.files.contains_key(path))
        }
    }

    #[tokio::test]
    async fn test_root_dir() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        assert_eq!(fs.root_dir(), 1);
    }

    #[tokio::test]
    async fn test_lookup_and_getattr() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        assert_ne!(id, 0);
        assert_ne!(id, 1);

        let attr = fs.getattr(id).await.unwrap();
        assert_eq!(attr.size, 11); // "Hello, NFS!" is 11 bytes
        assert!(matches!(attr.ftype, ftype3::NF3REG));
    }

    #[tokio::test]
    async fn test_lookup_not_found() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let result = fs.lookup(1, &b"nonexistent"[..].into()).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn test_read() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        let (data, eof) = fs.read(id, 0, 1024).await.unwrap();
        assert_eq!(&data, b"Hello, NFS!");
        assert!(eof);
    }

    #[tokio::test]
    async fn test_read_partial() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        let (data, eof) = fs.read(id, 0, 5).await.unwrap();
        assert_eq!(&data, b"Hello");
        assert!(!eof);
    }

    #[tokio::test]
    async fn test_readdir_root() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let result = fs.readdir(1, 0, 100).await.unwrap();
        assert!(result.end);
        // Should contain ".", "..", "hello.txt", "src"
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"src".to_string()));
    }

    #[tokio::test]
    async fn test_write_ops_return_rofs() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        assert!(matches!(
            fs.setattr(1, sattr3::default()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.write(1, 0, b"data").await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.create(1, &b"x"[..].into(), sattr3::default()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.mkdir(1, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.remove(1, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
    }

    #[tokio::test]
    async fn test_nested_lookup() {
        let fs = KinNfsFs::new(Arc::new(MemProvider::new()));
        let src_id = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let main_id = fs.lookup(src_id, &b"main.rs"[..].into()).await.unwrap();
        let attr = fs.getattr(main_id).await.unwrap();
        assert_eq!(attr.size, 12); // "fn main() {}" is 12 bytes
    }
}
