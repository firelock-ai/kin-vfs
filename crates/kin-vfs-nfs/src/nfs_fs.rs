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

use kin_vfs_core::{ContentProvider, VfsError, VfsName, VfsPath, VirtualStat};

/// Bidirectional inode table mapping byte-exact graph paths to NFS file IDs.
struct InodeTable {
    path_to_id: HashMap<VfsPath, fileid3>,
    id_to_path: HashMap<fileid3, VfsPath>,
    next_id: fileid3,
}

impl InodeTable {
    fn new() -> Self {
        let mut table = Self {
            path_to_id: HashMap::new(),
            id_to_path: HashMap::new(),
            next_id: 2, // 0 is reserved by NFS, 1 is root
        };
        // Root directory = inode 1, the empty path
        table.path_to_id.insert(VfsPath::root(), 1);
        table.id_to_path.insert(1, VfsPath::root());
        table
    }

    fn get_or_assign(&mut self, path: &VfsPath) -> fileid3 {
        if let Some(&id) = self.path_to_id.get(path) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.path_to_id.insert(path.clone(), id);
        self.id_to_path.insert(id, path.clone());
        id
    }

    fn get_path(&self, id: fileid3) -> Option<&VfsPath> {
        self.id_to_path.get(&id)
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
    /// Resolve an inode to its byte-exact path, or return NFS3ERR_STALE.
    fn id_to_path(&self, id: fileid3) -> Result<VfsPath, nfsstat3> {
        self.inodes
            .read()
            .get_path(id)
            .cloned()
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }

    /// Build a child path from a parent path plus the exact name bytes an NFS
    /// client sent.
    ///
    /// The name is validated, never lossily decoded: NFS filenames are opaque
    /// byte strings, and replacing invalid UTF-8 would address a *different*
    /// artifact than the client asked for. A name that cannot be a path
    /// component (empty, containing `/`, `.`, `..`, or NUL) is rejected.
    fn child_path(parent: &VfsPath, name: &[u8]) -> Result<VfsPath, nfsstat3> {
        let component = VfsName::from_bytes(name.to_vec()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        Ok(parent.join(&component))
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
            VfsError::InvalidInput { .. } => nfsstat3::NFS3ERR_INVAL,
            // A nested-repository boundary is a real entry whose contents this
            // export cannot serve. NOTSUPP says so; NOENT would deny it exists
            // and ISDIR would pretend it is an ordinary directory.
            VfsError::UnsupportedRepositoryBoundary { .. } => nfsstat3::NFS3ERR_NOTSUPP,
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
            let Some(parent) = parent_path.parent() else {
                return Ok(1);
            };
            let id = self.inodes.write().get_or_assign(&parent);
            return Ok(id);
        }

        let child = Self::child_path(&parent_path, name_bytes)?;

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
        debug!(parent = %parent_path, name = %child, id, "lookup");
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

    async fn write(&self, _id: fileid3, _offset: u64, _data: &[u8]) -> Result<fattr3, nfsstat3> {
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
        let parent_path = dir_path.parent().unwrap_or_else(VfsPath::root);
        let dotdot_id = if dir_path.is_root() {
            1
        } else {
            self.inodes.write().get_or_assign(&parent_path)
        };

        // Build the full ordered list: ".", "..", then directory contents.
        // Each entry carries its exact name bytes and the path to stat.
        let mut all_entries: Vec<(fileid3, Vec<u8>, VfsPath)> = Vec::new();
        all_entries.push((dot_id, b".".to_vec(), dir_path.clone()));
        all_entries.push((dotdot_id, b"..".to_vec(), parent_path));

        for entry in &entries {
            let child = dir_path.join(&entry.name);
            let child_id = self.inodes.write().get_or_assign(&child);
            all_entries.push((child_id, entry.name.as_bytes().to_vec(), child));
        }

        // Skip entries until we pass start_after, then collect up to max_entries.
        for (eid, name, entry_path) in &all_entries {
            if skipping {
                if *eid == start_after {
                    skipping = false;
                }
                continue;
            }
            if result_entries.len() >= max_entries {
                break;
            }

            let provider = Arc::clone(&self.provider);
            let entry_path = entry_path.clone();
            let attr = match tokio::task::spawn_blocking(move || provider.stat(&entry_path))
                .await
                .map_err(|_| nfsstat3::NFS3ERR_IO)?
            {
                Ok(st) => self.stat_to_fattr(&st, *eid),
                Err(e) => {
                    warn!(name = %String::from_utf8_lossy(name), error = %e, "readdir: stat failed, skipping entry");
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
        Ok(target.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_vfs_core::{DirEntry as VfsDirEntry, FileType, VfsResult};

    /// Non-UTF8 repository path: `logs/x-<0xFF><0xFE>.log`.
    const RAW_NAME: &[u8] = b"logs/x-\xff\xfe.log";

    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid test path")
    }

    fn vname(name: &[u8]) -> VfsName {
        VfsName::from_bytes(name.to_vec()).expect("valid test name")
    }

    /// Minimal in-memory provider covering every artifact kind the export must
    /// carry: source, an opaque lockfile, an executable, a symlink, a
    /// non-UTF8 name, and a nested-repository boundary.
    struct MemProvider {
        files: HashMap<VfsPath, Vec<u8>>,
    }

    impl MemProvider {
        fn new() -> Self {
            let mut files = HashMap::new();
            files.insert(vpath("hello.txt"), b"Hello, NFS!".to_vec());
            files.insert(vpath("src/main.rs"), b"fn main() {}".to_vec());
            files.insert(vpath("vendor.lock"), b"opaque\x00lock".to_vec());
            files.insert(vpath("scripts/run"), b"#!/bin/sh\n".to_vec());
            files.insert(vpath("current"), b"src/main.rs".to_vec());
            files.insert(
                VfsPath::from_bytes(RAW_NAME.to_vec()).unwrap(),
                b"raw bytes".to_vec(),
            );
            Self { files }
        }

        fn is_dir(&self, path: &VfsPath) -> bool {
            path.is_root()
                // `vendor` holds only the synthetic gitlink below, so it has no
                // file key to derive from.
                || path.as_bytes() == b"vendor"
                || self
                    .files
                    .keys()
                    .any(|candidate| path.is_ancestor_of(candidate))
        }

        fn is_gitlink(path: &VfsPath) -> bool {
            path.as_bytes() == b"vendor/dep"
        }
    }

    impl ContentProvider for MemProvider {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            if Self::is_gitlink(path) {
                return Err(VfsError::UnsupportedRepositoryBoundary {
                    path: path.to_string(),
                });
            }
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = (offset as usize).min(data.len());
            let end = (start + len as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            if Self::is_gitlink(path) {
                return Err(VfsError::UnsupportedRepositoryBoundary {
                    path: path.to_string(),
                });
            }
            if let Some(data) = self.files.get(path) {
                if path.as_bytes() == b"current" {
                    return Ok(VirtualStat::symlink(data.len() as u64, [0u8; 32], 1000));
                }
                let executable = path.as_bytes() == b"scripts/run";
                return Ok(VirtualStat::regular_file(
                    data.len() as u64,
                    [0u8; 32],
                    executable,
                    1000,
                ));
            }
            if self.is_dir(path) {
                return Ok(VirtualStat::directory(1000));
            }
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<VfsDirEntry>> {
            let mut entries: Vec<VfsDirEntry> = Vec::new();
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            for key in self.files.keys() {
                let Some(rest) = (if path.is_root() {
                    Some(key.as_bytes())
                } else {
                    path.strip_dir_prefix(key)
                }) else {
                    continue;
                };
                let (name, is_dir) = match rest.iter().position(|byte| *byte == b'/') {
                    Some(position) => (&rest[..position], true),
                    None => (rest, false),
                };
                if !seen.insert(name.to_vec()) {
                    continue;
                }
                let file_type = if is_dir {
                    FileType::Directory
                } else if name == b"current" {
                    FileType::Symlink
                } else {
                    FileType::File
                };
                entries.push(VfsDirEntry {
                    name: vname(name),
                    file_type,
                    object_id: None,
                });
            }
            if path.is_root() && seen.insert(b"vendor".to_vec()) {
                entries.push(VfsDirEntry {
                    name: vname(b"vendor"),
                    file_type: FileType::Directory,
                    object_id: None,
                });
            }
            if path.as_bytes() == b"vendor" {
                entries.push(VfsDirEntry {
                    name: vname(b"dep"),
                    file_type: FileType::Gitlink,
                    object_id: None,
                });
            }
            entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
            Ok(entries)
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.is_dir(path) || Self::is_gitlink(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            if path.as_bytes() == b"current" {
                return Ok(b"src/main.rs".to_vec());
            }
            Err(VfsError::InvalidInput {
                path: path.to_string(),
            })
        }
    }

    fn fs() -> KinNfsFs<MemProvider> {
        KinNfsFs::new(Arc::new(MemProvider::new()))
    }

    #[tokio::test]
    async fn test_root_dir() {
        assert_eq!(fs().root_dir(), 1);
    }

    #[tokio::test]
    async fn test_lookup_and_getattr() {
        let fs = fs();
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        assert_ne!(id, 0);
        assert_ne!(id, 1);

        let attr = fs.getattr(id).await.unwrap();
        assert_eq!(attr.size, 11); // "Hello, NFS!" is 11 bytes
        assert!(matches!(attr.ftype, ftype3::NF3REG));
    }

    #[tokio::test]
    async fn test_lookup_not_found() {
        let result = fs().lookup(1, &b"nonexistent"[..].into()).await;
        assert!(matches!(result, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn lookup_preserves_non_utf8_names_exactly() {
        let fs = fs();
        let logs = fs.lookup(1, &b"logs"[..].into()).await.unwrap();
        let raw = fs
            .lookup(logs, &b"x-\xff\xfe.log"[..].into())
            .await
            .expect("a non-UTF8 name must resolve, not be replaced");
        let attr = fs.getattr(raw).await.unwrap();
        assert_eq!(attr.size, 9); // "raw bytes"

        // A near-miss byte is a different artifact, not the same one.
        assert!(matches!(
            fs.lookup(logs, &b"x-\xff\xfd.log"[..].into()).await,
            Err(nfsstat3::NFS3ERR_NOENT)
        ));
    }

    #[tokio::test]
    async fn readdir_returns_raw_name_bytes() {
        let fs = fs();
        let logs = fs.lookup(1, &b"logs"[..].into()).await.unwrap();
        let result = fs.readdir(logs, 0, 100).await.unwrap();
        let names: Vec<Vec<u8>> = result
            .entries
            .iter()
            .map(|entry| entry.name.as_ref().to_vec())
            .collect();
        assert!(
            names.contains(&b"x-\xff\xfe.log".to_vec()),
            "raw name bytes must survive readdir: {names:?}"
        );
    }

    #[tokio::test]
    async fn lookup_rejects_malformed_name_components() {
        let fs = fs();
        // A client cannot smuggle traversal or separators through a filename.
        for malformed in [&b"a/b"[..], b"\0bad"] {
            assert!(
                matches!(
                    fs.lookup(1, &malformed[..].into()).await,
                    Err(nfsstat3::NFS3ERR_INVAL)
                ),
                "{malformed:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn gitlink_boundary_reports_notsupp() {
        let fs = fs();
        let vendor = fs.lookup(1, &b"vendor"[..].into()).await.unwrap();
        let dep = fs.lookup(vendor, &b"dep"[..].into()).await.unwrap();
        assert!(matches!(
            fs.getattr(dep).await,
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        ));
        assert!(matches!(
            fs.read(dep, 0, 16).await,
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        ));
    }

    #[tokio::test]
    async fn symlink_and_executable_kinds_are_preserved() {
        let fs = fs();
        let link = fs.lookup(1, &b"current"[..].into()).await.unwrap();
        let attr = fs.getattr(link).await.unwrap();
        assert!(matches!(attr.ftype, ftype3::NF3LNK));
        assert_eq!(fs.readlink(link).await.unwrap().as_ref(), b"src/main.rs");

        let scripts = fs.lookup(1, &b"scripts"[..].into()).await.unwrap();
        let run = fs.lookup(scripts, &b"run"[..].into()).await.unwrap();
        assert_eq!(fs.getattr(run).await.unwrap().mode, 0o755);
    }

    #[tokio::test]
    async fn opaque_lockfile_bytes_round_trip() {
        let fs = fs();
        let id = fs.lookup(1, &b"vendor.lock"[..].into()).await.unwrap();
        let (data, _) = fs.read(id, 0, 1024).await.unwrap();
        assert_eq!(data, b"opaque\x00lock");
    }

    #[tokio::test]
    async fn test_read() {
        let fs = fs();
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        let (data, eof) = fs.read(id, 0, 1024).await.unwrap();
        assert_eq!(&data, b"Hello, NFS!");
        assert!(eof);
    }

    #[tokio::test]
    async fn test_read_partial() {
        let fs = fs();
        let id = fs.lookup(1, &b"hello.txt"[..].into()).await.unwrap();
        let (data, eof) = fs.read(id, 0, 5).await.unwrap();
        assert_eq!(&data, b"Hello");
        assert!(!eof);
    }

    #[tokio::test]
    async fn test_readdir_root() {
        let result = fs().readdir(1, 0, 100).await.unwrap();
        assert!(result.end);
        let names: Vec<Vec<u8>> = result
            .entries
            .iter()
            .map(|e| e.name.as_ref().to_vec())
            .collect();
        for expected in [
            &b"."[..],
            b"..",
            b"hello.txt",
            b"src",
            b"vendor.lock",
            b"current",
        ] {
            assert!(names.contains(&expected.to_vec()), "missing {expected:?}");
        }
    }

    #[tokio::test]
    async fn test_write_ops_return_rofs() {
        let fs = fs();
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
        let fs = fs();
        let src_id = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let main_id = fs.lookup(src_id, &b"main.rs"[..].into()).await.unwrap();
        let attr = fs.getattr(main_id).await.unwrap();
        assert_eq!(attr.size, 12); // "fn main() {}" is 12 bytes
    }
}
