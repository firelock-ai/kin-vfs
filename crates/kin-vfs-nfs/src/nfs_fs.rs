// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! NFS filesystem adapter.
//!
//! Implements `nfsserve::vfs::NFSFileSystem` backed by a single
//! `ContentProvider`. Translates NFS operations (GETATTR, LOOKUP,
//! READ, READDIR, etc.) into ContentProvider calls.
//!
//! With no [`ContentWriter`] the adapter is read-only and every write returns
//! `NFS3ERR_ROFS`. Given one, writes are staged and admitted into graph truth
//! by the writer, and the adapter advertises `ReadWrite` so `nfsserve` stops
//! refusing them at the protocol layer before they reach this code.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use nfsserve::nfs::*;
use nfsserve::vfs::{DirEntry as NfsDirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use parking_lot::RwLock;
use tracing::{debug, warn};

use kin_vfs_core::writer::ContentWriter;
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

    /// Re-point `from`'s inode at `to`, so a handle held across a rename keeps
    /// resolving. A rename onto an existing path takes over that path's entry.
    fn rename(&mut self, from: &VfsPath, to: &VfsPath) {
        let Some(id) = self.path_to_id.remove(from) else {
            return;
        };
        if let Some(displaced) = self.path_to_id.insert(to.clone(), id) {
            self.id_to_path.remove(&displaced);
        }
        self.id_to_path.insert(id, to.clone());
    }
}

/// NFS filesystem backed by a single kin workspace's `ContentProvider`.
///
/// Each instance serves one workspace. The router (see `router.rs`) dispatches
/// per-workspace by path prefix, but this struct only needs to know about a
/// single flat `ContentProvider` namespace.
pub struct KinNfsFs<P: ContentProvider> {
    provider: Arc<P>,
    /// The write side, when this mount has one. `None` is a read-only mount.
    writer: Option<Arc<dyn ContentWriter>>,
    inodes: RwLock<InodeTable>,
    uid: u32,
    gid: u32,
}

impl<P: ContentProvider + 'static> KinNfsFs<P> {
    /// A read-only adapter over `provider`.
    pub fn new(provider: Arc<P>) -> Self {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            provider,
            writer: None,
            inodes: RwLock::new(InodeTable::new()),
            uid,
            gid,
        }
    }

    /// A writable adapter: reads from `provider`, admits writes through
    /// `writer`.
    ///
    /// `provider` is expected to already overlay `writer`'s staged writes (see
    /// `kin_vfs_core::WriteThroughProvider`), so a client reads back what it
    /// just wrote instead of the pre-write graph state.
    pub fn with_writer(provider: Arc<P>, writer: Arc<dyn ContentWriter>) -> Self {
        let mut adapter = Self::new(provider);
        adapter.writer = Some(writer);
        adapter
    }

    /// The write side, when this mount has one.
    pub fn writer(&self) -> Option<&Arc<dyn ContentWriter>> {
        self.writer.as_ref()
    }

    /// The writer, or `NFS3ERR_ROFS` on a read-only mount.
    fn require_writer(&self) -> Result<Arc<dyn ContentWriter>, nfsstat3> {
        self.writer.clone().ok_or(nfsstat3::NFS3ERR_ROFS)
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
            // The path is spelled correctly and lands outside the repository
            // anyway, because the working copy holds a symlink that redirects
            // it. ACCES is the refusal; INVAL would tell the client to spell it
            // differently, and nothing it can spell would change the answer.
            VfsError::EscapesRoot { .. } => nfsstat3::NFS3ERR_ACCES,
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
        // `nfsserve` refuses every write before dispatch when this says
        // ReadOnly, so a mount with a writer must say ReadWrite or the write
        // path below is unreachable.
        if self.writer.is_some() {
            VFSCapabilities::ReadWrite
        } else {
            VFSCapabilities::ReadOnly
        }
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

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let writer = self.require_writer()?;
        let path = self.id_to_path(id)?;
        // Size is the only attribute a write admission can carry: mode, uid,
        // gid and times are host metadata the graph does not own, so accepting
        // them would report a change the next read cannot reproduce. Answering
        // the current attributes is what a client expects from a no-op set.
        if let set_size3::size(size) = setattr.size {
            let target = path.clone();
            let staged = tokio::task::spawn_blocking(move || writer.set_len(&target, size))
                .await
                .map_err(|_| nfsstat3::NFS3ERR_IO)?
                .map_err(|e| Self::map_err(&e))?;
            return Ok(self.stat_to_fattr(&staged, id));
        }
        self.getattr(id).await
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

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let writer = self.require_writer()?;
        let path = self.id_to_path(id)?;
        let bytes = data.to_vec();
        let staged = tokio::task::spawn_blocking(move || writer.write_at(&path, offset, &bytes))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        Ok(self.stat_to_fattr(&staged, id))
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let writer = self.require_writer()?;
        let parent = self.id_to_path(dirid)?;
        let child = Self::child_path(&parent, filename.as_ref())?;
        let target = child.clone();
        let staged = tokio::task::spawn_blocking(move || writer.create_file(&target, false))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        let id = self.inodes.write().get_or_assign(&child);
        debug!(path = %child, id, "created through the mount");
        Ok((id, self.stat_to_fattr(&staged, id)))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let writer = self.require_writer()?;
        let parent = self.id_to_path(dirid)?;
        let child = Self::child_path(&parent, filename.as_ref())?;
        let target = child.clone();
        tokio::task::spawn_blocking(move || writer.create_file(&target, true))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        Ok(self.inodes.write().get_or_assign(&child))
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let writer = self.require_writer()?;
        let parent = self.id_to_path(dirid)?;
        let child = Self::child_path(&parent, dirname.as_ref())?;
        let target = child.clone();
        let staged = tokio::task::spawn_blocking(move || writer.create_dir(&target))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        let id = self.inodes.write().get_or_assign(&child);
        Ok((id, self.stat_to_fattr(&staged, id)))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let writer = self.require_writer()?;
        let parent = self.id_to_path(dirid)?;
        let child = Self::child_path(&parent, filename.as_ref())?;
        tokio::task::spawn_blocking(move || writer.remove(&child))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let writer = self.require_writer()?;
        let from = Self::child_path(&self.id_to_path(from_dirid)?, from_filename.as_ref())?;
        let to = Self::child_path(&self.id_to_path(to_dirid)?, to_filename.as_ref())?;
        let (from_key, to_key) = (from.clone(), to.clone());
        tokio::task::spawn_blocking(move || writer.rename(&from_key, &to_key))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(|e| Self::map_err(&e))?;
        // Move the inode rather than leaving the old one pointing at a path
        // that no longer exists: an NFS client holding a file handle across a
        // rename would otherwise get STALE for a file that is simply elsewhere.
        self.inodes.write().rename(&from, &to);
        Ok(())
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
        // A symlink is a tree entry kind the write admission does not build
        // yet. On a writable mount ROFS would be false, so this reports the
        // operation as unsupported, which is what it is.
        Err(if self.writer.is_some() {
            nfsstat3::NFS3ERR_NOTSUPP
        } else {
            nfsstat3::NFS3ERR_ROFS
        })
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
                });
            }
            if path.is_root() && seen.insert(b"vendor".to_vec()) {
                entries.push(VfsDirEntry {
                    name: vname(b"vendor"),
                    file_type: FileType::Directory,
                });
            }
            if path.as_bytes() == b"vendor" {
                entries.push(VfsDirEntry {
                    name: vname(b"dep"),
                    file_type: FileType::Gitlink,
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

    /// A writer that keeps everything in memory, so the adapter's write path
    /// can be exercised without a repository or a daemon.
    #[derive(Default)]
    struct MemWriter {
        staged: parking_lot::Mutex<std::collections::HashMap<VfsPath, Vec<u8>>>,
        removed: parking_lot::Mutex<Vec<VfsPath>>,
        admissions: parking_lot::Mutex<usize>,
    }

    impl MemWriter {
        fn stat_of(bytes: usize) -> VirtualStat {
            VirtualStat {
                size: bytes as u64,
                is_file: true,
                is_dir: false,
                is_symlink: false,
                mode: 0o644,
                mtime: 0,
                ctime: 0,
                nlink: 1,
                content_hash: None,
            }
        }
    }

    impl ContentWriter for MemWriter {
        fn write_at(
            &self,
            path: &VfsPath,
            offset: u64,
            data: &[u8],
        ) -> kin_vfs_core::VfsResult<VirtualStat> {
            let mut staged = self.staged.lock();
            let buffer = staged.entry(path.clone()).or_default();
            let end = offset as usize + data.len();
            if buffer.len() < end {
                buffer.resize(end, 0);
            }
            buffer[offset as usize..end].copy_from_slice(data);
            Ok(Self::stat_of(buffer.len()))
        }

        fn create_file(
            &self,
            path: &VfsPath,
            exclusive: bool,
        ) -> kin_vfs_core::VfsResult<VirtualStat> {
            let mut staged = self.staged.lock();
            if exclusive && staged.contains_key(path) {
                return Err(VfsError::InvalidInput {
                    path: path.to_string(),
                });
            }
            staged.insert(path.clone(), Vec::new());
            Ok(Self::stat_of(0))
        }

        fn set_len(&self, path: &VfsPath, size: u64) -> kin_vfs_core::VfsResult<VirtualStat> {
            let mut staged = self.staged.lock();
            let buffer = staged.entry(path.clone()).or_default();
            buffer.resize(size as usize, 0);
            Ok(Self::stat_of(buffer.len()))
        }

        fn create_dir(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<VirtualStat> {
            self.staged.lock().insert(path.clone(), Vec::new());
            let mut stat = Self::stat_of(0);
            stat.is_file = false;
            stat.is_dir = true;
            Ok(stat)
        }

        fn remove(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<()> {
            self.staged.lock().remove(path);
            self.removed.lock().push(path.clone());
            Ok(())
        }

        fn rename(&self, from: &VfsPath, to: &VfsPath) -> kin_vfs_core::VfsResult<()> {
            let mut staged = self.staged.lock();
            let bytes = staged.remove(from).unwrap_or_default();
            staged.insert(to.clone(), bytes);
            Ok(())
        }

        fn staged(&self, path: &VfsPath) -> Option<kin_vfs_core::writer::Staged> {
            self.staged
                .lock()
                .get(path)
                .map(|bytes| kin_vfs_core::writer::Staged::Present(Self::stat_of(bytes.len())))
        }

        fn staged_children(&self, _dir: &VfsPath) -> (Vec<kin_vfs_core::DirEntry>, Vec<VfsName>) {
            (Vec::new(), Vec::new())
        }

        fn read_staged(
            &self,
            path: &VfsPath,
            _offset: u64,
            _len: u64,
        ) -> kin_vfs_core::VfsResult<Vec<u8>> {
            self.staged
                .lock()
                .get(path)
                .cloned()
                .ok_or(VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_staged_link(&self, path: &VfsPath) -> kin_vfs_core::VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn admit(&self) -> kin_vfs_core::VfsResult<Option<kin_vfs_core::writer::Admission>> {
            *self.admissions.lock() += 1;
            Ok(None)
        }

        fn admission_due(&self, _debounce: std::time::Duration) -> bool {
            false
        }

        fn health(&self) -> kin_vfs_core::writer::WriteHealth {
            kin_vfs_core::writer::WriteHealth::Settled { last: None }
        }
    }

    fn writable_fs() -> (KinNfsFs<MemProvider>, Arc<MemWriter>) {
        let writer = Arc::new(MemWriter::default());
        let fs = KinNfsFs::with_writer(
            Arc::new(MemProvider::new()),
            writer.clone() as Arc<dyn ContentWriter>,
        );
        (fs, writer)
    }

    /// `nfsserve` refuses every write before dispatch when the export says
    /// ReadOnly, so this is what makes the whole write path reachable.
    #[tokio::test]
    async fn a_mount_with_a_writer_advertises_read_write() {
        let read_only = fs();
        let (writable, _) = writable_fs();
        assert!(matches!(
            writable.capabilities(),
            VFSCapabilities::ReadWrite
        ));
        assert!(matches!(
            read_only.capabilities(),
            VFSCapabilities::ReadOnly
        ));
    }

    #[tokio::test]
    async fn a_write_through_the_mount_reaches_the_writer() {
        let (fs, writer) = writable_fs();
        let id = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let id = fs.lookup(id, &b"main.rs"[..].into()).await.unwrap();

        let attr = fs.write(id, 0, b"hello there").await.unwrap();
        assert_eq!(attr.size, 11);
        assert_eq!(
            writer.staged.lock().get(&vpath("src/main.rs")).unwrap(),
            &b"hello there".to_vec()
        );
    }

    #[tokio::test]
    async fn creating_a_file_assigns_an_inode_that_resolves_back() {
        let (fs, writer) = writable_fs();
        let (id, attr) = fs
            .create(1, &b"fresh.rs"[..].into(), sattr3::default())
            .await
            .unwrap();
        assert_eq!(attr.fileid, id);
        assert!(writer.staged.lock().contains_key(&vpath("fresh.rs")));
        assert_eq!(fs.id_to_path(id).unwrap(), vpath("fresh.rs"));
    }

    #[tokio::test]
    async fn an_exclusive_create_refuses_a_second_time() {
        let (fs, _) = writable_fs();
        fs.create_exclusive(1, &b"once.rs"[..].into())
            .await
            .unwrap();
        assert!(fs
            .create_exclusive(1, &b"once.rs"[..].into())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn setting_the_size_truncates_through_the_writer() {
        let (fs, writer) = writable_fs();
        let id = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let id = fs.lookup(id, &b"main.rs"[..].into()).await.unwrap();
        fs.write(id, 0, b"0123456789").await.unwrap();

        let attr = sattr3 {
            size: set_size3::size(4),
            ..Default::default()
        };
        let after = fs.setattr(id, attr).await.unwrap();
        assert_eq!(after.size, 4);
        assert_eq!(
            writer
                .staged
                .lock()
                .get(&vpath("src/main.rs"))
                .unwrap()
                .len(),
            4
        );
    }

    /// A setattr carrying no size must not be an error: macOS sends one for
    /// mode and times on almost every save, and refusing it fails the save.
    #[tokio::test]
    async fn a_setattr_with_no_size_answers_the_current_attributes() {
        let (fs, _) = writable_fs();
        let id = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let id = fs.lookup(id, &b"main.rs"[..].into()).await.unwrap();
        let attr = fs.setattr(id, sattr3::default()).await.unwrap();
        assert_eq!(attr.fileid, id);
    }

    #[tokio::test]
    async fn removing_a_file_reaches_the_writer() {
        let (fs, writer) = writable_fs();
        let dir = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        fs.remove(dir, &b"main.rs"[..].into()).await.unwrap();
        assert_eq!(writer.removed.lock().as_slice(), &[vpath("src/main.rs")]);
    }

    /// A client holding a file handle across a rename must keep resolving. The
    /// inode moves with the path; leaving it behind answers STALE for a file
    /// that is simply somewhere else.
    #[tokio::test]
    async fn a_rename_moves_the_inode_with_the_path() {
        let (fs, _) = writable_fs();
        let dir = fs.lookup(1, &b"src"[..].into()).await.unwrap();
        let held = fs.lookup(dir, &b"main.rs"[..].into()).await.unwrap();

        fs.rename(dir, &b"main.rs"[..].into(), dir, &b"moved.rs"[..].into())
            .await
            .unwrap();
        assert_eq!(fs.id_to_path(held).unwrap(), vpath("src/moved.rs"));
    }

    /// ROFS would be false on a mount that accepts every other write. The
    /// operation is unbuilt, not forbidden, and the status code should say so.
    #[tokio::test]
    async fn a_symlink_on_a_writable_mount_reports_unsupported_not_read_only() {
        let read_only = fs();
        let (writable, _) = writable_fs();
        assert!(matches!(
            writable
                .symlink(
                    1,
                    &b"link"[..].into(),
                    &b"target"[..].into(),
                    &sattr3::default()
                )
                .await,
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        ));
        assert!(matches!(
            read_only
                .symlink(
                    1,
                    &b"link"[..].into(),
                    &b"target"[..].into(),
                    &sattr3::default()
                )
                .await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
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
