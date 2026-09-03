// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FUSE filesystem implementation backed by a `ContentProvider`.
//!
//! Maps FUSE kernel callbacks to `ContentProvider` operations. Each file and
//! directory in the virtual tree gets an inode allocated on first `lookup`.
//!
//! Reads always come from the graph. Writes are accepted only when the mount
//! carries a [`WorkspaceWriter`]: the bytes land on the projection surface and
//! the daemon must acknowledge the re-index before the operation reports
//! success, so a save that the graph never took fails visibly instead of
//! leaving the mount and the graph disagreeing. Without a writer the mount is
//! read-only and every mutation returns EROFS.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType as FuseFileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use parking_lot::Mutex;

use kin_vfs_core::{ContentProvider, FileType, VfsError, VfsName, VfsPath};

use crate::inode::{InodeTable, ROOT_INO};

use crate::write::WorkspaceWriter;

/// TTL for cached attributes. FUSE will re-validate after this period.
/// 1 second keeps things responsive while avoiding excessive round-trips.
const ATTR_TTL: Duration = Duration::from_secs(1);

/// Environment override for how long a write waits on the graph.
const CONVERGENCE_DEADLINE_ENV: &str = "KIN_VFS_FUSE_CONVERGE_MS";

/// How long a write waits for the graph to report it before failing.
///
/// The daemon's watcher reconciles a local edit in roughly a tenth of a second,
/// so this is a wide margin rather than an expected wait. It is overridable
/// because a large repository under load reconciles more slowly, and a mount
/// that fails a good write is worse than one that waits.
fn convergence_deadline() -> Duration {
    std::env::var(CONVERGENCE_DEADLINE_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(10))
}

/// What the graph must report for a path before a change counts as taken.
enum Expectation {
    /// The graph must report exactly these content bytes.
    Holds([u8; 32]),
    /// The graph must no longer hold the path at all.
    Absent,
}

/// One open file handle. Writes are tracked per handle so `flush` knows
/// whether this particular `close` has a change the graph still has to take.
struct OpenHandle {
    path: VfsPath,
    writable: bool,
    dirty: bool,
}

/// FUSE filesystem backed by a `ContentProvider`, optionally writable.
///
/// Reads are delegated to the provider, which is graph-backed. Mutations go
/// through the optional [`WorkspaceWriter`]; with none configured the mount is
/// read-only and every mutation returns EROFS.
pub struct KinFuseFs<P: ContentProvider> {
    provider: Arc<P>,
    inodes: Mutex<InodeTable>,
    /// Present when the mount may be written through. Absent means read-only.
    writer: Option<Arc<WorkspaceWriter>>,
    /// Open handles by file handle number.
    handles: Mutex<HashMap<u64, OpenHandle>>,
    /// Next file handle to hand out. Zero is never issued, so a caller that
    /// passes an unknown handle is distinguishable from one that passes none.
    next_fh: Mutex<u64>,
    /// Directories this mount created that the graph does not hold.
    ///
    /// An empty directory is not a graph artifact, so `mkdir -p a/b` followed
    /// by a write into `a/b` has a window where the parents exist on the
    /// projection surface and nowhere else. This set is what carries them
    /// across that window. It is mount-session state, deliberately not a read
    /// of the filesystem: a directory appears here only because this mount
    /// created it, never because a scan found it on disk.
    pending_dirs: Mutex<HashSet<VfsPath>>,
    /// UID to use for all files/dirs (the mounting user).
    uid: u32,
    /// GID to use for all files/dirs.
    gid: u32,
}

impl<P: ContentProvider> KinFuseFs<P> {
    /// A read-only mount: every mutation returns EROFS.
    pub fn new(provider: Arc<P>, uid: u32, gid: u32) -> Self {
        Self {
            provider,
            inodes: Mutex::new(InodeTable::new()),
            writer: None,
            handles: Mutex::new(HashMap::new()),
            next_fh: Mutex::new(1),
            pending_dirs: Mutex::new(HashSet::new()),
            uid,
            gid,
        }
    }

    /// A writable mount: mutations land on the projection surface and must be
    /// acknowledged by the graph before they report success.
    pub fn writable(provider: Arc<P>, uid: u32, gid: u32, writer: Arc<WorkspaceWriter>) -> Self {
        Self {
            writer: Some(writer),
            ..Self::new(provider, uid, gid)
        }
    }

    /// Whether this mount accepts writes at all.
    pub fn is_writable(&self) -> bool {
        self.writer.is_some()
    }

    fn allocate_handle(&self, path: VfsPath, writable: bool) -> u64 {
        let mut next = self.next_fh.lock();
        let fh = *next;
        *next += 1;
        self.handles.lock().insert(
            fh,
            OpenHandle {
                path,
                writable,
                dirty: false,
            },
        );
        fh
    }

    /// Bring a graph artifact onto the projection surface so a partial write
    /// lands on its real bytes rather than into a hole.
    fn materialize_for_write(
        &self,
        writer: &WorkspaceWriter,
        path: &VfsPath,
    ) -> Result<(), libc::c_int> {
        if writer.exists(path) {
            return Ok(());
        }
        match self.provider.stat(path) {
            Ok(stat) if stat.is_file => {
                let body = self
                    .provider
                    .read_file(path)
                    .map_err(|e| vfs_error_to_errno(&e))?;
                writer
                    .materialize(path, &body, stat.mode)
                    .map_err(|e| vfs_error_to_errno(&e))
            }
            // Absent from the graph too: nothing to materialize, the write
            // itself creates the file.
            Ok(_) | Err(_) => Ok(()),
        }
    }

    /// What the graph has to report before a change counts as taken.
    fn converge(&self, writer: &WorkspaceWriter, path: &VfsPath) -> Result<(), libc::c_int> {
        let expected = match writer.exists(path) {
            true => match writer.projection_digest(path) {
                Ok(digest) => Expectation::Holds(digest),
                Err(e) => return Err(vfs_error_to_errno(&e)),
            },
            false => Expectation::Absent,
        };
        self.await_graph(writer, path, expected)
    }

    /// Wait until the graph itself reports the change, then report success.
    ///
    /// The graph is the authority, so the only thing that proves a write landed
    /// in it is reading it back from it. Reconcile is driven by the daemon's
    /// watcher (the write-notify route is pre-v6 authority and a repository-v6
    /// daemon does not serve it), so there is no acknowledgement to trust here
    /// even in principle. Polling the exact content hash is what closes that
    /// gap: it cannot pass early, and it cannot pass on a same-size edit the
    /// way a size comparison would.
    ///
    /// Every lookup revalidates through the provider's conditional `ETag`
    /// handshake, so each poll asks the daemon rather than re-reading a cache.
    fn await_graph(
        &self,
        writer: &WorkspaceWriter,
        path: &VfsPath,
        expected: Expectation,
    ) -> Result<(), libc::c_int> {
        writer.nudge(path);

        let deadline = std::time::Instant::now() + convergence_deadline();
        let mut backoff = std::time::Duration::from_millis(10);
        loop {
            let observed = self.provider.stat(path);
            let converged = match (&expected, &observed) {
                (Expectation::Holds(digest), Ok(stat)) => {
                    stat.content_hash.as_ref() == Some(digest)
                }
                (Expectation::Absent, Err(VfsError::NotFound { .. })) => true,
                _ => false,
            };
            if converged {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                tracing::error!(
                    path = %path,
                    "the graph did not take a write through the mount within {:?}: {}",
                    convergence_deadline(),
                    match &expected {
                        Expectation::Holds(_) =>
                            "the graph still reports different content for this path",
                        Expectation::Absent => "the graph still holds this path",
                    }
                );
                return Err(libc::EIO);
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(std::time::Duration::from_millis(100));
        }
    }

    /// Convert a `VirtualStat` + inode into a FUSE `FileAttr`.
    fn make_attr(&self, ino: u64, stat: &kin_vfs_core::VirtualStat) -> FileAttr {
        let kind = if stat.is_dir {
            FuseFileType::Directory
        } else if stat.is_symlink {
            FuseFileType::Symlink
        } else {
            FuseFileType::RegularFile
        };

        let mtime = UNIX_EPOCH + Duration::from_secs(stat.mtime);
        let ctime = UNIX_EPOCH + Duration::from_secs(stat.ctime);

        FileAttr {
            ino,
            size: stat.size,
            blocks: stat.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime,
            crtime: ctime,
            kind,
            perm: stat.mode as u16,
            nlink: stat.nlink as u32,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Get attributes for a path, allocating an inode if needed.
    fn getattr_by_path(&self, path: &VfsPath) -> Result<FileAttr, libc::c_int> {
        let stat = self
            .provider
            .stat(path)
            .map_err(|e| vfs_error_to_errno(&e))?;

        let ino = self.inodes.lock().get_or_insert(path);
        Ok(self.make_attr(ino, &stat))
    }

    /// Resolve an inode to its byte-exact graph path.
    fn path_for(&self, ino: u64) -> Option<VfsPath> {
        self.inodes.lock().get_path(ino).cloned()
    }

    /// Attributes for a directory this mount created that the graph does not
    /// hold yet. Reported as an ordinary empty directory so a shell can keep
    /// descending into it while its first real child is still being written.
    fn pending_dir_attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FuseFileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Attributes for a file this mount just created that the graph has not
    /// reported back yet.
    fn empty_file_attr(&self, ino: u64, mode: u32) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FuseFileType::RegularFile,
            perm: mode as u16,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Attributes for a path, falling back to a directory this mount created.
    fn attr_for_path(&self, path: &VfsPath) -> Result<FileAttr, libc::c_int> {
        match self.getattr_by_path(path) {
            Ok(attr) => Ok(attr),
            Err(libc::ENOENT) if self.pending_dirs.lock().contains(path) => {
                let ino = self.inodes.lock().get_or_insert(path);
                Ok(self.pending_dir_attr(ino))
            }
            Err(errno) => Err(errno),
        }
    }

    /// The mount's writer, or EROFS when this mount is read-only.
    fn writer(&self) -> Result<Arc<WorkspaceWriter>, libc::c_int> {
        self.writer.clone().ok_or(libc::EROFS)
    }

    /// Resolve a parent inode and a raw kernel name to one graph path.
    fn child_of(&self, parent: u64, name: &OsStr) -> Result<VfsPath, libc::c_int> {
        let component = VfsName::from_bytes(name.as_bytes().to_vec()).map_err(|_| libc::EINVAL)?;
        self.inodes
            .lock()
            .child_path(parent, &component)
            .ok_or(libc::ENOENT)
    }
}

impl<P: ContentProvider + 'static> Filesystem for KinFuseFs<P> {
    /// Look up a directory entry by name and get its attributes.
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // The kernel hands us raw name bytes. Validate them as a path
        // component instead of requiring UTF-8: rejecting a non-UTF8 name here
        // would make graph-owned files unreachable through the mount, and
        // decoding it lossily would address a different artifact.
        let component = match VfsName::from_bytes(name.as_bytes().to_vec()) {
            Ok(component) => component,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let child_path = {
            let inodes = self.inodes.lock();
            match inodes.child_path(parent, &component) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        match self.attr_for_path(&child_path) {
            Ok(attr) => reply.entry(&ATTR_TTL, &attr, 0),
            Err(errno) => reply.error(errno),
        }
    }

    /// Get file attributes by inode.
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let _ = ino;
        match self.attr_for_path(&path) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    /// Open a file. We don't maintain per-open state, so just validate it exists.
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let accmode = flags & libc::O_ACCMODE;
        let wants_write = accmode == libc::O_WRONLY || accmode == libc::O_RDWR;

        let writer = match (wants_write, self.writer.clone()) {
            (true, None) => return reply.error(libc::EROFS),
            (true, Some(writer)) => Some(writer),
            (false, _) => None,
        };

        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Verify it exists and is a file.
        match self.provider.stat(&path) {
            Ok(stat) if stat.is_file => {}
            Ok(stat) if stat.is_dir => return reply.error(libc::EISDIR),
            Ok(_) => return reply.error(libc::ENOENT),
            // A file this mount created may not be in the graph yet; the
            // projection still holds it, so an open of it must not fail.
            Err(_) if writer.as_ref().is_some_and(|w| w.exists(&path)) => {}
            Err(e) => return reply.error(vfs_error_to_errno(&e)),
        }

        if let Some(writer) = &writer {
            // Bring the artifact onto the projection surface before the first
            // ranged write, so a partial write lands on its real bytes.
            if let Err(errno) = self.materialize_for_write(writer, &path) {
                return reply.error(errno);
            }
        }

        let fh = self.allocate_handle(path, wants_write);
        // A writable mount must not let the kernel keep serving a page cache
        // the graph has since reconciled underneath it, so the cache hint is
        // set only for read-only mounts.
        let open_flags = if self.writer.is_some() {
            0
        } else {
            fuser::consts::FOPEN_KEEP_CACHE
        };
        reply.opened(fh, open_flags);
    }

    /// Read file data.
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let data = if offset == 0 && size == 0 {
            match self.provider.read_file(&path) {
                Ok(d) => d,
                Err(e) => {
                    reply.error(vfs_error_to_errno(&e));
                    return;
                }
            }
        } else {
            match self.provider.read_range(&path, offset as u64, size as u64) {
                Ok(d) => d,
                Err(e) => {
                    reply.error(vfs_error_to_errno(&e));
                    return;
                }
            }
        };

        reply.data(&data);
    }

    /// Read directory entries.
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let entries = match self.provider.read_dir(&path) {
            Ok(e) => e,
            // A directory this mount created is not in the graph until it holds
            // a real child, so an empty listing is the honest answer for it.
            Err(_) if self.pending_dirs.lock().contains(&path) => Vec::new(),
            Err(e) => {
                reply.error(vfs_error_to_errno(&e));
                return;
            }
        };

        // Build the full entry list: ".", "..", then children. Names are exact
        // bytes: `reply.add` takes an `OsStr`, which on Unix is built from raw
        // bytes, so a non-UTF8 name reaches the caller unchanged.
        let mut full_entries: Vec<(u64, FuseFileType, Vec<u8>)> =
            Vec::with_capacity(entries.len() + 2);

        // "." entry — this directory itself.
        full_entries.push((ino, FuseFileType::Directory, b".".to_vec()));

        // ".." entry — parent directory (or self for root).
        let parent_ino = if ino == ROOT_INO {
            ROOT_INO
        } else {
            let parent_path = path.parent().unwrap_or_else(VfsPath::root);
            self.inodes.lock().get_ino(&parent_path).unwrap_or(ROOT_INO)
        };
        full_entries.push((parent_ino, FuseFileType::Directory, b"..".to_vec()));

        // Child entries.
        for entry in &entries {
            let child_path = path.join(&entry.name);
            let child_ino = self.inodes.lock().get_or_insert(&child_path);
            let ft = match entry.file_type {
                FileType::File => FuseFileType::RegularFile,
                FileType::Directory => FuseFileType::Directory,
                FileType::Symlink => FuseFileType::Symlink,
                // A nested-repository boundary is shown as a directory so it is
                // visible in listings; per-path operations on it still fail with
                // the typed unsupported-boundary error rather than serving
                // fabricated contents.
                FileType::Gitlink => FuseFileType::Directory,
            };
            full_entries.push((child_ino, ft, entry.name.as_bytes().to_vec()));
        }

        // Directories this mount created that the graph does not hold yet.
        // Skipping the ones the graph already returned keeps a directory from
        // appearing twice once its first child reconciles.
        let listed: std::collections::HashSet<Vec<u8>> = full_entries
            .iter()
            .map(|(_, _, name)| name.clone())
            .collect();
        let pending: Vec<VfsPath> = self
            .pending_dirs
            .lock()
            .iter()
            .filter(|candidate| candidate.parent().as_ref() == Some(&path))
            .cloned()
            .collect();
        for candidate in pending {
            let Some(name) = candidate.file_name().map(|n| n.to_vec()) else {
                continue;
            };
            if listed.contains(&name) {
                continue;
            }
            let child_ino = self.inodes.lock().get_or_insert(&candidate);
            full_entries.push((child_ino, FuseFileType::Directory, name));
        }

        // Skip entries before offset. Each entry's offset is its 1-based index.
        for (i, (child_ino, ft, name)) in full_entries.iter().enumerate().skip(offset as usize) {
            // reply.add returns true when the buffer is full.
            if reply.add(*child_ino, (i + 1) as i64, *ft, OsStr::from_bytes(name)) {
                break;
            }
        }

        reply.ok();
    }

    /// Read a symbolic link target.
    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match self.provider.read_link(&path) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
    }

    /// Stat the filesystem itself.
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {
        // Report a read-only filesystem with generous limits.
        reply.statfs(
            0,    // blocks
            0,    // bfree
            0,    // bavail
            0,    // files
            0,    // ffree
            4096, // bsize
            255,  // namelen
            4096, // frsize
        );
    }

    /// Access check against the exact projected mode. Writes remain read-only.
    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        if mask & libc::W_OK != 0 && self.writer.is_none() {
            reply.error(libc::EROFS);
            return;
        }

        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match self.provider.stat(&path) {
            Ok(stat)
                if (mask & libc::R_OK == 0 || stat.mode & 0o444 != 0)
                    && (mask & libc::X_OK == 0 || stat.mode & 0o111 != 0) =>
            {
                reply.ok()
            }
            Ok(_) => reply.error(libc::EACCES),
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
    }

    // --- Write operations ---
    //
    // Each one lands on the projection surface and then requires the graph to
    // acknowledge the change. An unacknowledged write is reported as a failed
    // syscall, because a projection the graph never took is exactly the
    // divergence a graph-first mount exists to prevent.

    /// Create and open a file.
    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let path = match self.child_of(parent, name) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };

        if let Err(e) = writer.create_file(&path, mode & 0o7777) {
            return reply.error(vfs_error_to_errno(&e));
        }
        if let Err(errno) = self.converge(&writer, &path) {
            return reply.error(errno);
        }

        let ino = self.inodes.lock().get_or_insert(&path);
        // The graph may not carry a brand-new empty file yet. Report the file
        // that was just created rather than failing the open that created it;
        // the next stat reads whatever the graph settled on.
        let attr = self
            .getattr_by_path(&path)
            .unwrap_or_else(|_| self.empty_file_attr(ino, mode & 0o7777));
        let fh = self.allocate_handle(path, true);
        reply.created(&ATTR_TTL, &attr, 0, fh, 0);
    }

    /// Write bytes at an offset.
    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        if offset < 0 {
            return reply.error(libc::EINVAL);
        }

        // Prefer the handle's path: it is the one this descriptor was opened
        // against, and it stays correct across a rename that moves the inode.
        let path = match self.handles.lock().get(&fh) {
            Some(handle) if handle.writable => handle.path.clone(),
            Some(_) => return reply.error(libc::EBADF),
            None => match self.path_for(ino) {
                Some(path) => path,
                None => return reply.error(libc::ENOENT),
            },
        };

        if let Err(errno) = self.materialize_for_write(&writer, &path) {
            return reply.error(errno);
        }

        match writer.write_at(&path, offset as u64, data) {
            Ok(written) => {
                if let Some(handle) = self.handles.lock().get_mut(&fh) {
                    handle.dirty = true;
                }
                reply.written(written)
            }
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
    }

    /// Close one descriptor. This is where `close(2)` gets its return value, so
    /// it is where a write the graph refused becomes visible to whoever saved
    /// the file.
    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        let Some(writer) = self.writer.clone() else {
            return reply.ok();
        };
        let dirty = match self.handles.lock().get(&fh) {
            Some(handle) if handle.dirty => Some(handle.path.clone()),
            _ => None,
        };
        let Some(path) = dirty else {
            return reply.ok();
        };

        if let Err(e) = writer.sync(&path) {
            return reply.error(vfs_error_to_errno(&e));
        }
        if let Err(errno) = self.converge(&writer, &path) {
            return reply.error(errno);
        }
        if let Some(handle) = self.handles.lock().get_mut(&fh) {
            handle.dirty = false;
        }
        reply.ok()
    }

    /// Release a descriptor. A handle still dirty here was never flushed (an
    /// mmap writer, or a process that died holding it), so the graph is told
    /// now rather than losing the change entirely. The kernel discards this
    /// reply, which is why `flush` carries the reportable failure.
    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let handle = self.handles.lock().remove(&fh);
        if let (Some(handle), Some(writer)) = (handle, self.writer.clone()) {
            if handle.dirty {
                let _ = writer.sync(&handle.path);
                let _ = self.converge(&writer, &handle.path);
            }
        }
        reply.ok()
    }

    /// Flush a file to durable storage and reconcile it.
    fn fsync(&mut self, _req: &Request, ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        let Some(writer) = self.writer.clone() else {
            return reply.ok();
        };
        let path = match self.handles.lock().get(&fh) {
            Some(handle) => handle.path.clone(),
            None => match self.path_for(ino) {
                Some(path) => path,
                None => return reply.error(libc::ENOENT),
            },
        };

        if let Err(e) = writer.sync(&path) {
            return reply.error(vfs_error_to_errno(&e));
        }
        if let Err(errno) = self.converge(&writer, &path) {
            return reply.error(errno);
        }
        if let Some(handle) = self.handles.lock().get_mut(&fh) {
            handle.dirty = false;
        }
        reply.ok()
    }

    /// Create a directory.
    ///
    /// An empty directory is not a graph artifact, so there is nothing to
    /// reconcile and nothing is announced. The directory is remembered as
    /// pending so a shell can descend into it before its first real child
    /// exists.
    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let path = match self.child_of(parent, name) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };

        if let Err(e) = writer.create_dir(&path) {
            return reply.error(vfs_error_to_errno(&e));
        }
        let ino = self.inodes.lock().get_or_insert(&path);
        self.pending_dirs.lock().insert(path);
        reply.entry(&ATTR_TTL, &self.pending_dir_attr(ino), 0);
    }

    /// Remove a file, and require the graph to drop it.
    ///
    /// The body is read from the graph first so a refusal can be undone. A
    /// removal the graph declines would otherwise leave the file gone from the
    /// projection and still present in the graph, which is the divergence this
    /// mount exists to prevent, and it would be reported as a failure while
    /// having changed something.
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let path = match self.child_of(parent, name) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };

        let restorable = self
            .provider
            .stat(&path)
            .ok()
            .filter(|stat| stat.is_file)
            .and_then(|stat| {
                self.provider
                    .read_file(&path)
                    .ok()
                    .map(|body| (body, stat.mode))
            });

        if let Err(e) = writer.remove_file(&path) {
            return reply.error(vfs_error_to_errno(&e));
        }
        match self.converge(&writer, &path) {
            Ok(()) => reply.ok(),
            Err(errno) => {
                if let Some((body, mode)) = restorable {
                    if let Err(e) = writer.materialize(&path, &body, mode) {
                        tracing::error!(
                            path = %path,
                            "the graph refused this removal and the projection could not be \
                             put back, so the two now disagree: {e}"
                        );
                    }
                }
                reply.error(errno)
            }
        }
    }

    /// Remove an empty directory.
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let path = match self.child_of(parent, name) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };

        if let Err(e) = writer.remove_dir(&path) {
            return reply.error(vfs_error_to_errno(&e));
        }
        self.pending_dirs.lock().remove(&path);
        reply.ok()
    }

    /// Move an entry. Both endpoints are announced: one artifact left a path
    /// and another arrived at one, and the graph has to take both halves.
    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let from = match self.child_of(parent, name) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };
        let to = match self.child_of(newparent, newname) {
            Ok(path) => path,
            Err(errno) => return reply.error(errno),
        };

        if let Err(e) = writer.rename(&from, &to) {
            return reply.error(vfs_error_to_errno(&e));
        }
        {
            let mut pending = self.pending_dirs.lock();
            if pending.remove(&from) {
                pending.insert(to.clone());
            }
        }
        // Both endpoints have to be taken: one artifact left a path and another
        // arrived at one. A refusal at either end is undone, so a failed rename
        // has changed nothing rather than leaving the projection moved and the
        // graph unmoved.
        let outcome = self
            .converge(&writer, &from)
            .and_then(|()| self.converge(&writer, &to));
        match outcome {
            Ok(()) => reply.ok(),
            Err(errno) => {
                if let Err(e) = writer.rename(&to, &from) {
                    tracing::error!(
                        from = %from,
                        to = %to,
                        "the graph refused this rename and the projection could not be put \
                         back, so the two now disagree: {e}"
                    );
                } else {
                    let mut pending = self.pending_dirs.lock();
                    if pending.remove(&to) {
                        pending.insert(from.clone());
                    }
                }
                reply.error(errno)
            }
        }
    }

    /// Set attributes. Size and mode change the projection and are reconciled;
    /// timestamps are accepted without changing graph truth, because refusing
    /// them breaks ordinary saves (`cp -p`, editors that stamp mtime) for no
    /// authority gain.
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let writer = match self.writer() {
            Ok(writer) => writer,
            Err(errno) => return reply.error(errno),
        };
        let path = match self.path_for(ino) {
            Some(path) => path,
            None => return reply.error(libc::ENOENT),
        };

        let mutating = size.is_some() || mode.is_some();

        if let Some(size) = size {
            if let Err(errno) = self.materialize_for_write(&writer, &path) {
                return reply.error(errno);
            }
            if let Err(e) = writer.truncate(&path, size) {
                return reply.error(vfs_error_to_errno(&e));
            }
        }
        if let Some(mode) = mode {
            if let Err(e) = writer.chmod(&path, mode & 0o7777) {
                return reply.error(vfs_error_to_errno(&e));
            }
        }
        if mutating {
            if let Err(errno) = self.converge(&writer, &path) {
                return reply.error(errno);
            }
        }

        match self.attr_for_path(&path) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request,
        _parent: u64,
        _link_name: &OsStr,
        _target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        reply.error(libc::EROFS);
    }

    fn link(
        &mut self,
        _req: &Request,
        _ino: u64,
        _newparent: u64,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(libc::EROFS);
    }

    fn mknod(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(libc::EROFS);
    }
}

/// Map `VfsError` to a libc errno.
fn vfs_error_to_errno(e: &VfsError) -> libc::c_int {
    match e {
        VfsError::NotFound { .. } => libc::ENOENT,
        VfsError::IsDirectory { .. } => libc::EISDIR,
        VfsError::NotDirectory { .. } => libc::ENOTDIR,
        VfsError::PermissionDenied { .. } => libc::EACCES,
        VfsError::InvalidInput { .. } => libc::EINVAL,
        // A well-formed path that a symlink in the working copy redirects out
        // of the repository. EACCES rather than EINVAL: there is no spelling of
        // it that this mount would accept.
        VfsError::EscapesRoot { .. } => libc::EACCES,
        // The path names a nested-repository boundary with no child projection:
        // it exists, but its contents are not ours to serve.
        VfsError::UnsupportedRepositoryBoundary { .. } => libc::ENOTSUP,
        // A write failure carries the errno the kernel already decided on:
        // EEXIST for a clobbered create, ENOTEMPTY for a populated rmdir,
        // ENOSPC for a full disk. Collapsing all of those to EIO would make
        // `mkdir` on an existing directory and a failing disk report the same
        // thing, and no ordinary tool could tell them apart.
        VfsError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
        VfsError::Provider(_) => libc::EIO,
    }
}
