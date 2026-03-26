// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FUSE filesystem implementation backed by a `ContentProvider`.
//!
//! Maps FUSE kernel callbacks to `ContentProvider` operations. Each file and
//! directory in the virtual tree gets an inode allocated on first `lookup`.
//! File content is read-only — writes are rejected with EROFS.

use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType as FuseFileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, Request,
};
use parking_lot::Mutex;

use kin_vfs_core::{ContentProvider, FileType, VfsError};

use crate::inode::{InodeTable, ROOT_INO};

/// TTL for cached attributes. FUSE will re-validate after this period.
/// 1 second keeps things responsive while avoiding excessive round-trips.
const ATTR_TTL: Duration = Duration::from_secs(1);

/// Read-only FUSE filesystem backed by a `ContentProvider`.
///
/// All file I/O is delegated to the provider. The filesystem is read-only:
/// any write, create, mkdir, or delete operation returns EROFS (read-only FS).
pub struct KinFuseFs<P: ContentProvider> {
    provider: Arc<P>,
    inodes: Mutex<InodeTable>,
    /// UID to use for all files/dirs (the mounting user).
    uid: u32,
    /// GID to use for all files/dirs.
    gid: u32,
}

impl<P: ContentProvider> KinFuseFs<P> {
    pub fn new(provider: Arc<P>, uid: u32, gid: u32) -> Self {
        Self {
            provider,
            inodes: Mutex::new(InodeTable::new()),
            uid,
            gid,
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
            blocks: (stat.size + 511) / 512,
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
    fn getattr_by_path(
        &self,
        path: &str,
    ) -> Result<FileAttr, libc::c_int> {
        let stat = self
            .provider
            .stat(path)
            .map_err(|e| vfs_error_to_errno(&e))?;

        let ino = self.inodes.lock().get_or_insert(path);
        Ok(self.make_attr(ino, &stat))
    }
}

impl<P: ContentProvider + 'static> Filesystem for KinFuseFs<P> {
    /// Look up a directory entry by name and get its attributes.
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let child_path = {
            let inodes = self.inodes.lock();
            match inodes.child_path(parent, name_str) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        match self.getattr_by_path(&child_path) {
            Ok(attr) => reply.entry(&ATTR_TTL, &attr, 0),
            Err(errno) => reply.error(errno),
        }
    }

    /// Get file attributes by inode.
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let stat = match self.provider.stat(&path) {
            Ok(s) => s,
            Err(e) => {
                reply.error(vfs_error_to_errno(&e));
                return;
            }
        };

        let attr = self.make_attr(ino, &stat);
        reply.attr(&ATTR_TTL, &attr);
    }

    /// Open a file. We don't maintain per-open state, so just validate it exists.
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        // Reject writes — read-only filesystem.
        let accmode = flags & libc::O_ACCMODE;
        if accmode == libc::O_WRONLY || accmode == libc::O_RDWR {
            reply.error(libc::EROFS);
            return;
        }

        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Verify it exists and is a file.
        match self.provider.stat(&path) {
            Ok(stat) if stat.is_file => {
                // fh=0, flags=FOPEN_KEEP_CACHE for caching.
                reply.opened(0, fuser::consts::FOPEN_KEEP_CACHE);
            }
            Ok(stat) if stat.is_dir => reply.error(libc::EISDIR),
            Ok(_) => reply.error(libc::ENOENT),
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
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
        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
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
            match self
                .provider
                .read_range(&path, offset as u64, size as u64)
            {
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
        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        let entries = match self.provider.read_dir(&path) {
            Ok(e) => e,
            Err(e) => {
                reply.error(vfs_error_to_errno(&e));
                return;
            }
        };

        // Build the full entry list: ".", "..", then children.
        let mut full_entries: Vec<(u64, FuseFileType, String)> = Vec::with_capacity(entries.len() + 2);

        // "." entry — this directory itself.
        full_entries.push((ino, FuseFileType::Directory, ".".to_string()));

        // ".." entry — parent directory (or self for root).
        let parent_ino = if ino == ROOT_INO {
            ROOT_INO
        } else {
            let inodes = self.inodes.lock();
            let parent_path = inodes
                .get_path(ino)
                .and_then(|p| {
                    if let Some(last_slash) = p.rfind('/') {
                        Some(&p[..last_slash])
                    } else {
                        Some("")
                    }
                })
                .unwrap_or("");
            inodes.get_ino(parent_path).unwrap_or(ROOT_INO)
        };
        full_entries.push((parent_ino, FuseFileType::Directory, "..".to_string()));

        // Child entries.
        for entry in &entries {
            let child_path = if path.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", path, entry.name)
            };

            let child_ino = self.inodes.lock().get_or_insert(&child_path);
            let ft = match entry.file_type {
                FileType::File => FuseFileType::RegularFile,
                FileType::Directory => FuseFileType::Directory,
                FileType::Symlink => FuseFileType::Symlink,
            };
            full_entries.push((child_ino, ft, entry.name.clone()));
        }

        // Skip entries before offset. Each entry's offset is its 1-based index.
        for (i, (child_ino, ft, name)) in full_entries.iter().enumerate().skip(offset as usize) {
            // reply.add returns true when the buffer is full.
            if reply.add(*child_ino, (i + 1) as i64, *ft, name) {
                break;
            }
        }

        reply.ok();
    }

    /// Read a symbolic link target.
    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        match self.provider.read_link(&path) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
    }

    /// Stat the filesystem itself.
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {
        // Report a read-only filesystem with generous limits.
        reply.statfs(
            0,          // blocks
            0,          // bfree
            0,          // bavail
            0,          // files
            0,          // ffree
            4096,       // bsize
            255,        // namelen
            4096,       // frsize
        );
    }

    /// Access check. We allow read/execute for everyone, deny writes.
    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        // Deny write access — read-only filesystem.
        if mask & libc::W_OK != 0 {
            reply.error(libc::EROFS);
            return;
        }

        let path = {
            let inodes = self.inodes.lock();
            match inodes.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        match self.provider.exists(&path) {
            Ok(true) => reply.ok(),
            Ok(false) => reply.error(libc::ENOENT),
            Err(e) => reply.error(vfs_error_to_errno(&e)),
        }
    }

    // --- Write operations: all return EROFS ---

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        reply.error(libc::EROFS);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(libc::EROFS);
    }

    fn unlink(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: fuser::ReplyEmpty) {
        reply.error(libc::EROFS);
    }

    fn rmdir(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: fuser::ReplyEmpty) {
        reply.error(libc::EROFS);
    }

    fn rename(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        _newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.error(libc::EROFS);
    }

    fn create(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        reply.error(libc::EROFS);
    }

    fn setattr(
        &mut self,
        _req: &Request,
        _ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        reply.error(libc::EROFS);
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
        VfsError::Io(_) => libc::EIO,
        VfsError::Provider(_) => libc::EIO,
    }
}
