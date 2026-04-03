// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Multi-workspace NFS router.
//!
//! The NFS export root shows all registered workspaces as top-level
//! directories. Each workspace is backed by its own `ContentProvider`
//! (lazily created `KinDaemonProvider` pointing at the workspace's
//! kin-daemon instance).
//!
//! Inode layout:
//! - 1 = virtual root directory (lists workspace names)
//! - Per-workspace inodes are offset into non-overlapping ranges so that
//!   each `KinNfsFs` can use its own local inode space.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use nfsserve::nfs::*;
use nfsserve::vfs::{DirEntry as NfsDirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use parking_lot::RwLock;
use tracing::debug;

// ContentProvider bound is used transitively via KinNfsFs<KinDaemonProvider>.
use kin_vfs_daemon::KinDaemonProvider;

use crate::nfs_fs::KinNfsFs;
use crate::registry::WorkspaceEntry;

/// How many inodes are reserved per workspace slot.
/// Each workspace gets a range of `INODES_PER_WORKSPACE` IDs so that
/// per-workspace adapters can allocate local inodes without collision.
const INODES_PER_WORKSPACE: u64 = 1 << 40; // ~1 trillion per workspace

/// Router-level root inode.
const ROOT_INODE: fileid3 = 1;

/// First workspace slot starts at this offset. Slot N uses
/// `WORKSPACE_BASE + N * INODES_PER_WORKSPACE`.
const WORKSPACE_BASE: u64 = 1 << 20; // leave room for router-level synthetics

/// A workspace slot: the adapter plus its inode offset.
struct WorkspaceSlot {
    adapter: Arc<KinNfsFs<KinDaemonProvider>>,
    /// The base offset added to local inodes for this workspace.
    offset: u64,
}

/// Multi-workspace NFS router.
///
/// Presents registered workspaces as top-level directories under `/`.
/// Routes NFS operations to per-workspace `KinNfsFs` adapters with
/// translated inode IDs.
pub struct KinNfsRouter {
    /// Workspace slots keyed by display name. Populated lazily.
    slots: RwLock<HashMap<String, WorkspaceSlot>>,
    /// Registry entries (name → daemon_url) loaded at construction.
    entries: Vec<WorkspaceEntry>,
    /// Next slot index for inode-range allocation.
    next_slot: RwLock<u64>,
    uid: u32,
    gid: u32,
}

impl KinNfsRouter {
    /// Create a router serving the given workspace entries.
    pub fn new(entries: Vec<WorkspaceEntry>) -> Self {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            slots: RwLock::new(HashMap::new()),
            entries,
            next_slot: RwLock::new(0),
            uid,
            gid,
        }
    }

    /// Get or lazily create the adapter for a workspace by name.
    fn get_or_create_slot(&self, name: &str) -> Option<(Arc<KinNfsFs<KinDaemonProvider>>, u64)> {
        // Fast path: already created.
        {
            let slots = self.slots.read();
            if let Some(slot) = slots.get(name) {
                return Some((Arc::clone(&slot.adapter), slot.offset));
            }
        }

        // Slow path: find the entry and create the adapter.
        let entry = self.entries.iter().find(|e| e.name == name)?;
        let provider = Arc::new(KinDaemonProvider::new(&entry.daemon_url));
        let adapter = Arc::new(KinNfsFs::new(provider));

        let mut next = self.next_slot.write();
        let slot_idx = *next;
        *next += 1;
        let offset = WORKSPACE_BASE + slot_idx * INODES_PER_WORKSPACE;

        let mut slots = self.slots.write();
        // Double-check: another thread may have created it.
        if let Some(slot) = slots.get(name) {
            return Some((Arc::clone(&slot.adapter), slot.offset));
        }
        slots.insert(
            name.to_string(),
            WorkspaceSlot {
                adapter: Arc::clone(&adapter),
                offset,
            },
        );

        Some((adapter, offset))
    }

    /// Determine which workspace an inode belongs to and return the
    /// adapter, the local inode, and the slot offset.
    fn resolve_inode(
        &self,
        id: fileid3,
    ) -> Result<(Arc<KinNfsFs<KinDaemonProvider>>, fileid3, u64), nfsstat3> {
        if id < WORKSPACE_BASE {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        let slots = self.slots.read();
        for slot in slots.values() {
            if id >= slot.offset && id < slot.offset + INODES_PER_WORKSPACE {
                let local_id = id - slot.offset;
                return Ok((Arc::clone(&slot.adapter), local_id, slot.offset));
            }
        }
        Err(nfsstat3::NFS3ERR_STALE)
    }

    /// Build `fattr3` for the virtual root directory.
    fn root_attr(&self) -> fattr3 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let time = nfstime3 {
            seconds: now,
            nseconds: 0,
        };
        fattr3 {
            ftype: ftype3::NF3DIR,
            mode: 0o755,
            nlink: 2 + self.entries.len() as u32,
            uid: self.uid,
            gid: self.gid,
            size: 0,
            used: 0,
            rdev: specdata3::default(),
            fsid: 1,
            fileid: ROOT_INODE,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }

    /// Stable synthetic inode for a workspace's top-level directory entry
    /// in the root listing. These are small IDs between 2 and WORKSPACE_BASE.
    fn workspace_root_inode(&self, name: &str) -> fileid3 {
        // Use position in entries list + 2 (0 reserved, 1 = root).
        self.entries
            .iter()
            .position(|e| e.name == name)
            .map(|i| i as u64 + 2)
            .unwrap_or(0)
    }
}

#[async_trait]
impl NFSFileSystem for KinNfsRouter {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_INODE
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let name_bytes: &[u8] = filename.as_ref();

        if dirid == ROOT_INODE {
            // Looking up a workspace name in the root.
            if name_bytes == b"." || name_bytes == b".." {
                return Ok(ROOT_INODE);
            }
            let ws_name = String::from_utf8_lossy(name_bytes);
            let (adapter, offset) = self
                .get_or_create_slot(&ws_name)
                .ok_or(nfsstat3::NFS3ERR_NOENT)?;
            // The workspace's root dir is inode 1 locally → offset + 1 globally.
            let global_id = offset + adapter.root_dir();
            debug!(workspace = %ws_name, global_id, "router: lookup workspace root");
            return Ok(global_id);
        }

        // Check if dirid is a workspace-root synthetic inode (2..WORKSPACE_BASE).
        if dirid >= 2 && dirid < WORKSPACE_BASE {
            let idx = (dirid - 2) as usize;
            if let Some(entry) = self.entries.get(idx) {
                // This is the workspace root viewed from the root listing.
                // Redirect to the actual workspace adapter's root.
                let (adapter, offset) = self
                    .get_or_create_slot(&entry.name)
                    .ok_or(nfsstat3::NFS3ERR_STALE)?;
                let local_id = adapter.lookup(adapter.root_dir(), filename).await?;
                return Ok(local_id + offset);
            }
            return Err(nfsstat3::NFS3ERR_STALE);
        }

        // Delegate to per-workspace adapter.
        let (adapter, local_dirid, offset) = self.resolve_inode(dirid)?;
        let local_id = adapter.lookup(local_dirid, filename).await?;
        Ok(local_id + offset)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        if id == ROOT_INODE {
            return Ok(self.root_attr());
        }

        // Workspace-root synthetic inodes.
        if id >= 2 && id < WORKSPACE_BASE {
            let idx = (id - 2) as usize;
            if let Some(entry) = self.entries.get(idx) {
                let (adapter, _offset) = self
                    .get_or_create_slot(&entry.name)
                    .ok_or(nfsstat3::NFS3ERR_STALE)?;
                let mut attr = adapter.getattr(adapter.root_dir()).await?;
                attr.fileid = id; // Present with the synthetic inode ID.
                return Ok(attr);
            }
            return Err(nfsstat3::NFS3ERR_STALE);
        }

        let (adapter, local_id, offset) = self.resolve_inode(id)?;
        let mut attr = adapter.getattr(local_id).await?;
        attr.fileid = local_id + offset; // Translate back to global.
        Ok(attr)
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
        if id == ROOT_INODE || (id >= 2 && id < WORKSPACE_BASE) {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        let (adapter, local_id, _) = self.resolve_inode(id)?;
        adapter.read(local_id, offset, count).await
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
        if dirid == ROOT_INODE {
            // Synthesize root listing from workspace entries.
            let mut all: Vec<(fileid3, Vec<u8>)> = Vec::new();
            all.push((ROOT_INODE, b".".to_vec()));
            all.push((ROOT_INODE, b"..".to_vec()));

            for entry in &self.entries {
                let ws_inode = self.workspace_root_inode(&entry.name);
                all.push((ws_inode, entry.name.as_bytes().to_vec()));
            }

            let mut result = Vec::new();
            let mut skipping = start_after != 0;

            for (eid, name) in &all {
                if skipping {
                    if *eid == start_after {
                        skipping = false;
                    }
                    continue;
                }
                if result.len() >= max_entries {
                    break;
                }

                let attr = if *eid == ROOT_INODE {
                    self.root_attr()
                } else {
                    // Workspace root attr.
                    let idx = (*eid - 2) as usize;
                    if let Some(entry) = self.entries.get(idx) {
                        match self.get_or_create_slot(&entry.name) {
                            Some((adapter, _)) => {
                                let mut a = adapter
                                    .getattr(adapter.root_dir())
                                    .await
                                    .unwrap_or_else(|_| self.root_attr());
                                a.fileid = *eid;
                                a
                            }
                            None => self.root_attr(),
                        }
                    } else {
                        self.root_attr()
                    }
                };

                result.push(NfsDirEntry {
                    fileid: *eid,
                    name: name.clone().into(),
                    attr,
                });
            }

            let end = result.len() < max_entries || {
                let skip_count = if start_after == 0 {
                    0
                } else {
                    all.iter()
                        .position(|(eid, _)| *eid == start_after)
                        .map(|p| p + 1)
                        .unwrap_or(0)
                };
                skip_count + result.len() >= all.len()
            };

            return Ok(ReadDirResult {
                entries: result,
                end,
            });
        }

        // Workspace-root synthetic inodes.
        if dirid >= 2 && dirid < WORKSPACE_BASE {
            let idx = (dirid - 2) as usize;
            if let Some(entry) = self.entries.get(idx) {
                let (adapter, offset) = self
                    .get_or_create_slot(&entry.name)
                    .ok_or(nfsstat3::NFS3ERR_STALE)?;
                // Translate start_after from global to local.
                let local_start = if start_after >= offset {
                    start_after - offset
                } else {
                    0
                };
                let mut result = adapter
                    .readdir(adapter.root_dir(), local_start, max_entries)
                    .await?;
                // Translate local inodes to global, but keep ".." pointing to router root.
                for e in &mut result.entries {
                    if e.name.as_ref() == b".." {
                        e.fileid = ROOT_INODE;
                        e.attr.fileid = ROOT_INODE;
                    } else {
                        e.fileid += offset;
                        e.attr.fileid += offset;
                    }
                }
                return Ok(result);
            }
            return Err(nfsstat3::NFS3ERR_STALE);
        }

        // Per-workspace directory.
        let (adapter, local_dirid, offset) = self.resolve_inode(dirid)?;
        let local_start = if start_after >= offset {
            start_after - offset
        } else {
            0
        };
        let mut result = adapter
            .readdir(local_dirid, local_start, max_entries)
            .await?;
        for e in &mut result.entries {
            e.fileid += offset;
            e.attr.fileid += offset;
        }
        Ok(result)
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
        if id == ROOT_INODE || (id >= 2 && id < WORKSPACE_BASE) {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let (adapter, local_id, _) = self.resolve_inode(id)?;
        adapter.readlink(local_id).await
    }
}
