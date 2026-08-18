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
use tracing::{debug, warn};

use kin_vfs_core::writer::{ContentWriter, NoWrites, WriteHealth, WriteThroughProvider};
use kin_vfs_daemon::{KinDaemonProvider, KinDaemonWriter};

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

/// What a workspace's adapter reads through.
///
/// A writable workspace reads through the overlay so a client sees its own
/// unadmitted writes; a read-only one reads graph truth directly.
type WorkspaceProvider = WriteThroughProvider<KinDaemonProvider>;

/// A workspace slot: the adapter plus its inode offset.
struct WorkspaceSlot {
    adapter: Arc<KinNfsFs<WorkspaceProvider>>,
    /// The base offset added to local inodes for this workspace.
    offset: u64,
    /// The write side, when this workspace has one.
    writer: Option<Arc<dyn ContentWriter>>,
}

/// Multi-workspace NFS router.
///
/// Presents registered workspaces as top-level directories under `/`.
/// Routes NFS operations to per-workspace `KinNfsFs` adapters with
/// translated inode IDs.
/// The live slot registry, shared between the router and whoever supervises it.
///
/// `NFSTcpListener::bind` takes the filesystem by value, so a server that wants
/// to admit writes on a timer or answer a status probe cannot hold the router
/// itself. It holds this instead, which is the same registry the router
/// populates.
type SharedSlots = Arc<RwLock<HashMap<String, WorkspaceSlot>>>;

/// Per-workspace write health, plus the workspaces that could not open
/// writable and why.
pub type WriteHealthReport = (Vec<(String, WriteHealth)>, Vec<(String, String)>);

/// A handle onto a running export's write side.
///
/// Everything a supervisor needs (admit on a timer, admit now, report health)
/// and nothing it does not: it cannot serve NFS, so it cannot be mistaken for
/// a second export.
#[derive(Clone)]
pub struct MountControl {
    slots: SharedSlots,
    refusals: Arc<RwLock<HashMap<String, String>>>,
    writable: bool,
}

impl MountControl {
    /// Whether the export this controls admits writes.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// The write health of every workspace that has a write side, plus the
    /// reason any workspace asked to open writable could not be.
    pub fn write_health(&self) -> WriteHealthReport {
        let health = self
            .slots
            .read()
            .iter()
            .filter_map(|(name, slot)| {
                slot.writer
                    .as_ref()
                    .map(|writer| (name.clone(), writer.health()))
            })
            .collect();
        let refusals = self
            .refusals
            .read()
            .iter()
            .map(|(name, reason)| (name.clone(), reason.clone()))
            .collect();
        (health, refusals)
    }

    /// Admit every workspace whose debounce window has closed, and name the
    /// changes that resulted.
    ///
    /// Blocking: each admission is one synchronous daemon request. Callers on
    /// an async runtime must move this off the worker.
    pub fn admit_due(&self, debounce: std::time::Duration) -> Vec<(String, String)> {
        let due: Vec<(String, Arc<dyn ContentWriter>)> = self
            .slots
            .read()
            .iter()
            .filter_map(|(name, slot)| {
                let writer = slot.writer.clone()?;
                writer
                    .admission_due(debounce)
                    .then(|| (name.clone(), writer))
            })
            .collect();
        let mut admitted = Vec::new();
        for (name, writer) in due {
            match writer.admit() {
                Ok(Some(admission)) => admitted.push((name, admission.change_id)),
                Ok(None) => {}
                Err(error) => warn!(workspace = %name, %error, "admission failed"),
            }
        }
        admitted
    }

    /// Admit every workspace now, ignoring the debounce. Reports one result per
    /// workspace that has a write side.
    pub fn admit_now(&self) -> Vec<(String, Result<Option<String>, String>)> {
        let writers: Vec<(String, Arc<dyn ContentWriter>)> = self
            .slots
            .read()
            .iter()
            .filter_map(|(name, slot)| Some((name.clone(), slot.writer.clone()?)))
            .collect();
        writers
            .into_iter()
            .map(|(name, writer)| {
                let outcome = match writer.admit() {
                    Ok(admission) => Ok(admission.map(|a| a.change_id)),
                    Err(error) => Err(error.to_string()),
                };
                (name, outcome)
            })
            .collect()
    }
}

pub struct KinNfsRouter {
    /// Workspace slots keyed by display name. Populated lazily.
    slots: SharedSlots,
    /// Registry entries (name → daemon_url) loaded at construction.
    entries: Vec<WorkspaceEntry>,
    /// Next slot index for inode-range allocation.
    next_slot: RwLock<u64>,
    /// Whether this export admits writes into graph truth.
    ///
    /// Decided at construction, not per slot: `nfsserve` asks the export once
    /// per write, before any lookup has created a slot, so a lazily-discovered
    /// answer would refuse the first write on every freshly started server.
    writable: bool,
    /// Why a named workspace could not be opened writable, when one could not.
    refusals: Arc<RwLock<HashMap<String, String>>>,
    uid: u32,
    gid: u32,
}

impl KinNfsRouter {
    /// A read-only router serving the given workspace entries.
    pub fn new(entries: Vec<WorkspaceEntry>) -> Self {
        Self::with_writes(entries, false)
    }

    /// A router serving `entries`, admitting writes into graph truth when
    /// `writable`.
    pub fn with_writes(entries: Vec<WorkspaceEntry>, writable: bool) -> Self {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            slots: Arc::new(RwLock::new(HashMap::new())),
            entries,
            next_slot: RwLock::new(0),
            writable,
            refusals: Arc::new(RwLock::new(HashMap::new())),
            uid,
            gid,
        }
    }

    /// Whether this export admits writes.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// A handle onto this export's write side that outlives handing the router
    /// to the listener.
    pub fn control(&self) -> MountControl {
        MountControl {
            slots: Arc::clone(&self.slots),
            refusals: Arc::clone(&self.refusals),
            writable: self.writable,
        }
    }

    /// Get or lazily create the adapter for a workspace by name.
    fn get_or_create_slot(&self, name: &str) -> Option<(Arc<KinNfsFs<WorkspaceProvider>>, u64)> {
        // Fast path: already created.
        {
            let slots = self.slots.read();
            if let Some(slot) = slots.get(name) {
                return Some((Arc::clone(&slot.adapter), slot.offset));
            }
        }

        // Slow path: find the entry and create the adapter. Pass the served
        // workspace root so the provider adopts that repo's `.kin/daemon.token`
        // bearer token when the kin-daemon requires one.
        let entry = self.entries.iter().find(|e| e.name == name)?;
        let graph =
            KinDaemonProvider::with_auth(&entry.daemon_url, None, Some(entry.path.clone()), None);
        // A writer that cannot be built is recorded and the workspace is served
        // read-only. Serving it writable anyway would accept writes with no way
        // to admit them, which is exactly the silent disk-only landing this
        // whole path exists to prevent.
        let writer: Option<Arc<dyn ContentWriter>> = if self.writable {
            match KinDaemonWriter::new(&entry.daemon_url, entry.path.clone(), None) {
                Ok(writer) => Some(Arc::new(writer)),
                Err(error) => {
                    warn!(workspace = %name, %error, "serving read-only: no write admission");
                    self.refusals
                        .write()
                        .insert(name.to_string(), error.to_string());
                    None
                }
            }
        } else {
            None
        };
        let adapter = match writer.clone() {
            Some(writer) => {
                let provider = Arc::new(WriteThroughProvider::new(graph, Arc::clone(&writer)));
                Arc::new(KinNfsFs::with_writer(provider, writer))
            }
            None => Arc::new(KinNfsFs::new(Arc::new(WriteThroughProvider::new(
                graph,
                Arc::new(NoWrites),
            )))),
        };

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
                writer,
            },
        );

        Some((adapter, offset))
    }

    /// Determine which workspace an inode belongs to and return the
    /// adapter, the local inode, and the slot offset.
    fn resolve_inode(
        &self,
        id: fileid3,
    ) -> Result<(Arc<KinNfsFs<WorkspaceProvider>>, fileid3, u64), nfsstat3> {
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

    /// Refuse every mutation on a read-only export.
    ///
    /// This runs before any inode reasoning. A read-only export answering
    /// ISDIR for a write to its root would be describing the object instead of
    /// the export, and a client would read that as "try a file instead" rather
    /// than "this export takes no writes".
    fn refuse_when_read_only(&self) -> Result<(), nfsstat3> {
        if self.writable {
            Ok(())
        } else {
            Err(nfsstat3::NFS3ERR_ROFS)
        }
    }

    /// Resolve a directory inode a mutation names to its workspace adapter.
    ///
    /// A client that listed the export root holds the *synthetic* inode for a
    /// workspace directory (2..`WORKSPACE_BASE`), not that workspace's own root
    /// inode, and every create/mkdir/remove at the top of a workspace arrives
    /// carrying it. Resolving only the offset ranges would answer STALE for
    /// exactly the writes a user makes first.
    fn workspace_dir(
        &self,
        dirid: fileid3,
    ) -> Result<(Arc<KinNfsFs<WorkspaceProvider>>, fileid3, u64), nfsstat3> {
        self.refuse_when_read_only()?;
        if dirid == ROOT_INODE {
            // The export root lists workspaces. It holds no files of its own,
            // and creating one would name a workspace that does not exist.
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        if (2..WORKSPACE_BASE).contains(&dirid) {
            let entry = self
                .entries
                .get((dirid - 2) as usize)
                .ok_or(nfsstat3::NFS3ERR_STALE)?;
            let (adapter, offset) = self
                .get_or_create_slot(&entry.name)
                .ok_or(nfsstat3::NFS3ERR_STALE)?;
            let root = adapter.root_dir();
            return Ok((adapter, root, offset));
        }
        self.resolve_inode(dirid)
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
        if self.writable {
            VFSCapabilities::ReadWrite
        } else {
            VFSCapabilities::ReadOnly
        }
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
            // Match the client's raw name bytes against the registered names
            // exactly. Lossy-decoding first would map every invalid byte to
            // U+FFFD, so two workspaces whose names differ only in invalid
            // UTF-8 — or one such name and a workspace literally containing
            // U+FFFD — would collide and route reads to the wrong repository.
            let ws_name = self
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .find(|name| name.as_bytes() == name_bytes)
                .ok_or(nfsstat3::NFS3ERR_NOENT)?;
            let (adapter, offset) = self
                .get_or_create_slot(ws_name)
                .ok_or(nfsstat3::NFS3ERR_NOENT)?;
            // The workspace's root dir is inode 1 locally → offset + 1 globally.
            let global_id = offset + adapter.root_dir();
            debug!(workspace = %ws_name, global_id, "router: lookup workspace root");
            return Ok(global_id);
        }

        // Check if dirid is a workspace-root synthetic inode (2..WORKSPACE_BASE).
        if (2..WORKSPACE_BASE).contains(&dirid) {
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
        if (2..WORKSPACE_BASE).contains(&id) {
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

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        self.refuse_when_read_only()?;
        // The export root and the synthetic per-workspace directory entries are
        // the router's own, not any workspace's. They are not writable, and a
        // client trying is asking the wrong object.
        if id == ROOT_INODE || (2..WORKSPACE_BASE).contains(&id) {
            return Err(nfsstat3::NFS3ERR_ROFS);
        }
        let (adapter, local_id, offset) = self.resolve_inode(id)?;
        let mut attr = adapter.setattr(local_id, setattr).await?;
        attr.fileid = local_id + offset;
        Ok(attr)
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        if id == ROOT_INODE || (2..WORKSPACE_BASE).contains(&id) {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        let (adapter, local_id, _) = self.resolve_inode(id)?;
        adapter.read(local_id, offset, count).await
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        self.refuse_when_read_only()?;
        if id == ROOT_INODE || (2..WORKSPACE_BASE).contains(&id) {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        let (adapter, local_id, offset_base) = self.resolve_inode(id)?;
        let mut attr = adapter.write(local_id, offset, data).await?;
        attr.fileid = local_id + offset_base;
        Ok(attr)
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let (adapter, local_dirid, offset) = self.workspace_dir(dirid)?;
        let (local_id, mut fattr) = adapter.create(local_dirid, filename, attr).await?;
        fattr.fileid = local_id + offset;
        Ok((local_id + offset, fattr))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let (adapter, local_dirid, offset) = self.workspace_dir(dirid)?;
        let local_id = adapter.create_exclusive(local_dirid, filename).await?;
        Ok(local_id + offset)
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let (adapter, local_dirid, offset) = self.workspace_dir(dirid)?;
        let (local_id, mut fattr) = adapter.mkdir(local_dirid, dirname).await?;
        fattr.fileid = local_id + offset;
        Ok((local_id + offset, fattr))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let (adapter, local_dirid, _) = self.workspace_dir(dirid)?;
        adapter.remove(local_dirid, filename).await
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let (adapter, local_from, from_offset) = self.workspace_dir(from_dirid)?;
        let (_, local_to, to_offset) = self.workspace_dir(to_dirid)?;
        // A rename across two workspaces is a rename across two repositories
        // and two graphs. Refusing it is what XDEV means, and it is what lets
        // the single-adapter call below be correct.
        if from_offset != to_offset {
            return Err(nfsstat3::NFS3ERR_XDEV);
        }
        adapter
            .rename(local_from, from_filename, local_to, to_filename)
            .await
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
        if (2..WORKSPACE_BASE).contains(&dirid) {
            let idx = (dirid - 2) as usize;
            if let Some(entry) = self.entries.get(idx) {
                let (adapter, offset) = self
                    .get_or_create_slot(&entry.name)
                    .ok_or(nfsstat3::NFS3ERR_STALE)?;
                // Translate start_after from global to local.
                let local_start = start_after.saturating_sub(offset);
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
        let local_start = start_after.saturating_sub(offset);
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
        if id == ROOT_INODE || (2..WORKSPACE_BASE).contains(&id) {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let (adapter, local_id, _) = self.resolve_inode(id)?;
        adapter.readlink(local_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<WorkspaceEntry> {
        vec![WorkspaceEntry {
            name: "demo".into(),
            path: std::path::PathBuf::from("/nonexistent/demo"),
            daemon_url: "http://127.0.0.1:1".into(),
        }]
    }

    #[test]
    fn capabilities_follow_the_export_not_a_lazily_created_slot() {
        // `nfsserve` asks the export once per write, before any lookup has
        // created a slot. An answer derived from the slots map would refuse
        // the first write on every freshly started server.
        assert!(matches!(
            KinNfsRouter::new(entries()).capabilities(),
            VFSCapabilities::ReadOnly
        ));
        assert!(matches!(
            KinNfsRouter::with_writes(entries(), true).capabilities(),
            VFSCapabilities::ReadWrite
        ));
    }

    /// The read-only refusal must be about the export, not about the object.
    /// A writable export answers ISDIR for the same call, which is what proves
    /// the ROFS above is a real refusal rather than a constant.
    #[tokio::test]
    async fn a_read_only_export_refuses_where_a_writable_one_describes_the_object() {
        let read_only = KinNfsRouter::new(entries());
        let writable = KinNfsRouter::with_writes(entries(), true);
        let root = read_only.root_dir();

        assert!(matches!(
            read_only.write(root, 0, b"x").await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            writable.write(root, 0, b"x").await,
            Err(nfsstat3::NFS3ERR_ISDIR)
        ));
        assert!(matches!(
            read_only.mkdir(root, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        // The export root lists workspaces and holds no files of its own, so a
        // writable export still refuses a directory there.
        assert!(matches!(
            writable.mkdir(root, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
    }

    #[test]
    fn a_read_only_export_reports_no_write_side() {
        let control = KinNfsRouter::new(entries()).control();
        assert!(!control.is_writable());
        let (health, refusals) = control.write_health();
        assert!(health.is_empty());
        assert!(refusals.is_empty());
        assert!(control
            .admit_due(std::time::Duration::from_millis(0))
            .is_empty());
    }
}
