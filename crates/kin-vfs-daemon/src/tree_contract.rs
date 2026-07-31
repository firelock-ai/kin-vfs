// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The strict, versioned kin-daemon repository-tree contract.
//!
//! `GET /vfs/tree` returns one [`WorkspaceTreeSnapshot`]: a schema-versioned
//! document carrying the exact repository/workspace authority binding it
//! projects, the exact resolved artifacts, and a canonical identity
//! independently recomputed as the strong HTTP `ETag`. The shared `kin-model`
//! document carries one record per tracked leaf with its stable `artifact_id`,
//! byte-exact path, exact [`TreeEntry`], size, and timestamp. The artifact set
//! must recompute to the binding's graph-owned workspace-tree hash. Unknown
//! fields anywhere are rejected (`deny_unknown_fields`), as are non-canonical
//! ordering, duplicate artifact IDs, duplicate paths, file/directory prefix
//! collisions, invalid path encodings, non-zero gitlink sizes, unsupported
//! schemas, or an ETag mismatch — all **before** any cache state changes.
//!
//! Freshness is a single conditional request: the provider sends
//! `If-None-Match` with the cached etag and the daemon answers `304 Not
//! Modified` or a complete new snapshot. There is no separate version probe, so
//! there is no version-then-tree window in which the tree can change under the
//! check. A refresh either installs one fully validated snapshot or retains
//! the prior one unchanged.

use std::collections::BTreeMap;

#[cfg(test)]
use kin_model::WorkspaceTreeArtifact;
use kin_model::{ArtifactId, Hash256, TreeEntry, WorkspaceSnapshotBinding, WorkspaceTreeSnapshot};
use kin_vfs_core::{
    DirEntry, FileType, SnapshotToken, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
};
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};

/// One validated artifact held in the provider cache.
#[derive(Debug, Clone)]
pub(crate) struct TreeArtifact {
    pub(crate) artifact_id: ArtifactId,
    pub(crate) entry: TreeEntry,
    pub(crate) size: u64,
    pub(crate) mtime: u64,
}

/// Exact mutation identity for one derived directory.
///
/// `authority_generation` is the monotonic component exposed as directory
/// `mtime` and as the provider cache version. `membership` binds that clock to
/// every byte-exact descendant path, stable artifact identity, tree entry,
/// size, and projection timestamp. The pair is deterministic from one
/// validated graph snapshot and survives provider reopen; it never depends on
/// ambient filesystem metadata. Schema 3 carries no per-directory tombstone
/// clock, so the repository generation conservatively advances every existing
/// derived directory in an installed successor; the membership digest records
/// which directory views actually changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryMutationIdentity {
    pub(crate) authority_generation: u64,
    pub(crate) workspace_generation: u64,
    pub(crate) membership: Hash256,
}

#[derive(Debug, Clone)]
struct CachedDirectory {
    /// Stable lookup capability for an open virtual directory descriptor.
    ///
    /// Fresh snapshots derive a collision-resistant identity from the exact
    /// snapshot token and path. Schema 3 has no producer-issued directory
    /// identity or transition record, so no leaf-snapshot comparison can prove
    /// that a directory object survived succession, even at the same path.
    /// Every installed successor therefore receives fresh derived capabilities.
    object_id: [u8; 32],
    mutation: DirectoryMutationIdentity,
    entries: Vec<DirEntry>,
}

/// A fully validated tree snapshot, indexed for lookup.
#[derive(Debug)]
pub(crate) struct CachedTree {
    pub(crate) binding: WorkspaceSnapshotBinding,
    /// Monotonic repository-authority generation, derived from `binding`.
    /// This is also the logical mtime of every directory in this exact
    /// snapshot, so daemon invalidation and directory metadata advance on the
    /// same graph-owned clock.
    pub(crate) version: u64,
    pub(crate) etag: String,
    /// Explicit invalidation requires the next refresh to omit
    /// `If-None-Match`, while retaining descriptor and inode-history authority
    /// until a validated successor installs.
    refresh_required: bool,
    /// Opaque identity of this exact validated snapshot, used to constrain
    /// descriptor-relative follow-up requests.
    pub(crate) snapshot_token: SnapshotToken,
    pub(crate) by_path: BTreeMap<VfsPath, TreeArtifact>,
    /// Every ancestor directory derived from artifact paths, plus the root,
    /// with its exact descendant identity and precomputed listing.
    directories: BTreeMap<VfsPath, CachedDirectory>,
    /// Reverse index for descriptor-relative lookup in the current graph
    /// snapshot. Cross-path continuity requires producer-issued identity;
    /// schema-derived capabilities otherwise fail closed.
    directories_by_object_id: BTreeMap<[u8; 32], VfsPath>,
    /// Every host inode projection published during this provider lifetime.
    ///
    /// Open descriptors live in the shim and can outlast arbitrarily many tree
    /// refreshes, so the daemon cannot know when a prior graph object is no
    /// longer observable. Conservatively retaining the complete projection
    /// history prevents a successor object from reusing an inode that an open
    /// descriptor may still expose.
    host_inode_registry: BTreeMap<u64, [u8; 32]>,
}

impl CachedTree {
    /// Validate one wire document into an indexed snapshot. Any violation
    /// rejects the whole document; the caller must leave prior cache state
    /// untouched on error.
    pub(crate) fn from_snapshot(snapshot: WorkspaceTreeSnapshot) -> Result<Self, String> {
        let etag = snapshot
            .identity()
            .map_err(|error| format!("invalid workspace tree snapshot: {error}"))?
            .to_string();
        let snapshot_token = exact_snapshot_token(&etag);
        let authority_generation = snapshot.binding.roots.generation;
        let workspace_generation = snapshot.binding.workspace_generation;
        let mut by_path: BTreeMap<VfsPath, TreeArtifact> = BTreeMap::new();
        for artifact in snapshot.artifacts {
            let path = VfsPath::from_bytes(artifact.path.as_bytes().to_vec())
                .map_err(|error| format!("invalid tree path {}: {error}", artifact.path))?;
            if by_path
                .insert(
                    path,
                    TreeArtifact {
                        artifact_id: artifact.artifact_id,
                        entry: artifact.entry,
                        size: artifact.size,
                        mtime: artifact.mtime,
                    },
                )
                .is_some()
            {
                return Err("validated workspace tree repeated a repository path".to_string());
            }
        }

        let directories = build_directory_index(
            &by_path,
            snapshot_token,
            authority_generation,
            workspace_generation,
        )?;
        for dir in directories.keys() {
            if by_path.contains_key(dir) {
                return Err(format!(
                    "file/directory prefix collision at {dir} in tree snapshot"
                ));
            }
        }

        let mut tree = Self {
            binding: snapshot.binding,
            version: authority_generation,
            etag,
            refresh_required: false,
            snapshot_token,
            by_path,
            directories,
            directories_by_object_id: BTreeMap::new(),
            host_inode_registry: BTreeMap::new(),
        };
        tree.rebuild_directory_authority()?;
        tree.install_host_inode_history(None)?;
        Ok(tree)
    }

    /// Return the conditional validator unless an explicit invalidation
    /// requires one unconditional refresh.
    pub(crate) fn conditional_etag(&self) -> Option<&str> {
        (!self.refresh_required).then_some(self.etag.as_str())
    }

    /// Force an unconditional refresh without discarding installed descriptor
    /// authority or lifetime inode reservations.
    pub(crate) fn require_refresh(&mut self) {
        self.refresh_required = true;
    }

    /// Record that an unconditional refresh completed and the current snapshot
    /// remained authoritative.
    pub(crate) fn mark_refreshed(&mut self) {
        self.refresh_required = false;
    }

    #[cfg(test)]
    pub(crate) fn has_host_inode_reservation(&self, object_id: [u8; 32]) -> bool {
        let inode = kin_vfs_core::pathmap::synthetic_object_inode(&object_id);
        self.host_inode_registry.get(&inode) == Some(&object_id)
    }

    /// The stable graph identity currently located at `path`.
    ///
    /// Paths are locations; this is the identity. A path reused by a different
    /// artifact after a refresh reports a different id, which is how callers
    /// detect that "the same path" is no longer the same thing.
    pub(crate) fn artifact_id_at(&self, path: &VfsPath) -> Option<ArtifactId> {
        self.by_path.get(path).map(|artifact| artifact.artifact_id)
    }

    pub(crate) fn is_dir(&self, path: &VfsPath) -> bool {
        self.directories.contains_key(path)
    }

    pub(crate) fn exists(&self, path: &VfsPath) -> bool {
        self.by_path.contains_key(path) || self.directories.contains_key(path)
    }

    /// Exact graph-derived mutation identity for one directory.
    pub(crate) fn directory_mutation(&self, path: &VfsPath) -> Option<DirectoryMutationIdentity> {
        self.directories
            .get(path)
            .map(|directory| directory.mutation)
    }

    /// Resolve a stable open-directory capability in this exact snapshot.
    pub(crate) fn resolve_directory(&self, object_id: [u8; 32]) -> VfsResult<VfsPath> {
        self.directories_by_object_id
            .get(&object_id)
            .cloned()
            .ok_or_else(|| {
                VfsError::Provider(
                    "open directory capability is absent from the current graph snapshot"
                        .to_string(),
                )
            })
    }

    /// Resolve `path` to its artifact, or the precise kind error.
    pub(crate) fn require_artifact(&self, path: &VfsPath) -> VfsResult<&TreeArtifact> {
        if let Some(artifact) = self.by_path.get(path) {
            Ok(artifact)
        } else if self.is_dir(path) {
            Err(VfsError::IsDirectory {
                path: path.to_string(),
            })
        } else {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }
    }

    /// Metadata for any path in the snapshot. Directory mtime is the
    /// repository-authority generation bound to its exact descendant
    /// membership, rather than a descendant timestamp that can regress after
    /// removal. Gitlinks refuse with the typed repository-boundary error.
    pub(crate) fn stat_path(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        if let Some(artifact) = self.by_path.get(path) {
            return stat_for_entry(artifact.entry, artifact.size, artifact.mtime, path)
                .map(|stat| stat.with_object_id(artifact_object_id(artifact.artifact_id)));
        }
        if let Some(directory) = self.directories.get(path) {
            return Ok(
                VirtualStat::directory(directory.mutation.authority_generation)
                    .with_object_id(directory.object_id),
            );
        }
        Err(VfsError::NotFound {
            path: path.to_string(),
        })
    }

    /// List the children of a directory with byte-exact names. Gitlink
    /// children are carried explicitly as [`FileType::Gitlink`].
    pub(crate) fn list_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        let Some(directory) = self.directories.get(path) else {
            if self.by_path.contains_key(path) {
                return Err(VfsError::NotDirectory {
                    path: path.to_string(),
                });
            }
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        };

        Ok(directory.entries.clone())
    }

    /// Install authority inherited across one validated snapshot succession.
    ///
    /// Schema 3 exposes leaves, not first-class directory identities or
    /// transitions. The same pair of snapshots can describe ordinary child
    /// churn or delete/recreate with the leaves moved away and back. Derived
    /// directory capabilities therefore remain fresh at every installed
    /// successor. Producer-issued providers with durable directory identities
    /// preserve them through their own `resolve_directory` implementation.
    ///
    /// Artifact identities remain stable, and the complete prior host-inode
    /// reservation history is inherited before this successor may publish.
    pub(crate) fn install_successor_authority(
        &mut self,
        current: &CachedTree,
    ) -> Result<(), String> {
        self.install_host_inode_history(Some(current))
    }

    fn rebuild_directory_authority(&mut self) -> Result<(), String> {
        let mut reverse = BTreeMap::new();
        for (path, directory) in &self.directories {
            if let Some(previous) = reverse.insert(directory.object_id, path.clone()) {
                return Err(format!(
                    "derived directory capability collision between {previous} and {path}"
                ));
            }
        }

        let object_ids_by_directory: BTreeMap<VfsPath, [u8; 32]> = self
            .directories
            .iter()
            .map(|(path, directory)| (path.clone(), directory.object_id))
            .collect();
        for (directory_path, directory) in &mut self.directories {
            for entry in &mut directory.entries {
                let child_path = directory_path.join(&entry.name);
                entry.object_id = match entry.file_type {
                    FileType::Directory => object_ids_by_directory.get(&child_path).copied(),
                    FileType::File | FileType::Symlink | FileType::Gitlink => self
                        .by_path
                        .get(&child_path)
                        .map(|artifact| artifact_object_id(artifact.artifact_id)),
                };
                if entry.object_id.is_none() {
                    return Err(format!(
                        "directory listing identity missing for graph child {child_path}"
                    ));
                }
            }
        }
        self.directories_by_object_id = reverse;
        self.validate_host_inode_uniqueness()
    }

    /// Refuse a snapshot whose distinct graph identities collapse to one
    /// host-visible inode.
    ///
    /// The shim's ABI is necessarily 64-bit, but silently exposing a collision
    /// lets inode-keyed walkers mistake two graph objects for one. Kin-backed
    /// providers know the complete mounted identity set, so they validate it
    /// before installation and fail loud rather than publish ambiguous stat and
    /// dirent results.
    fn validate_host_inode_uniqueness(&self) -> Result<(), String> {
        validate_host_inode_uniqueness_with(
            self.current_object_ids(),
            kin_vfs_core::pathmap::synthetic_object_inode,
        )
    }

    fn current_object_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        let artifact_ids = self
            .by_path
            .values()
            .map(|artifact| artifact_object_id(artifact.artifact_id));
        let directory_ids = self
            .directories
            .values()
            .map(|directory| directory.object_id);
        artifact_ids.chain(directory_ids)
    }

    fn install_host_inode_history(&mut self, current: Option<&CachedTree>) -> Result<(), String> {
        let mut registry = current
            .map(|tree| tree.host_inode_registry.clone())
            .unwrap_or_default();
        extend_host_inode_registry_with(
            &mut registry,
            self.current_object_ids(),
            kin_vfs_core::pathmap::synthetic_object_inode,
        )?;
        self.host_inode_registry = registry;
        Ok(())
    }
}

fn validate_host_inode_uniqueness_with(
    object_ids: impl IntoIterator<Item = [u8; 32]>,
    inode_for: impl FnMut(&[u8; 32]) -> u64,
) -> Result<(), String> {
    let mut by_inode = BTreeMap::new();
    extend_host_inode_registry_with(&mut by_inode, object_ids, inode_for)
}

fn extend_host_inode_registry_with(
    by_inode: &mut BTreeMap<u64, [u8; 32]>,
    object_ids: impl IntoIterator<Item = [u8; 32]>,
    mut inode_for: impl FnMut(&[u8; 32]) -> u64,
) -> Result<(), String> {
    for object_id in object_ids {
        let inode = inode_for(&object_id);
        if inode == 0 {
            return Err("graph object identity maps to reserved host inode 0".to_string());
        }
        match by_inode.entry(inode) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(object_id);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &object_id => {
                return Err(format!(
                    "distinct graph object identities collide on host inode {inode}"
                ));
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    Ok(())
}

fn exact_snapshot_token(etag: &str) -> SnapshotToken {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-vfs-exact-snapshot-token-v1\0");
    hasher.update(etag.as_bytes());
    hasher.finalize().into()
}

fn build_directory_index(
    by_path: &BTreeMap<VfsPath, TreeArtifact>,
    snapshot_token: SnapshotToken,
    authority_generation: u64,
    workspace_generation: u64,
) -> Result<BTreeMap<VfsPath, CachedDirectory>, String> {
    // One pass over path-sorted artifacts feeds each ancestor exactly once.
    // Work is proportional to total path depth rather than directories ×
    // artifacts, which keeps large repositories practical.
    let mut builders = BTreeMap::new();
    builders.insert(VfsPath::root(), DirectoryBuilder::new(&VfsPath::root())?);
    for (artifact_path, artifact) in by_path {
        let mut current = artifact_path.parent();
        while let Some(directory) = current {
            let builder = match builders.entry(directory.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(DirectoryBuilder::new(&directory)?)
                }
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            };
            builder.add_descendant(&directory, artifact_path, artifact)?;
            current = directory.parent();
        }
    }

    builders
        .into_iter()
        .map(|(path, builder)| {
            builder
                .finish(
                    &path,
                    snapshot_token,
                    authority_generation,
                    workspace_generation,
                )
                .map(|directory| (path, directory))
        })
        .collect()
}

struct DirectoryBuilder {
    hasher: Sha256,
    descendant_count: u64,
    entries: BTreeMap<Vec<u8>, FileType>,
}

impl DirectoryBuilder {
    fn new(path: &VfsPath) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"kin-vfs-directory-membership-v1\0");
        hash_len_prefixed(&mut hasher, path.as_bytes())?;
        Ok(Self {
            hasher,
            descendant_count: 0,
            entries: BTreeMap::new(),
        })
    }

    fn add_descendant(
        &mut self,
        directory: &VfsPath,
        descendant: &VfsPath,
        artifact: &TreeArtifact,
    ) -> Result<(), String> {
        self.descendant_count = self
            .descendant_count
            .checked_add(1)
            .ok_or_else(|| "directory descendant count exceeds u64".to_string())?;
        hash_len_prefixed(&mut self.hasher, descendant.as_bytes())?;
        self.hasher.update(artifact.artifact_id.0.as_bytes());
        match artifact.entry {
            TreeEntry::Blob { hash, executable } => {
                self.hasher.update([0]);
                self.hasher.update(hash.as_bytes());
                self.hasher.update([u8::from(executable)]);
            }
            TreeEntry::Symlink { target_blob } => {
                self.hasher.update([1]);
                self.hasher.update(target_blob.as_bytes());
            }
            TreeEntry::Gitlink { target } => {
                self.hasher.update([2]);
                hash_len_prefixed(&mut self.hasher, target.as_bytes())?;
            }
        }
        self.hasher.update(artifact.size.to_be_bytes());
        self.hasher.update(artifact.mtime.to_be_bytes());

        let rest = directory
            .strip_dir_prefix(descendant)
            .ok_or_else(|| "directory index received a non-descendant path".to_string())?;
        let (child, child_type) = match rest.iter().position(|byte| *byte == b'/') {
            Some(position) => (&rest[..position], FileType::Directory),
            None => (rest, file_type(artifact.entry)),
        };
        match self.entries.entry(child.to_vec()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(child_type);
            }
            std::collections::btree_map::Entry::Occupied(entry) if *entry.get() == child_type => {}
            std::collections::btree_map::Entry::Occupied(entry) => {
                return Err(format!(
                    "tree child {} appears as both {:?} and {:?}",
                    String::from_utf8_lossy(entry.key()),
                    entry.get(),
                    child_type
                ));
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        path: &VfsPath,
        snapshot_token: SnapshotToken,
        authority_generation: u64,
        workspace_generation: u64,
    ) -> Result<CachedDirectory, String> {
        self.hasher.update(self.descendant_count.to_be_bytes());
        let membership = Hash256::from_bytes(self.hasher.finalize().into());
        let object_id = fresh_directory_object_id(path, snapshot_token)?;
        let entries = self
            .entries
            .into_iter()
            .map(|(name, file_type)| {
                VfsName::from_bytes(name)
                    .map(|name| DirEntry {
                        name,
                        file_type,
                        object_id: None,
                    })
                    .map_err(|error| format!("invalid tree entry name: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CachedDirectory {
            object_id,
            mutation: DirectoryMutationIdentity {
                authority_generation,
                workspace_generation,
                membership,
            },
            entries,
        })
    }
}

fn fresh_directory_object_id(
    path: &VfsPath,
    snapshot_token: SnapshotToken,
) -> Result<[u8; 32], String> {
    if path.is_root() {
        return Ok(Sha256::digest(b"kin-vfs-root-directory-capability-v1\0").into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kin-vfs-fresh-directory-capability-v2\0");
    hasher.update(snapshot_token);
    hash_len_prefixed(&mut hasher, path.as_bytes())?;
    Ok(hasher.finalize().into())
}

/// Stable VFS object identity for one first-class graph artifact.
fn artifact_object_id(artifact_id: ArtifactId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-vfs-artifact-object-v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), String> {
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| "directory identity input exceeds u64".to_string())?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(())
}

/// How a freshly validated snapshot relates to the currently installed one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Succession {
    /// Install the new snapshot.
    Install,
    /// The current snapshot is the same or newer; retain it unchanged.
    RetainCurrent,
}

/// Decide atomically whether `next` may replace `current`.
///
/// A regressed version retains the current (newer) snapshot — the stale
/// response never installs. Repository and workspace identity are immutable
/// for the lifetime of one cache; changing either requires an explicit cache
/// reset/remount. Two *different* snapshots claiming one version is a ref race
/// or server corruption and fails loud; the prior snapshot stays.
pub(crate) fn plan_succession(
    current: Option<&CachedTree>,
    next: &CachedTree,
) -> Result<Succession, String> {
    let Some(current) = current else {
        return Ok(Succession::Install);
    };
    if next.binding.repository_id != current.binding.repository_id
        || next.binding.workspace_id != current.binding.workspace_id
    {
        return Err(format!(
            "tree snapshot authority identity changed from repository {}/workspace {} to repository {}/workspace {}; reset the cache or remount explicitly",
            current.binding.repository_id,
            current.binding.workspace_id,
            next.binding.repository_id,
            next.binding.workspace_id,
        ));
    }
    if next.version > current.version {
        let current_root = current
            .directory_mutation(&VfsPath::root())
            .expect("every validated snapshot indexes the root");
        let next_root = next
            .directory_mutation(&VfsPath::root())
            .expect("every validated snapshot indexes the root");
        if next_root.workspace_generation < current_root.workspace_generation {
            return Err(format!(
                "tree snapshot workspace generation regressed from {} to {} while repository authority advanced",
                current_root.workspace_generation, next_root.workspace_generation
            ));
        }
        if next_root.membership != current_root.membership
            && next_root.workspace_generation == current_root.workspace_generation
        {
            return Err(format!(
                "tree snapshot descendant membership changed at workspace generation {}",
                next_root.workspace_generation
            ));
        }
        return Ok(Succession::Install);
    }
    if next.version == current.version {
        if next.etag == current.etag && next.binding == current.binding {
            return Ok(Succession::RetainCurrent);
        }
        return Err(format!(
            "conflicting tree snapshots for version {}: etag/authority binding diverged",
            next.version
        ));
    }
    Ok(Succession::RetainCurrent)
}

/// Quote an etag for `If-None-Match` (strong validator form).
pub(crate) fn if_none_match_value(etag: &str) -> String {
    format!("\"{etag}\"")
}

/// Extract and unquote the strong `ETag` response header. The daemon must send
/// exactly `"{etag}"`; anything else (missing, weak, unquoted) is a contract
/// violation.
pub(crate) fn parse_etag_header(headers: &HeaderMap) -> Result<String, String> {
    let raw = headers
        .get(reqwest::header::ETAG)
        .ok_or_else(|| "tree response missing ETag header".to_string())?
        .to_str()
        .map_err(|_| "tree ETag header is not visible ASCII".to_string())?;
    let inner = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("tree ETag header {raw:?} is not a quoted strong validator"))?;
    if inner.is_empty() {
        return Err("tree ETag header is empty".to_string());
    }
    Ok(inner.to_string())
}

/// Convert a [`TreeEntry`] to the VFS directory-entry type, carrying gitlinks
/// explicitly instead of coercing them.
pub(crate) fn file_type(entry: TreeEntry) -> FileType {
    match entry {
        TreeEntry::Blob { .. } => FileType::File,
        TreeEntry::Symlink { .. } => FileType::Symlink,
        TreeEntry::Gitlink { .. } => FileType::Gitlink,
    }
}

/// Metadata for one artifact. Gitlinks refuse with the typed
/// repository-boundary error — they are never presented as blobs, symlinks, or
/// ordinary directories.
pub(crate) fn stat_for_entry(
    entry: TreeEntry,
    size: u64,
    mtime: u64,
    path: &VfsPath,
) -> VfsResult<VirtualStat> {
    match entry {
        TreeEntry::Blob { hash, executable } => Ok(VirtualStat::regular_file(
            size,
            *hash.as_bytes(),
            executable,
            mtime,
        )),
        TreeEntry::Symlink { target_blob } => {
            Ok(VirtualStat::symlink(size, *target_blob.as_bytes(), mtime))
        }
        TreeEntry::Gitlink { .. } => Err(VfsError::UnsupportedRepositoryBoundary {
            path: path.to_string(),
        }),
    }
}

/// The content-addressed identity a read of `entry` must verify against, or
/// the typed boundary error for gitlinks.
pub(crate) fn blob_identity(entry: TreeEntry, path: &VfsPath) -> VfsResult<Hash256> {
    entry
        .blob_identity()
        .ok_or_else(|| VfsError::UnsupportedRepositoryBoundary {
            path: path.to_string(),
        })
}

/// Verify a complete blob body against its content address.
pub(crate) fn verify_blob(expected: Hash256, data: &[u8], path: &VfsPath) -> VfsResult<()> {
    let actual: [u8; 32] = Sha256::digest(data).into();
    if actual == *expected.as_bytes() {
        Ok(())
    } else {
        Err(VfsError::Provider(format!(
            "graph blob hash mismatch for {path}: expected {expected}, got {}",
            hex::encode(actual)
        )))
    }
}

/// Verify a complete blob body length against the exact tree size.
pub(crate) fn verify_size(expected: u64, actual: usize, path: &VfsPath) -> VfsResult<()> {
    if usize::try_from(expected).ok() == Some(actual) {
        Ok(())
    } else {
        Err(VfsError::Provider(format!(
            "graph blob size mismatch for {path}: expected {expected}, got {actual}"
        )))
    }
}

/// Slice a body that was already verified against its whole-object content
/// address.
///
/// A partial HTTP body cannot be proven against a whole-blob SHA-256 merely
/// because the server echoes that hash in a header. Until the tree contract
/// carries authenticated chunk hashes or Merkle proofs, providers must verify
/// the complete body first and only then expose a range.
pub(crate) fn slice_verified_blob(
    data: &[u8],
    offset: u64,
    len: u64,
    path: &VfsPath,
) -> VfsResult<Vec<u8>> {
    let total = u64::try_from(data.len())
        .map_err(|_| VfsError::Provider(format!("graph blob for {path} exceeds u64")))?;
    if len == 0 || offset >= total {
        return Ok(Vec::new());
    }
    let start = usize::try_from(offset)
        .map_err(|_| VfsError::Provider("range offset exceeds usize".to_string()))?;
    let end = usize::try_from(offset.saturating_add(len).min(total))
        .map_err(|_| VfsError::Provider("range end exceeds usize".to_string()))?;
    data.get(start..end).map(ToOwned::to_owned).ok_or_else(|| {
        VfsError::Provider(format!(
            "verified graph blob range {offset}..{end} is invalid for {path}"
        ))
    })
}

/// Test fixture builders shared by the provider contract tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use kin_model::{compute_resolved_tree_hash, RepoPath, ResolvedArtifact, ResolvedTree};
    use uuid::Uuid;

    pub(crate) fn artifact_id(value: u128) -> ArtifactId {
        ArtifactId(Uuid::from_u128(value))
    }

    fn root(byte: u8) -> kin_model::AuthorityRoot {
        kin_model::AuthorityRoot::new(
            kin_model::REPOSITORY_ROOT_SCHEMA_VERSION,
            Hash256::from_bytes([byte; 32]),
        )
    }

    pub(crate) fn binding(workspace_tree_hash: Hash256) -> WorkspaceSnapshotBinding {
        let change = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0xcd; 32]));
        WorkspaceSnapshotBinding {
            repository_id: kin_model::RepositoryId::new("fixture-repository").unwrap(),
            workspace_id: kin_model::WorkspaceId::from_uuid(Uuid::from_u128(0xfeed)),
            workspace_head: kin_model::WorkspaceHead::Symbolic {
                target: kin_model::RefName::branch(b"main").unwrap(),
            },
            base_target: Some(kin_model::RefTarget::change(change)),
            base_tree_hash: Some(workspace_tree_hash),
            workspace_tree_hash,
            roots: kin_model::RootBundle {
                version: kin_model::REPOSITORY_ROOT_SCHEMA_VERSION,
                generation: 7,
                history: root(1),
                ref_state: root(2),
                ref_log: root(3),
                collaboration: root(4),
                replication: root(5),
                local_state: root(6),
            },
            workspace_generation: 3,
            admission_policy: kin_model::EffectiveAdmissionPolicyStamp {
                shared: kin_model::AdmissionPolicyStamp {
                    hash: kin_model::AdmissionPolicyHash(Hash256::from_bytes([0xa1; 32])),
                    generation: 2,
                },
                local: kin_model::LocalOverlayStamp {
                    hash: kin_model::LocalOverlayHash(Hash256::from_bytes([0xa2; 32])),
                    generation: 1,
                },
            },
        }
    }

    pub(crate) fn blob_artifact(
        id: u128,
        path: &[u8],
        content_byte: u8,
        executable: bool,
        size: u64,
    ) -> WorkspaceTreeArtifact {
        WorkspaceTreeArtifact {
            artifact_id: artifact_id(id),
            path: RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry: TreeEntry::blob(Hash256::from_bytes([content_byte; 32]), executable),
            size,
            mtime: 1_000 + id as u64,
        }
    }

    /// A blob artifact whose hash is the real SHA-256 of `content`.
    pub(crate) fn content_artifact(
        id: u128,
        path: &[u8],
        content: &[u8],
        executable: bool,
    ) -> WorkspaceTreeArtifact {
        WorkspaceTreeArtifact {
            artifact_id: artifact_id(id),
            path: RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry: TreeEntry::blob(
                Hash256::from_bytes(Sha256::digest(content).into()),
                executable,
            ),
            size: content.len() as u64,
            mtime: 1_000 + id as u64,
        }
    }

    /// A symlink artifact whose target blob is the real SHA-256 of `target`.
    pub(crate) fn symlink_artifact(id: u128, path: &[u8], target: &[u8]) -> WorkspaceTreeArtifact {
        WorkspaceTreeArtifact {
            artifact_id: artifact_id(id),
            path: RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry: TreeEntry::symlink(Hash256::from_bytes(Sha256::digest(target).into())),
            size: target.len() as u64,
            mtime: 1_000 + id as u64,
        }
    }

    pub(crate) fn gitlink_artifact(id: u128, path: &[u8]) -> WorkspaceTreeArtifact {
        WorkspaceTreeArtifact {
            artifact_id: artifact_id(id),
            path: RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry: TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x22; 20])),
            size: 0,
            mtime: 1_000 + id as u64,
        }
    }

    pub(crate) fn snapshot(artifacts: Vec<WorkspaceTreeArtifact>) -> WorkspaceTreeSnapshot {
        let tree = resolved_tree(&artifacts);
        let workspace_tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        WorkspaceTreeSnapshot::new(binding(workspace_tree_hash), artifacts).unwrap()
    }

    fn resolved_tree(artifacts: &[WorkspaceTreeArtifact]) -> ResolvedTree {
        ResolvedTree::from_artifacts(artifacts.iter().map(|artifact| {
            ResolvedArtifact::new(artifact.artifact_id, artifact.path.clone(), artifact.entry)
        }))
        .unwrap()
    }

    pub(crate) fn rebind(snapshot: &mut WorkspaceTreeSnapshot) {
        snapshot.binding.workspace_tree_hash =
            compute_resolved_tree_hash(&resolved_tree(&snapshot.artifacts)).unwrap();
        snapshot
            .artifacts
            .sort_by_key(|artifact| artifact.artifact_id);
    }
}

/// Golden wire fixtures shared with the Kin daemon.
///
/// These pin the exact JSON both sides must agree on. A change to any encoding
/// — path bytes_hex, Hash256 array form, entry tagging, field names — shows up
/// here as a diff instead of a silent runtime mismatch against the peer.
#[cfg(test)]
mod golden {
    use super::fixtures::{
        artifact_id, content_artifact, gitlink_artifact, snapshot, symlink_artifact,
    };
    use super::*;

    const TREE_FIXTURE: &str = include_str!("../../../tests/fixtures/tree-snapshot.json");

    /// The exact document the fixture encodes. Kept in code so the fixture is
    /// generated from the real types, never hand-maintained.
    fn golden_snapshot() -> WorkspaceTreeSnapshot {
        snapshot(vec![
            content_artifact(1, b"README.md", b"# Kin VFS\n", false),
            content_artifact(2, b"src/main.rs", b"fn main() {}\n", false),
            content_artifact(
                3,
                b"compose.yaml",
                b"services:\n  api:\n    image: kin/example\n",
                false,
            ),
            content_artifact(4, b"vendor.lock", b"opaque-lock-v9\x00\x01payload\n", false),
            content_artifact(
                5,
                b"legacy/model.f90",
                b"      PROGRAM LEGACY\n      END\n",
                false,
            ),
            content_artifact(6, b"scripts/run-kin", b"#!/bin/sh\nexec kin \"$@\"\n", true),
            content_artifact(
                7,
                b"assets/logo.bin",
                &[0x00, 0xff, 0x89, b'K', b'I', b'N'],
                false,
            ),
            symlink_artifact(8, b"current", b"src/main.rs"),
            content_artifact(9, b"logs/x-\xff\xfe.log", b"raw bytes win\n", false),
            gitlink_artifact(10, b"vendor/dep"),
        ])
    }

    #[test]
    fn tree_snapshot_matches_the_shared_golden_fixture() {
        let encoded = serde_json::to_string_pretty(&golden_snapshot()).expect("encode");
        assert_eq!(
            encoded.trim(),
            TREE_FIXTURE.trim(),
            "the /vfs/tree wire encoding changed. If this is intentional, this is a \
             PEER CONTRACT CHANGE: regenerate tests/fixtures/tree-snapshot.json and land \
             the matching kin-daemon change together."
        );
    }

    #[test]
    fn golden_fixture_decodes_and_validates() {
        // The fixture must not merely round-trip: it must survive full
        // validation, so the shared contract and the enforced contract cannot
        // drift apart.
        let decoded: WorkspaceTreeSnapshot =
            serde_json::from_str(TREE_FIXTURE).expect("decode fixture");
        let expected_etag = decoded.identity().expect("identify fixture").to_string();
        let tree = CachedTree::from_snapshot(decoded).expect("fixture must validate");

        assert_eq!(tree.version, 7);
        assert_eq!(tree.etag, expected_etag);
        assert!(matches!(
            tree.binding.workspace_head,
            kin_model::WorkspaceHead::Symbolic { ref target }
                if target.as_bytes() == b"refs/heads/main"
        ));

        // Byte-exact non-UTF8 path identity survives the wire.
        let raw = VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).unwrap();
        assert_eq!(tree.artifact_id_at(&raw), Some(artifact_id(9)));

        // Executable bit, symlink kind, and gitlink boundary all survive.
        let script = VfsPath::from_utf8("scripts/run-kin").unwrap();
        assert_eq!(tree.stat_path(&script).unwrap().mode, 0o755);
        assert!(
            tree.stat_path(&VfsPath::from_utf8("current").unwrap())
                .unwrap()
                .is_symlink
        );
        assert!(matches!(
            tree.stat_path(&VfsPath::from_utf8("vendor/dep").unwrap()),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
    }

    /// Emit the fixture from the real types. Ignored by default; run to
    /// regenerate after an intentional contract change:
    ///   cargo test -p kin-vfs-daemon -- --ignored regenerate_golden
    #[test]
    #[ignore = "regenerates tests/fixtures/tree-snapshot.json"]
    fn regenerate_golden_tree_fixture() {
        let encoded = serde_json::to_string_pretty(&golden_snapshot()).expect("encode");
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/tree-snapshot.json"
        );
        std::fs::write(path, format!("{encoded}\n")).expect("write fixture");
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{blob_artifact, gitlink_artifact, rebind, snapshot, symlink_artifact};
    use super::*;
    use kin_model::GitObjectId;
    use uuid::Uuid;

    #[test]
    fn unsupported_schema_versions_are_rejected() {
        let mut document = snapshot(vec![]);
        document.schema = 1;
        assert!(CachedTree::from_snapshot(document)
            .unwrap_err()
            .contains("unsupported workspace tree snapshot version"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut json = serde_json::to_value(snapshot(vec![])).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<WorkspaceTreeSnapshot>(json).is_err());

        let artifact_json = serde_json::json!({
            "artifact_id": Uuid::from_u128(1),
            "path": {"bytes_hex": "61"},
            "entry": {"type": "blob", "hash": vec![1; 32], "executable": false},
            "size": 1,
            "mtime": 0,
            "legacy_kind": "regular",
        });
        assert!(serde_json::from_value::<WorkspaceTreeArtifact>(artifact_json).is_err());
    }

    #[test]
    fn duplicate_artifact_ids_and_paths_are_rejected() {
        let mut duplicate_id = snapshot(vec![
            blob_artifact(1, b"a.txt", 1, false, 1),
            blob_artifact(2, b"b.txt", 2, false, 1),
        ]);
        duplicate_id.artifacts[1].artifact_id = duplicate_id.artifacts[0].artifact_id;
        assert!(CachedTree::from_snapshot(duplicate_id)
            .unwrap_err()
            .contains("canonical unique identity order"));

        let mut duplicate_path = snapshot(vec![
            blob_artifact(1, b"a.txt", 1, false, 1),
            blob_artifact(2, b"b.txt", 2, false, 1),
        ]);
        duplicate_path.artifacts[1].path = duplicate_path.artifacts[0].path.clone();
        assert!(CachedTree::from_snapshot(duplicate_path)
            .unwrap_err()
            .contains("more than once"));
    }

    #[test]
    fn workspace_binding_must_identify_the_exact_artifact_tree() {
        let mut document = snapshot(vec![blob_artifact(1, b"compose.yaml", 1, false, 1)]);
        document.binding.workspace_tree_hash = Hash256::from_bytes([0xff; 32]);

        assert!(CachedTree::from_snapshot(document)
            .unwrap_err()
            .contains("workspace tree hash"));
    }

    #[test]
    fn prefix_collisions_are_rejected() {
        let mut collision = snapshot(vec![
            blob_artifact(1, b"tools", 1, false, 1),
            blob_artifact(2, b"run", 2, true, 1),
        ]);
        collision.artifacts[1].path = kin_model::RepoPath::from_utf8("tools/run").unwrap();
        assert!(CachedTree::from_snapshot(collision)
            .unwrap_err()
            .contains("file/directory collision"));
    }

    #[test]
    fn non_canonical_paths_are_rejected_at_decode() {
        for invalid_hex in [
            hex::encode(b"/absolute"),
            hex::encode(b"dir//file"),
            hex::encode(b"dir/./file"),
            hex::encode(b"../escape"),
            "6".to_string(),  // odd-length hex
            "6A".to_string(), // non-canonical (uppercase) hex
            String::new(),    // empty path
        ] {
            let json = serde_json::json!({
                "artifact_id": Uuid::from_u128(9),
                "path": {"bytes_hex": invalid_hex},
                "entry": {"type": "blob", "hash": vec![1; 32], "executable": false},
                "size": 1,
                "mtime": 0,
            });
            assert!(
                serde_json::from_value::<WorkspaceTreeArtifact>(json).is_err(),
                "{invalid_hex:?} must be rejected"
            );
        }
    }

    #[test]
    fn gitlink_sizes_must_be_zero() {
        let mut document = snapshot(vec![super::fixtures::gitlink_artifact(1, b"vendor/dep")]);
        document.artifacts[0].size = 4;
        assert!(CachedTree::from_snapshot(document)
            .unwrap_err()
            .contains("must advertise zero bytes"));
    }

    #[test]
    fn gitlinks_are_carried_in_listings_and_refused_per_path() {
        let mut gitlink = blob_artifact(2, b"vendor/dep", 0, false, 0);
        gitlink.entry = TreeEntry::gitlink(GitObjectId::sha1([0x22; 20]));
        let tree = CachedTree::from_snapshot(snapshot(vec![
            blob_artifact(1, b"a.txt", 1, false, 1),
            gitlink,
        ]))
        .unwrap();

        let vendor = VfsPath::from_utf8("vendor").unwrap();
        let listing = tree.list_dir(&vendor).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].name.as_bytes(), b"dep");
        assert_eq!(listing[0].file_type, FileType::Gitlink);

        let dep = VfsPath::from_utf8("vendor/dep").unwrap();
        assert!(matches!(
            tree.stat_path(&dep),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        let artifact = tree.require_artifact(&dep).unwrap();
        assert!(matches!(
            blob_identity(artifact.entry, &dep),
            Err(VfsError::UnsupportedRepositoryBoundary { .. })
        ));
        // The boundary still carries its stable graph identity.
        assert_eq!(
            tree.artifact_id_at(&dep),
            Some(super::fixtures::artifact_id(2))
        );
    }

    #[test]
    fn dirs_derive_from_paths_and_root_stats() {
        let tree = CachedTree::from_snapshot(snapshot(vec![
            blob_artifact(1, b"compose.yaml", 1, false, 10),
            blob_artifact(2, b"scripts/run", 2, true, 20),
            blob_artifact(3, b"logs/x-\xff.log", 3, false, 5),
        ]))
        .unwrap();

        assert!(tree.is_dir(&VfsPath::root()));
        assert!(tree.is_dir(&VfsPath::from_utf8("scripts").unwrap()));
        assert!(tree.is_dir(&VfsPath::from_utf8("logs").unwrap()));
        assert!(!tree.is_dir(&VfsPath::from_utf8("compose.yaml").unwrap()));

        let root_stat = tree.stat_path(&VfsPath::root()).unwrap();
        assert!(root_stat.is_dir);
        assert_eq!(root_stat.mtime, tree.version);
        assert_eq!(root_stat.mtime, 7, "directory mtime is graph generation");

        // Byte-exact non-UTF8 lookup.
        let raw = VfsPath::from_bytes(b"logs/x-\xff.log".to_vec()).unwrap();
        let stat = tree.stat_path(&raw).unwrap();
        assert_eq!(stat.size, 5);
        let near_miss = VfsPath::from_bytes(b"logs/x-\xfe.log".to_vec()).unwrap();
        assert!(matches!(
            tree.stat_path(&near_miss),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn graph_object_identity_distinguishes_replacement_and_refuses_inferred_directory_rename() {
        let initial = CachedTree::from_snapshot(snapshot(vec![
            blob_artifact(1, b"same.bin", 1, false, 1),
            blob_artifact(2, b"old-dir/child.bin", 2, false, 1),
        ]))
        .unwrap();
        let mut replacement = CachedTree::from_snapshot(snapshot(vec![
            blob_artifact(2, b"new-dir/child.bin", 2, false, 1),
            blob_artifact(99, b"same.bin", 1, false, 1),
        ]))
        .unwrap();
        replacement.install_successor_authority(&initial).unwrap();

        let old_leaf = initial
            .stat_path(&VfsPath::from_utf8("same.bin").unwrap())
            .unwrap();
        let replacement_leaf = replacement
            .stat_path(&VfsPath::from_utf8("same.bin").unwrap())
            .unwrap();
        assert_ne!(
            old_leaf.object_id, replacement_leaf.object_id,
            "path reuse by another artifact must not reuse object identity"
        );

        let old_dir = initial
            .stat_path(&VfsPath::from_utf8("old-dir").unwrap())
            .unwrap();
        let new_dir = replacement
            .stat_path(&VfsPath::from_utf8("new-dir").unwrap())
            .unwrap();
        assert_ne!(
            old_dir.object_id, new_dir.object_id,
            "leaf continuity cannot prove that a derived directory object moved"
        );
        assert!(
            replacement
                .resolve_directory(old_dir.object_id.unwrap())
                .is_err(),
            "the old directory capability must fail closed after an unproven cross-path move"
        );

        let old_child = initial
            .stat_path(&VfsPath::from_utf8("old-dir/child.bin").unwrap())
            .unwrap();
        let moved_child = replacement
            .stat_path(&VfsPath::from_utf8("new-dir/child.bin").unwrap())
            .unwrap();
        assert_eq!(
            old_child.object_id, moved_child.object_id,
            "a leaf rename preserves its graph artifact identity"
        );
    }

    #[test]
    fn schema_derived_directory_capabilities_fail_closed_across_successors() {
        let initial_document = snapshot(vec![
            blob_artifact(1, b"old/anchor.bin", 1, false, 1),
            blob_artifact(2, b"old/keep.bin", 2, false, 1),
        ]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let old = VfsPath::from_utf8("old").unwrap();
        let original_id = initial.stat_path(&old).unwrap().object_id.unwrap();

        let mut churn_document = initial_document;
        churn_document
            .artifacts
            .retain(|artifact| artifact.artifact_id != fixtures::artifact_id(1));
        churn_document
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.artifact_id == fixtures::artifact_id(2))
            .unwrap()
            .path = kin_model::RepoPath::from_utf8("old/renamed.bin").unwrap();
        churn_document
            .artifacts
            .push(blob_artifact(3, b"old/added.bin", 3, false, 1));
        advance_snapshot(&mut churn_document, 8, 4);
        let mut churn = CachedTree::from_snapshot(churn_document.clone()).unwrap();
        churn.install_successor_authority(&initial).unwrap();
        assert_ne!(
            churn.stat_path(&old).unwrap().object_id,
            Some(original_id),
            "leaf continuity cannot prove that the containing directory object survived"
        );
        assert!(
            churn.resolve_directory(original_id).is_err(),
            "a schema-derived capability must fail closed after same-path succession"
        );
        let churn_id = churn.stat_path(&old).unwrap().object_id.unwrap();

        let mut moved_document = churn_document;
        for artifact in &mut moved_document.artifacts {
            let name = artifact.path.as_bytes().strip_prefix(b"old/").unwrap();
            artifact.path =
                kin_model::RepoPath::from_bytes([b"moved/".as_slice(), name].concat()).unwrap();
        }
        advance_snapshot(&mut moved_document, 9, 5);
        let mut moved = CachedTree::from_snapshot(moved_document).unwrap();
        moved.install_successor_authority(&churn).unwrap();
        let moved_path = VfsPath::from_utf8("moved").unwrap();
        assert_ne!(
            moved.stat_path(&moved_path).unwrap().object_id,
            Some(churn_id),
            "identical descendant shape is not producer proof of a directory rename"
        );
        assert!(
            moved.resolve_directory(churn_id).is_err(),
            "the same successor snapshot can result from delete/recreate plus moving the leaves, so the old capability must fail closed"
        );

        let root_entry = moved
            .list_dir(&VfsPath::root())
            .unwrap()
            .into_iter()
            .find(|entry| entry.name.as_bytes() == b"moved")
            .unwrap();
        assert_eq!(
            root_entry.object_id,
            moved.stat_path(&moved_path).unwrap().object_id,
            "parent listings must carry the successor's fresh directory identity"
        );
    }

    #[test]
    fn same_path_delete_recreate_with_leaf_move_out_and_back_drops_capability() {
        let initial_document = snapshot(vec![
            blob_artifact(1, b"dir/keep.bin", 1, false, 1),
            blob_artifact(2, b"dir/other.bin", 2, false, 1),
        ]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let directory = VfsPath::from_utf8("dir").unwrap();
        let keep = VfsPath::from_utf8("dir/keep.bin").unwrap();
        let old_directory_id = initial.stat_path(&directory).unwrap().object_id.unwrap();
        let keep_id = initial.stat_path(&keep).unwrap().object_id;

        // These two leaf snapshots are also produced by moving both leaves out,
        // deleting `dir`, recreating it, and moving the same leaves back before
        // S2. Schema 3 carries no directory tombstone or transition that could
        // distinguish that history from ordinary in-place succession.
        let mut successor_document = initial_document;
        advance_snapshot(&mut successor_document, 8, 4);
        let mut successor = CachedTree::from_snapshot(successor_document).unwrap();
        successor.install_successor_authority(&initial).unwrap();

        assert_eq!(
            successor.stat_path(&keep).unwrap().object_id,
            keep_id,
            "the first-class leaf keeps its graph artifact identity"
        );
        assert_ne!(
            successor.stat_path(&directory).unwrap().object_id,
            Some(old_directory_id),
            "same-path leaf continuity must not transfer a derived directory capability"
        );
        assert!(
            successor.resolve_directory(old_directory_id).is_err(),
            "an old descriptor must not be redirected into a same-path replacement directory"
        );
    }

    #[test]
    fn split_with_path_reuse_drops_old_directory_capability() {
        let initial_document = snapshot(vec![
            blob_artifact(1, b"old/a.bin", 1, false, 1),
            blob_artifact(2, b"old/b.bin", 2, false, 1),
        ]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let old_path = VfsPath::from_utf8("old").unwrap();
        let old_id = initial.stat_path(&old_path).unwrap().object_id.unwrap();

        let mut split_document = initial_document;
        split_document
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.artifact_id == fixtures::artifact_id(2))
            .unwrap()
            .path = kin_model::RepoPath::from_utf8("moved/b.bin").unwrap();
        split_document
            .artifacts
            .push(blob_artifact(99, b"old/replacement.bin", 9, false, 1));
        advance_snapshot(&mut split_document, 8, 4);
        let mut split = CachedTree::from_snapshot(split_document).unwrap();
        split.install_successor_authority(&initial).unwrap();

        assert!(
            split.resolve_directory(old_id).is_err(),
            "survivors split between the reused old path and a moved path, so the old dirfd must fail closed"
        );
        assert_ne!(
            split.stat_path(&old_path).unwrap().object_id,
            Some(old_id),
            "path reuse must receive a fresh directory identity"
        );
        assert_ne!(
            split
                .stat_path(&VfsPath::from_utf8("moved").unwrap())
                .unwrap()
                .object_id,
            Some(old_id),
            "one split descendant must not capture the old directory identity"
        );
    }

    #[test]
    fn one_child_move_with_old_path_reuse_drops_old_directory_capability() {
        let initial_document = snapshot(vec![blob_artifact(1, b"old/a.bin", 1, false, 1)]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let old_path = VfsPath::from_utf8("old").unwrap();
        let moved_path = VfsPath::from_utf8("moved").unwrap();
        let old_id = initial.stat_path(&old_path).unwrap().object_id.unwrap();

        let mut reused_document = initial_document;
        reused_document.artifacts[0].path = kin_model::RepoPath::from_utf8("moved/a.bin").unwrap();
        reused_document
            .artifacts
            .push(blob_artifact(99, b"old/b.bin", 9, false, 1));
        advance_snapshot(&mut reused_document, 8, 4);
        let mut reused = CachedTree::from_snapshot(reused_document).unwrap();
        reused.install_successor_authority(&initial).unwrap();

        assert!(
            reused.resolve_directory(old_id).is_err(),
            "one moved leaf cannot prove that its derived parent moved when the old path still exists"
        );
        assert_ne!(
            reused.stat_path(&old_path).unwrap().object_id,
            Some(old_id),
            "the reused old path must receive a fresh capability"
        );
        assert_ne!(
            reused.stat_path(&moved_path).unwrap().object_id,
            Some(old_id),
            "the moved child destination must not capture the ambiguous old capability"
        );
    }

    #[test]
    fn non_bijective_cross_path_move_drops_old_directory_capability() {
        let initial_document = snapshot(vec![
            blob_artifact(1, b"old/a.bin", 1, false, 1),
            blob_artifact(2, b"old/b.bin", 2, false, 1),
        ]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let old_path = VfsPath::from_utf8("old").unwrap();
        let old_id = initial.stat_path(&old_path).unwrap().object_id.unwrap();

        let mut partial_document = initial_document;
        partial_document
            .artifacts
            .retain(|artifact| artifact.artifact_id == fixtures::artifact_id(1));
        partial_document.artifacts[0].path = kin_model::RepoPath::from_utf8("moved/a.bin").unwrap();
        advance_snapshot(&mut partial_document, 8, 4);
        let mut partial = CachedTree::from_snapshot(partial_document).unwrap();
        partial.install_successor_authority(&initial).unwrap();

        assert!(
            partial.resolve_directory(old_id).is_err(),
            "deleting part of a subtree while moving the survivor is not a bijective directory move"
        );
    }

    #[test]
    fn converging_directories_drop_both_prior_capabilities() {
        let initial_document = snapshot(vec![
            blob_artifact(1, b"left/a.bin", 1, false, 1),
            blob_artifact(2, b"right/b.bin", 2, false, 1),
        ]);
        let initial = CachedTree::from_snapshot(initial_document.clone()).unwrap();
        let left_id = initial
            .stat_path(&VfsPath::from_utf8("left").unwrap())
            .unwrap()
            .object_id
            .unwrap();
        let right_id = initial
            .stat_path(&VfsPath::from_utf8("right").unwrap())
            .unwrap()
            .object_id
            .unwrap();

        let mut merged_document = initial_document;
        for artifact in &mut merged_document.artifacts {
            let name = artifact
                .path
                .as_bytes()
                .rsplit(|byte| *byte == b'/')
                .next()
                .unwrap();
            artifact.path =
                kin_model::RepoPath::from_bytes([b"merged/".as_slice(), name].concat()).unwrap();
        }
        advance_snapshot(&mut merged_document, 8, 4);
        let mut merged = CachedTree::from_snapshot(merged_document).unwrap();
        merged.install_successor_authority(&initial).unwrap();

        assert!(merged.resolve_directory(left_id).is_err());
        assert!(merged.resolve_directory(right_id).is_err());
        let merged_id = merged
            .stat_path(&VfsPath::from_utf8("merged").unwrap())
            .unwrap()
            .object_id
            .unwrap();
        assert_ne!(merged_id, left_id);
        assert_ne!(merged_id, right_id);
    }

    #[test]
    fn duplicate_basenames_have_distinct_listing_identities_matching_stat() {
        let tree = CachedTree::from_snapshot(snapshot(vec![
            blob_artifact(1, b"left/same.bin", 1, false, 1),
            blob_artifact(2, b"right/same.bin", 2, false, 1),
        ]))
        .unwrap();

        let entry_id = |directory: &str| {
            tree.list_dir(&VfsPath::from_utf8(directory).unwrap())
                .unwrap()
                .into_iter()
                .find(|entry| entry.name.as_bytes() == b"same.bin")
                .unwrap()
                .object_id
                .unwrap()
        };
        let left_entry = entry_id("left");
        let right_entry = entry_id("right");
        assert_ne!(
            left_entry, right_entry,
            "equal basenames must not collide in readdir identity"
        );
        assert_eq!(
            Some(left_entry),
            tree.stat_path(&VfsPath::from_utf8("left/same.bin").unwrap())
                .unwrap()
                .object_id
        );
        assert_eq!(
            Some(right_entry),
            tree.stat_path(&VfsPath::from_utf8("right/same.bin").unwrap())
                .unwrap()
                .object_id
        );
    }

    #[test]
    fn host_inode_collision_is_detected_before_snapshot_installation() {
        let first = [1; 32];
        let second = [2; 32];
        assert!(
            validate_host_inode_uniqueness_with([first, second], |_| 42).is_err(),
            "an injected 64-bit collision must fail loud rather than alias graph objects"
        );
        assert!(
            validate_host_inode_uniqueness_with([first, first], |_| 42).is_ok(),
            "repeated observations of the same graph object are not a collision"
        );
        assert!(
            validate_host_inode_uniqueness_with([first], |_| 0).is_err(),
            "host inode zero is reserved and must never identify a graph object"
        );
    }

    #[test]
    fn host_inode_collision_is_detected_across_snapshot_succession() {
        let first = [1; 32];
        let successor = [2; 32];
        let mut lifetime_registry = BTreeMap::new();

        extend_host_inode_registry_with(&mut lifetime_registry, [first], |_| 42).unwrap();
        assert!(
            extend_host_inode_registry_with(&mut lifetime_registry, [successor], |_| 42).is_err(),
            "a successor snapshot must not reuse an inode that a descriptor from a prior snapshot can still expose"
        );
        assert_eq!(
            lifetime_registry.get(&42),
            Some(&first),
            "collision refusal must leave the prior live identity registered"
        );
    }

    #[test]
    fn host_inode_history_is_inherited_transitively_across_snapshot_succession() {
        let first_path = VfsPath::from_utf8("first.bin").unwrap();
        let second_path = VfsPath::from_utf8("second.bin").unwrap();
        let third_path = VfsPath::from_utf8("third.bin").unwrap();

        let first =
            CachedTree::from_snapshot(snapshot(vec![blob_artifact(1, b"first.bin", 1, false, 1)]))
                .unwrap();
        let first_id = first.stat_path(&first_path).unwrap().object_id.unwrap();

        let mut second =
            CachedTree::from_snapshot(snapshot(vec![blob_artifact(2, b"second.bin", 2, false, 1)]))
                .unwrap();
        let second_id = second.stat_path(&second_path).unwrap().object_id.unwrap();
        second.install_successor_authority(&first).unwrap();

        let mut third =
            CachedTree::from_snapshot(snapshot(vec![blob_artifact(3, b"third.bin", 3, false, 1)]))
                .unwrap();
        let third_id = third.stat_path(&third_path).unwrap().object_id.unwrap();
        third.install_successor_authority(&second).unwrap();

        for retained_id in [first_id, second_id, third_id] {
            let inode = kin_vfs_core::pathmap::synthetic_object_inode(&retained_id);
            assert_eq!(
                third.host_inode_registry.get(&inode),
                Some(&retained_id),
                "every previously published graph identity must remain reserved"
            );
        }
    }

    fn advance_snapshot(
        document: &mut WorkspaceTreeSnapshot,
        authority_generation: u64,
        workspace_generation: u64,
    ) {
        rebind(document);
        document.binding.roots.generation = authority_generation;
        document.binding.workspace_generation = workspace_generation;
    }

    fn names_and_kinds(tree: &CachedTree, path: &VfsPath) -> Vec<(Vec<u8>, FileType)> {
        tree.list_dir(path)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.into_bytes(), entry.file_type))
            .collect()
    }

    #[test]
    fn deleting_newest_descendant_advances_directory_mutation_without_regression() {
        let current_document = snapshot(vec![
            blob_artifact(1, b"src/older.rs", 1, false, 1),
            blob_artifact(99, b"src/newest.rs", 2, false, 1),
            blob_artifact(3, b"compose.yaml", 3, false, 1),
        ]);
        let current = CachedTree::from_snapshot(current_document.clone()).unwrap();
        let src = VfsPath::from_utf8("src").unwrap();
        let current_mutation = current.directory_mutation(&src).unwrap();
        assert_eq!(current.stat_path(&src).unwrap().mtime, 7);

        let mut next_document = current_document;
        next_document
            .artifacts
            .retain(|artifact| artifact.path.as_bytes() != b"src/newest.rs");
        advance_snapshot(&mut next_document, 8, 4);
        let next = CachedTree::from_snapshot(next_document).unwrap();
        let next_mutation = next.directory_mutation(&src).unwrap();

        assert_eq!(next.stat_path(&src).unwrap().mtime, 8);
        assert!(
            next.stat_path(&src).unwrap().mtime > current.stat_path(&src).unwrap().mtime,
            "removing the descendant with the largest leaf mtime must advance, never regress"
        );
        assert_ne!(next_mutation.membership, current_mutation.membership);
        assert_eq!(
            names_and_kinds(&next, &src),
            vec![(b"older.rs".to_vec(), FileType::File)]
        );
    }

    #[test]
    fn rename_mode_and_type_changes_advance_every_affected_directory() {
        let current_document = snapshot(vec![
            blob_artifact(1, b"left/keep.txt", 1, false, 1),
            blob_artifact(2, b"left/move.bin", 2, false, 6),
            blob_artifact(3, b"right/keep.txt", 3, false, 1),
            blob_artifact(4, b"right/compose.yaml", 4, false, 12),
            blob_artifact(5, b"right/raw-\xff.bin", 5, false, 4),
            symlink_artifact(6, b"right/current", b"compose.yaml"),
            gitlink_artifact(7, b"right/vendor"),
        ]);
        let current = CachedTree::from_snapshot(current_document.clone()).unwrap();
        let left = VfsPath::from_utf8("left").unwrap();
        let right = VfsPath::from_utf8("right").unwrap();
        let root = VfsPath::root();

        let mut renamed_document = current_document;
        renamed_document
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path.as_bytes() == b"left/move.bin")
            .unwrap()
            .path = kin_model::RepoPath::from_utf8("right/move.bin").unwrap();
        advance_snapshot(&mut renamed_document, 8, 4);
        let renamed = CachedTree::from_snapshot(renamed_document.clone()).unwrap();

        for directory in [&root, &left, &right] {
            assert!(
                renamed.stat_path(directory).unwrap().mtime
                    > current.stat_path(directory).unwrap().mtime,
                "rename must advance {directory}"
            );
            assert_ne!(
                renamed.directory_mutation(directory).unwrap().membership,
                current.directory_mutation(directory).unwrap().membership,
                "rename must change exact membership for {directory}"
            );
        }
        assert_eq!(
            names_and_kinds(&renamed, &left),
            vec![(b"keep.txt".to_vec(), FileType::File)]
        );
        assert_eq!(
            names_and_kinds(&renamed, &right),
            vec![
                (b"compose.yaml".to_vec(), FileType::File),
                (b"current".to_vec(), FileType::Symlink),
                (b"keep.txt".to_vec(), FileType::File),
                (b"move.bin".to_vec(), FileType::File),
                (b"raw-\xff.bin".to_vec(), FileType::File),
                (b"vendor".to_vec(), FileType::Gitlink),
            ],
            "Compose, binary, symlink, gitlink, and raw names share one exact listing"
        );

        let mut mode_document = renamed_document;
        let compose = mode_document
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path.as_bytes() == b"right/compose.yaml")
            .unwrap();
        let TreeEntry::Blob { hash, .. } = compose.entry else {
            panic!("Compose fixture must be a blob");
        };
        compose.entry = TreeEntry::blob(hash, true);
        advance_snapshot(&mut mode_document, 9, 5);
        let mode_changed = CachedTree::from_snapshot(mode_document.clone()).unwrap();
        assert_eq!(
            mode_changed
                .stat_path(&VfsPath::from_utf8("right/compose.yaml").unwrap())
                .unwrap()
                .mode,
            0o755,
            "mode-only updates preserve the exact executable facet"
        );
        assert_eq!(mode_changed.stat_path(&right).unwrap().mtime, 9);
        assert_ne!(
            mode_changed.directory_mutation(&right).unwrap().membership,
            renamed.directory_mutation(&right).unwrap().membership,
            "mode is part of descendant mutation identity"
        );

        let mut type_document = mode_document;
        let raw = type_document
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path.as_bytes() == b"right/raw-\xff.bin")
            .unwrap();
        raw.entry = TreeEntry::symlink(Hash256::from_bytes([0x55; 32]));
        raw.size = 7;
        advance_snapshot(&mut type_document, 10, 6);
        let type_changed = CachedTree::from_snapshot(type_document).unwrap();
        assert_eq!(
            names_and_kinds(&type_changed, &right)
                .into_iter()
                .find(|(name, _)| name == b"raw-\xff.bin")
                .unwrap()
                .1,
            FileType::Symlink
        );
        assert_eq!(type_changed.stat_path(&right).unwrap().mtime, 10);
        assert_ne!(
            type_changed.directory_mutation(&right).unwrap().membership,
            mode_changed.directory_mutation(&right).unwrap().membership,
            "entry kind is part of descendant mutation identity"
        );
    }

    #[test]
    fn empty_nonempty_and_reopen_transitions_are_stable_and_monotonic() {
        let empty_document = snapshot(vec![]);
        let empty = CachedTree::from_snapshot(empty_document.clone()).unwrap();
        let reopened_empty = CachedTree::from_snapshot(empty_document.clone()).unwrap();
        let root = VfsPath::root();

        assert_eq!(empty.stat_path(&root).unwrap().mtime, 7);
        assert!(empty.list_dir(&root).unwrap().is_empty());
        assert_eq!(
            empty.directory_mutation(&root),
            reopened_empty.directory_mutation(&root),
            "reopening the identical empty snapshot must reproduce its identity"
        );
        assert_eq!(empty.etag, reopened_empty.etag);

        let mut nonempty_document = empty_document;
        nonempty_document
            .artifacts
            .push(blob_artifact(8, b"raw/\xff.bin", 8, true, 4));
        advance_snapshot(&mut nonempty_document, 8, 4);
        let nonempty = CachedTree::from_snapshot(nonempty_document.clone()).unwrap();
        let raw_dir = VfsPath::from_utf8("raw").unwrap();
        assert_eq!(nonempty.stat_path(&root).unwrap().mtime, 8);
        assert_eq!(nonempty.stat_path(&raw_dir).unwrap().mtime, 8);
        assert_eq!(
            nonempty
                .stat_path(&VfsPath::from_bytes(b"raw/\xff.bin".to_vec()).unwrap())
                .unwrap()
                .mode,
            0o755
        );

        let mut empty_again_document = nonempty_document;
        empty_again_document.artifacts.clear();
        advance_snapshot(&mut empty_again_document, 9, 5);
        let empty_again = CachedTree::from_snapshot(empty_again_document.clone()).unwrap();
        let reopened_empty_again = CachedTree::from_snapshot(empty_again_document.clone()).unwrap();
        let repeated_empty_again = CachedTree::from_snapshot(empty_again_document).unwrap();

        assert_eq!(empty_again.stat_path(&root).unwrap().mtime, 9);
        assert!(empty_again.list_dir(&root).unwrap().is_empty());
        assert!(!empty_again.is_dir(&raw_dir));
        assert!(matches!(
            empty_again.stat_path(&raw_dir),
            Err(VfsError::NotFound { .. })
        ));
        assert_eq!(
            empty_again.directory_mutation(&root),
            reopened_empty_again.directory_mutation(&root)
        );
        assert_eq!(
            reopened_empty_again.directory_mutation(&root),
            repeated_empty_again.directory_mutation(&root),
            "repeated construction from one exact snapshot is deterministic"
        );
        assert!(
            empty_again.stat_path(&root).unwrap().mtime > nonempty.stat_path(&root).unwrap().mtime
        );
    }

    #[test]
    fn succession_installs_advancing_versions_only() {
        let make = || snapshot(vec![blob_artifact(1, b"a", 1, false, 1)]);
        let current = CachedTree::from_snapshot(make()).unwrap(); // version 7

        let mut newer = make();
        newer.binding.roots.generation = 8;
        let newer = CachedTree::from_snapshot(newer).unwrap();
        assert_eq!(
            plan_succession(Some(&current), &newer),
            Ok(Succession::Install)
        );
        assert_eq!(plan_succession(None, &newer), Ok(Succession::Install));

        // The identical snapshot re-fetched is idempotent.
        let same = CachedTree::from_snapshot(make()).unwrap();
        assert_eq!(
            plan_succession(Some(&current), &same),
            Ok(Succession::RetainCurrent)
        );

        // A stale (regressed) snapshot never installs.
        let mut stale = make();
        stale.binding.roots.generation = 6;
        let stale = CachedTree::from_snapshot(stale).unwrap();
        assert_eq!(
            plan_succession(Some(&current), &stale),
            Ok(Succession::RetainCurrent)
        );

        // Two different snapshots claiming one version is a ref race.
        let mut race = make();
        race.artifacts[0].mtime += 1;
        let race = CachedTree::from_snapshot(race).unwrap();
        assert!(plan_succession(Some(&current), &race).is_err());

        let mut binding_race = make();
        binding_race.binding.workspace_head = kin_model::WorkspaceHead::Symbolic {
            target: kin_model::RefName::branch(b"other").unwrap(),
        };
        let binding_race = CachedTree::from_snapshot(binding_race).unwrap();
        assert!(plan_succession(Some(&current), &binding_race).is_err());

        // A later generation may move or detach the workspace head, but it
        // must never silently switch the mount to another repository or
        // workspace.
        let mut another_repository = make();
        another_repository.binding.roots.generation = 8;
        another_repository.binding.repository_id =
            kin_model::RepositoryId::new("other-repository").unwrap();
        let another_repository = CachedTree::from_snapshot(another_repository).unwrap();
        assert!(plan_succession(Some(&current), &another_repository)
            .unwrap_err()
            .contains("authority identity changed"));

        let mut another_workspace = make();
        another_workspace.binding.roots.generation = 8;
        another_workspace.binding.workspace_id =
            kin_model::WorkspaceId::from_uuid(uuid::Uuid::from_u128(0xbeef));
        let another_workspace = CachedTree::from_snapshot(another_workspace).unwrap();
        assert!(plan_succession(Some(&current), &another_workspace)
            .unwrap_err()
            .contains("authority identity changed"));

        let mut detached_checkout = make();
        detached_checkout.binding.roots.generation = 8;
        let target = kin_model::RefTarget::change(kin_model::SemanticChangeId::from_hash(
            Hash256::from_bytes([0xee; 32]),
        ));
        detached_checkout.binding.workspace_head = kin_model::WorkspaceHead::Detached {
            target: target.clone(),
        };
        detached_checkout.binding.base_target = Some(target);
        let detached_checkout = CachedTree::from_snapshot(detached_checkout).unwrap();
        assert_eq!(
            plan_succession(Some(&current), &detached_checkout),
            Ok(Succession::Install)
        );

        let mut changed_without_workspace_generation = make();
        changed_without_workspace_generation.artifacts[0].entry =
            TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false);
        rebind(&mut changed_without_workspace_generation);
        changed_without_workspace_generation
            .binding
            .roots
            .generation = 8;
        let changed_without_workspace_generation =
            CachedTree::from_snapshot(changed_without_workspace_generation).unwrap();
        assert!(
            plan_succession(Some(&current), &changed_without_workspace_generation)
                .unwrap_err()
                .contains("descendant membership changed")
        );

        let mut regressed_workspace = make();
        regressed_workspace.binding.roots.generation = 8;
        regressed_workspace.binding.workspace_generation = 2;
        let regressed_workspace = CachedTree::from_snapshot(regressed_workspace).unwrap();
        assert!(plan_succession(Some(&current), &regressed_workspace)
            .unwrap_err()
            .contains("workspace generation regressed"));
    }

    #[test]
    fn etag_header_binding_is_strict() {
        let mut headers = HeaderMap::new();
        assert!(parse_etag_header(&headers).is_err(), "missing header");

        headers.insert(reqwest::header::ETAG, "\"tree-7\"".parse().unwrap());
        assert_eq!(parse_etag_header(&headers).unwrap(), "tree-7");

        headers.insert(reqwest::header::ETAG, "tree-7".parse().unwrap());
        assert!(parse_etag_header(&headers).is_err(), "unquoted");

        headers.insert(reqwest::header::ETAG, "W/\"tree-7\"".parse().unwrap());
        assert!(parse_etag_header(&headers).is_err(), "weak validator");

        assert_eq!(if_none_match_value("tree-7"), "\"tree-7\"");
    }
}
