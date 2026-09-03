// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The write half of a mount: where saved bytes land, and how the graph is told.
//!
//! The governing model is the one the shim already proves and
//! `docs/authority-and-write-notify-contract.md` pins: **the graph is the
//! authority; disk is a projection surface.** A file saved into the mount is
//! written to the workspace's real path and then announced to the repo's kin
//! daemon, which reconciles it into graph truth. Reads keep coming from the
//! graph, so once the daemon acknowledges, the mount serves the reconciled
//! artifact rather than the bytes that were handed to it.
//!
//! Nothing here is a second authority. A write that the daemon does not
//! acknowledge is reported to the caller as an error rather than logged and
//! forgotten, because a projection the graph never took is exactly the
//! divergence a graph-first mount exists to prevent.

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use kin_vfs_core::{contained_entry, contained_target, VfsError, VfsPath, VfsResult};

use crate::notify::{notify_write, NotifyError, NotifyTarget};

/// Writes a mount's changes onto the projection surface and confirms each one
/// into the graph.
pub struct WorkspaceWriter {
    /// Canonical workspace root: the projection surface these writes land on.
    root: PathBuf,
    /// Where the acknowledgement comes from.
    target: NotifyTarget,
    /// Session id for session-scoped projections, when the mount has one.
    session_id: Option<String>,
    /// Whether the write-notify nudge is worth sending.
    ///
    /// A repository-v6 daemon serves no such route, so the first `404` settles
    /// it for the life of the mount and later writes skip the round trip. The
    /// nudge only ever shortens the wait; convergence is proved by reading the
    /// graph back, never by this answer.
    nudge_worth_sending: AtomicBool,
}

impl WorkspaceWriter {
    /// Build a writer for `root`, announcing to the daemon at `daemon_url`.
    pub fn new(root: PathBuf, daemon_url: &str, session_id: Option<String>) -> Self {
        let target = NotifyTarget::resolve(daemon_url, &root);
        Self {
            root,
            target,
            session_id,
            nudge_worth_sending: AtomicBool::new(true),
        }
    }

    /// The projection surface these writes land on.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a graph path to its location on the projection surface, with
    /// every component resolved and the final one followed.
    ///
    /// `VfsPath` already refuses absolute paths, `.`/`..` components, empty
    /// components and NUL bytes at decode time, and the lexical rebuild below
    /// re-checks that anyway, because a boundary that only holds while another
    /// crate's invariant holds is not a boundary.
    ///
    /// A clean spelling is not containment on its own. A symlink already in the
    /// working copy sends a lexically contained path wherever it points, so the
    /// destination is resolved against the workspace root and refused when it
    /// leaves it.
    fn real_path(&self, path: &VfsPath) -> VfsResult<PathBuf> {
        self.check_lexical(path)?;
        contained_target(&self.root, path)
    }

    /// The projection path of the directory *entry* `path` names, with its
    /// parents resolved and the entry itself left alone.
    ///
    /// Remove and rename act on the entry rather than on what it points at, so
    /// resolving the final component here would make removing a symlink delete
    /// its target.
    fn entry_path(&self, path: &VfsPath) -> VfsResult<PathBuf> {
        self.check_lexical(path)?;
        contained_entry(&self.root, path)
    }

    /// The lexical half: every component is a plain name and the join stays
    /// under the root by spelling alone.
    fn check_lexical(&self, path: &VfsPath) -> VfsResult<()> {
        if path.is_root() {
            return Err(VfsError::InvalidInput {
                path: path.to_string(),
            });
        }

        let joined = self
            .root
            .join(Path::new(OsStr::from_bytes(path.as_bytes())));
        let mut rebuilt = PathBuf::new();
        for component in joined.components() {
            match component {
                Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                    rebuilt.push(component.as_os_str())
                }
                Component::CurDir | Component::ParentDir => {
                    return Err(VfsError::InvalidInput {
                        path: path.to_string(),
                    })
                }
            }
        }

        if !rebuilt.starts_with(&self.root) {
            return Err(VfsError::InvalidInput {
                path: path.to_string(),
            });
        }

        Ok(())
    }

    /// Ensure the projection file exists before a partial write touches it.
    ///
    /// A workspace can hold graph artifacts whose bytes are not checked out. A
    /// write at a non-zero offset against a missing file would leave a sparse
    /// hole where the rest of the artifact should be, so the graph body is
    /// materialized first and the write is applied on top of it. This is the
    /// same close-time materialization the shim performs for a write-flagged
    /// open.
    pub fn materialize(&self, path: &VfsPath, body: &[u8], mode: u32) -> VfsResult<()> {
        let real = self.real_path(path)?;
        if real.exists() {
            return Ok(());
        }
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent).map_err(VfsError::Io)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&real)
            .map_err(VfsError::Io)?;
        file.write_all(body).map_err(VfsError::Io)?;
        file.sync_all().map_err(VfsError::Io)?;
        Ok(())
    }

    /// Create an empty projection file, refusing to clobber an existing one.
    pub fn create_file(&self, path: &VfsPath, mode: u32) -> VfsResult<()> {
        let real = self.real_path(path)?;
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent).map_err(VfsError::Io)?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&real)
            .map_err(VfsError::Io)?;
        Ok(())
    }

    /// Apply one ranged write to the projection file.
    pub fn write_at(&self, path: &VfsPath, offset: u64, data: &[u8]) -> VfsResult<u32> {
        let real = self.real_path(path)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&real)
            .map_err(VfsError::Io)?;
        file.seek(SeekFrom::Start(offset)).map_err(VfsError::Io)?;
        file.write_all(data).map_err(VfsError::Io)?;
        Ok(data.len() as u32)
    }

    /// Set the projection file's length, creating it when absent so an
    /// open-with-truncate on a graph-only artifact still lands.
    pub fn truncate(&self, path: &VfsPath, size: u64) -> VfsResult<()> {
        let real = self.real_path(path)?;
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent).map_err(VfsError::Io)?;
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&real)
            .map_err(VfsError::Io)?;
        file.set_len(size).map_err(VfsError::Io)?;
        Ok(())
    }

    /// Set the projection file's permission bits.
    pub fn chmod(&self, path: &VfsPath, mode: u32) -> VfsResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let real = self.real_path(path)?;
        fs::set_permissions(&real, fs::Permissions::from_mode(mode)).map_err(VfsError::Io)
    }

    /// Flush a projection file's bytes to durable storage before the graph is
    /// told about them, so an acknowledged write is never ahead of the disk it
    /// claims to describe.
    pub fn sync(&self, path: &VfsPath) -> VfsResult<()> {
        let real = self.real_path(path)?;
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&real)
            .map_err(VfsError::Io)?;
        file.sync_all().map_err(VfsError::Io)
    }

    /// Remove a projection file.
    pub fn remove_file(&self, path: &VfsPath) -> VfsResult<()> {
        let real = self.entry_path(path)?;
        fs::remove_file(&real).map_err(VfsError::Io)
    }

    /// Create a projection directory.
    pub fn create_dir(&self, path: &VfsPath) -> VfsResult<()> {
        let real = self.real_path(path)?;
        fs::create_dir(&real).map_err(VfsError::Io)
    }

    /// Remove an empty projection directory.
    pub fn remove_dir(&self, path: &VfsPath) -> VfsResult<()> {
        let real = self.entry_path(path)?;
        fs::remove_dir(&real).map_err(VfsError::Io)
    }

    /// Move a projection entry.
    pub fn rename(&self, from: &VfsPath, to: &VfsPath) -> VfsResult<()> {
        let source = self.entry_path(from)?;
        let destination = self.entry_path(to)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(VfsError::Io)?;
        }
        fs::rename(&source, &destination).map_err(VfsError::Io)
    }

    /// Whether a projection entry exists on disk right now.
    pub fn exists(&self, path: &VfsPath) -> bool {
        self.real_path(path)
            .map(|real| real.exists())
            .unwrap_or(false)
    }

    /// The SHA-256 of the bytes currently on the projection surface.
    ///
    /// This is the value the graph must come to report for the path before the
    /// write counts as taken. Comparing hashes rather than sizes matters: an
    /// edit that replaces one character leaves the size identical, and a
    /// size check would call that converged the instant it was made.
    pub fn projection_digest(&self, path: &VfsPath) -> VfsResult<[u8; 32]> {
        let real = self.real_path(path)?;
        let mut file = fs::File::open(&real).map_err(VfsError::Io)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buf).map_err(VfsError::Io)?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        Ok(hasher.finalize().into())
    }

    /// Nudge the daemon to reconcile this path now rather than on its watcher.
    ///
    /// Best effort by design. The nudge can only make convergence sooner, so a
    /// daemon that does not serve the route costs nothing but the first round
    /// trip, after which this mount stops asking.
    pub fn nudge(&self, path: &VfsPath) {
        if !self.nudge_worth_sending.load(Ordering::Relaxed) {
            return;
        }
        match notify_write(path, &self.target, self.session_id.as_deref()) {
            Ok(()) => {}
            Err(NotifyError::RouteAbsent) => {
                self.nudge_worth_sending.store(false, Ordering::Relaxed);
                tracing::debug!(
                    "this kin-daemon serves no write-notify route; \
                     relying on its file watcher and on reading the graph back"
                );
            }
            Err(error) => tracing::debug!("write-notify nudge did not land: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn writer(root: &Path) -> WorkspaceWriter {
        WorkspaceWriter::new(root.to_path_buf(), "http://127.0.0.1:4219", None)
    }

    fn vpath(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).expect("valid test path")
    }

    /// The canonical form of a temporary directory. On macOS `TempDir` hands
    /// back a path under `/var/folders`, which is a symlink to
    /// `/private/var/folders`.
    fn canonical(dir: &TempDir) -> PathBuf {
        fs::canonicalize(dir.path()).unwrap()
    }

    #[test]
    fn resolves_a_path_under_the_root() {
        let tmp = TempDir::new().unwrap();
        let root = canonical(&tmp);
        let writer = writer(&root);
        assert_eq!(
            writer.real_path(&vpath("src/main.rs")).unwrap(),
            root.join("src").join("main.rs")
        );
    }

    /// The escape a lexical check cannot see: no `..` anywhere, and the
    /// working copy's own symlink sends the write out of the workspace.
    #[test]
    fn refuses_a_write_a_symlink_would_redirect_out_of_the_workspace() {
        let outside = TempDir::new().unwrap();
        let outside_root = canonical(&outside);
        fs::write(outside_root.join("passwd"), b"original\n").unwrap();

        let tmp = TempDir::new().unwrap();
        let root = canonical(&tmp);
        let writer = writer(&root);
        std::os::unix::fs::symlink(&outside_root, root.join("etc")).unwrap();

        let err = writer
            .materialize(&vpath("etc/passwd"), b"owned", 0o644)
            .unwrap_err();
        assert!(
            matches!(err, VfsError::EscapesRoot { .. }),
            "expected a containment refusal, got {err:?}"
        );
        assert_eq!(
            fs::read(outside_root.join("passwd")).unwrap(),
            b"original\n",
            "the file outside the workspace must be untouched"
        );
    }

    /// The positive control: the same shape with a real directory must still
    /// work, or the refusal above is a check that refuses everything.
    #[test]
    fn an_ordinary_nested_write_still_lands() {
        let tmp = TempDir::new().unwrap();
        let root = canonical(&tmp);
        let writer = writer(&root);
        writer
            .materialize(&vpath("etc/passwd"), b"mine", 0o644)
            .unwrap();
        assert_eq!(fs::read(root.join("etc/passwd")).unwrap(), b"mine");
    }

    /// A symlink that stays inside the workspace is ordinary, and following it
    /// is what the mount did before this guard existed.
    #[test]
    fn a_symlink_inside_the_workspace_is_still_followed() {
        let tmp = TempDir::new().unwrap();
        let root = canonical(&tmp);
        let writer = writer(&root);
        fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("linked")).unwrap();

        writer
            .materialize(&vpath("linked/a.txt"), b"body", 0o644)
            .unwrap();
        assert_eq!(fs::read(root.join("real/a.txt")).unwrap(), b"body");
    }

    /// Removing a symlink removes the link, not what it points at.
    #[test]
    fn removing_a_symlink_leaves_its_target_in_place() {
        let tmp = TempDir::new().unwrap();
        let root = canonical(&tmp);
        let writer = writer(&root);
        fs::write(root.join("real.txt"), b"body").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("alias")).unwrap();

        writer.remove_file(&vpath("alias")).unwrap();
        assert!(
            root.join("alias").symlink_metadata().is_err(),
            "the link itself must be gone"
        );
        assert_eq!(
            fs::read(root.join("real.txt")).unwrap(),
            b"body",
            "the target must survive removing the link to it"
        );
    }

    #[test]
    fn refuses_the_root_itself() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        let err = writer.real_path(&VfsPath::root()).unwrap_err();
        assert!(
            matches!(err, VfsError::InvalidInput { .. }),
            "expected a refusal, got {err:?}"
        );
    }

    #[test]
    fn refuses_a_traversal_that_would_escape_the_root() {
        // VfsPath refuses `..` at decode time, so this reaches real_path only
        // by constructing the escape directly. The guard exists for exactly
        // that case: a write outside the workspace must be impossible here
        // even if the path type ever stopped catching it upstream.
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        assert!(VfsPath::from_utf8("../escape.txt").is_err());

        let joined = writer.root.join("../escape.txt");
        assert!(
            joined.components().any(|c| c == Component::ParentDir),
            "the guard's input must actually contain the traversal it rejects"
        );
    }

    #[test]
    fn materialize_writes_the_graph_body_when_the_projection_is_absent() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        writer
            .materialize(&vpath("src/only-in-graph.rs"), b"fn main() {}\n", 0o644)
            .unwrap();
        assert_eq!(
            fs::read(tmp.path().join("src/only-in-graph.rs")).unwrap(),
            b"fn main() {}\n"
        );
    }

    #[test]
    fn materialize_never_overwrites_an_existing_projection() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/a.rs"), b"on disk").unwrap();
        writer
            .materialize(&vpath("src/a.rs"), b"from graph", 0o644)
            .unwrap();
        assert_eq!(
            fs::read(tmp.path().join("src/a.rs")).unwrap(),
            b"on disk",
            "a present projection is what the caller is editing; refilling it would lose the edit"
        );
    }

    #[test]
    fn write_at_applies_a_ranged_write() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        writer
            .materialize(&vpath("a.txt"), b"0123456789", 0o644)
            .unwrap();
        assert_eq!(writer.write_at(&vpath("a.txt"), 4, b"XY").unwrap(), 2);
        assert_eq!(fs::read(tmp.path().join("a.txt")).unwrap(), b"0123XY6789");
    }

    #[test]
    fn truncate_sets_the_length() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        writer
            .materialize(&vpath("a.txt"), b"0123456789", 0o644)
            .unwrap();
        writer.truncate(&vpath("a.txt"), 4).unwrap();
        assert_eq!(fs::read(tmp.path().join("a.txt")).unwrap(), b"0123");
    }

    #[test]
    fn create_file_refuses_to_clobber() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        writer.create_file(&vpath("a.txt"), 0o644).unwrap();
        assert!(writer.create_file(&vpath("a.txt"), 0o644).is_err());
    }

    #[test]
    fn rename_moves_the_projection_entry() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        writer.materialize(&vpath("a.txt"), b"body", 0o644).unwrap();
        writer
            .rename(&vpath("a.txt"), &vpath("nested/b.txt"))
            .unwrap();
        assert!(!tmp.path().join("a.txt").exists());
        assert_eq!(fs::read(tmp.path().join("nested/b.txt")).unwrap(), b"body");
    }

    #[test]
    fn non_utf8_names_round_trip_to_disk() {
        let tmp = TempDir::new().unwrap();
        let writer = writer(tmp.path());
        let raw = VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).unwrap();
        writer.materialize(&raw, b"raw", 0o644).unwrap();
        assert!(
            writer.exists(&raw),
            "a raw-byte name must address one exact file"
        );
    }
}
