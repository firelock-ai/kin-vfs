// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph-authoritative write admission for projection surfaces.
//!
//! [`KinDaemonWriter`] is the write half of the projection: a mount stages a
//! write into the served repository's working copy, and an admission folds
//! every staged path into graph truth through the same daemon seam `kin commit`
//! uses (`POST /commands/commit`, whose `forced_filesystem_admission` phase
//! derives the exact tree from the working copy and publishes one
//! repository-authority transaction).
//!
//! Why the working copy is the staging medium rather than an invention of this
//! crate: it is the input the admission phase already reads, so a staged write
//! and a hand-edited file are admitted by one code path in the daemon, and the
//! change a mount produces is byte-identical to the change `kin commit` would
//! have produced for the same bytes. A second staging area would need its own
//! admission path, and two admission paths is two authority models.
//!
//! This is an ingestion boundary, not file-search authority. The staged set is
//! explicit: [`ContentWriter::staged`] answers only for paths this writer wrote,
//! so a graph miss is never repaired from disk. A staged stat deliberately
//! carries no `content_hash` — nothing addresses those bytes by hash until the
//! graph admits them, and a hash here would invite exactly that.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use kin_vfs_core::writer::{Admission, ContentWriter, Staged, WriteHealth};
use kin_vfs_core::{DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat};

use crate::auth::DaemonAuth;
use crate::endpoint::DaemonEndpoint;

/// The daemon route that admits a working copy into graph truth.
///
/// Not in [`crate::routes`] with the read routes on purpose: those are pinned
/// by the provider contract test as the complete read surface, and adding a
/// write route to that set would make the contract assert something it does not
/// check. This constant is pinned by [`tests::commit_route_is_pinned`] instead.
const COMMIT_ROUTE: &str = "/commands/commit";

/// Default quiescence before staged writes are admitted, in milliseconds.
///
/// One editor save is many NFS `WRITE` calls, and admitting per call would mint
/// a change per 64 KiB chunk. The window closes on the last write, not the
/// first, so a slow save is one change rather than several.
pub const DEFAULT_ADMIT_DEBOUNCE_MS: u64 = 1_200;

/// Environment override for the debounce, in milliseconds.
pub const ADMIT_DEBOUNCE_ENV: &str = "KIN_VFS_ADMIT_DEBOUNCE_MS";

/// Read the configured admission debounce.
pub fn configured_debounce() -> Duration {
    let millis = std::env::var(ADMIT_DEBOUNCE_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_ADMIT_DEBOUNCE_MS);
    Duration::from_millis(millis)
}

/// Why an author could not be resolved, phrased as the remedy.
pub const UNRESOLVED_AUTHOR: &str = "cannot attribute a mount write: set `user.name` and `user.email` in the served repository's git config, or set KIN_AUTHOR to \"Name <email>\"";

/// Resolve the author a mount's changes are attributed to.
///
/// Precedence matches what the Kin CLI resolves for a commit: an explicit
/// override first, then the served repository's merged git identity. A
/// synthesized `user@host.local` address is refused rather than adopted,
/// because git invents one when no identity is configured and a commit carrying
/// it looks authored right up until it reaches a public branch.
pub fn resolve_author(repo_root: &Path) -> Option<String> {
    if let Some(explicit) = std::env::var("KIN_AUTHOR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some(explicit);
    }
    let name = git_config_value(repo_root, "user.name")?;
    let email = git_config_value(repo_root, "user.email")?;
    if email.to_ascii_lowercase().ends_with(".local") {
        warn!(%email, "refusing a git-synthesized author address");
        return None;
    }
    Some(format!("{name} <{email}>"))
}

fn git_config_value(repo_root: &Path, key: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["config", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// The host-name form of a byte-exact repository path.
///
/// Unix path names are byte strings and are carried through exactly. Windows
/// path names are UTF-16 and cannot hold every byte string, so a name it cannot
/// represent is refused rather than coerced: coercing would stage one path's
/// bytes under a different path's name, and the admission would then publish
/// the wrong artifact.
#[cfg(unix)]
fn host_component(path: &VfsPath) -> VfsResult<std::ffi::OsString> {
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::OsStr::from_bytes(path.as_bytes()).to_os_string())
}

#[cfg(not(unix))]
fn host_component(path: &VfsPath) -> VfsResult<std::ffi::OsString> {
    match std::str::from_utf8(path.as_bytes()) {
        Ok(text) => Ok(std::ffi::OsString::from(text)),
        Err(_) => Err(VfsError::InvalidInput {
            path: path.to_string(),
        }),
    }
}

/// Staging state: what this writer owes the graph, and how the last attempt went.
#[derive(Default)]
struct Staging {
    entries: BTreeMap<VfsPath, Staged>,
    last_touch: Option<Instant>,
    last_admission: Option<Admission>,
    last_error: Option<String>,
}

/// Stages writes into a served repository's working copy and admits them into
/// graph truth through the kin daemon.
pub struct KinDaemonWriter {
    repo_root: PathBuf,
    author: String,
    endpoint: DaemonEndpoint,
    auth: DaemonAuth,
    /// Built on first use for the same reason the read provider's is: a
    /// blocking client constructed on a tokio worker panics, and this writer
    /// is built from the export's async handler.
    client: std::sync::OnceLock<reqwest::blocking::Client>,
    staging: Mutex<Staging>,
}

/// What the daemon answers a successful admission with.
#[derive(Debug, serde::Deserialize)]
struct CommitReply {
    change_id: String,
    branch: String,
    #[serde(default)]
    file_count: usize,
}

impl KinDaemonWriter {
    /// A writer for `repo_root`, admitting through the daemon at `base_url`.
    ///
    /// Fails when no author can be resolved. A write that cannot be attributed
    /// must not be accepted at all, rather than accepted and then refused at
    /// admission time with the bytes already on disk.
    pub fn new(
        base_url: impl Into<String>,
        repo_root: PathBuf,
        auth_token: Option<String>,
    ) -> VfsResult<Self> {
        let author = resolve_author(&repo_root)
            .ok_or_else(|| VfsError::Provider(UNRESOLVED_AUTHOR.to_string()))?;
        Ok(Self {
            endpoint: DaemonEndpoint::new(base_url.into(), Some(repo_root.clone())),
            auth: DaemonAuth::new(auth_token, Some(repo_root.clone())),
            client: std::sync::OnceLock::new(),
            repo_root,
            author,
            staging: Mutex::new(Staging::default()),
        })
    }

    /// The HTTP client, built on first use.
    fn client(&self) -> &reqwest::blocking::Client {
        self.client.get_or_init(reqwest::blocking::Client::new)
    }

    /// The author this writer attributes its changes to.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// The served repository root.
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// The host path a workspace-relative VFS path stages at.
    ///
    /// [`VfsPath`] is validated on construction to be relative with no `.` or
    /// `..` components, so this join cannot leave the repository. That
    /// invariant is the containment guarantee; there is no second check here
    /// because a second check would suggest the first is optional.
    fn host_path(&self, path: &VfsPath) -> VfsResult<PathBuf> {
        Ok(self.repo_root.join(host_component(path)?))
    }

    /// Stat a staged host path.
    ///
    /// No `content_hash`: the bytes are not graph truth yet, and nothing may
    /// address them by hash until they are.
    fn stage_stat(&self, host: &Path) -> VfsResult<VirtualStat> {
        let meta = std::fs::symlink_metadata(host)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|delta| delta.as_secs())
            .unwrap_or(0);
        let file_type = meta.file_type();
        let mode = host_mode(&meta);
        Ok(VirtualStat {
            size: meta.len(),
            is_file: file_type.is_file(),
            is_dir: file_type.is_dir(),
            is_symlink: file_type.is_symlink(),
            mode,
            mtime,
            ctime: mtime,
            nlink: 1,
            content_hash: None,
        })
    }

    /// Record `path` as staged with the disposition its host state now implies.
    fn mark(&self, path: &VfsPath, staged: Staged) {
        let mut guard = self.staging.lock();
        guard.entries.insert(path.clone(), staged);
        guard.last_touch = Some(Instant::now());
        guard.last_error = None;
    }

    /// Restat `path` on the host and record it as present.
    fn mark_present(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        let stat = self.stage_stat(&self.host_path(path)?)?;
        self.mark(path, Staged::Present(stat.clone()));
        Ok(stat)
    }

    /// The admission request URL, re-resolved from the live advertisement.
    ///
    /// Deliberately not the cached base URL. A cached port is not authority:
    /// after the intended daemon exits the OS may hand that port to a different
    /// repository's daemon, and an admission is a commit. Publishing this
    /// repository's working copy into another repository's graph is the worst
    /// outcome available on this path, so a missing advertisement fails closed
    /// here exactly as it does on the read path.
    fn commit_url(&self) -> Result<String, String> {
        self.endpoint.preflight_scoped_request()?;
        let base = self.endpoint.prepared_base_url()?;
        Ok(format!("{}{COMMIT_ROUTE}", base.trim_end_matches('/')))
    }

    /// The message a mount's admission carries.
    fn admission_message(paths: &[VfsPath]) -> String {
        match paths {
            [] => "Admit a mount write".to_string(),
            [one] => format!("Admit {one} from the Kin mount"),
            many => format!("Admit {} paths from the Kin mount", many.len()),
        }
    }
}

/// The Unix mode a staged host entry projects as.
///
/// Windows has no Unix mode, and inventing one from its attribute bits would
/// report a permission the graph never recorded. The projection's own defaults
/// are used there instead, which is what a graph-owned tree entry carries when
/// nothing more specific is known.
#[cfg(unix)]
fn host_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn host_mode(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() {
        0o755
    } else {
        0o644
    }
}

/// A symlink target as its exact stored bytes.
#[cfg(unix)]
fn link_target_bytes(target: PathBuf) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt;
    target.into_os_string().into_vec()
}

#[cfg(not(unix))]
fn link_target_bytes(target: PathBuf) -> Vec<u8> {
    target.to_string_lossy().into_owned().into_bytes()
}

impl ContentWriter for KinDaemonWriter {
    fn write_at(&self, path: &VfsPath, offset: u64, data: &[u8]) -> VfsResult<VirtualStat> {
        let host = self.host_path(path)?;
        if let Some(parent) = host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&host)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        debug!(path = %path, offset, len = data.len(), "staged a mount write");
        self.mark_present(path)
    }

    fn create_file(&self, path: &VfsPath, exclusive: bool) -> VfsResult<VirtualStat> {
        let host = self.host_path(path)?;
        if let Some(parent) = host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if exclusive {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        options.open(&host)?;
        self.mark_present(path)
    }

    fn set_len(&self, path: &VfsPath, size: u64) -> VfsResult<VirtualStat> {
        let host = self.host_path(path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&host)?;
        file.set_len(size)?;
        file.sync_all()?;
        drop(file);
        self.mark_present(path)
    }

    fn create_dir(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        std::fs::create_dir_all(self.host_path(path)?)?;
        self.mark_present(path)
    }

    fn remove(&self, path: &VfsPath) -> VfsResult<()> {
        let host = self.host_path(path)?;
        let meta = std::fs::symlink_metadata(&host)?;
        if meta.is_dir() {
            std::fs::remove_dir(&host)?;
        } else {
            std::fs::remove_file(&host)?;
        }
        self.mark(path, Staged::Removed);
        Ok(())
    }

    fn rename(&self, from: &VfsPath, to: &VfsPath) -> VfsResult<()> {
        let to_host = self.host_path(to)?;
        if let Some(parent) = to_host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(self.host_path(from)?, &to_host)?;
        self.mark(from, Staged::Removed);
        self.mark_present(to)?;
        Ok(())
    }

    fn staged(&self, path: &VfsPath) -> Option<Staged> {
        self.staging.lock().entries.get(path).cloned()
    }

    fn staged_children(&self, dir: &VfsPath) -> (Vec<DirEntry>, Vec<VfsName>) {
        let guard = self.staging.lock();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for (path, staged) in guard.entries.iter() {
            // Only direct children: `strip_dir_prefix` yields the remainder
            // after `dir/`, and a remainder carrying a separator is a deeper
            // descendant whose own parent listing owns it.
            let Some(remainder) = dir.strip_dir_prefix(path) else {
                continue;
            };
            if remainder.contains(&b'/') {
                continue;
            }
            let Ok(name) = VfsName::from_bytes(remainder.to_vec()) else {
                continue;
            };
            match staged {
                Staged::Present(stat) => added.push(DirEntry {
                    name,
                    file_type: if stat.is_dir {
                        FileType::Directory
                    } else if stat.is_symlink {
                        FileType::Symlink
                    } else {
                        FileType::File
                    },
                }),
                Staged::Removed => removed.push(name),
            }
        }
        (added, removed)
    }

    fn read_staged(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        // Membership first. Reading a path this writer did not stage would make
        // the working copy an answer authority for graph misses, which is the
        // one thing this boundary must never become.
        if !matches!(self.staged(path), Some(Staged::Present(_))) {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }
        let bytes = std::fs::read(self.host_path(path)?)?;
        let start = offset.min(bytes.len() as u64) as usize;
        let end = offset.saturating_add(len).min(bytes.len() as u64) as usize;
        Ok(bytes[start..end].to_vec())
    }

    fn read_staged_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        if !matches!(self.staged(path), Some(Staged::Present(_))) {
            return Err(VfsError::NotFound {
                path: path.to_string(),
            });
        }
        let target = std::fs::read_link(self.host_path(path)?)?;
        Ok(link_target_bytes(target))
    }

    fn admit(&self) -> VfsResult<Option<Admission>> {
        let paths: Vec<VfsPath> = {
            let guard = self.staging.lock();
            guard.entries.keys().cloned().collect()
        };
        if paths.is_empty() {
            return Ok(None);
        }

        let message = Self::admission_message(&paths);
        let body = serde_json::json!({
            "operation_id": kin_model::OperationId::new(),
            "timestamp": kin_model::Timestamp::now(),
            "message": message,
            "author": kin_model::AuthorId::new(self.author.clone()),
        });
        let url = match self.commit_url() {
            Ok(url) => url,
            Err(reason) => return Err(self.record_failure(reason)),
        };
        let mut request = self.client().post(url).json(&body);
        if let Some(token) = self.auth.token() {
            request = request.bearer_auth(token);
        }

        let response = match request.send() {
            Ok(response) => response,
            Err(error) => return Err(self.record_failure(format!("admission transport: {error}"))),
        };
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().unwrap_or_default();
            return Err(self.record_failure(format!(
                "the graph refused the admission (HTTP {status}): {}",
                detail.trim()
            )));
        }
        let reply: CommitReply = match response.json() {
            Ok(reply) => reply,
            Err(error) => {
                return Err(self.record_failure(format!("decoding the admission reply: {error}")))
            }
        };

        let admission = Admission {
            change_id: reply.change_id,
            branch: reply.branch,
            file_count: reply.file_count,
            paths: paths.clone(),
        };
        info!(
            change_id = %admission.change_id,
            branch = %admission.branch,
            paths = paths.len(),
            "admitted mount writes into graph truth"
        );

        // Clear only what this admission carried. A write that landed while the
        // request was outstanding is still owed, and dropping the whole set
        // here would lose it silently.
        let mut guard = self.staging.lock();
        for path in &paths {
            guard.entries.remove(path);
        }
        guard.last_admission = Some(admission.clone());
        guard.last_error = None;
        if guard.entries.is_empty() {
            guard.last_touch = None;
        }
        Ok(Some(admission))
    }

    fn admission_due(&self, debounce: Duration) -> bool {
        let guard = self.staging.lock();
        if guard.entries.is_empty() {
            return false;
        }
        match guard.last_touch {
            Some(touched) => touched.elapsed() >= debounce,
            None => true,
        }
    }

    fn health(&self) -> WriteHealth {
        let guard = self.staging.lock();
        let paths: Vec<VfsPath> = guard.entries.keys().cloned().collect();
        match (&guard.last_error, paths.is_empty()) {
            (Some(reason), _) => WriteHealth::Degraded {
                paths,
                reason: reason.clone(),
            },
            (None, true) => WriteHealth::Settled {
                last: guard.last_admission.clone(),
            },
            (None, false) => WriteHealth::Pending { paths },
        }
    }
}

impl KinDaemonWriter {
    /// Record why an admission failed and hand the caller the same reason.
    ///
    /// The staged entries stay staged. A failed admission that cleared them
    /// would leave the mount reporting settled with the bytes on disk and
    /// nothing in the graph, which is exactly the state this boundary exists to
    /// make impossible.
    fn record_failure(&self, reason: String) -> VfsError {
        warn!(%reason, "admission failed; staged writes are still owed");
        self.staging.lock().last_error = Some(reason.clone());
        VfsError::Provider(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    /// A writer over a fresh repo, pointed at a port nothing listens on.
    ///
    /// Every test that admits here is testing the failure path deliberately:
    /// admission must fail loud and keep the writes owed. A test needing a
    /// successful admission needs a real daemon, which the proof script drives.
    fn writer(root: &std::path::Path) -> KinDaemonWriter {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["init", "-q"])
            .status()
            .unwrap();
        for (key, value) in [("user.name", "Probe"), ("user.email", "probe@example.com")] {
            std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["config", key, value])
                .status()
                .unwrap();
        }
        // Port 1 is reserved and nothing binds it, so an admission fails on
        // connect rather than on a stranger's response.
        KinDaemonWriter::new("http://127.0.0.1:1", root.to_path_buf(), None).unwrap()
    }

    /// The bug this guards is a hang, not a crash. `reqwest::blocking::Client::new`
    /// starts a runtime on a background thread and waits for it; doing that from
    /// a tokio worker panics with "Cannot drop a runtime in a context where
    /// blocking is not allowed". The panic kills only that handler, so an NFS
    /// client gets no reply and blocks in the kernel, which looks like a slow
    /// mount rather than a failure. Building the client on first use, inside
    /// `spawn_blocking`, is what keeps this constructible here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_writer_is_constructible_from_an_async_worker() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        // Touch the staging path too: construction alone would pass even if the
        // client were built eagerly somewhere else on this thread.
        writer.write_at(&path("a.rs"), 0, b"x").unwrap();
        assert!(matches!(
            writer.staged(&path("a.rs")),
            Some(Staged::Present(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_read_provider_is_constructible_from_an_async_worker() {
        let provider = crate::KinDaemonProvider::with_auth(
            "http://127.0.0.1:1",
            None,
            Some(std::path::PathBuf::from("/nonexistent")),
            None,
        );
        assert!(!provider.is_available());
    }

    #[test]
    fn the_commit_route_is_pinned() {
        assert_eq!(COMMIT_ROUTE, "/commands/commit");
    }

    #[test]
    fn a_write_lands_in_the_working_copy_and_is_staged() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        let stat = writer.write_at(&path("src/new.rs"), 0, b"hello").unwrap();

        assert_eq!(stat.size, 5);
        assert!(stat.is_file);
        assert_eq!(
            std::fs::read(dir.path().join("src/new.rs")).unwrap(),
            b"hello".to_vec()
        );
        assert!(matches!(
            writer.staged(&path("src/new.rs")),
            Some(Staged::Present(_))
        ));
    }

    /// A staged stat must not advertise a content hash: nothing addresses these
    /// bytes by hash until the graph admits them, and a hash here would invite
    /// a blob fetch for content the graph has never seen.
    #[test]
    fn a_staged_stat_carries_no_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        let stat = writer.write_at(&path("a.rs"), 0, b"x").unwrap();
        assert!(stat.content_hash.is_none());
    }

    #[test]
    fn a_write_at_an_offset_extends_rather_than_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        writer.write_at(&path("a.rs"), 0, b"0123456789").unwrap();
        writer.write_at(&path("a.rs"), 4, b"XY").unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("a.rs")).unwrap(),
            b"0123XY6789".to_vec()
        );
    }

    #[test]
    fn truncating_to_zero_leaves_an_empty_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        writer.write_at(&path("a.rs"), 0, b"content").unwrap();
        let stat = writer.set_len(&path("a.rs"), 0).unwrap();
        assert_eq!(stat.size, 0);
        assert!(std::fs::read(dir.path().join("a.rs")).unwrap().is_empty());
    }

    #[test]
    fn removing_a_file_stages_it_as_removed_and_takes_it_off_disk() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        std::fs::write(dir.path().join("gone.rs"), b"bye").unwrap();
        writer.remove(&path("gone.rs")).unwrap();
        assert_eq!(writer.staged(&path("gone.rs")), Some(Staged::Removed));
        assert!(!dir.path().join("gone.rs").exists());
    }

    #[test]
    fn a_rename_stages_the_old_name_removed_and_the_new_one_present() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        writer.write_at(&path("from.rs"), 0, b"body").unwrap();
        writer.rename(&path("from.rs"), &path("to.rs")).unwrap();
        assert_eq!(writer.staged(&path("from.rs")), Some(Staged::Removed));
        assert!(matches!(
            writer.staged(&path("to.rs")),
            Some(Staged::Present(_))
        ));
        assert_eq!(
            std::fs::read(dir.path().join("to.rs")).unwrap(),
            b"body".to_vec()
        );
    }

    /// The membership guard, stated as a test: a path this writer never wrote
    /// is not readable from the staging medium even when the bytes are sitting
    /// right there on disk. Delete the `staged` check in `read_staged` and this
    /// fails with the file's contents.
    #[test]
    fn an_unstaged_path_is_not_readable_even_when_the_bytes_are_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        std::fs::write(dir.path().join("untouched.rs"), b"on disk").unwrap();
        let result = writer.read_staged(&path("untouched.rs"), 0, 64);
        assert!(
            matches!(result, Err(VfsError::NotFound { .. })),
            "expected NotFound, got {result:?}"
        );
    }

    #[test]
    fn staged_children_reports_direct_children_only() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        writer.write_at(&path("src/a.rs"), 0, b"a").unwrap();
        writer.write_at(&path("src/deep/b.rs"), 0, b"b").unwrap();
        writer.write_at(&path("src/gone.rs"), 0, b"g").unwrap();
        writer.remove(&path("src/gone.rs")).unwrap();

        let (added, removed) = writer.staged_children(&path("src"));
        let added: Vec<String> = added.into_iter().map(|e| e.name.to_string()).collect();
        let removed: Vec<String> = removed.into_iter().map(|n| n.to_string()).collect();
        assert_eq!(added, vec!["a.rs".to_string()]);
        assert_eq!(removed, vec!["gone.rs".to_string()]);
    }

    #[test]
    fn admitting_nothing_is_a_no_op_rather_than_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        assert_eq!(writer.admit().unwrap(), None);
        assert_eq!(writer.health().label(), "settled");
    }

    /// The rule that makes a mount write safe to trust: an admission that fails
    /// leaves the paths owed and says why, so a status probe can never report
    /// settled while the bytes are on disk and absent from the graph.
    #[test]
    fn a_failed_admission_keeps_the_paths_owed_and_reports_why() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        writer.write_at(&path("a.rs"), 0, b"x").unwrap();

        // The assertion is that the failure is carried, not which failure
        // fired. This writer points at a port nothing serves and its repo
        // carries no manifest, so either the local preflight or the transport
        // can be first, and pinning one would make the test a hostage to
        // which check the endpoint runs earlier.
        let error = writer.admit().unwrap_err();
        let reported = error.to_string();
        assert!(!reported.is_empty());
        match writer.health() {
            WriteHealth::Degraded { paths, reason } => {
                assert_eq!(paths, vec![path("a.rs")]);
                assert!(
                    reported.contains(&reason),
                    "the caller and the status probe must be told the same thing:\n  caller: {reported}\n  probe:  {reason}"
                );
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
        assert!(matches!(
            writer.staged(&path("a.rs")),
            Some(Staged::Present(_))
        ));
    }

    #[test]
    fn a_pending_write_is_due_only_after_the_debounce_window_closes() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        assert!(!writer.admission_due(Duration::from_millis(0)));

        writer.write_at(&path("a.rs"), 0, b"x").unwrap();
        assert!(!writer.admission_due(Duration::from_secs(3_600)));
        assert!(writer.admission_due(Duration::from_millis(0)));
        assert_eq!(writer.health().label(), "pending");
    }

    #[test]
    fn a_path_stages_inside_the_repository_root() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        let host = writer.host_path(&path("src/main.rs")).unwrap();
        assert_eq!(host, dir.path().join("src/main.rs"));
        assert!(host.starts_with(dir.path()));
        // `..` never reaches here: VfsPath refuses to hold one at all.
        assert!(VfsPath::from_utf8("../escape").is_err());
    }

    #[test]
    fn an_author_is_refused_when_git_would_synthesize_one() {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .status()
            .unwrap();
        for (key, value) in [("user.name", "Nobody"), ("user.email", "nobody@Mac.local")] {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(["config", key, value])
                .status()
                .unwrap();
        }
        assert_eq!(resolve_author(dir.path()), None);
        let refused = KinDaemonWriter::new("http://127.0.0.1:1", dir.path().to_path_buf(), None);
        assert!(refused.is_err());
    }

    #[test]
    fn an_admission_message_names_what_it_carries() {
        assert_eq!(
            KinDaemonWriter::admission_message(&[path("src/main.rs")]),
            "Admit src/main.rs from the Kin mount"
        );
        assert_eq!(
            KinDaemonWriter::admission_message(&[path("a.rs"), path("b.rs")]),
            "Admit 2 paths from the Kin mount"
        );
    }

    #[test]
    fn the_debounce_is_configurable_and_defaults() {
        // Read the default without touching process-global env: an override
        // set here would race every other test in this binary.
        assert_eq!(
            DEFAULT_ADMIT_DEBOUNCE_MS, 1_200,
            "the default debounce is part of the mount's felt behavior"
        );
        assert_eq!(ADMIT_DEBOUNCE_ENV, "KIN_VFS_ADMIT_DEBOUNCE_MS");
        assert!(configured_debounce() >= Duration::from_millis(1));
    }
}
