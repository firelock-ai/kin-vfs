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
use std::sync::Arc;
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

/// Staging state: what this writer owes the graph, and how the last attempt went.
#[derive(Default)]
struct Staging {
    entries: BTreeMap<VfsPath, StagedEntry>,
    last_touch: Option<Instant>,
    last_admission: Option<Admission>,
    last_error: Option<String>,
}

/// One staged mutation and its unique identity.
///
/// The identity is deliberately not derived from file metadata. Two writes can
/// have the same size, mode, and one-second mtime while carrying different
/// bytes. Pointer identity cannot wrap like a numeric generation counter, so a
/// successful older admission can remove only the exact mutation it snapped.
struct StagedEntry {
    staged: Staged,
    revision: Arc<()>,
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

    /// The host path a write to `path` lands on, with every component resolved
    /// and the final one followed.
    ///
    /// [`VfsPath`] is validated on construction to be relative with no `.` or
    /// `..` component, and that is the lexical half of containment only. A
    /// symlink already in the working copy redirects a lexically clean path
    /// wherever it points, so the destination is resolved here and refused when
    /// it leaves the repository root.
    fn content_path(&self, path: &VfsPath) -> VfsResult<PathBuf> {
        kin_vfs_core::contained_target(&self.repo_root, path)
    }

    /// The host path of the directory *entry* `path` names, with its parents
    /// resolved and the entry itself left alone.
    ///
    /// Remove, rename, `readlink` and the staged stat all act on the entry
    /// rather than on what it points at. Resolving the final component here
    /// would make removing a symlink delete its target.
    fn entry_path(&self, path: &VfsPath) -> VfsResult<PathBuf> {
        kin_vfs_core::contained_entry(&self.repo_root, path)
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
        guard.entries.insert(
            path.clone(),
            StagedEntry {
                staged,
                revision: Arc::new(()),
            },
        );
        guard.last_touch = Some(Instant::now());
        guard.last_error = None;
    }

    /// Restat `path` on the host and record it as present.
    fn mark_present(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        let stat = self.stage_stat(&self.entry_path(path)?)?;
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

    /// The admission request body.
    ///
    /// `attributed` carries the resolved author. It is dropped only on the one
    /// retry below, for a daemon that does not know the field.
    fn commit_body(&self, message: &str, attributed: bool) -> serde_json::Value {
        let mut body = serde_json::json!({
            "operation_id": kin_model::OperationId::new(),
            "timestamp": kin_model::Timestamp::now(),
            "message": message,
        });
        if attributed {
            body["author"] = serde_json::json!(kin_model::AuthorId::new(self.author.clone()));
        }
        body
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

/// Whether this refusal is a daemon rejecting the `author` field itself.
///
/// Narrow on purpose. The daemon answers 422 for any body it cannot
/// deserialize, so a broad match would retry an unattributed commit after an
/// unrelated schema error and report the second, more confusing failure.
fn refuses_the_author_field(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::UNPROCESSABLE_ENTITY && body.contains("unknown field `author`")
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
        let host = self.content_path(path)?;
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
        let host = self.content_path(path)?;
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
        let host = self.content_path(path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&host)?;
        file.set_len(size)?;
        file.sync_all()?;
        drop(file);
        self.mark_present(path)
    }

    fn create_dir(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        std::fs::create_dir_all(self.content_path(path)?)?;
        self.mark_present(path)
    }

    fn remove(&self, path: &VfsPath) -> VfsResult<()> {
        let host = self.entry_path(path)?;
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
        let to_host = self.entry_path(to)?;
        if let Some(parent) = to_host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(self.entry_path(from)?, &to_host)?;
        self.mark(from, Staged::Removed);
        self.mark_present(to)?;
        Ok(())
    }

    fn staged(&self, path: &VfsPath) -> Option<Staged> {
        self.staging
            .lock()
            .entries
            .get(path)
            .map(|entry| entry.staged.clone())
    }

    fn staged_children(&self, dir: &VfsPath) -> (Vec<DirEntry>, Vec<VfsName>) {
        let guard = self.staging.lock();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for (path, entry) in guard.entries.iter() {
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
            match &entry.staged {
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
        let bytes = std::fs::read(self.content_path(path)?)?;
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
        let target = std::fs::read_link(self.entry_path(path)?)?;
        Ok(link_target_bytes(target))
    }

    fn admit(&self) -> VfsResult<Option<Admission>> {
        let pending: Vec<(VfsPath, Arc<()>)> = {
            let guard = self.staging.lock();
            guard
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), Arc::clone(&entry.revision)))
                .collect()
        };
        let paths: Vec<VfsPath> = pending.iter().map(|(path, _)| path.clone()).collect();
        if paths.is_empty() {
            return Ok(None);
        }

        let message = Self::admission_message(&paths);
        let url = match self.commit_url() {
            Ok(url) => url,
            Err(reason) => return Err(self.record_failure(reason)),
        };

        // One retry, and only for one thing: a daemon older than kin#876 does
        // not know the `author` field and rejects the whole body for it. That
        // daemon resolves the author itself, which is what `kin commit` against
        // it does too, so dropping the field reproduces its own behavior rather
        // than inventing a second one. The retry is keyed on the daemon naming
        // that exact field, so a 422 about anything else still fails.
        let mut attributed = true;
        let (status, body_text) = loop {
            let mut request = self
                .client()
                .post(&url)
                .json(&self.commit_body(&message, attributed));
            if let Some(token) = self.auth.token() {
                request = request.bearer_auth(token);
            }
            let response = match request.send() {
                Ok(response) => response,
                Err(error) => {
                    return Err(self.record_failure(format!("admission transport: {error}")))
                }
            };
            let status = response.status();
            let text = response.text().unwrap_or_default();
            if attributed && refuses_the_author_field(status, &text) {
                warn!(
                    "this daemon predates commit attribution; admitting without an explicit author"
                );
                attributed = false;
                continue;
            }
            break (status, text);
        };

        if !status.is_success() {
            return Err(self.record_failure(format!(
                "the graph refused the admission (HTTP {status}): {}",
                body_text.trim()
            )));
        }
        let reply: CommitReply = match serde_json::from_str(&body_text) {
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

        // Clear only the exact mutation snapshot this admission carried. A
        // same-path write that landed while the request was outstanding has a
        // different revision and remains owed even though its map key matches.
        let mut guard = self.staging.lock();
        for (path, revision) in &pending {
            let unchanged = guard
                .entries
                .get(path)
                .is_some_and(|entry| Arc::ptr_eq(&entry.revision, revision));
            if unchanged {
                guard.entries.remove(path);
            }
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

    fn initialize_repo(root: &std::path::Path) {
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
    }

    /// A writer over a fresh repo, pointed at a port nothing listens on.
    ///
    /// Every test that admits here is testing the failure path deliberately:
    /// admission must fail loud and keep the writes owed. A test needing a
    /// successful admission needs a real daemon, which the proof script drives.
    fn writer(root: &std::path::Path) -> KinDaemonWriter {
        initialize_repo(root);
        // Port 1 is reserved and nothing binds it, so an admission fails on
        // connect rather than on a stranger's response.
        KinDaemonWriter::new("http://127.0.0.1:1", root.to_path_buf(), None).unwrap()
    }

    fn successful_writer(root: &std::path::Path, port: u16) -> KinDaemonWriter {
        initialize_repo(root);
        let identity_path = root.join(kin_vfs_core::pathmap::REPOSITORY_IDENTITY_MARKER);
        std::fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
        std::fs::write(
            identity_path,
            br#"{"repo_id":"race-probe","workspace_id":"race-workspace"}"#,
        )
        .unwrap();
        std::fs::write(root.join(".kin/daemon.port"), port.to_string()).unwrap();
        KinDaemonWriter::new(format!("http://127.0.0.1:{port}"), root.to_path_buf(), None).unwrap()
    }

    fn read_http_request(stream: &mut std::net::TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = std::io::Read::read(stream, &mut chunk).unwrap();
            if count == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..count]);
            let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                return;
            }
        }
    }

    fn write_commit_reply(stream: &mut std::net::TcpStream, change_id: &str) {
        let body = format!(r#"{{"change_id":"{change_id}","branch":"main","file_count":1}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        std::io::Write::write_all(stream, response.as_bytes()).unwrap();
        std::io::Write::flush(stream).unwrap();
    }

    /// Serve two successful commit requests while holding the first response.
    /// The request signal identifies the window after the old admission began
    /// and before it can clear its staged snapshot.
    fn held_two_commit_server() -> (
        u16,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_seen_tx, request_seen_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            read_http_request(&mut first);
            request_seen_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            write_commit_reply(&mut first, "change-a");

            let (mut second, _) = listener.accept().unwrap();
            read_http_request(&mut second);
            write_commit_reply(&mut second, "change-b");
        });
        (port, request_seen_rx, release_tx, server)
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

    /// A successful response can clear only the staged mutation it snapped.
    /// NFS keeps accepting writes while admission runs on a blocking worker, so
    /// a newer same-path mutation must remain pending and receive another
    /// admission instead of disappearing behind the older response.
    #[test]
    fn an_in_flight_admission_keeps_a_newer_same_path_write_owed() {
        let dir = tempfile::tempdir().unwrap();
        let (port, first_request_seen, release_first, server) = held_two_commit_server();
        let writer = Arc::new(successful_writer(dir.path(), port));
        let target = path("same.txt");
        writer.write_at(&target, 0, b"A").unwrap();

        let admitting = Arc::clone(&writer);
        let first_admission = std::thread::spawn(move || admitting.admit());
        first_request_seen
            .recv_timeout(Duration::from_secs(10))
            .unwrap();

        // Same size and same-second metadata make this intentionally
        // indistinguishable by stat. Only mutation identity can separate it.
        writer.write_at(&target, 0, b"B").unwrap();
        release_first.send(()).unwrap();
        let first = first_admission.join().unwrap().unwrap().unwrap();
        assert_eq!(first.change_id, "change-a");
        assert_eq!(std::fs::read(dir.path().join("same.txt")).unwrap(), b"B");
        assert!(matches!(writer.staged(&target), Some(Staged::Present(_))));
        assert_eq!(
            writer.health(),
            WriteHealth::Pending {
                paths: vec![target.clone()]
            }
        );

        let second = writer.admit().unwrap().unwrap();
        assert_eq!(second.change_id, "change-b");
        assert_eq!(second.paths, vec![target.clone()]);
        assert!(writer.staged(&target).is_none());
        match writer.health() {
            WriteHealth::Settled { last: Some(last) } => {
                assert_eq!(last.change_id, "change-b");
                assert_eq!(last.paths, vec![target]);
            }
            other => panic!("expected the second admission to settle the writer, got {other:?}"),
        }
        server.join().unwrap();
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
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let writer = writer(&root);
        let host = writer.content_path(&path("src/main.rs")).unwrap();
        assert_eq!(host, root.join("src/main.rs"));
        assert!(host.starts_with(&root));
        // `..` never reaches here: VfsPath refuses to hold one at all.
        assert!(VfsPath::from_utf8("../escape").is_err());
    }

    /// The escape the lexical check could not see. `VfsPath` guarantees no
    /// `..`, and `notes/passwd` has none; the working copy's own symlink is
    /// what sends it outside the repository.
    #[cfg(unix)]
    #[test]
    fn a_write_through_a_symlink_that_leaves_the_repository_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        let outside_root = std::fs::canonicalize(outside.path()).unwrap();
        std::fs::write(outside_root.join("passwd"), b"original\n").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let writer = writer(&root);
        std::os::unix::fs::symlink(&outside_root, root.join("notes")).unwrap();

        let error = writer
            .write_at(&path("notes/passwd"), 0, b"owned")
            .unwrap_err();
        assert!(
            matches!(error, VfsError::EscapesRoot { .. }),
            "expected a containment refusal, got {error:?}"
        );
        assert_eq!(
            std::fs::read(outside_root.join("passwd")).unwrap(),
            b"original\n",
            "the file outside the repository must be untouched"
        );
        assert!(
            writer.staged(&path("notes/passwd")).is_none(),
            "a refused write must stage nothing, or the admission would carry it"
        );
    }

    /// The positive control for the test above: the same call shape, one
    /// directory that is real rather than a symlink out, must still work. A
    /// containment check that refused everything would pass the test above and
    /// break the mount.
    #[test]
    fn an_ordinary_nested_write_still_stages() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let writer = writer(&root);
        writer.write_at(&path("notes/passwd"), 0, b"mine").unwrap();
        assert_eq!(
            std::fs::read(root.join("notes/passwd")).unwrap(),
            b"mine",
            "the write must land inside the repository"
        );
    }

    /// Removing a symlink removes the link. Resolving the final component
    /// would delete whatever it points at, which is a data-loss bug wearing a
    /// security fix's clothes.
    #[cfg(unix)]
    #[test]
    fn removing_a_symlink_leaves_its_target_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let writer = writer(&root);
        std::fs::write(root.join("real.txt"), b"body").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("alias")).unwrap();

        writer.remove(&path("alias")).unwrap();
        assert!(
            root.join("alias").symlink_metadata().is_err(),
            "the link itself must be gone"
        );
        assert_eq!(
            std::fs::read(root.join("real.txt")).unwrap(),
            b"body",
            "the target must survive removing the link to it"
        );
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
    fn the_author_retry_fires_only_for_the_author_field() {
        use reqwest::StatusCode;
        let refusal = "Failed to deserialize the JSON body into the target type: author: \
                       unknown field `author`, expected one of `operation_id`, `timestamp`, \
                       `message`, `session_id` at line 1 column 9";
        assert!(refuses_the_author_field(
            StatusCode::UNPROCESSABLE_ENTITY,
            refusal
        ));
        // A different unprocessable body is a real refusal, not a version skew.
        assert!(!refuses_the_author_field(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown field `timestamp`"
        ));
        // The same text under a different status is not this case either.
        assert!(!refuses_the_author_field(
            StatusCode::BAD_REQUEST,
            "unknown field `author`"
        ));
    }

    #[test]
    fn the_admission_body_carries_the_author_unless_the_retry_drops_it() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        let attributed = writer.commit_body("m", true);
        assert_eq!(attributed["author"], serde_json::json!(writer.author()));
        assert_eq!(attributed["message"], "m");
        assert!(attributed.get("operation_id").is_some());
        assert!(attributed.get("timestamp").is_some());

        let unattributed = writer.commit_body("m", false);
        assert!(
            unattributed.get("author").is_none(),
            "the retry must omit the field, not send it empty"
        );
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
