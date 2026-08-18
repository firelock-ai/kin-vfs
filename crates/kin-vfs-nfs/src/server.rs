// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! NFS server lifecycle.
//!
//! Manages the NFS TCP listener, port allocation, PID file, and
//! graceful shutdown. The server hosts the multi-workspace router
//! and serves all registered workspaces over a single NFS export.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use tokio::sync::watch;
use tracing::{error, info};

use crate::registry::WorkspaceEntry;
use crate::router::{KinNfsRouter, MountControl};
use crate::status::ExportStatus;

/// Configuration for the NFS server.
#[derive(Debug, Clone)]
pub struct NfsServerConfig {
    /// Port to bind (0 = pick a free port).
    pub port: u16,
    /// IP address to bind (default: 127.0.0.1).
    pub bind_addr: String,
    /// Mount point (default: ~/.kin/mnt/).
    pub mount_point: PathBuf,
    /// Directory for runtime state files (nfs.port, nfs.pid).
    /// Default: ~/.kin/
    pub state_dir: PathBuf,
    /// Whether writes through the mount are admitted into graph truth.
    pub writable: bool,
    /// How long staged writes must be quiescent before they are admitted.
    pub admit_debounce: std::time::Duration,
}

impl Default for NfsServerConfig {
    fn default() -> Self {
        let kin_dir = default_kin_dir();
        Self {
            port: 0,
            bind_addr: "127.0.0.1".to_string(),
            // Mount under /Volumes/Kin so it auto-appears in Finder sidebar.
            // Falls back to ~/.kin/mnt if /Volumes is not writable.
            mount_point: default_mount_point(&kin_dir),
            state_dir: kin_dir,
            writable: false,
            admit_debounce: kin_vfs_daemon::kin_writer::configured_debounce(),
        }
    }
}

/// NFS server handle. Holds runtime state and supports graceful shutdown.
pub struct NfsServer {
    config: NfsServerConfig,
    shutdown_tx: watch::Sender<bool>,
    port: u16,
    control: MountControl,
}

impl NfsServer {
    /// Start the NFS server with the given config and workspace entries.
    ///
    /// This binds the TCP listener and spawns the NFS handler loop.
    /// Returns the server handle (call `shutdown()` to stop).
    pub async fn start(config: NfsServerConfig, entries: Vec<WorkspaceEntry>) -> Result<Self> {
        let router = KinNfsRouter::with_writes(entries, config.writable);
        let control = router.control();

        let bind_str = format!("{}:{}", config.bind_addr, config.port);
        let listener = NFSTcpListener::bind(&bind_str, router)
            .await
            .with_context(|| format!("binding NFS listener on {bind_str}"))?;

        let port = listener.get_listen_port();
        info!(port, "NFS server listening");

        // Write port and PID files.
        write_state_file(&config.state_dir, "nfs.port", &port.to_string())?;
        write_state_file(
            &config.state_dir,
            "nfs.pid",
            &std::process::id().to_string(),
        )?;

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // Publish once before the first tick, so a probe run immediately after
        // start reads this export rather than nothing.
        publish_status(&control, port, &config);
        spawn_admission_loop(
            control.clone(),
            config.clone(),
            port,
            shutdown_tx.subscribe(),
        );

        // Spawn the NFS handler loop.
        tokio::spawn(async move {
            tokio::select! {
                result = listener.handle_forever() => {
                    if let Err(e) = result {
                        error!(%e, "NFS listener exited with error");
                    }
                }
                _ = async {
                    while !*shutdown_rx.borrow_and_update() {
                        shutdown_rx.changed().await.ok();
                    }
                } => {
                    info!("NFS server shutting down");
                }
            }
        });

        Ok(Self {
            config,
            shutdown_tx,
            port,
            control,
        })
    }

    /// The write side of this export.
    pub fn control(&self) -> &MountControl {
        &self.control
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The configured mount point.
    pub fn mount_point(&self) -> &Path {
        &self.config.mount_point
    }

    /// Signal the server to shut down.
    ///
    /// Staged writes are admitted first. A mount that stopped with bytes on
    /// disk and nothing in the graph is the exact failure this write path
    /// exists to prevent, and stopping is the last chance to avoid it.
    pub fn shutdown(&self) {
        if self.config.writable {
            for (workspace, outcome) in self.control.admit_now() {
                match outcome {
                    Ok(Some(change_id)) => {
                        info!(%workspace, %change_id, "admitted staged writes before shutdown")
                    }
                    Ok(None) => {}
                    Err(reason) => error!(
                        %workspace, %reason,
                        "staged writes could not be admitted before shutdown; \
                         they remain in the working copy and are not graph truth"
                    ),
                }
            }
        }
        let _ = self.shutdown_tx.send(true);
        // Clean up state files.
        let _ = std::fs::remove_file(self.config.state_dir.join("nfs.port"));
        let _ = std::fs::remove_file(self.config.state_dir.join("nfs.pid"));
        ExportStatus::remove(&self.config.state_dir);
        info!("NFS server shutdown signaled, state files cleaned up");
    }
}

impl Drop for NfsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Admit staged writes whose debounce window has closed, until shutdown.
///
/// One editor save is many NFS `WRITE` calls, so the loop waits for quiescence
/// rather than admitting per call. Admission is blocking work moved off the
/// runtime worker: it is one synchronous daemon request that can outlast any
/// deadline a caller would be right to set, and a commit is not cancellable.
fn spawn_admission_loop(
    control: MountControl,
    config: NfsServerConfig,
    port: u16,
    mut shutdown: watch::Receiver<bool>,
) {
    // Poll several times per window so an admission fires close to the moment
    // the window closes rather than up to a whole window late.
    let debounce = config.admit_debounce;
    let tick = (debounce / 4).max(std::time::Duration::from_millis(100));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow_and_update() {
                        return;
                    }
                }
            }
            if config.writable {
                // An explicit sync outranks the debounce: a script that asked
                // for its writes to be graph truth now must not be told to wait
                // out a window tuned for interactive editing.
                if take_sync_request(&config.state_dir) {
                    let admitting = control.clone();
                    let results = tokio::task::spawn_blocking(move || admitting.admit_now()).await;
                    write_sync_result(&config.state_dir, results.unwrap_or_default());
                } else {
                    let admitting = control.clone();
                    match tokio::task::spawn_blocking(move || admitting.admit_due(debounce)).await {
                        Ok(changes) => {
                            for (workspace, change_id) in changes {
                                info!(%workspace, %change_id, "mount writes are graph truth");
                            }
                        }
                        Err(e) => error!(%e, "admission task panicked"),
                    }
                }
            }
            publish_status(&control, port, &config);
        }
    });
}

/// The file a caller creates to ask for an immediate admission.
pub const SYNC_REQUEST_FILE: &str = "nfs.sync";

/// The file the export writes the outcome of that admission to.
pub const SYNC_RESULT_FILE: &str = "nfs.sync.result";

/// Consume a pending sync request, reporting whether there was one.
fn take_sync_request(state_dir: &Path) -> bool {
    std::fs::remove_file(state_dir.join(SYNC_REQUEST_FILE)).is_ok()
}

/// Publish the outcome of an explicit sync, one line per workspace.
///
/// Written after the admissions have all returned, so a caller that sees the
/// file has the complete answer rather than a partial one.
fn write_sync_result(state_dir: &Path, results: Vec<(String, Result<Option<String>, String>)>) {
    let rendered: Vec<String> = results
        .into_iter()
        .map(|(workspace, outcome)| match outcome {
            Ok(Some(change_id)) => format!("ok\t{workspace}\t{change_id}"),
            Ok(None) => format!("empty\t{workspace}\t-"),
            Err(reason) => format!("error\t{workspace}\t{reason}"),
        })
        .collect();
    let _ = std::fs::write(
        state_dir.join(SYNC_RESULT_FILE),
        format!("{}\n", rendered.join("\n")),
    );
}

/// Ask a running export to admit its staged writes now, and wait for the
/// answer.
///
/// Returns one `(state, workspace, detail)` row per workspace. `state` is
/// `ok`, `empty`, or `error`.
pub fn request_sync(
    state_dir: &Path,
    timeout: std::time::Duration,
) -> Result<Vec<(String, String, String)>> {
    let result_path = state_dir.join(SYNC_RESULT_FILE);
    let _ = std::fs::remove_file(&result_path);
    std::fs::write(state_dir.join(SYNC_REQUEST_FILE), "1")
        .with_context(|| format!("asking {} to sync", state_dir.display()))?;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(raw) = std::fs::read_to_string(&result_path) {
            let _ = std::fs::remove_file(&result_path);
            return Ok(raw
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let mut parts = line.splitn(3, '\t');
                    (
                        parts.next().unwrap_or("error").to_string(),
                        parts.next().unwrap_or("?").to_string(),
                        parts.next().unwrap_or("").to_string(),
                    )
                })
                .collect());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!(
        "the export did not answer a sync request within {timeout:?}; it may be stopped, or an \
         admission may still be running"
    )
}

/// Write what this export currently reports about itself.
fn publish_status(control: &MountControl, port: u16, config: &NfsServerConfig) {
    let (health, refusals) = control.write_health();
    let status = ExportStatus::build(
        port,
        config.mount_point.clone(),
        config.writable,
        health,
        refusals,
    );
    if let Err(e) = status.write(&config.state_dir) {
        error!(%e, "could not publish export status");
    }
}

// ---------------------------------------------------------------------------
// State file helpers
// ---------------------------------------------------------------------------

fn write_state_file(dir: &Path, name: &str, content: &str) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let path = dir.join(name);
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read the NFS port from the state directory, if the server is running.
pub fn read_port(state_dir: &Path) -> Option<u16> {
    let path = state_dir.join("nfs.port");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Read the NFS server PID from the state directory.
pub fn read_pid(state_dir: &Path) -> Option<u32> {
    let path = state_dir.join("nfs.pid");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Check if a process with the given PID is still alive.
pub fn is_pid_alive(pid: u32) -> bool {
    // kill(pid, 0) checks existence without sending a signal.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Default `~/.kin/` directory.
fn default_kin_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".kin")
}

/// Default mount point: ~/Kin — user-writable, no sudo needed, persists
/// across unmounts. Visible in Finder sidebar by dragging to Favorites.
fn default_mount_point(_kin_dir: &Path) -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join("Kin"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/kin-mount"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        write_state_file(dir.path(), "nfs.port", "2049").unwrap();
        assert_eq!(read_port(dir.path()), Some(2049));

        write_state_file(dir.path(), "nfs.pid", "12345").unwrap();
        assert_eq!(read_pid(dir.path()), Some(12345));
    }

    #[test]
    fn test_read_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_port(dir.path()), None);
        assert_eq!(read_pid(dir.path()), None);
    }

    #[test]
    fn test_is_pid_alive() {
        // Current process should be alive.
        assert!(is_pid_alive(std::process::id()));
        // PID 0 is the kernel scheduler — kill(0, 0) sends to process group,
        // so use a large unlikely PID instead.
        assert!(!is_pid_alive(4_000_000));
    }

    #[test]
    fn test_default_config() {
        let config = NfsServerConfig::default();
        assert_eq!(config.port, 0);
        assert_eq!(config.bind_addr, "127.0.0.1");
        // On macOS, defaults to /Volumes/Kin; elsewhere ~/.kin/mnt
        assert!(
            config.mount_point.ends_with("Kin") || config.mount_point.ends_with("mnt"),
            "unexpected mount point: {:?}",
            config.mount_point
        );
        assert!(config.state_dir.ends_with(".kin"));
        // Read-only by default: a mount that admitted writes without the caller
        // asking would commit to a repository nobody offered it.
        assert!(!config.writable);
    }
}
