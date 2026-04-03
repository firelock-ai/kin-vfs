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
use crate::router::KinNfsRouter;

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
        }
    }
}

/// NFS server handle. Holds runtime state and supports graceful shutdown.
pub struct NfsServer {
    config: NfsServerConfig,
    shutdown_tx: watch::Sender<bool>,
    port: u16,
}

impl NfsServer {
    /// Start the NFS server with the given config and workspace entries.
    ///
    /// This binds the TCP listener and spawns the NFS handler loop.
    /// Returns the server handle (call `shutdown()` to stop).
    pub async fn start(
        config: NfsServerConfig,
        entries: Vec<WorkspaceEntry>,
    ) -> Result<Self> {
        let router = KinNfsRouter::new(entries);

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
        })
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
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        // Clean up state files.
        let _ = std::fs::remove_file(self.config.state_dir.join("nfs.port"));
        let _ = std::fs::remove_file(self.config.state_dir.join("nfs.pid"));
        info!("NFS server shutdown signaled, state files cleaned up");
    }
}

impl Drop for NfsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---------------------------------------------------------------------------
// State file helpers
// ---------------------------------------------------------------------------

fn write_state_file(dir: &Path, name: &str, content: &str) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let path = dir.join(name);
    std::fs::write(&path, content)
        .with_context(|| format!("writing {}", path.display()))?;
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

/// Preferred mount point: /Volumes/Kin (auto-appears in Finder sidebar),
/// falling back to ~/.kin/mnt if /Volumes is not writable.
fn default_mount_point(kin_dir: &Path) -> PathBuf {
    let volumes_kin = PathBuf::from("/Volumes/Kin");
    if volumes_kin.exists() || PathBuf::from("/Volumes").is_dir() {
        volumes_kin
    } else {
        kin_dir.join("mnt")
    }
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
    }
}
