// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The export's own account of itself, readable by another process.
//!
//! `kin-vfs nfs-status` runs in a different process from the server, so it
//! cannot ask the running export anything directly. The server publishes this
//! document instead, and the probe reads it beside two facts it can establish
//! for itself: whether the mount is in the mount table, and whether reading it
//! answers.
//!
//! Written on every admission tick rather than only on change, so a stale file
//! is distinguishable from a current one by its own `written_at`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use kin_vfs_core::writer::WriteHealth;

/// The status file's name inside the state directory.
pub const STATUS_FILE: &str = "nfs.status.json";

/// One workspace's write side, as the export sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceStatus {
    /// The workspace's export name.
    pub name: String,
    /// `settled`, `pending`, `degraded`, or `read-only`.
    pub state: String,
    /// Paths written through the mount that are not graph truth yet.
    #[serde(default)]
    pub unadmitted: Vec<String>,
    /// Why the workspace is degraded or read-only, when it is.
    #[serde(default)]
    pub reason: Option<String>,
    /// The change the last admission published.
    #[serde(default)]
    pub last_change_id: Option<String>,
}

/// What the running export publishes about itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStatus {
    /// The port the NFS listener is bound to.
    pub port: u16,
    /// Where the export is mounted.
    pub mount_point: PathBuf,
    /// Whether writes are admitted into graph truth.
    pub writable: bool,
    /// Epoch seconds this document was written.
    pub written_at: u64,
    /// One entry per workspace with a write side, or a refusal.
    pub workspaces: Vec<WorkspaceStatus>,
}

impl ExportStatus {
    /// Build a status document from what a [`crate::router::MountControl`]
    /// reports.
    pub fn build(
        port: u16,
        mount_point: PathBuf,
        writable: bool,
        health: Vec<(String, WriteHealth)>,
        refusals: Vec<(String, String)>,
    ) -> Self {
        let mut workspaces: Vec<WorkspaceStatus> = health
            .into_iter()
            .map(|(name, health)| {
                let unadmitted = health
                    .unadmitted()
                    .iter()
                    .map(|path| path.to_string())
                    .collect();
                let (state, reason, last_change_id) = match &health {
                    WriteHealth::Settled { last } => {
                        ("settled", None, last.as_ref().map(|a| a.change_id.clone()))
                    }
                    WriteHealth::Pending { .. } => ("pending", None, None),
                    WriteHealth::Degraded { reason, .. } => {
                        ("degraded", Some(reason.clone()), None)
                    }
                };
                WorkspaceStatus {
                    name,
                    state: state.to_string(),
                    unadmitted,
                    reason,
                    last_change_id,
                }
            })
            .collect();
        // A workspace the export could not open writable is the case a status
        // probe most needs to see, so it is carried as a workspace rather than
        // omitted for having no write side.
        workspaces.extend(refusals.into_iter().map(|(name, reason)| WorkspaceStatus {
            name,
            state: "read-only".to_string(),
            unadmitted: Vec::new(),
            reason: Some(reason),
            last_change_id: None,
        }));
        workspaces.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            port,
            mount_point,
            writable,
            written_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            workspaces,
        }
    }

    /// The single word a status line leads with.
    ///
    /// The worst workspace decides: one degraded workspace makes the export
    /// degraded, because a probe that averaged them would report healthy while
    /// a user's writes sat unadmitted.
    pub fn state(&self) -> &'static str {
        if !self.writable {
            return "read-only";
        }
        if self.workspaces.iter().any(|w| w.state == "degraded") {
            return "degraded";
        }
        if self.workspaces.iter().any(|w| w.state == "read-only") {
            return "degraded";
        }
        if self.workspaces.iter().any(|w| w.state == "pending") {
            return "pending";
        }
        "writable"
    }

    /// Write the document into `state_dir`.
    pub fn write(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join(STATUS_FILE);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Read the document from `state_dir`, if the export published one.
    pub fn read(state_dir: &Path) -> Option<Self> {
        let raw = std::fs::read_to_string(state_dir.join(STATUS_FILE)).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Remove the document. Called when the export stops, so a probe cannot
    /// read a stopped export's last word as a running export's current one.
    pub fn remove(state_dir: &Path) {
        let _ = std::fs::remove_file(state_dir.join(STATUS_FILE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_vfs_core::writer::Admission;
    use kin_vfs_core::VfsPath;

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    #[test]
    fn one_degraded_workspace_degrades_the_export() {
        let status = ExportStatus::build(
            2049,
            PathBuf::from("/mnt"),
            true,
            vec![
                ("clean".into(), WriteHealth::Settled { last: None }),
                (
                    "stuck".into(),
                    WriteHealth::Degraded {
                        paths: vec![path("a.rs")],
                        reason: "the graph refused the admission".into(),
                    },
                ),
            ],
            Vec::new(),
        );
        assert_eq!(status.state(), "degraded");
    }

    #[test]
    fn a_workspace_that_could_not_open_writable_degrades_the_export() {
        let status = ExportStatus::build(
            2049,
            PathBuf::from("/mnt"),
            true,
            Vec::new(),
            vec![("no-author".into(), "cannot attribute a mount write".into())],
        );
        assert_eq!(status.state(), "degraded");
        assert_eq!(status.workspaces[0].state, "read-only");
        assert!(status.workspaces[0].reason.is_some());
    }

    #[test]
    fn pending_paths_are_reported_by_name() {
        let status = ExportStatus::build(
            2049,
            PathBuf::from("/mnt"),
            true,
            vec![(
                "w".into(),
                WriteHealth::Pending {
                    paths: vec![path("src/main.rs")],
                },
            )],
            Vec::new(),
        );
        assert_eq!(status.state(), "pending");
        assert_eq!(status.workspaces[0].unadmitted, vec!["src/main.rs"]);
    }

    #[test]
    fn a_settled_export_names_the_change_that_settled_it() {
        let status = ExportStatus::build(
            2049,
            PathBuf::from("/mnt"),
            true,
            vec![(
                "w".into(),
                WriteHealth::Settled {
                    last: Some(Admission {
                        change_id: "chg-1".into(),
                        branch: "main".into(),
                        file_count: 1,
                        paths: vec![path("src/main.rs")],
                    }),
                },
            )],
            Vec::new(),
        );
        assert_eq!(status.state(), "writable");
        assert_eq!(
            status.workspaces[0].last_change_id.as_deref(),
            Some("chg-1")
        );
    }

    #[test]
    fn a_read_only_export_never_reports_writable() {
        let status =
            ExportStatus::build(2049, PathBuf::from("/mnt"), false, Vec::new(), Vec::new());
        assert_eq!(status.state(), "read-only");
    }

    #[test]
    fn a_removed_status_cannot_be_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let status = ExportStatus::build(1, PathBuf::from("/mnt"), true, Vec::new(), Vec::new());
        status.write(dir.path()).unwrap();
        assert!(ExportStatus::read(dir.path()).is_some());
        ExportStatus::remove(dir.path());
        assert!(ExportStatus::read(dir.path()).is_none());
    }
}
