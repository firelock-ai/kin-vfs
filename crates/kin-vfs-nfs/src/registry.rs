// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persistent workspace registry.
//!
//! Tracks which Kin workspaces are known on this machine. Persists to
//! `~/.kin/vfs-workspaces.json`. The NFS server reads this at startup
//! to know which workspaces to expose as top-level directories.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single registered workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    /// Display name (used as NFS directory name).
    pub name: String,
    /// Absolute path to workspace root (contains `.kin/`).
    pub path: PathBuf,
    /// kin-daemon URL for this workspace (e.g., `"http://127.0.0.1:4219"`).
    pub daemon_url: String,
}

/// On-disk JSON envelope.
#[derive(Debug, Serialize, Deserialize)]
struct RegistryFile {
    workspaces: Vec<WorkspaceEntry>,
}

/// Persistent registry of known Kin workspaces.
pub struct WorkspaceRegistry {
    entries: Vec<WorkspaceEntry>,
    config_path: PathBuf,
}

impl WorkspaceRegistry {
    /// Load the registry from a JSON file. Returns an empty registry if the
    /// file does not exist.
    pub fn load(config_path: &Path) -> Result<Self> {
        if !config_path.exists() {
            return Ok(Self {
                entries: Vec::new(),
                config_path: config_path.to_path_buf(),
            });
        }

        let data = std::fs::read_to_string(config_path)
            .with_context(|| format!("reading registry from {}", config_path.display()))?;
        let file: RegistryFile = serde_json::from_str(&data)
            .with_context(|| format!("parsing registry JSON from {}", config_path.display()))?;

        Ok(Self {
            entries: file.workspaces,
            config_path: config_path.to_path_buf(),
        })
    }

    /// Persist the registry to its JSON file.
    pub fn save(&self) -> Result<()> {
        let file = RegistryFile {
            workspaces: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&file)?;

        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.config_path, json)
            .with_context(|| format!("writing registry to {}", self.config_path.display()))?;
        Ok(())
    }

    /// Register a workspace. The display name is derived from the directory
    /// basename. If a name collision occurs, a `-2`, `-3`, etc. suffix is
    /// appended.
    pub fn register(&mut self, path: PathBuf, daemon_url: String) -> Result<&WorkspaceEntry> {
        let base_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "workspace".to_string());

        let name = if !self.entries.iter().any(|e| e.name == base_name) {
            base_name.clone()
        } else {
            let mut suffix = 2u32;
            loop {
                let candidate = format!("{}-{}", base_name, suffix);
                if !self.entries.iter().any(|e| e.name == candidate) {
                    break candidate;
                }
                suffix += 1;
            }
        };

        self.entries.push(WorkspaceEntry {
            name,
            path,
            daemon_url,
        });

        Ok(self.entries.last().unwrap())
    }

    /// Remove a workspace by name. Returns `true` if an entry was removed.
    pub fn deregister(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < before
    }

    /// Look up a workspace by name.
    pub fn get(&self, name: &str) -> Option<&WorkspaceEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// All registered workspaces.
    pub fn list(&self) -> &[WorkspaceEntry] {
        &self.entries
    }

    /// Default config path: `~/.kin/vfs-workspaces.json`.
    pub fn default_config_path() -> PathBuf {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        home.join(".kin").join("vfs-workspaces.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reg.json");
        let mut reg = WorkspaceRegistry::load(&path).unwrap();

        let entry = reg
            .register("/tmp/my-project".into(), "http://127.0.0.1:4219".into())
            .unwrap();
        assert_eq!(entry.name, "my-project");

        assert_eq!(reg.list().len(), 1);
        assert_eq!(reg.list()[0].name, "my-project");
    }

    #[test]
    fn register_deduplication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reg.json");
        let mut reg = WorkspaceRegistry::load(&path).unwrap();

        reg.register("/tmp/project".into(), "http://127.0.0.1:4219".into())
            .unwrap();
        let second = reg
            .register("/other/project".into(), "http://127.0.0.1:4220".into())
            .unwrap();
        assert_eq!(second.name, "project-2");

        let third = reg
            .register("/yet/another/project".into(), "http://127.0.0.1:4221".into())
            .unwrap();
        assert_eq!(third.name, "project-3");
    }

    #[test]
    fn deregister_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reg.json");
        let mut reg = WorkspaceRegistry::load(&path).unwrap();

        reg.register("/tmp/foo".into(), "http://127.0.0.1:4219".into())
            .unwrap();
        assert_eq!(reg.list().len(), 1);

        assert!(reg.deregister("foo"));
        assert_eq!(reg.list().len(), 0);

        // Removing a non-existent entry returns false.
        assert!(!reg.deregister("foo"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("vfs-workspaces.json");

        let mut reg = WorkspaceRegistry::load(&config).unwrap();
        reg.register("/tmp/alpha".into(), "http://127.0.0.1:4219".into())
            .unwrap();
        reg.register("/tmp/beta".into(), "http://127.0.0.1:4220".into())
            .unwrap();
        reg.save().unwrap();

        let loaded = WorkspaceRegistry::load(&config).unwrap();
        assert_eq!(loaded.list().len(), 2);
        assert_eq!(loaded.list()[0].name, "alpha");
        assert_eq!(loaded.list()[1].name, "beta");
    }

    #[test]
    fn get_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reg.json");
        let mut reg = WorkspaceRegistry::load(&path).unwrap();

        reg.register("/tmp/abc".into(), "http://127.0.0.1:4219".into())
            .unwrap();

        assert!(reg.get("abc").is_some());
        assert_eq!(reg.get("abc").unwrap().daemon_url, "http://127.0.0.1:4219");
        assert!(reg.get("nonexistent").is_none());
    }
}
