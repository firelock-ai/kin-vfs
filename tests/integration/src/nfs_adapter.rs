// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for the NFS adapter and multi-workspace router.
//!
//! Exercises the full NFS filesystem adapter and router through the
//! `NFSFileSystem` trait without requiring an actual NFS mount or
//! network listener. Verifies that the adapter correctly translates
//! NFS operations into ContentProvider calls.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use nfsserve::nfs::*;
    use nfsserve::vfs::NFSFileSystem;

    use kin_vfs_core::{
        ContentProvider, DirEntry, FileType, VfsError, VfsName, VfsPath, VfsResult, VirtualStat,
    };
    use kin_vfs_nfs::nfs_fs::KinNfsFs;
    use kin_vfs_nfs::registry::WorkspaceEntry;
    use kin_vfs_nfs::router::KinNfsRouter;

    // ---------------------------------------------------------------
    // Test ContentProvider — simulates a workspace
    // ---------------------------------------------------------------

    struct MockWorkspace {
        files: HashMap<VfsPath, Vec<u8>>,
        /// Paths that are directories in their own right (no file content).
        dirs: Vec<VfsPath>,
    }

    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid fixture path")
    }

    fn vname(name: &[u8]) -> VfsName {
        VfsName::from_bytes(name.to_vec()).expect("valid fixture name")
    }

    impl MockWorkspace {
        fn project_a() -> Self {
            let mut files = HashMap::new();
            files.insert(
                vpath("README.md"),
                b"# Project A\nGraph-first repo.".to_vec(),
            );
            files.insert(
                vpath("src/main.rs"),
                b"fn main() { println!(\"A\"); }".to_vec(),
            );
            files.insert(
                vpath("src/lib.rs"),
                b"pub fn greet() -> &'static str { \"hello\" }".to_vec(),
            );
            files.insert(
                vpath("Cargo.toml"),
                b"[package]\nname = \"project-a\"".to_vec(),
            );
            // A non-UTF8 tracked path must be reachable through the export.
            files.insert(
                VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).unwrap(),
                b"raw bytes".to_vec(),
            );
            Self {
                files,
                dirs: Vec::new(),
            }
        }

        // Reserved fixture for multi-project routing tests (pairs with project_a).
        #[allow(dead_code)]
        fn project_b() -> Self {
            let mut files = HashMap::new();
            files.insert(vpath("index.ts"), b"console.log('Project B');".to_vec());
            files.insert(vpath("package.json"), b"{\"name\": \"project-b\"}".to_vec());
            Self {
                files,
                dirs: Vec::new(),
            }
        }

        fn is_dir(&self, path: &VfsPath) -> bool {
            path.is_root()
                || self.dirs.contains(path)
                || self
                    .files
                    .keys()
                    .any(|candidate| path.is_ancestor_of(candidate))
        }
    }

    impl ContentProvider for MockWorkspace {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = (offset as usize).min(data.len());
            let end = (start + len as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            if self.is_dir(path) {
                return Ok(VirtualStat::directory(1000));
            }
            if let Some(data) = self.files.get(path) {
                return Ok(VirtualStat::regular_file(
                    data.len() as u64,
                    [0u8; 32],
                    false,
                    1000,
                ));
            }
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            let mut entries = Vec::new();
            for key in self.files.keys() {
                let Some(rest) = (if path.is_root() {
                    Some(key.as_bytes())
                } else {
                    path.strip_dir_prefix(key)
                }) else {
                    continue;
                };
                let (name, is_dir) = match rest.iter().position(|byte| *byte == b'/') {
                    Some(position) => (&rest[..position], true),
                    None => (rest, false),
                };
                if !seen.insert(name.to_vec()) {
                    continue;
                }
                entries.push(DirEntry {
                    name: vname(name),
                    file_type: if is_dir {
                        FileType::Directory
                    } else {
                        FileType::File
                    },
                    object_id: None,
                });
            }
            entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
            Ok(entries)
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.is_dir(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::InvalidInput {
                path: path.to_string(),
            })
        }
    }

    // ---------------------------------------------------------------
    // Single-workspace adapter tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn adapter_full_workflow() {
        let fs = KinNfsFs::new(Arc::new(MockWorkspace::project_a()));
        let root = fs.root_dir();

        // 1. Root getattr is a directory.
        let root_attr = fs.getattr(root).await.unwrap();
        assert!(matches!(root_attr.ftype, ftype3::NF3DIR));

        // 2. Lookup files in root.
        let readme_id = fs.lookup(root, &b"README.md"[..].into()).await.unwrap();
        let src_id = fs.lookup(root, &b"src"[..].into()).await.unwrap();
        let cargo_id = fs.lookup(root, &b"Cargo.toml"[..].into()).await.unwrap();
        assert_ne!(readme_id, src_id);
        assert_ne!(readme_id, cargo_id);

        // 3. Getattr on file — correct size and type.
        let readme_attr = fs.getattr(readme_id).await.unwrap();
        assert!(matches!(readme_attr.ftype, ftype3::NF3REG));
        assert_eq!(readme_attr.size, 29); // "# Project A\nGraph-first repo."

        // 4. Getattr on directory.
        let src_attr = fs.getattr(src_id).await.unwrap();
        assert!(matches!(src_attr.ftype, ftype3::NF3DIR));

        // 5. Read full file content.
        let (data, eof) = fs.read(readme_id, 0, 4096).await.unwrap();
        assert_eq!(&data, b"# Project A\nGraph-first repo.");
        assert!(eof);

        // 6. Read partial content (first 9 bytes).
        let (data, eof) = fs.read(readme_id, 0, 9).await.unwrap();
        assert_eq!(&data, b"# Project");
        assert!(!eof);

        // 7. Read with offset.
        let (data, _) = fs.read(readme_id, 2, 7).await.unwrap();
        assert_eq!(&data, b"Project");

        // 8. Nested lookup: src/main.rs
        let main_id = fs.lookup(src_id, &b"main.rs"[..].into()).await.unwrap();
        let main_attr = fs.getattr(main_id).await.unwrap();
        assert!(matches!(main_attr.ftype, ftype3::NF3REG));
        let (main_data, _) = fs.read(main_id, 0, 4096).await.unwrap();
        assert_eq!(&main_data, b"fn main() { println!(\"A\"); }");

        // 9. Readdir on root — should contain ".", "..", and entries.
        let dir_result = fs.readdir(root, 0, 100).await.unwrap();
        assert!(dir_result.end);
        let names: Vec<String> = dir_result
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"README.md".to_string()));
        assert!(names.contains(&"src".to_string()));
        assert!(names.contains(&"Cargo.toml".to_string()));

        // 10. Readdir on src/ — should contain main.rs and lib.rs.
        let src_dir = fs.readdir(src_id, 0, 100).await.unwrap();
        let src_names: Vec<String> = src_dir
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(src_names.contains(&"main.rs".to_string()));
        assert!(src_names.contains(&"lib.rs".to_string()));

        // 11. Lookup nonexistent returns NOENT.
        let err = fs.lookup(root, &b"nonexistent"[..].into()).await;
        assert!(matches!(err, Err(nfsstat3::NFS3ERR_NOENT)));

        // 12. All write ops return ROFS.
        assert!(matches!(
            fs.write(readme_id, 0, b"x").await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.create(root, &b"new"[..].into(), sattr3::default()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.mkdir(root, &b"newdir"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.remove(root, &b"README.md"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            fs.setattr(readme_id, sattr3::default()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
    }

    #[tokio::test]
    async fn adapter_dot_dotdot_navigation() {
        let fs = KinNfsFs::new(Arc::new(MockWorkspace::project_a()));
        let root = fs.root_dir();

        // "." on root returns root.
        let dot = fs.lookup(root, &b"."[..].into()).await.unwrap();
        assert_eq!(dot, root);

        // ".." on root returns root.
        let dotdot = fs.lookup(root, &b".."[..].into()).await.unwrap();
        assert_eq!(dotdot, root);

        // "." on a subdir returns the same dir.
        let src_id = fs.lookup(root, &b"src"[..].into()).await.unwrap();
        let src_dot = fs.lookup(src_id, &b"."[..].into()).await.unwrap();
        assert_eq!(src_dot, src_id);

        // ".." on a subdir returns parent (root).
        let src_dotdot = fs.lookup(src_id, &b".."[..].into()).await.unwrap();
        let root_attr = fs.getattr(src_dotdot).await.unwrap();
        assert!(matches!(root_attr.ftype, ftype3::NF3DIR));
    }

    #[tokio::test]
    async fn adapter_readdir_pagination() {
        let fs = KinNfsFs::new(Arc::new(MockWorkspace::project_a()));
        let root = fs.root_dir();

        // Get all entries to know total count.
        let all = fs.readdir(root, 0, 100).await.unwrap();
        let total = all.entries.len();
        assert!(total > 3); // ".", "..", plus real entries

        // Get first 3 entries only.
        let page1 = fs.readdir(root, 0, 3).await.unwrap();
        assert_eq!(page1.entries.len(), 3);
        assert!(!page1.end);

        // Continue from the last entry's fileid.
        let last_id = page1.entries.last().unwrap().fileid;
        let page2 = fs.readdir(root, last_id, 100).await.unwrap();
        assert!(!page2.entries.is_empty());

        // No entries from page2 should have the same NAME as page1
        // (fileids can overlap for "." and ".." which share the root inode).
        let page1_names: Vec<String> = page1
            .entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        for e in &page2.entries {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            assert!(
                !page1_names.contains(&name),
                "name overlap detected: {}",
                name
            );
        }
    }

    // ---------------------------------------------------------------
    // Multi-workspace router tests
    // ---------------------------------------------------------------

    fn test_entries() -> Vec<WorkspaceEntry> {
        vec![
            WorkspaceEntry {
                name: "project-a".to_string(),
                path: "/tmp/project-a".into(),
                daemon_url: "http://127.0.0.1:4219".to_string(),
            },
            WorkspaceEntry {
                name: "project-b".to_string(),
                path: "/tmp/project-b".into(),
                daemon_url: "http://127.0.0.1:4220".to_string(),
            },
        ]
    }

    #[tokio::test]
    async fn router_root_getattr() {
        let router = KinNfsRouter::new(test_entries());
        let root = router.root_dir();
        assert_eq!(root, 1);

        // Root getattr is a directory with correct nlink.
        let attr = router.getattr(root).await.unwrap();
        assert!(matches!(attr.ftype, ftype3::NF3DIR));
        assert_eq!(attr.fileid, 1);
        // nlink = 2 + number of workspaces
        assert_eq!(attr.nlink, 4); // 2 + 2 entries
        assert_eq!(attr.mode, 0o755);
    }

    #[tokio::test]
    async fn router_lookup_nonexistent_workspace() {
        let router = KinNfsRouter::new(test_entries());
        let err = router
            .lookup(router.root_dir(), &b"no-such-workspace"[..].into())
            .await;
        assert!(matches!(err, Err(nfsstat3::NFS3ERR_NOENT)));
    }

    #[tokio::test]
    async fn router_write_ops_return_rofs() {
        let router = KinNfsRouter::new(test_entries());
        let root = router.root_dir();
        assert!(matches!(
            router.setattr(root, sattr3::default()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            router.write(root, 0, b"x").await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            router
                .create(root, &b"x"[..].into(), sattr3::default())
                .await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            router.mkdir(root, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
        assert!(matches!(
            router.remove(root, &b"x"[..].into()).await,
            Err(nfsstat3::NFS3ERR_ROFS)
        ));
    }

    #[tokio::test]
    async fn router_read_on_root_returns_isdir() {
        let router = KinNfsRouter::new(test_entries());
        let err = router.read(router.root_dir(), 0, 4096).await;
        assert!(matches!(err, Err(nfsstat3::NFS3ERR_ISDIR)));
    }

    #[tokio::test]
    async fn router_readlink_on_root_returns_inval() {
        let router = KinNfsRouter::new(test_entries());
        let err = router.readlink(router.root_dir()).await;
        assert!(matches!(err, Err(nfsstat3::NFS3ERR_INVAL)));
    }

    #[tokio::test]
    async fn router_root_dotdot_returns_root() {
        let router = KinNfsRouter::new(test_entries());
        let root = router.root_dir();
        let dot = router.lookup(root, &b"."[..].into()).await.unwrap();
        assert_eq!(dot, root);
        let dotdot = router.lookup(root, &b".."[..].into()).await.unwrap();
        assert_eq!(dotdot, root);
    }

    /// A workspace lookup must compare the client's raw name bytes against the
    /// registered names exactly.
    ///
    /// Lossy-decoding first maps every invalid byte to U+FFFD, so a client
    /// asking for a name containing invalid UTF-8 would match a *different*
    /// registered workspace and read that repository's files instead. Routing
    /// to the wrong repository is the multi-workspace form of returning another
    /// artifact's bytes.
    ///
    /// Only the refusal path is asserted: a successful lookup constructs a
    /// blocking `KinDaemonProvider`, which cannot be dropped inside an async
    /// context.
    #[tokio::test]
    async fn router_refuses_non_utf8_workspace_names_instead_of_collapsing_them() {
        let entries = vec![WorkspaceEntry {
            name: "project\u{fffd}".to_string(),
            path: std::path::PathBuf::from("/tmp/kin-router-test"),
            daemon_url: "http://127.0.0.1:19999".to_string(),
        }];
        let router = KinNfsRouter::new(entries);

        // A DIFFERENT byte string that lossy-decodes to the registered name
        // must NOT resolve to that workspace.
        assert!(
            matches!(
                router
                    .lookup(router.root_dir(), &b"project\xff"[..].into())
                    .await,
                Err(nfsstat3::NFS3ERR_NOENT)
            ),
            "invalid UTF-8 must not collapse onto a registered workspace name"
        );

        // An unrelated name is likewise refused.
        assert!(matches!(
            router.lookup(router.root_dir(), &b"other"[..].into()).await,
            Err(nfsstat3::NFS3ERR_NOENT)
        ));
    }
}
