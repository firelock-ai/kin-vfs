// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider conformance test suite.
//!
//! Any implementation of `ContentProvider` must pass these tests.
//! Usage: construct your provider, call `run_all(provider)`, assert no failures.
//!
//! These tests verify the contract defined in `kin-vfs-core::provider::ContentProvider`.

use kin_vfs_core::{ContentProvider, VfsError, VfsPath};

/// Build a validated byte-exact path for a conformance fixture.
fn vpath(path: &str) -> VfsPath {
    VfsPath::from_utf8(path).expect("conformance fixture path must be valid")
}

/// The non-UTF8 fixture path every provider must serve byte-exactly.
fn raw_path() -> VfsPath {
    VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).expect("valid raw path")
}

/// Result of a single conformance check.
#[derive(Debug)]
pub struct ConformanceResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: Option<String>,
}

/// Run all conformance checks against a provider that has the following
/// test data pre-loaded:
///
/// - File `"src/main.rs"` with content `b"fn main() {}"`
/// - File `"src/lib.rs"` with content `b"// lib"`
/// - File `"README.md"` with content `b"# Hello"`
/// - File `logs/x-<0xFF><0xFE>.log` with content `b"raw bytes"` (proves byte-exact
///   path identity; the name is deliberately not valid UTF-8)
///
/// Returns a list of conformance results.
pub fn run_all<P: ContentProvider>(provider: &P) -> Vec<ConformanceResult> {
    vec![
        check_read_existing_file(provider),
        check_read_nonexistent_file(provider),
        check_read_range_within_bounds(provider),
        check_read_range_past_end(provider),
        check_read_range_at_end(provider),
        check_stat_file(provider),
        check_stat_directory(provider),
        check_stat_nonexistent(provider),
        check_read_dir_root(provider),
        check_read_dir_subdirectory(provider),
        check_exists_file(provider),
        check_exists_directory(provider),
        check_exists_nonexistent(provider),
        check_read_link_on_regular_file(provider),
        check_version_is_deterministic(provider),
        check_non_utf8_path_is_byte_exact(provider),
        check_root_is_a_directory(provider),
    ]
}

/// A provider must address artifacts by exact bytes. A repository path that is
/// not valid UTF-8 is ordinary on Unix and must serve its own content — never
/// another artifact's, and never a not-found.
fn check_non_utf8_path_is_byte_exact<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_file: non-UTF8 path serves its own exact bytes";
    match provider.read_file(&raw_path()) {
        Ok(data) if data == b"raw bytes" => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(data) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected b\"raw bytes\", got {} bytes", data.len())),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

/// The empty path is the workspace root and must stat as a directory.
fn check_root_is_a_directory<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "stat: the root path is a directory";
    match provider.stat(&VfsPath::root()) {
        Ok(stat) if stat.is_dir && !stat.is_file => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(_) => ConformanceResult {
            name,
            passed: false,
            detail: Some("root must report is_dir".to_string()),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_read_existing_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_file: existing file returns correct content";
    match provider.read_file(&vpath("src/main.rs")) {
        Ok(data) => ConformanceResult {
            name,
            passed: data == b"fn main() {}",
            detail: if data != b"fn main() {}" {
                Some(format!(
                    "expected b\"fn main() {{}}\", got {} bytes",
                    data.len()
                ))
            } else {
                None
            },
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_read_nonexistent_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_file: nonexistent path returns NotFound";
    match provider.read_file(&vpath("does/not/exist.rs")) {
        Err(VfsError::NotFound { .. }) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(data) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got Ok({} bytes)", data.len())),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got: {e}")),
        },
    }
}

fn check_read_range_within_bounds<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_range: within bounds returns correct slice";
    // "fn main() {}" — offset 3, len 4 = "main"
    match provider.read_range(&vpath("src/main.rs"), 3, 4) {
        Ok(data) => ConformanceResult {
            name,
            passed: data == b"main",
            detail: if data != b"main" {
                Some(format!(
                    "expected b\"main\", got {:?}",
                    String::from_utf8_lossy(&data)
                ))
            } else {
                None
            },
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_read_range_past_end<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_range: past end returns available bytes (no error)";
    // "fn main() {}" is 12 bytes; offset 10, len 100 should return 2 bytes
    match provider.read_range(&vpath("src/main.rs"), 10, 100) {
        Ok(data) => ConformanceResult {
            name,
            passed: data.len() <= 2,
            detail: if data.len() > 2 {
                Some(format!("expected <= 2 bytes, got {}", data.len()))
            } else {
                None
            },
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_read_range_at_end<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_range: offset at or past file size returns empty";
    match provider.read_range(&vpath("src/main.rs"), 1000, 10) {
        Ok(data) => ConformanceResult {
            name,
            passed: data.is_empty(),
            detail: if !data.is_empty() {
                Some(format!("expected empty, got {} bytes", data.len()))
            } else {
                None
            },
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_stat_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "stat: file returns is_file=true, correct size";
    match provider.stat(&vpath("src/main.rs")) {
        Ok(stat) => {
            let ok = stat.is_file && !stat.is_dir && stat.size == 12;
            ConformanceResult {
                name,
                passed: ok,
                detail: if !ok {
                    Some(format!(
                        "is_file={}, is_dir={}, size={} (expected is_file=true, is_dir=false, size=12)",
                        stat.is_file, stat.is_dir, stat.size
                    ))
                } else {
                    None
                },
            }
        }
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_stat_directory<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "stat: directory returns is_dir=true";
    match provider.stat(&vpath("src")) {
        Ok(stat) => ConformanceResult {
            name,
            passed: stat.is_dir && !stat.is_file,
            detail: if !stat.is_dir || stat.is_file {
                Some(format!("is_file={}, is_dir={}", stat.is_file, stat.is_dir))
            } else {
                None
            },
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_stat_nonexistent<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "stat: nonexistent path returns NotFound";
    match provider.stat(&vpath("nope/nothing")) {
        Err(VfsError::NotFound { .. }) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(stat) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!(
                "expected NotFound, got stat (is_file={}, is_dir={})",
                stat.is_file, stat.is_dir
            )),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got: {e}")),
        },
    }
}

fn check_read_dir_root<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_dir: root lists top-level entries";
    match provider.read_dir(&VfsPath::root()) {
        Ok(entries) => {
            let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_bytes()).collect();
            let has_src = names.contains(&&b"src"[..]);
            let has_readme = names.contains(&&b"README.md"[..]);
            ConformanceResult {
                name,
                passed: has_src && has_readme,
                detail: if !(has_src && has_readme) {
                    Some(format!(
                        "expected entries to contain 'src' and 'README.md', got: {:?}",
                        names
                    ))
                } else {
                    None
                },
            }
        }
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_read_dir_subdirectory<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_dir: subdirectory lists correct children";
    match provider.read_dir(&vpath("src")) {
        Ok(entries) => {
            let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_bytes()).collect();
            let has_main = names.contains(&&b"main.rs"[..]);
            let has_lib = names.contains(&&b"lib.rs"[..]);
            ConformanceResult {
                name,
                passed: has_main && has_lib && entries.len() == 2,
                detail: if !(has_main && has_lib && entries.len() == 2) {
                    Some(format!("expected [main.rs, lib.rs], got: {:?}", names))
                } else {
                    None
                },
            }
        }
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("unexpected error: {e}")),
        },
    }
}

fn check_exists_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "exists: existing file returns true";
    match provider.exists(&vpath("src/main.rs")) {
        Ok(true) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(false) => ConformanceResult {
            name,
            passed: false,
            detail: Some("returned false".into()),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("error: {e}")),
        },
    }
}

fn check_exists_directory<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "exists: existing directory returns true";
    match provider.exists(&vpath("src")) {
        Ok(true) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(false) => ConformanceResult {
            name,
            passed: false,
            detail: Some("returned false".into()),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("error: {e}")),
        },
    }
}

fn check_exists_nonexistent<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "exists: nonexistent path returns false";
    match provider.exists(&vpath("nope/nothing")) {
        Ok(false) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(true) => ConformanceResult {
            name,
            passed: false,
            detail: Some("returned true".into()),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("error: {e}")),
        },
    }
}

fn check_read_link_on_regular_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_link: a regular file reports InvalidInput";
    // POSIX `readlink(2)` on a non-symlink is EINVAL, not ENOENT: the path
    // exists, the operation does not apply. Reporting NotFound would tell a
    // caller the artifact is absent when it is present and readable.
    match provider.read_link(&vpath("src/main.rs")) {
        Err(VfsError::InvalidInput { .. }) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(target) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected InvalidInput, got Ok({target:?})")),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected InvalidInput, got: {e}")),
        },
    }
}

fn check_version_is_deterministic<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "version: consecutive calls return same value (no mutation)";
    let v1 = provider.version();
    let v2 = provider.version();
    ConformanceResult {
        name,
        passed: v1 == v2,
        detail: if v1 != v2 {
            Some(format!("v1={v1}, v2={v2}"))
        } else {
            None
        },
    }
}

// ── Built-in test: run conformance against an in-memory provider ────────

#[cfg(test)]
mod tests {
    use super::*;
    use kin_vfs_core::{DirEntry, FileType, VfsName, VfsResult, VirtualStat};
    use std::collections::HashMap;

    /// Reference provider carrying the documented conformance fixture,
    /// including the non-UTF8 path.
    struct MemoryProvider {
        files: HashMap<VfsPath, Vec<u8>>,
    }

    impl MemoryProvider {
        fn new() -> Self {
            let mut files = HashMap::new();
            files.insert(vpath("src/main.rs"), b"fn main() {}".to_vec());
            files.insert(vpath("src/lib.rs"), b"// lib".to_vec());
            files.insert(vpath("README.md"), b"# Hello".to_vec());
            files.insert(raw_path(), b"raw bytes".to_vec());
            Self { files }
        }

        fn directories(&self) -> std::collections::HashSet<VfsPath> {
            let mut dirs = std::collections::HashSet::new();
            dirs.insert(VfsPath::root());
            for path in self.files.keys() {
                let mut current = path.parent();
                while let Some(dir) = current {
                    current = dir.parent();
                    dirs.insert(dir);
                }
            }
            dirs
        }
    }

    impl ContentProvider for MemoryProvider {
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
            let end = start.saturating_add(len as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            if let Some(data) = self.files.get(path) {
                return Ok(VirtualStat::regular_file(
                    data.len() as u64,
                    [0u8; 32],
                    false,
                    0,
                ));
            }
            if self.directories().contains(path) {
                return Ok(VirtualStat::directory(0));
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
                    name: VfsName::from_bytes(name.to_vec()).expect("valid name"),
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
            Ok(self.files.contains_key(path) || self.directories().contains(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::InvalidInput {
                path: path.to_string(),
            })
        }
    }

    #[test]
    fn reference_provider_passes_every_conformance_check() {
        let results = run_all(&MemoryProvider::new());
        let failures: Vec<&ConformanceResult> = results.iter().filter(|r| !r.passed).collect();
        assert!(
            failures.is_empty(),
            "conformance failures: {:?}",
            failures
                .iter()
                .map(|r| (r.name, r.detail.as_deref()))
                .collect::<Vec<_>>()
        );
        assert!(results.len() >= 17, "expected the full check set");
    }
}
