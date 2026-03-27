// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! ContentProvider conformance test suite.
//!
//! Any implementation of `ContentProvider` must pass these tests.
//! Usage: construct your provider, call `run_all(provider)`, assert no failures.
//!
//! These tests verify the contract defined in `kin-vfs-core::provider::ContentProvider`.

use kin_vfs_core::{ContentProvider, VfsError};

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
///
/// Returns a list of conformance results.
pub fn run_all<P: ContentProvider>(provider: &P) -> Vec<ConformanceResult> {
    let mut results = Vec::new();

    results.push(check_read_existing_file(provider));
    results.push(check_read_nonexistent_file(provider));
    results.push(check_read_range_within_bounds(provider));
    results.push(check_read_range_past_end(provider));
    results.push(check_read_range_at_end(provider));
    results.push(check_stat_file(provider));
    results.push(check_stat_directory(provider));
    results.push(check_stat_nonexistent(provider));
    results.push(check_read_dir_root(provider));
    results.push(check_read_dir_subdirectory(provider));
    results.push(check_exists_file(provider));
    results.push(check_exists_directory(provider));
    results.push(check_exists_nonexistent(provider));
    results.push(check_read_link_default(provider));
    results.push(check_version_is_deterministic(provider));

    results
}

fn check_read_existing_file<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_file: existing file returns correct content";
    match provider.read_file("src/main.rs") {
        Ok(data) => ConformanceResult {
            name,
            passed: data == b"fn main() {}",
            detail: if data != b"fn main() {}" {
                Some(format!("expected b\"fn main() {{}}\", got {} bytes", data.len()))
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
    match provider.read_file("does/not/exist.rs") {
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
    match provider.read_range("src/main.rs", 3, 4) {
        Ok(data) => ConformanceResult {
            name,
            passed: data == b"main",
            detail: if data != b"main" {
                Some(format!("expected b\"main\", got {:?}", String::from_utf8_lossy(&data)))
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
    match provider.read_range("src/main.rs", 10, 100) {
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
    match provider.read_range("src/main.rs", 1000, 10) {
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
    match provider.stat("src/main.rs") {
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
    match provider.stat("src") {
        Ok(stat) => ConformanceResult {
            name,
            passed: stat.is_dir && !stat.is_file,
            detail: if !(stat.is_dir && !stat.is_file) {
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
    match provider.stat("nope/nothing") {
        Err(VfsError::NotFound { .. }) => ConformanceResult {
            name,
            passed: true,
            detail: None,
        },
        Ok(stat) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got stat (is_file={}, is_dir={})", stat.is_file, stat.is_dir)),
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
    match provider.read_dir("") {
        Ok(entries) => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            let has_src = names.contains(&"src");
            let has_readme = names.contains(&"README.md");
            ConformanceResult {
                name,
                passed: has_src && has_readme,
                detail: if !(has_src && has_readme) {
                    Some(format!("expected entries to contain 'src' and 'README.md', got: {:?}", names))
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
    match provider.read_dir("src") {
        Ok(entries) => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            let has_main = names.contains(&"main.rs");
            let has_lib = names.contains(&"lib.rs");
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
    match provider.exists("src/main.rs") {
        Ok(true) => ConformanceResult { name, passed: true, detail: None },
        Ok(false) => ConformanceResult { name, passed: false, detail: Some("returned false".into()) },
        Err(e) => ConformanceResult { name, passed: false, detail: Some(format!("error: {e}")) },
    }
}

fn check_exists_directory<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "exists: existing directory returns true";
    match provider.exists("src") {
        Ok(true) => ConformanceResult { name, passed: true, detail: None },
        Ok(false) => ConformanceResult { name, passed: false, detail: Some("returned false".into()) },
        Err(e) => ConformanceResult { name, passed: false, detail: Some(format!("error: {e}")) },
    }
}

fn check_exists_nonexistent<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "exists: nonexistent path returns false";
    match provider.exists("nope/nothing") {
        Ok(false) => ConformanceResult { name, passed: true, detail: None },
        Ok(true) => ConformanceResult { name, passed: false, detail: Some("returned true".into()) },
        Err(e) => ConformanceResult { name, passed: false, detail: Some(format!("error: {e}")) },
    }
}

fn check_read_link_default<P: ContentProvider>(provider: &P) -> ConformanceResult {
    let name = "read_link: default impl returns NotFound";
    match provider.read_link("src/main.rs") {
        Err(VfsError::NotFound { .. }) => ConformanceResult { name, passed: true, detail: None },
        Ok(target) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got Ok({target})")),
        },
        Err(e) => ConformanceResult {
            name,
            passed: false,
            detail: Some(format!("expected NotFound, got: {e}")),
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
    use kin_vfs_core::{DirEntry, FileType, VfsResult, VirtualStat};
    use std::collections::HashMap;

    struct MemoryProvider {
        files: HashMap<String, Vec<u8>>,
    }

    impl MemoryProvider {
        fn test_fixture() -> Self {
            let mut files = HashMap::new();
            files.insert("src/main.rs".into(), b"fn main() {}".to_vec());
            files.insert("src/lib.rs".into(), b"// lib".to_vec());
            files.insert("README.md".into(), b"# Hello".to_vec());
            Self { files }
        }

        fn directories(&self) -> std::collections::HashSet<String> {
            let mut dirs = std::collections::HashSet::new();
            dirs.insert(String::new());
            for path in self.files.keys() {
                if let Some(last_slash) = path.rfind('/') {
                    let mut prefix = String::new();
                    for component in path[..last_slash].split('/') {
                        if !prefix.is_empty() {
                            prefix.push('/');
                        }
                        prefix.push_str(component);
                        dirs.insert(prefix.clone());
                    }
                }
            }
            dirs
        }
    }

    impl ContentProvider for MemoryProvider {
        fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound { path: path.to_string() })
        }

        fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            if start >= data.len() {
                return Ok(vec![]);
            }
            let end = std::cmp::min(start + len as usize, data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
            if let Some(data) = self.files.get(path) {
                Ok(VirtualStat::file(data.len() as u64, [0u8; 32], 0))
            } else if self.directories().contains(path) {
                Ok(VirtualStat::directory(0))
            } else {
                Err(VfsError::NotFound { path: path.to_string() })
            }
        }

        fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{}/", path)
            };

            let mut seen = std::collections::HashSet::new();
            let mut entries = Vec::new();

            for file_path in self.files.keys() {
                let rest = if prefix.is_empty() {
                    file_path.as_str()
                } else if let Some(r) = file_path.strip_prefix(&prefix) {
                    r
                } else {
                    continue;
                };

                let child_name = if let Some(slash) = rest.find('/') {
                    &rest[..slash]
                } else {
                    rest
                };

                if !child_name.is_empty() && seen.insert(child_name.to_string()) {
                    let is_dir = rest.contains('/');
                    entries.push(DirEntry {
                        name: child_name.to_string(),
                        file_type: if is_dir { FileType::Directory } else { FileType::File },
                    });
                }
            }

            if !path.is_empty() && entries.is_empty() && !self.directories().contains(path) {
                return Err(VfsError::NotFound { path: path.to_string() });
            }

            Ok(entries)
        }

        fn exists(&self, path: &str) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.directories().contains(path))
        }
    }

    #[test]
    fn all_conformance_checks_pass() {
        let provider = MemoryProvider::test_fixture();
        let results = run_all(&provider);

        let mut failures = Vec::new();
        for r in &results {
            if !r.passed {
                failures.push(format!(
                    "FAIL: {} — {}",
                    r.name,
                    r.detail.as_deref().unwrap_or("no detail")
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "Conformance failures:\n{}",
            failures.join("\n")
        );
    }
}
