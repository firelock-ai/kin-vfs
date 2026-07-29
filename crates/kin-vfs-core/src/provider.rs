// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::path::VfsPath;
use crate::{DirEntry, VfsResult, VirtualStat};
use sha2::{Digest, Sha256};

/// Trait for anything that can serve file content by byte-exact path.
///
/// This is the standalone-valuable abstraction. Any project can implement
/// this to back a VirtualFileTree — blob stores, HTTP backends, in-memory
/// maps, or Kin's semantic graph. Paths are validated [`VfsPath`] values:
/// byte-exact, workspace-relative, with the empty path as the root. `String`
/// is never a path identity here.
pub trait ContentProvider: Send + Sync {
    /// Read the full content of a file.
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>>;

    /// Read a byte range from a file.
    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>>;

    /// Read content pinned to an exact identity captured by an open descriptor.
    ///
    /// The default implementation is fail-closed compatibility for providers
    /// that do not expose content-addressed lookup directly: it first checks
    /// the current path binding, reads the whole object, and independently
    /// verifies the returned size and SHA-256 before slicing. The post-read
    /// digest closes the stat/read race; a concurrent replacement can never
    /// return different bytes under the opened identity. Providers backed by
    /// a blob store should override this and resolve `content_hash` directly,
    /// which also preserves access after unlink or rename without whole-file
    /// fallback reads.
    fn read_blob(
        &self,
        content_hash: [u8; 32],
        total_size: u64,
        path_hint: &VfsPath,
        offset: u64,
        len: u64,
    ) -> VfsResult<Vec<u8>> {
        let stat = self.stat(path_hint)?;
        if stat.content_hash != Some(content_hash) || stat.size != total_size {
            return Err(crate::VfsError::Provider(format!(
                "open descriptor identity changed for {path_hint}"
            )));
        }
        let data = self.read_file(path_hint)?;
        let actual_hash: [u8; 32] = Sha256::digest(&data).into();
        if u64::try_from(data.len()).ok() != Some(total_size) || actual_hash != content_hash {
            return Err(crate::VfsError::Provider(format!(
                "open descriptor bytes changed for {path_hint}"
            )));
        }
        if offset == 0 && len == 0 {
            return Ok(data);
        }
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = start
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            .min(data.len());
        Ok(data[start..end].to_vec())
    }

    /// Get metadata for a path (file or directory).
    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat>;

    /// List entries in a directory.
    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>>;

    /// Check if a path exists.
    fn exists(&self, path: &VfsPath) -> VfsResult<bool>;

    /// Read a symbolic link target as its exact stored bytes.
    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>>;

    /// Return a monotonically increasing version counter.
    /// Used for cache invalidation — when this changes, cached data may be
    /// stale. Once a non-zero authority version has been observed, transient
    /// refresh failure must retain it rather than regressing to zero.
    fn version(&self) -> u64 {
        0
    }
}

/// Async counterpart of [`ContentProvider`] for use in async contexts.
///
/// The VFS daemon server runs on tokio but the original `ContentProvider`
/// trait is synchronous (required by the shim, which has no async runtime).
/// Implementors that talk to async backends (e.g. reqwest async HTTP) should
/// implement this trait to avoid `spawn_blocking` overhead.
pub trait AsyncContentProvider: Send + Sync {
    /// Read the full content of a file.
    fn read_file(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Read a byte range from a file.
    fn read_range(
        &self,
        path: &VfsPath,
        offset: u64,
        len: u64,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Get metadata for a path (file or directory).
    fn stat(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<VirtualStat>> + Send;

    /// List entries in a directory.
    fn read_dir(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<DirEntry>>> + Send;

    /// Check if a path exists.
    fn exists(&self, path: &VfsPath) -> impl std::future::Future<Output = VfsResult<bool>> + Send;

    /// Read a symbolic link target as its exact stored bytes.
    fn read_link(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Return a monotonically increasing version counter. Once established,
    /// transient refresh failure must retain the last validated value.
    fn version(&self) -> impl std::future::Future<Output = u64> + Send {
        async { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VfsError;

    struct RaceProvider {
        advertised: Vec<u8>,
        returned: Vec<u8>,
    }

    impl ContentProvider for RaceProvider {
        fn read_file(&self, _path: &VfsPath) -> VfsResult<Vec<u8>> {
            Ok(self.returned.clone())
        }

        fn read_range(&self, _path: &VfsPath, _offset: u64, _len: u64) -> VfsResult<Vec<u8>> {
            unreachable!("descriptor fallback verifies a complete body before slicing")
        }

        fn stat(&self, _path: &VfsPath) -> VfsResult<VirtualStat> {
            Ok(VirtualStat::regular_file(
                self.advertised.len() as u64,
                Sha256::digest(&self.advertised).into(),
                false,
                1,
            ))
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            Err(VfsError::NotDirectory {
                path: path.to_string(),
            })
        }

        fn exists(&self, _path: &VfsPath) -> VfsResult<bool> {
            Ok(true)
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::InvalidInput {
                path: path.to_string(),
            })
        }
    }

    #[test]
    fn default_blob_fallback_verifies_post_read_identity_before_slicing() {
        let path = VfsPath::from_utf8("large.bin").unwrap();
        let original = b"original descriptor bytes".to_vec();
        let hash: [u8; 32] = Sha256::digest(&original).into();

        let stable = RaceProvider {
            advertised: original.clone(),
            returned: original,
        };
        assert_eq!(
            stable.read_blob(hash, 25, &path, 9, 10).unwrap(),
            b"descriptor"
        );

        let replaced = RaceProvider {
            advertised: b"original descriptor bytes".to_vec(),
            returned: b"replacement object bytes".to_vec(),
        };
        assert!(
            matches!(
                replaced.read_blob(hash, 25, &path, 0, 1),
                Err(VfsError::Provider(_))
            ),
            "a replacement between stat and read must fail closed"
        );
    }
}
