// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Virtual file descriptor table.
//!
//! Virtual fds start at `VFD_BASE` (10_000) to avoid collision with real
//! kernel-allocated fds (which start at 0 and rarely exceed a few hundred
//! in normal programs).

use std::collections::HashMap;

/// Base value for virtual file descriptors.
pub const VFD_BASE: i32 = 10_000;

/// Maximum number of simultaneous virtual fds.
const MAX_VFDS: usize = 4096;

/// Size threshold for caching file content in the fd handle.
const SMALL_FILE_THRESHOLD: usize = 64 * 1024; // 64 KiB

/// A virtual file descriptor table.
pub struct FdTable {
    map: HashMap<i32, VirtualFileHandle>,
    next_fd: i32,
    /// Tracked mmap'd anonymous regions for virtual files.
    /// Maps (address, length) so we can intercept `munmap` correctly.
    mmap_regions: Vec<MmapRegion>,
    /// Real kernel fds opened for writing on workspace paths.
    /// Maps fd -> workspace path. Used to notify daemon on close.
    write_fds: HashMap<i32, String>,
    /// In-flight atomic writes. Maps real kernel fd -> atomic write metadata.
    /// On close, the temp file is renamed to the target path.
    atomic_writes: HashMap<i32, AtomicWriteEntry>,
}

/// A tracked anonymous mmap region created for a virtual file.
#[derive(Debug, Clone)]
pub struct MmapRegion {
    /// Start address of the mapping.
    pub addr: usize,
    /// Length of the mapping.
    pub len: usize,
}

/// A pre-packed directory entry for getdents/getdirentries buffer filling.
#[derive(Debug, Clone)]
pub struct DirEntryRaw {
    /// Entry name (file/directory/symlink name, no path).
    pub name: String,
    /// Inode number (synthetic, derived from hash of path).
    pub d_ino: u64,
    /// Entry type: DT_REG (8), DT_DIR (4), DT_LNK (10).
    pub d_type: u8,
}

/// State for a single open virtual file.
#[derive(Debug, Clone)]
pub struct VirtualFileHandle {
    /// Absolute path to the file.
    pub path: String,
    /// Current read offset.
    pub offset: u64,
    /// Total file size.
    pub size: u64,
    /// Cached content for small files (< 64 KiB).
    pub cached_content: Option<Vec<u8>>,
    /// Whether this fd represents a directory.
    pub is_directory: bool,
    /// Pre-fetched directory entries (only set for directory fds).
    pub dir_entries: Option<Vec<DirEntryRaw>>,
    /// How far through `dir_entries` we have read (index, not byte offset).
    pub dir_offset: usize,
    /// Workspace-relative path for files opened for writing.
    /// Set on materialize-on-write, used to notify daemon on close.
    pub write_path: Option<String>,
}

/// Metadata for an in-flight atomic write.
///
/// When a tool writes to a virtual file, content is first written to a temp
/// file (`{target}.kin_tmp_{pid}`) in the same directory. On close, the temp
/// file is atomically renamed to the final path. This prevents partial writes
/// from corrupting the real file.
#[derive(Debug, Clone)]
pub struct AtomicWriteEntry {
    /// The final target path.
    pub target_path: String,
    /// The temp file path (same directory, `.kin_tmp_{pid}` suffix).
    pub temp_path: String,
}

impl FdTable {
    /// Create a new empty fd table.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_fd: VFD_BASE,
            mmap_regions: Vec::new(),
            write_fds: HashMap::new(),
            atomic_writes: HashMap::new(),
        }
    }

    /// Allocate a new virtual fd number, advancing the counter.
    fn next_vfd(&mut self) -> Option<i32> {
        if self.map.len() >= MAX_VFDS {
            return None;
        }
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1);
        if self.next_fd < VFD_BASE {
            self.next_fd = VFD_BASE;
        }
        Some(fd)
    }

    /// Allocate a virtual fd for the given path and stat info.
    /// `content` is cached only if it fits under the small-file threshold.
    /// Returns the virtual fd, or `None` if the table is full.
    pub fn allocate(
        &mut self,
        path: &str,
        size: u64,
        content: Option<Vec<u8>>,
    ) -> Option<i32> {
        let fd = self.next_vfd()?;

        // Only cache small content.
        let cached = content.and_then(|c| {
            if c.len() <= SMALL_FILE_THRESHOLD {
                Some(c)
            } else {
                None
            }
        });

        self.map.insert(
            fd,
            VirtualFileHandle {
                path: path.to_string(),
                offset: 0,
                size,
                cached_content: cached,
                is_directory: false,
                dir_entries: None,
                dir_offset: 0,
                write_path: None,
            },
        );

        Some(fd)
    }

    /// Allocate a virtual fd for a directory, pre-loaded with entries.
    /// Returns the virtual fd, or `None` if the table is full.
    pub fn allocate_dir(
        &mut self,
        path: &str,
        entries: Vec<DirEntryRaw>,
    ) -> Option<i32> {
        let fd = self.next_vfd()?;

        self.map.insert(
            fd,
            VirtualFileHandle {
                path: path.to_string(),
                offset: 0,
                size: 0,
                cached_content: None,
                is_directory: true,
                dir_entries: Some(entries),
                dir_offset: 0,
                write_path: None,
            },
        );

        Some(fd)
    }

    /// Look up a virtual fd. Returns `None` if not found.
    pub fn get(&self, fd: i32) -> Option<&VirtualFileHandle> {
        self.map.get(&fd)
    }

    /// Look up a virtual fd mutably.
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut VirtualFileHandle> {
        self.map.get_mut(&fd)
    }

    /// Returns true if `fd` is a virtual fd managed by this table.
    pub fn is_virtual(&self, fd: i32) -> bool {
        self.map.contains_key(&fd)
    }

    /// Advance the read offset for a virtual fd. Returns the new offset.
    pub fn advance_offset(&mut self, fd: i32, bytes_read: u64) -> Option<u64> {
        let handle = self.map.get_mut(&fd)?;
        handle.offset = handle.offset.saturating_add(bytes_read);
        Some(handle.offset)
    }

    /// Seek a virtual fd. Returns the new offset, or `None` if invalid.
    ///
    /// Whence values follow libc: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2.
    pub fn seek(&mut self, fd: i32, offset: i64, whence: i32) -> Option<u64> {
        let handle = self.map.get_mut(&fd)?;
        let new_offset = match whence {
            libc::SEEK_SET => {
                if offset < 0 {
                    return None;
                }
                offset as u64
            }
            libc::SEEK_CUR => {
                let cur = handle.offset as i64;
                let new = cur.saturating_add(offset);
                if new < 0 {
                    return None;
                }
                new as u64
            }
            libc::SEEK_END => {
                let end = handle.size as i64;
                let new = end.saturating_add(offset);
                if new < 0 {
                    return None;
                }
                new as u64
            }
            _ => return None,
        };
        handle.offset = new_offset;
        Some(new_offset)
    }

    /// Close a virtual fd. Returns the handle if it existed, so the caller
    /// can check `write_path` for daemon notification.
    pub fn close(&mut self, fd: i32) -> Option<VirtualFileHandle> {
        self.map.remove(&fd)
    }

    /// Track a real kernel fd as opened for writing on a workspace path.
    /// On close, the caller can retrieve the path to notify the daemon.
    pub fn track_write(&mut self, fd: i32, path: String) {
        self.write_fds.insert(fd, path);
    }

    /// Close a tracked write fd. Returns the workspace path if found.
    pub fn close_write(&mut self, fd: i32) -> Option<String> {
        self.write_fds.remove(&fd)
    }

    /// Check if a real fd is tracked as a write fd.
    pub fn is_write_tracked(&self, fd: i32) -> bool {
        self.write_fds.contains_key(&fd)
    }

    // ── Atomic write tracking ──────────────────────────────────────────

    /// Track an in-flight atomic write: the real kernel fd writes to a temp
    /// file, which will be renamed to the target path on close.
    pub fn track_atomic_write(&mut self, fd: i32, target_path: String, temp_path: String) {
        self.atomic_writes.insert(
            fd,
            AtomicWriteEntry {
                target_path,
                temp_path,
            },
        );
    }

    /// Close an atomic write fd. Returns the entry so the caller can
    /// perform the atomic rename and notify the daemon.
    pub fn close_atomic_write(&mut self, fd: i32) -> Option<AtomicWriteEntry> {
        self.atomic_writes.remove(&fd)
    }

    /// Check if a real fd is tracked as an atomic write.
    pub fn is_atomic_write(&self, fd: i32) -> bool {
        self.atomic_writes.contains_key(&fd)
    }

    // ── mmap region tracking ────────────────────────────────────────────

    /// Record an anonymous mmap region created for a virtual file.
    pub fn track_mmap(&mut self, addr: usize, len: usize) {
        self.mmap_regions.push(MmapRegion { addr, len });
    }

    /// Check if an address is a tracked virtual mmap. If found, removes
    /// it from tracking and returns the region info.
    pub fn untrack_mmap(&mut self, addr: usize) -> Option<MmapRegion> {
        if let Some(idx) = self.mmap_regions.iter().position(|r| r.addr == addr) {
            Some(self.mmap_regions.swap_remove(idx))
        } else {
            None
        }
    }

    /// Check whether an address belongs to a tracked virtual mmap
    /// (without removing it).
    pub fn is_virtual_mmap(&self, addr: usize) -> bool {
        self.mmap_regions.iter().any(|r| r.addr == addr)
    }

    /// Number of open virtual fds.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Number of tracked mmap regions.
    #[cfg(test)]
    pub fn mmap_count(&self) -> usize {
        self.mmap_regions.len()
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_and_get() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/file.txt", 100, None).unwrap();
        assert!(fd >= VFD_BASE);

        let handle = table.get(fd).unwrap();
        assert_eq!(handle.path, "/ws/file.txt");
        assert_eq!(handle.size, 100);
        assert_eq!(handle.offset, 0);
        assert!(handle.cached_content.is_none());
    }

    #[test]
    fn allocate_with_small_content() {
        let mut table = FdTable::new();
        let content = vec![0u8; 1024]; // 1 KiB — under threshold
        let fd = table.allocate("/ws/small.txt", 1024, Some(content.clone())).unwrap();

        let handle = table.get(fd).unwrap();
        assert_eq!(handle.cached_content.as_ref().unwrap(), &content);
    }

    #[test]
    fn allocate_drops_large_content() {
        let mut table = FdTable::new();
        let content = vec![0u8; 128 * 1024]; // 128 KiB — over threshold
        let fd = table.allocate("/ws/big.bin", 131072, Some(content)).unwrap();

        let handle = table.get(fd).unwrap();
        assert!(handle.cached_content.is_none());
    }

    #[test]
    fn advance_offset() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.advance_offset(fd, 50), Some(50));
        assert_eq!(table.advance_offset(fd, 30), Some(80));
        assert_eq!(table.get(fd).unwrap().offset, 80);
    }

    #[test]
    fn seek_set() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, 100, libc::SEEK_SET), Some(100));
        assert_eq!(table.get(fd).unwrap().offset, 100);
    }

    #[test]
    fn seek_cur() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();
        table.seek(fd, 50, libc::SEEK_SET);

        assert_eq!(table.seek(fd, 25, libc::SEEK_CUR), Some(75));
        assert_eq!(table.seek(fd, -10, libc::SEEK_CUR), Some(65));
    }

    #[test]
    fn seek_end() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, 0, libc::SEEK_END), Some(200));
        assert_eq!(table.seek(fd, -50, libc::SEEK_END), Some(150));
    }

    #[test]
    fn seek_negative_result_returns_none() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, -1, libc::SEEK_SET), None);
        assert_eq!(table.seek(fd, -300, libc::SEEK_END), None);
    }

    #[test]
    fn seek_invalid_whence() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 200, None).unwrap();
        assert_eq!(table.seek(fd, 0, 99), None);
    }

    #[test]
    fn close_removes_fd() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/f.txt", 100, None).unwrap();
        assert!(table.is_virtual(fd));

        assert!(table.close(fd).is_some());
        assert!(!table.is_virtual(fd));
        assert!(table.get(fd).is_none());
    }

    #[test]
    fn close_nonexistent_returns_none() {
        let mut table = FdTable::new();
        assert!(table.close(VFD_BASE + 999).is_none());
    }

    #[test]
    fn multiple_fds() {
        let mut table = FdTable::new();
        let fd1 = table.allocate("/ws/a.txt", 10, None).unwrap();
        let fd2 = table.allocate("/ws/b.txt", 20, None).unwrap();
        let fd3 = table.allocate("/ws/c.txt", 30, None).unwrap();

        assert_ne!(fd1, fd2);
        assert_ne!(fd2, fd3);
        assert_eq!(table.len(), 3);

        assert_eq!(table.get(fd1).unwrap().path, "/ws/a.txt");
        assert_eq!(table.get(fd2).unwrap().path, "/ws/b.txt");
        assert_eq!(table.get(fd3).unwrap().path, "/ws/c.txt");
    }

    #[test]
    fn is_virtual_check() {
        let table = FdTable::new();
        // Real kernel fds are not virtual.
        assert!(!table.is_virtual(0));
        assert!(!table.is_virtual(1));
        assert!(!table.is_virtual(2));
        assert!(!table.is_virtual(255));
    }

    // ── Directory handle tests ──────────────────────────────────────────

    #[test]
    fn allocate_dir_and_get() {
        let mut table = FdTable::new();
        let entries = vec![
            DirEntryRaw { name: "foo.rs".into(), d_ino: 100, d_type: 8 },
            DirEntryRaw { name: "bar".into(), d_ino: 101, d_type: 4 },
        ];
        let fd = table.allocate_dir("/ws/src", entries.clone()).unwrap();
        assert!(fd >= VFD_BASE);

        let handle = table.get(fd).unwrap();
        assert!(handle.is_directory);
        assert_eq!(handle.dir_offset, 0);
        let dir_ents = handle.dir_entries.as_ref().unwrap();
        assert_eq!(dir_ents.len(), 2);
        assert_eq!(dir_ents[0].name, "foo.rs");
        assert_eq!(dir_ents[1].name, "bar");
    }

    #[test]
    fn dir_offset_tracking() {
        let mut table = FdTable::new();
        let entries = vec![
            DirEntryRaw { name: "a.txt".into(), d_ino: 1, d_type: 8 },
            DirEntryRaw { name: "b.txt".into(), d_ino: 2, d_type: 8 },
            DirEntryRaw { name: "c.txt".into(), d_ino: 3, d_type: 8 },
        ];
        let fd = table.allocate_dir("/ws", entries).unwrap();

        // Advance dir_offset manually.
        {
            let handle = table.get_mut(fd).unwrap();
            assert_eq!(handle.dir_offset, 0);
            handle.dir_offset = 2;
        }
        assert_eq!(table.get(fd).unwrap().dir_offset, 2);
    }

    #[test]
    fn close_dir_fd() {
        let mut table = FdTable::new();
        let fd = table.allocate_dir("/ws", vec![]).unwrap();
        assert!(table.is_virtual(fd));
        assert!(table.close(fd).is_some());
        assert!(!table.is_virtual(fd));
    }

    // ── mmap tracking tests ─────────────────────────────────────────────

    #[test]
    fn mmap_track_and_untrack() {
        let mut table = FdTable::new();
        assert_eq!(table.mmap_count(), 0);

        table.track_mmap(0x1000, 4096);
        table.track_mmap(0x2000, 8192);
        assert_eq!(table.mmap_count(), 2);
        assert!(table.is_virtual_mmap(0x1000));
        assert!(table.is_virtual_mmap(0x2000));
        assert!(!table.is_virtual_mmap(0x3000));

        let region = table.untrack_mmap(0x1000).unwrap();
        assert_eq!(region.addr, 0x1000);
        assert_eq!(region.len, 4096);
        assert_eq!(table.mmap_count(), 1);
        assert!(!table.is_virtual_mmap(0x1000));

        // Untracking nonexistent returns None.
        assert!(table.untrack_mmap(0x9999).is_none());
    }

    // ── Write tracking tests ──────────────────────────────────────────────

    #[test]
    fn track_write_and_close() {
        let mut table = FdTable::new();
        // Track a real kernel fd (3) as opened for writing.
        table.track_write(3, "/ws/src/main.rs".to_string());
        assert!(table.is_write_tracked(3));

        // Closing returns the path.
        let path = table.close_write(3).unwrap();
        assert_eq!(path, "/ws/src/main.rs");
        assert!(!table.is_write_tracked(3));
    }

    #[test]
    fn close_write_nonexistent_returns_none() {
        let mut table = FdTable::new();
        assert!(table.close_write(42).is_none());
    }

    #[test]
    fn close_read_only_vfd_has_no_write_path() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/readme.md", 256, None).unwrap();
        // Virtual read-only fd — write_path should be None.
        let handle = table.close(fd).unwrap();
        assert!(handle.write_path.is_none());
    }

    #[test]
    fn virtual_handle_default_write_path_is_none() {
        let mut table = FdTable::new();
        let fd = table.allocate("/ws/file.rs", 100, None).unwrap();
        assert!(table.get(fd).unwrap().write_path.is_none());
    }

    // ── Atomic write tracking tests ──────────────────────────────────────

    #[test]
    fn track_atomic_write_and_close() {
        let mut table = FdTable::new();
        table.track_atomic_write(
            7,
            "/ws/src/main.rs".to_string(),
            "/ws/src/main.rs.kin_tmp_12345".to_string(),
        );
        assert!(table.is_atomic_write(7));

        let entry = table.close_atomic_write(7).unwrap();
        assert_eq!(entry.target_path, "/ws/src/main.rs");
        assert_eq!(entry.temp_path, "/ws/src/main.rs.kin_tmp_12345");
        assert!(!table.is_atomic_write(7));
    }

    #[test]
    fn close_atomic_write_nonexistent_returns_none() {
        let mut table = FdTable::new();
        assert!(table.close_atomic_write(42).is_none());
    }

    #[test]
    fn atomic_write_coexists_with_write_tracking() {
        let mut table = FdTable::new();
        // Both atomic and write tracking on same fd
        table.track_write(5, "/ws/file.rs".to_string());
        table.track_atomic_write(
            5,
            "/ws/file.rs".to_string(),
            "/ws/file.rs.kin_tmp_999".to_string(),
        );

        assert!(table.is_write_tracked(5));
        assert!(table.is_atomic_write(5));

        // Close both
        let atomic = table.close_atomic_write(5).unwrap();
        assert_eq!(atomic.target_path, "/ws/file.rs");
        let write_path = table.close_write(5).unwrap();
        assert_eq!(write_path, "/ws/file.rs");
    }

    #[test]
    fn write_tracking_does_not_interfere_with_virtual_fds() {
        let mut table = FdTable::new();
        // Track a real write fd.
        table.track_write(5, "/ws/src/lib.rs".to_string());
        // Allocate a virtual fd.
        let vfd = table.allocate("/ws/other.rs", 50, None).unwrap();
        assert!(vfd >= VFD_BASE);

        // Both coexist.
        assert!(table.is_write_tracked(5));
        assert!(table.is_virtual(vfd));

        // Closing the write fd doesn't affect the virtual fd.
        table.close_write(5);
        assert!(table.is_virtual(vfd));
    }
}
