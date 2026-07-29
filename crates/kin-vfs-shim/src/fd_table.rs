// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Virtual file descriptor table.
//!
//! Virtual fds start above the process's RLIMIT_NOFILE soft limit (with a
//! floor of 10,000) to avoid collision with real kernel-allocated fds. The
//! base is computed once at init time via `vfd_base()`. On wrap-around,
//! occupied slots are skipped; if all slots are taken, allocation returns
//! `None` (the EMFILE equivalent).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use kin_vfs_core::VirtualStat;
use parking_lot::{Mutex, MutexGuard};

/// Maximum number of simultaneous virtual fds.
const MAX_VFDS: usize = 4096;

/// Lazily computed VFD base, placed above the process's RLIMIT_NOFILE.
static VFD_BASE_CELL: OnceLock<i32> = OnceLock::new();

/// Compute the VFD base from the soft RLIMIT_NOFILE.
///
/// Virtual fds are placed above the maximum possible real fd so that the
/// kernel can never allocate a real fd that collides with a virtual one.
fn compute_vfd_base() -> i32 {
    #[cfg(unix)]
    {
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if ret == 0 && rlim.rlim_cur != libc::RLIM_INFINITY {
            // Place VFDs 1000 above the soft limit, with a floor of 10_000.
            let base = (rlim.rlim_cur as i32).saturating_add(1000);
            return base.max(10_000);
        }
    }
    // Fallback for non-Unix or when getrlimit fails.
    100_000
}

/// Returns the VFD base value, computing it once on first call.
pub fn vfd_base() -> i32 {
    *VFD_BASE_CELL.get_or_init(compute_vfd_base)
}

/// Size threshold for caching file content in the fd handle.
///
/// Public so the interpose `open`/`openat` read path can make the same
/// small-vs-large decision *before* fetching: a file at or under this size is
/// pulled whole and cached for zero-roundtrip reads, while a larger file is left
/// uncached and served by range reads — so the shim never loads a large file
/// wholesale (nor fetches bytes it would immediately discard).
pub const SMALL_FILE_THRESHOLD: usize = 64 * 1024; // 64 KiB

/// A virtual file descriptor table.
///
/// # Signal Safety
///
/// This table is wrapped in a `parking_lot::RwLock` in `ShimState` (lib.rs).
/// `parking_lot::RwLock` is NOT async-signal-safe. This is inherent to the
/// LD_PRELOAD/DYLD_INSERT_LIBRARIES approach -- the shim runs in the context of
/// arbitrary host processes, and signal handlers in those processes could
/// interrupt a lock acquisition. In practice, this is extremely unlikely to
/// cause issues because:
///
/// 1. Signal handlers rarely call file I/O functions that would enter the shim.
/// 2. Lock hold times are microseconds (hash lookup + offset update).
/// 3. parking_lot uses adaptive spinning, reducing signal-deadlock risk compared
///    to pthread mutexes.
///
/// This is a known limitation accepted in the VFS architecture decision.
pub struct FdTable {
    map: HashMap<i32, VirtualFileHandle>,
    next_fd: i32,
    /// Tracked mmap'd anonymous regions for virtual files.
    /// Maps (address, length) so we can intercept `munmap` correctly.
    mmap_regions: Vec<MmapRegion>,
    /// Real kernel fds opened for writing on workspace paths.
    /// Maps fd -> exact workspace path bytes. Used to notify the daemon on
    /// close.
    write_fds: HashMap<i32, Vec<u8>>,
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
    /// Exact entry-name bytes (file/directory/symlink name, no path).
    ///
    /// Packed verbatim into `getdents64`/`getdirentries` records, so a name
    /// that is not valid UTF-8 reaches the host tool unchanged.
    pub name: Vec<u8>,
    /// Inode number supplied by the graph listing identity, or zero when the
    /// provider cannot expose one.
    pub d_ino: u64,
    /// Entry type: DT_REG (8), DT_DIR (4), DT_LNK (10).
    pub d_type: u8,
}

/// Mutable state belonging to one open-file description.
///
/// POSIX descriptors created by `dup`, `dup2`, and `dup3` refer to the same
/// open-file description. In particular, they share the byte offset and
/// directory-stream position. Keeping those cursors behind one reference-
/// counted mutex also serializes an uncached range read with `lseek` and other
/// reads on every duplicate.
#[derive(Debug, Default)]
pub struct OpenFileDescriptionState {
    /// Current read offset.
    pub offset: u64,
    /// How far through `dir_entries` we have read (index, not byte offset).
    pub dir_offset: usize,
    /// Whether this open-file description currently owns an advisory flock.
    ///
    /// `flock(2)` state follows the open-file description rather than an
    /// individual descriptor, so every `dup` alias observes unlocks and the
    /// lock survives closing any one alias.
    pub flocked: bool,
    /// Real kernel descriptor holding an anonymous, byte-exact copy of this
    /// graph file once an operation exposes it to the native descriptor table.
    ///
    /// The descriptor is owned by the shared open-file-description state, so
    /// every synthetic and ordinary duplicate uses the same kernel open-file
    /// description for offsets across `fcntl`, `fork`, and `exec`.
    pub native_backing_fd: Option<i32>,
}

impl Drop for OpenFileDescriptionState {
    fn drop(&mut self) {
        if let Some(fd) = self.native_backing_fd.take() {
            // This may re-enter the shim when the last descriptor is closed
            // from inside an intercepted call. The outer re-entry guard routes
            // that nested close directly to libc.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// Why a virtual descriptor duplication failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateError {
    /// The source descriptor is not present in the virtual table.
    NotVirtual,
    /// The source is valid but no virtual descriptor slot remains.
    TableFull,
}

/// Why a virtual seek failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekError {
    /// The whence or resulting negative offset is invalid.
    Invalid,
    /// The requested result cannot be represented by `off_t`.
    Overflow,
}

/// State for a single virtual descriptor.
#[derive(Debug, Clone)]
pub struct VirtualFileHandle {
    /// Absolute host path to the file, as exact bytes.
    pub path: Vec<u8>,
    /// Metadata captured when this descriptor opened.
    ///
    /// Native descriptor identity survives unlink, rename, and path
    /// replacement. Descriptor-based stat operations must therefore use this
    /// snapshot rather than re-querying `path`.
    pub opened_stat: Option<VirtualStat>,
    /// Stable synthetic inode captured at open.
    pub opened_inode: u64,
    /// Link target captured for Linux `O_PATH|O_NOFOLLOW` descriptors.
    pub link_target: Option<Vec<u8>>,
    /// Total file size.
    pub size: u64,
    /// Cached content for small files (< 64 KiB).
    pub cached_content: Option<Vec<u8>>,
    /// Whether this fd represents a directory.
    pub is_directory: bool,
    /// Whether data/directory IO is permitted on this descriptor.
    ///
    /// Linux access-mode 3 creates a metadata-only descriptor: `fstat` and
    /// close are valid, but read/write/mmap/getdents/lseek must fail with
    /// EBADF. Keeping this right on the handle prevents that check-only mode
    /// from being silently upgraded to an ordinary readable virtual fd.
    pub io_permitted: bool,
    /// Linux `O_PATH` descriptor: path/metadata operations only.
    pub path_only: bool,
    /// Pre-fetched directory entries (only set for directory fds).
    pub dir_entries: Option<Vec<DirEntryRaw>>,
    /// Open-file status flags reported by `F_GETFL`.
    pub status_flags: i32,
    /// Per-descriptor flags reported by `F_GETFD`.
    pub descriptor_flags: i32,
    /// Shared mutable open-file-description state.
    open_file: Arc<Mutex<OpenFileDescriptionState>>,
    /// Whether this descriptor number has a matching kernel descriptor.
    ///
    /// Synthetic descriptors above `vfd_base()` need no reservation. A
    /// `dup2`/`dup3` destination in the ordinary kernel range does: without a
    /// kernel duplicate of the graph-backed open file description, the next
    /// native `open` could reuse that integer while the shim still treats it
    /// as virtual.
    pub kernel_backed: bool,
    /// Workspace-relative path bytes for files opened for writing.
    /// Set on materialize-on-write, used to notify the daemon on close.
    pub write_path: Option<Vec<u8>>,
}

impl VirtualFileHandle {
    /// Lock the shared open-file-description cursors.
    ///
    /// Callers performing a position-dependent blocking read intentionally
    /// retain this guard across the daemon request. That gives duplicated
    /// descriptors the same serialization and cursor semantics as a kernel
    /// open-file description.
    pub fn lock_open_file(&self) -> MutexGuard<'_, OpenFileDescriptionState> {
        self.open_file.lock()
    }

    /// Snapshot the current byte offset.
    pub fn offset(&self) -> u64 {
        self.open_file.lock().offset
    }

    /// Snapshot the current directory-stream position.
    pub fn dir_offset(&self) -> usize {
        self.open_file.lock().dir_offset
    }

    /// Update the shared directory-stream position.
    pub fn set_dir_offset(&self, offset: usize) {
        self.open_file.lock().dir_offset = offset;
    }

    /// Return the kernel descriptor shared by this open-file description once
    /// it has crossed into the native descriptor table.
    pub fn native_backing_fd(&self) -> Option<i32> {
        self.open_file.lock().native_backing_fd
    }
}

#[derive(Default)]
struct OpenedFileState {
    opened_stat: Option<VirtualStat>,
    path_only: bool,
    link_target: Option<Vec<u8>>,
}

/// Rights and descriptor flags captured by a graph-backed file open.
#[derive(Debug, Clone)]
pub struct OpenedFileOptions {
    /// Whether data I/O is permitted.
    pub io_permitted: bool,
    /// Whether this is a Linux metadata-only `O_PATH` descriptor.
    pub path_only: bool,
    /// Link target captured for `O_PATH|O_NOFOLLOW`.
    pub link_target: Option<Vec<u8>>,
    /// Original open flags used to derive status and descriptor flags.
    pub flags: i32,
}

/// Metadata for an in-flight atomic write.
///
/// When a tool writes to a virtual file, content is first written to a temp
/// file (`{target}.kin_tmp_{pid}`) in the same directory. On close, the temp
/// file is atomically renamed to the final path. This prevents partial writes
/// from corrupting the real file.
#[derive(Debug, Clone)]
pub struct AtomicWriteEntry {
    /// The final target path, as exact bytes.
    pub target_path: Vec<u8>,
    /// The temp file path (same directory, `.kin_tmp_{pid}` suffix).
    pub temp_path: Vec<u8>,
}

impl FdTable {
    /// Create a new empty fd table.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_fd: vfd_base(),
            mmap_regions: Vec::new(),
            write_fds: HashMap::new(),
            atomic_writes: HashMap::new(),
        }
    }

    /// Allocate a new virtual fd number, advancing the counter.
    ///
    /// Scans forward from `next_fd` looking for an unoccupied slot. If
    /// wrap-around brings us back to the starting point with every slot
    /// occupied, returns `None` (EMFILE equivalent).
    fn next_vfd(&mut self) -> Option<i32> {
        if self.map.len() >= MAX_VFDS {
            return None;
        }
        let base = vfd_base();
        // Try up to MAX_VFDS slots to find one that is not already occupied.
        for _ in 0..MAX_VFDS {
            let fd = self.next_fd;
            self.next_fd = self.next_fd.wrapping_add(1);
            if self.next_fd < base || self.next_fd >= base + MAX_VFDS as i32 {
                self.next_fd = base;
            }
            if !self.map.contains_key(&fd) {
                return Some(fd);
            }
        }
        None // All slots occupied.
    }

    /// Allocate a virtual fd for the given path and stat info.
    /// `content` is cached only if it fits under the small-file threshold.
    /// Returns the virtual fd, or `None` if the table is full.
    pub fn allocate(&mut self, path: &[u8], size: u64, content: Option<Vec<u8>>) -> Option<i32> {
        self.allocate_with_io(
            path,
            size,
            content,
            true,
            OpenedFileState::default(),
            libc::O_RDONLY,
        )
    }

    /// Allocate a Linux access-mode-3 metadata-only file descriptor.
    pub fn allocate_check_only(
        &mut self,
        path: &[u8],
        size: u64,
        content: Option<Vec<u8>>,
    ) -> Option<i32> {
        self.allocate_with_io(
            path,
            size,
            content,
            false,
            OpenedFileState::default(),
            libc::O_ACCMODE,
        )
    }

    /// Allocate a production descriptor with its open-time identity pinned.
    pub fn allocate_opened(
        &mut self,
        path: &[u8],
        stat: VirtualStat,
        content: Option<Vec<u8>>,
        options: OpenedFileOptions,
    ) -> Option<i32> {
        let size = stat.size;
        self.allocate_with_io(
            path,
            size,
            content,
            options.io_permitted,
            OpenedFileState {
                opened_stat: Some(stat),
                path_only: options.path_only,
                link_target: options.link_target,
            },
            options.flags,
        )
    }

    fn allocate_with_io(
        &mut self,
        path: &[u8],
        size: u64,
        content: Option<Vec<u8>>,
        io_permitted: bool,
        opened: OpenedFileState,
        flags: i32,
    ) -> Option<i32> {
        let fd = self.next_vfd()?;
        let opened_inode = opened
            .opened_stat
            .as_ref()
            .and_then(|stat| stat.object_id.as_ref())
            .map(kin_vfs_core::pathmap::synthetic_object_inode)
            .unwrap_or_else(|| kin_vfs_core::pathmap::synthetic_inode(path));

        // Only cache small content.
        let cached = content.filter(|c| c.len() <= SMALL_FILE_THRESHOLD);

        self.map.insert(
            fd,
            VirtualFileHandle {
                path: path.to_vec(),
                opened_stat: opened.opened_stat,
                opened_inode,
                link_target: opened.link_target,
                size,
                cached_content: cached,
                is_directory: false,
                io_permitted,
                path_only: opened.path_only,
                dir_entries: None,
                status_flags: flags & !libc::O_CLOEXEC,
                descriptor_flags: if flags & libc::O_CLOEXEC != 0 {
                    libc::FD_CLOEXEC
                } else {
                    0
                },
                open_file: Arc::new(Mutex::new(OpenFileDescriptionState::default())),
                kernel_backed: false,
                write_path: None,
            },
        );

        Some(fd)
    }

    /// Allocate a virtual fd for a directory, pre-loaded with entries.
    /// Returns the virtual fd, or `None` if the table is full.
    pub fn allocate_dir(&mut self, path: &[u8], entries: Vec<DirEntryRaw>) -> Option<i32> {
        self.allocate_dir_with_io(path, entries, true, false, None, libc::O_RDONLY)
    }

    /// Allocate a Linux access-mode-3 metadata-only directory descriptor.
    pub fn allocate_dir_check_only(
        &mut self,
        path: &[u8],
        entries: Vec<DirEntryRaw>,
    ) -> Option<i32> {
        self.allocate_dir_with_io(path, entries, false, false, None, libc::O_ACCMODE)
    }

    /// Allocate a production directory descriptor with open-time metadata.
    pub fn allocate_opened_dir(
        &mut self,
        path: &[u8],
        stat: VirtualStat,
        entries: Vec<DirEntryRaw>,
        io_permitted: bool,
        path_only: bool,
        flags: i32,
    ) -> Option<i32> {
        self.allocate_dir_with_io(path, entries, io_permitted, path_only, Some(stat), flags)
    }

    fn allocate_dir_with_io(
        &mut self,
        path: &[u8],
        entries: Vec<DirEntryRaw>,
        io_permitted: bool,
        path_only: bool,
        opened_stat: Option<VirtualStat>,
        flags: i32,
    ) -> Option<i32> {
        let fd = self.next_vfd()?;
        let opened_inode = opened_stat
            .as_ref()
            .and_then(|stat| stat.object_id.as_ref())
            .map(kin_vfs_core::pathmap::synthetic_object_inode)
            .unwrap_or_else(|| kin_vfs_core::pathmap::synthetic_inode(path));

        self.map.insert(
            fd,
            VirtualFileHandle {
                path: path.to_vec(),
                opened_stat,
                opened_inode,
                link_target: None,
                size: 0,
                cached_content: None,
                is_directory: true,
                io_permitted,
                path_only,
                dir_entries: Some(entries),
                status_flags: flags & !libc::O_CLOEXEC,
                descriptor_flags: if flags & libc::O_CLOEXEC != 0 {
                    libc::FD_CLOEXEC
                } else {
                    0
                },
                open_file: Arc::new(Mutex::new(OpenFileDescriptionState::default())),
                kernel_backed: false,
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

    /// Update per-descriptor flags for a synthetic descriptor.
    pub fn set_descriptor_flags(&mut self, fd: i32, flags: i32) -> bool {
        let Some(handle) = self.map.get_mut(&fd) else {
            return false;
        };
        handle.descriptor_flags = flags;
        true
    }

    /// Returns true if `fd` is a virtual fd managed by this table.
    pub fn is_virtual(&self, fd: i32) -> bool {
        self.map.contains_key(&fd)
    }

    /// Advance the read offset for a virtual fd. Returns the new offset.
    pub fn advance_offset(&mut self, fd: i32, bytes_read: u64) -> Option<u64> {
        let handle = self.map.get(&fd)?;
        let mut open_file = handle.open_file.lock();
        open_file.offset = open_file.offset.saturating_add(bytes_read);
        Some(open_file.offset)
    }

    /// Seek a virtual fd. Returns the new offset, or `None` if invalid.
    ///
    /// Whence values follow libc: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2.
    pub fn seek(&mut self, fd: i32, offset: i64, whence: i32) -> Result<u64, SeekError> {
        let handle = self.map.get(&fd).ok_or(SeekError::Invalid)?;
        let mut open_file = handle.open_file.lock();
        let new_offset = match whence {
            libc::SEEK_SET => {
                if offset < 0 {
                    return Err(SeekError::Invalid);
                }
                offset as u64
            }
            libc::SEEK_CUR => {
                let cur = i64::try_from(open_file.offset).map_err(|_| SeekError::Overflow)?;
                let new = cur.checked_add(offset).ok_or(SeekError::Overflow)?;
                if new < 0 {
                    return Err(SeekError::Invalid);
                }
                new as u64
            }
            libc::SEEK_END => {
                let end = i64::try_from(handle.size).map_err(|_| SeekError::Overflow)?;
                let new = end.checked_add(offset).ok_or(SeekError::Overflow)?;
                if new < 0 {
                    return Err(SeekError::Invalid);
                }
                new as u64
            }
            _ => return Err(SeekError::Invalid),
        };
        open_file.offset = new_offset;
        Ok(new_offset)
    }

    /// Close a virtual fd. Returns the handle if it existed, so the caller
    /// can check `write_path` for daemon notification.
    pub fn close(&mut self, fd: i32) -> Option<VirtualFileHandle> {
        self.map.remove(&fd)
    }

    /// Duplicate a virtual fd into a new synthetic descriptor.
    ///
    /// The descriptor entry is distinct, while the reference-counted
    /// open-file description (including both cursors) remains shared.
    pub fn duplicate(&mut self, fd: i32) -> Result<i32, DuplicateError> {
        let mut handle = self.map.get(&fd).ok_or(DuplicateError::NotVirtual)?.clone();
        handle.kernel_backed = false;
        handle.descriptor_flags = 0;
        let new_fd = self.next_vfd().ok_or(DuplicateError::TableFull)?;
        self.map.insert(new_fd, handle);
        Ok(new_fd)
    }

    /// Duplicate a virtual fd into a specific descriptor number.
    ///
    /// `kernel_backed` must be true when `dst_fd` is in the kernel descriptor
    /// range and the caller has already installed a matching kernel duplicate.
    pub fn duplicate_into(
        &mut self,
        src_fd: i32,
        dst_fd: i32,
        kernel_backed: bool,
        descriptor_flags: i32,
    ) -> Result<i32, DuplicateError> {
        let mut handle = self
            .map
            .get(&src_fd)
            .ok_or(DuplicateError::NotVirtual)?
            .clone();
        if !self.map.contains_key(&dst_fd) && self.map.len() >= MAX_VFDS {
            return Err(DuplicateError::TableFull);
        }
        handle.kernel_backed = kernel_backed;
        handle.descriptor_flags = descriptor_flags;
        if self.map.contains_key(&dst_fd) {
            self.close(dst_fd);
        }
        self.map.insert(dst_fd, handle);
        Ok(dst_fd)
    }

    /// Clone one descriptor entry so a caller can retain its open-file
    /// description across a blocking daemon request without retaining the
    /// table lock.
    pub fn snapshot(&self, fd: i32) -> Option<VirtualFileHandle> {
        self.map.get(&fd).cloned()
    }

    /// Record an advisory flock-style lock on a virtual fd.
    pub fn set_flock(&mut self, fd: i32, locked: bool) {
        if let Some(handle) = self.map.get(&fd) {
            handle.lock_open_file().flocked = locked;
        }
    }

    /// Check whether a virtual fd currently has a recorded flock-style lock.
    pub fn has_flock(&self, fd: i32) -> bool {
        self.map
            .get(&fd)
            .is_some_and(|handle| handle.lock_open_file().flocked)
    }

    /// Track a real kernel fd as opened for writing on a workspace path.
    /// On close, the caller can retrieve the path to notify the daemon.
    pub fn track_write(&mut self, fd: i32, path: Vec<u8>) {
        self.write_fds.insert(fd, path);
    }

    /// Close a tracked write fd. Returns the workspace path if found.
    pub fn close_write(&mut self, fd: i32) -> Option<Vec<u8>> {
        self.write_fds.remove(&fd)
    }

    /// Check if a real fd is tracked as a write fd.
    pub fn is_write_tracked(&self, fd: i32) -> bool {
        self.write_fds.contains_key(&fd)
    }

    // ── Atomic write tracking ──────────────────────────────────────────

    /// Track an in-flight atomic write: the real kernel fd writes to a temp
    /// file, which will be renamed to the target path on close.
    pub fn track_atomic_write(&mut self, fd: i32, target_path: Vec<u8>, temp_path: Vec<u8>) {
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
    // Test-only introspection helper; a paired `is_empty` would be dead code.
    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
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
        let fd = table.allocate(b"/ws/file.txt", 100, None).unwrap();
        assert!(fd >= vfd_base());

        let handle = table.get(fd).unwrap();
        assert_eq!(handle.path, b"/ws/file.txt");
        assert_eq!(handle.size, 100);
        assert_eq!(handle.offset(), 0);
        assert!(handle.cached_content.is_none());
        assert!(handle.io_permitted);
    }

    #[test]
    fn check_only_descriptor_preserves_metadata_but_denies_io_right() {
        let mut table = FdTable::new();
        let file = table
            .allocate_check_only(b"/ws/check-only.txt", 12, None)
            .unwrap();
        let dir = table
            .allocate_dir_check_only(b"/ws/check-only-dir", Vec::new())
            .unwrap();

        let file_handle = table.get(file).unwrap();
        assert_eq!(file_handle.size, 12);
        assert!(!file_handle.is_directory);
        assert!(!file_handle.io_permitted);

        let dir_handle = table.get(dir).unwrap();
        assert!(dir_handle.is_directory);
        assert!(!dir_handle.io_permitted);
    }

    #[test]
    fn opened_descriptor_pins_metadata_inode_and_path_capability() {
        let mut table = FdTable::new();
        let object_id = [11; 32];
        let mut stat = VirtualStat::regular_file(12, [7; 32], false, 41).with_object_id(object_id);
        stat.mode = 0o440;
        let fd = table
            .allocate_opened(
                b"/ws/pinned.txt",
                stat.clone(),
                None,
                OpenedFileOptions {
                    io_permitted: false,
                    path_only: true,
                    link_target: Some(b"target.txt".to_vec()),
                    flags: libc::O_RDONLY | libc::O_CLOEXEC,
                },
            )
            .unwrap();

        let handle = table.get(fd).unwrap();
        let opened = handle.opened_stat.as_ref().unwrap();
        assert_eq!(opened.size, stat.size);
        assert_eq!(opened.content_hash, stat.content_hash);
        assert_eq!(opened.mode, stat.mode);
        assert_eq!(opened.mtime, stat.mtime);
        assert_eq!(
            handle.opened_inode,
            kin_vfs_core::pathmap::synthetic_object_inode(&object_id)
        );
        assert_eq!(handle.link_target.as_deref(), Some(&b"target.txt"[..]));
        assert!(!handle.io_permitted);
        assert!(handle.path_only);
        let expected_inode = handle.opened_inode;
        let expected_target = handle.link_target.clone();
        let expected_path_only = handle.path_only;
        let expected_io_permitted = handle.io_permitted;

        let duplicate = table.duplicate(fd).unwrap();
        let duplicate_handle = table.get(duplicate).unwrap();
        assert_eq!(duplicate_handle.opened_inode, expected_inode);
        assert_eq!(duplicate_handle.link_target, expected_target);
        assert_eq!(duplicate_handle.path_only, expected_path_only);
        assert_eq!(duplicate_handle.io_permitted, expected_io_permitted);
    }

    #[test]
    fn allocate_with_small_content() {
        let mut table = FdTable::new();
        let content = vec![0u8; 1024]; // 1 KiB — under threshold
        let fd = table
            .allocate(b"/ws/small.txt", 1024, Some(content.clone()))
            .unwrap();

        let handle = table.get(fd).unwrap();
        assert_eq!(handle.cached_content.as_ref().unwrap(), &content);
    }

    #[test]
    fn allocate_drops_large_content() {
        let mut table = FdTable::new();
        let content = vec![0u8; 128 * 1024]; // 128 KiB — over threshold
        let fd = table
            .allocate(b"/ws/big.bin", 131072, Some(content))
            .unwrap();

        let handle = table.get(fd).unwrap();
        assert!(handle.cached_content.is_none());
    }

    #[test]
    fn advance_offset() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.advance_offset(fd, 50), Some(50));
        assert_eq!(table.advance_offset(fd, 30), Some(80));
        assert_eq!(table.get(fd).unwrap().offset(), 80);
    }

    #[test]
    fn seek_set() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, 100, libc::SEEK_SET), Ok(100));
        assert_eq!(table.get(fd).unwrap().offset(), 100);
    }

    #[test]
    fn seek_cur() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();
        assert_eq!(table.seek(fd, 50, libc::SEEK_SET), Ok(50));

        assert_eq!(table.seek(fd, 25, libc::SEEK_CUR), Ok(75));
        assert_eq!(table.seek(fd, -10, libc::SEEK_CUR), Ok(65));
    }

    #[test]
    fn seek_end() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, 0, libc::SEEK_END), Ok(200));
        assert_eq!(table.seek(fd, -50, libc::SEEK_END), Ok(150));
    }

    #[test]
    fn seek_negative_result_returns_none() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();

        assert_eq!(table.seek(fd, -1, libc::SEEK_SET), Err(SeekError::Invalid));
        assert_eq!(
            table.seek(fd, -300, libc::SEEK_END),
            Err(SeekError::Invalid)
        );
    }

    #[test]
    fn seek_invalid_whence() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();
        assert_eq!(table.seek(fd, 0, 99), Err(SeekError::Invalid));
    }

    #[test]
    fn seek_overflow_preserves_the_prior_offset() {
        let mut table = FdTable::new();
        let fd = table
            .allocate(b"/ws/huge.bin", i64::MAX as u64, None)
            .unwrap();
        assert_eq!(
            table.seek(fd, i64::MAX, libc::SEEK_SET),
            Ok(i64::MAX as u64)
        );
        assert_eq!(table.seek(fd, 1, libc::SEEK_CUR), Err(SeekError::Overflow));
        assert_eq!(table.get(fd).unwrap().offset(), i64::MAX as u64);
        assert_eq!(table.seek(fd, 1, libc::SEEK_END), Err(SeekError::Overflow));
        assert_eq!(table.get(fd).unwrap().offset(), i64::MAX as u64);
    }

    #[test]
    fn seek_end_rejects_a_size_outside_off_t() {
        let mut table = FdTable::new();
        let fd = table
            .allocate(b"/ws/unrepresentable.bin", i64::MAX as u64 + 1, None)
            .unwrap();
        assert_eq!(table.seek(fd, 0, libc::SEEK_END), Err(SeekError::Overflow));
        assert_eq!(table.get(fd).unwrap().offset(), 0);
    }

    #[test]
    fn close_removes_fd() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 100, None).unwrap();
        assert!(table.is_virtual(fd));

        assert!(table.close(fd).is_some());
        assert!(!table.is_virtual(fd));
        assert!(table.get(fd).is_none());
    }

    #[test]
    fn close_nonexistent_returns_none() {
        let mut table = FdTable::new();
        assert!(table.close(vfd_base() + 999).is_none());
    }

    #[test]
    fn duplicate_virtual_fd_shares_open_file_offset() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();
        assert_eq!(table.seek(fd, 75, libc::SEEK_SET), Ok(75));
        table.set_flock(fd, true);

        let dup = table.duplicate(fd).unwrap();
        assert_ne!(dup, fd);
        assert_eq!(table.get(dup).unwrap().path, b"/ws/f.txt");
        assert_eq!(table.get(dup).unwrap().offset(), 75);
        assert_eq!(table.seek(dup, 25, libc::SEEK_CUR), Ok(100));
        assert_eq!(table.get(fd).unwrap().offset(), 100);
        assert!(table.has_flock(dup));
        table.close(fd).expect("close original descriptor");
        assert!(
            table.has_flock(dup),
            "closing one alias must retain the open-file-description lock"
        );
        table.set_flock(dup, false);
        assert!(!table.has_flock(dup));
    }

    #[test]
    fn duplicate_into_replaces_existing_virtual_fd() {
        let mut table = FdTable::new();
        let src = table.allocate(b"/ws/src.txt", 50, None).unwrap();
        let dst = table.allocate(b"/ws/dst.txt", 60, None).unwrap();

        let replaced = table.duplicate_into(src, dst, false, 0).unwrap();
        assert_eq!(replaced, dst);
        assert_eq!(table.get(dst).unwrap().path, b"/ws/src.txt");
        assert_eq!(table.get(src).unwrap().path, b"/ws/src.txt");
        assert!(!table.get(dst).unwrap().kernel_backed);
    }

    #[test]
    fn duplicate_reports_table_exhaustion_without_losing_the_source() {
        let mut table = FdTable::new();
        let source = table
            .allocate(b"/ws/source.txt", 1, Some(vec![b'x']))
            .unwrap();
        for index in 1..MAX_VFDS {
            let path = format!("/ws/fill-{index}");
            table
                .allocate(path.as_bytes(), 0, Some(Vec::new()))
                .expect("fill every virtual descriptor slot");
        }

        assert_eq!(table.duplicate(source), Err(DuplicateError::TableFull));
        assert_eq!(table.get(source).unwrap().path, b"/ws/source.txt");
    }

    #[test]
    fn in_flight_open_file_state_cannot_advance_a_reused_descriptor() {
        let mut table = FdTable::new();
        let old_fd = table.allocate(b"/ws/old.txt", 50, None).unwrap();
        let in_flight = table.snapshot(old_fd).unwrap();
        table.close(old_fd).unwrap();

        let replacement = table.allocate(b"/ws/new.txt", 60, None).unwrap();
        table
            .duplicate_into(replacement, old_fd, false, 0)
            .expect("reuse old descriptor number");

        in_flight.lock_open_file().offset = 19;
        assert_eq!(in_flight.offset(), 19);
        assert_eq!(
            table.get(old_fd).unwrap().offset(),
            0,
            "late completion must not advance the replacement open-file description"
        );
    }

    #[test]
    fn ordinary_dup_target_records_kernel_descriptor_ownership() {
        let mut table = FdTable::new();
        let src = table.allocate(b"/ws/src.txt", 50, None).unwrap();
        table
            .duplicate_into(src, 7, true, 0)
            .expect("install ordinary descriptor target");
        assert!(table.get(7).unwrap().kernel_backed);
        assert_eq!(table.get(7).unwrap().offset(), 0);
        assert_eq!(table.seek(src, 4, libc::SEEK_SET), Ok(4));
        assert_eq!(table.get(7).unwrap().offset(), 4);
    }

    #[test]
    fn flock_state_clears_on_close() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/f.txt", 200, None).unwrap();
        table.set_flock(fd, true);
        assert!(table.has_flock(fd));
        table.close(fd);
        assert!(!table.has_flock(fd));
    }

    #[test]
    fn multiple_fds() {
        let mut table = FdTable::new();
        let fd1 = table.allocate(b"/ws/a.txt", 10, None).unwrap();
        let fd2 = table.allocate(b"/ws/b.txt", 20, None).unwrap();
        let fd3 = table.allocate(b"/ws/c.txt", 30, None).unwrap();

        assert_ne!(fd1, fd2);
        assert_ne!(fd2, fd3);
        assert_eq!(table.len(), 3);

        assert_eq!(table.get(fd1).unwrap().path, b"/ws/a.txt");
        assert_eq!(table.get(fd2).unwrap().path, b"/ws/b.txt");
        assert_eq!(table.get(fd3).unwrap().path, b"/ws/c.txt");
    }

    #[test]
    fn non_utf8_handle_paths_and_entry_names_round_trip() {
        let mut table = FdTable::new();
        let raw_path = b"/ws/logs/x-\xff\xfe.log";
        let fd = table.allocate(raw_path, 12, None).unwrap();
        assert_eq!(table.get(fd).unwrap().path, raw_path);

        let dir = table
            .allocate_dir(
                b"/ws/logs",
                vec![DirEntryRaw {
                    name: b"x-\xff\xfe.log".to_vec(),
                    d_ino: 7,
                    d_type: 8,
                }],
            )
            .unwrap();
        let entries = table.get(dir).unwrap().dir_entries.as_ref().unwrap();
        assert_eq!(entries[0].name, b"x-\xff\xfe.log");

        table.track_write(4, raw_path.to_vec());
        assert_eq!(table.close_write(4).unwrap(), raw_path);
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
            DirEntryRaw {
                name: b"foo.rs".to_vec(),
                d_ino: 100,
                d_type: 8,
            },
            DirEntryRaw {
                name: b"bar".to_vec(),
                d_ino: 101,
                d_type: 4,
            },
        ];
        let fd = table.allocate_dir(b"/ws/src", entries.clone()).unwrap();
        assert!(fd >= vfd_base());

        let handle = table.get(fd).unwrap();
        assert!(handle.is_directory);
        assert_eq!(handle.dir_offset(), 0);
        let dir_ents = handle.dir_entries.as_ref().unwrap();
        assert_eq!(dir_ents.len(), 2);
        assert_eq!(dir_ents[0].name, b"foo.rs");
        assert_eq!(dir_ents[1].name, b"bar");
    }

    #[test]
    fn dir_offset_tracking() {
        let mut table = FdTable::new();
        let entries = vec![
            DirEntryRaw {
                name: b"a.txt".to_vec(),
                d_ino: 1,
                d_type: 8,
            },
            DirEntryRaw {
                name: b"b.txt".to_vec(),
                d_ino: 2,
                d_type: 8,
            },
            DirEntryRaw {
                name: b"c.txt".to_vec(),
                d_ino: 3,
                d_type: 8,
            },
        ];
        let fd = table.allocate_dir(b"/ws", entries).unwrap();

        let duplicate = table.duplicate(fd).unwrap();
        table.get(fd).unwrap().set_dir_offset(2);
        assert_eq!(table.get(fd).unwrap().dir_offset(), 2);
        assert_eq!(
            table.get(duplicate).unwrap().dir_offset(),
            2,
            "duplicates share one directory-stream position"
        );
    }

    #[test]
    fn close_dir_fd() {
        let mut table = FdTable::new();
        let fd = table.allocate_dir(b"/ws", vec![]).unwrap();
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
        table.track_write(3, b"/ws/src/main.rs".to_vec());
        assert!(table.is_write_tracked(3));

        // Closing returns the path.
        let path = table.close_write(3).unwrap();
        assert_eq!(path, b"/ws/src/main.rs");
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
        let fd = table.allocate(b"/ws/readme.md", 256, None).unwrap();
        // Virtual read-only fd — write_path should be None.
        let handle = table.close(fd).unwrap();
        assert!(handle.write_path.is_none());
    }

    #[test]
    fn virtual_handle_default_write_path_is_none() {
        let mut table = FdTable::new();
        let fd = table.allocate(b"/ws/file.rs", 100, None).unwrap();
        assert!(table.get(fd).unwrap().write_path.is_none());
    }

    // ── Atomic write tracking tests ──────────────────────────────────────

    #[test]
    fn track_atomic_write_and_close() {
        let mut table = FdTable::new();
        table.track_atomic_write(
            7,
            b"/ws/src/main.rs".to_vec(),
            b"/ws/src/main.rs.kin_tmp_12345".to_vec(),
        );
        assert!(table.is_atomic_write(7));

        let entry = table.close_atomic_write(7).unwrap();
        assert_eq!(entry.target_path, b"/ws/src/main.rs");
        assert_eq!(entry.temp_path, b"/ws/src/main.rs.kin_tmp_12345");
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
        table.track_write(5, b"/ws/file.rs".to_vec());
        table.track_atomic_write(
            5,
            b"/ws/file.rs".to_vec(),
            b"/ws/file.rs.kin_tmp_999".to_vec(),
        );

        assert!(table.is_write_tracked(5));
        assert!(table.is_atomic_write(5));

        // Close both
        let atomic = table.close_atomic_write(5).unwrap();
        assert_eq!(atomic.target_path, b"/ws/file.rs");
        let write_path = table.close_write(5).unwrap();
        assert_eq!(write_path, b"/ws/file.rs");
    }

    #[test]
    fn write_tracking_does_not_interfere_with_virtual_fds() {
        let mut table = FdTable::new();
        // Track a real write fd.
        table.track_write(5, b"/ws/src/lib.rs".to_vec());
        // Allocate a virtual fd.
        let vfd = table.allocate(b"/ws/other.rs", 50, None).unwrap();
        assert!(vfd >= vfd_base());

        // Both coexist.
        assert!(table.is_write_tracked(5));
        assert!(table.is_virtual(vfd));

        // Closing the write fd doesn't affect the virtual fd.
        table.close_write(5);
        assert!(table.is_virtual(vfd));
    }

    // ── Dynamic VFD base tests ──────────────────────────────────────────

    #[test]
    fn vfd_base_is_at_least_10000() {
        assert!(vfd_base() >= 10_000);
    }

    #[test]
    fn allocated_fds_are_above_vfd_base() {
        let mut table = FdTable::new();
        let fd1 = table.allocate(b"/ws/a.txt", 10, None).unwrap();
        let fd2 = table.allocate(b"/ws/b.txt", 20, None).unwrap();
        assert!(fd1 >= vfd_base());
        assert!(fd2 >= vfd_base());
    }

    #[test]
    fn wrap_around_skips_occupied_slots() {
        let mut table = FdTable::new();
        // Allocate first fd.
        let fd1 = table.allocate(b"/ws/first.txt", 10, None).unwrap();
        // Close it — the slot is now free.
        table.close(fd1);
        // Allocate MAX_VFDS - 1 more fds so next_fd wraps around.
        let mut fds = Vec::new();
        for i in 0..(MAX_VFDS - 1) {
            let fd = table
                .allocate(format!("/ws/f{i}.txt").as_bytes(), 10, None)
                .unwrap();
            fds.push(fd);
        }
        // Table has MAX_VFDS - 1 entries. next_vfd should wrap and find fd1's
        // old slot (which was freed).
        let fd_wrap = table.allocate(b"/ws/wrap.txt", 10, None).unwrap();
        assert!(fd_wrap >= vfd_base());
        // Should have reclaimed the freed slot.
        assert_eq!(fd_wrap, fd1);
    }

    #[test]
    fn full_table_returns_none() {
        let mut table = FdTable::new();
        // Fill the entire table.
        for i in 0..MAX_VFDS {
            assert!(
                table
                    .allocate(format!("/ws/f{i}.txt").as_bytes(), 10, None)
                    .is_some(),
                "allocation {} should succeed",
                i
            );
        }
        // Table is full — next allocation should fail.
        assert!(table.allocate(b"/ws/overflow.txt", 10, None).is_none());
    }
}
