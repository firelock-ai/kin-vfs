# kin-vfs

Purpose-built virtual filesystem for the Kin ecosystem. Serves files directly from a content-addressed blob store, eliminating file duplication. Working trees appear as normal directories, but every file is backed by content-addressed storage -- zero extra disk usage, instant checkouts, and transparent reads for any tool that opens a file.

## Repo Topology

```
kin-vfs/
├── crates/
│   ├── kin-vfs-core/       ContentProvider trait, VirtualFileTree, LRU cache, error types
│   ├── kin-vfs-daemon/     Tokio daemon: Unix socket server, protocol framing, KinDaemonProvider
│   ├── kin-vfs-shim/       cdylib interception layer: hooks libc calls via LD_PRELOAD / DYLD
│   ├── kin-vfs-fuse/       FUSE mount mode: macFUSE/FUSE-T/libfuse virtual mount (optional)
│   └── kin-vfs-cli/        CLI binary (kin-vfs): start, stop, status, mount, unmount
├── tests/
│   └── integration/        End-to-end tests spanning daemon + shim
└── Cargo.toml              Workspace root (resolver v2)
```

## Crate Roles

| Crate | Role |
|-------|------|
| `kin-vfs-core` | Shared primitives: `ContentProvider` trait, `VirtualFileTree` for path-to-content mapping, `VirtualStat`/`DirEntry`/`FileType` stat types, `VfsError`/`VfsResult` error types, LRU blob cache. Standalone-valuable -- usable by any project, not just Kin. |
| `kin-vfs-daemon` | Tokio-based server that listens on a Unix socket (named pipe on Windows), resolves virtual paths to blob hashes, and streams content back. Exports `VfsDaemonServer`, `KinDaemonProvider` (bridges to kin-daemon on `:4219`), length-prefixed `read_frame`/`write_frame` framing, and `VfsRequest`/`VfsResponse` protocol types. |
| `kin-vfs-shim` | cdylib loaded via `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS). Intercepts `open`, `read`, `stat`, `close`, etc. via `dlsym(RTLD_NEXT)`. Windows path uses ProjFS kernel callbacks instead. Synchronous client -- no tokio runtime; runs inside arbitrary host processes. |
| `kin-vfs-fuse` | FUSE mount mode (optional, behind `fuse` feature). Implements `fuser::Filesystem` backed by any `ContentProvider`. Supports macFUSE (kernel ext), FUSE-T (userspace), and libfuse (Linux). Read-only mount — writes return EROFS. Alternative to the shim for cases where a real mount point is preferred (no SIP issues, works with static binaries). |
| `kin-vfs-cli` | CLI binary (`kin-vfs`). Commands: `start`/`stop`/`status` for the socket daemon. With `--features fuse`: `mount`/`unmount`/`fuse-status` for FUSE virtual mounts. Auto-detects `.kin/` by walking up from the given path. |

## How the Parts Connect

```
                  Mode A: Shim (per-process)         Mode B: FUSE (system-wide)

 ┌──────────┐     LD_PRELOAD / DYLD / ProjFS     ┌──────────┐   mount point
 │   Tool   │ ──────────────────────────────────► │   Shim   │   ┌──────────┐
 │ (editor, │   intercepts open/read/stat/etc.    │ (cdylib)  │   │   FUSE   │
 │  build,  │                                     └─────┬──────┘   │  mount   │◄── any process
 │  grep…)  │                                           │ msgpack  └─────┬────┘     reads files
 └──────────┘                                           │ over           │ fuser
                                                        │ unix sock      │ callbacks
                                                  ┌─────▼────────────────▼──┐
                                                  │     ContentProvider      │
                                                  │  (KinDaemonProvider or   │
                                                  │   any backend)           │
                                                  └──────────┬──────────────┘
                                                             │
                                                  ┌──────────▼──────────────┐
                                                  │      Blob Store          │
                                                  │      (CAS / kin)         │
                                                  └─────────────────────────┘
```

**Data flow:** A host process (editor, build tool, grep) attempts to open/read a file. The shim intercepts the libc call, checks if the path falls within the workspace root, and if so routes the request to the daemon over a Unix socket using MessagePack-encoded frames. The daemon resolves the virtual path through its `ContentProvider` (either `KinDaemonProvider` connecting to kin-daemon on `:4219`, or a placeholder) and returns file content. The shim presents the content back to the host process as if it were a normal file read.

**Writes are materialized:** When a tool writes to a virtual file, the shim materializes it to disk so the write lands on a real fd. Reads remain virtual.

## Key Design Decisions

- **LD_PRELOAD / DYLD on Linux and macOS, ProjFS on Windows.** The shim is a cdylib loaded into any process; it overrides libc symbols to intercept file I/O transparently. On Windows, ProjFS requires an active process to service kernel callbacks (unlike LD_PRELOAD which piggybacks on the host process), so `shim_init_windows()` is called explicitly from the daemon.

- **Synchronous client in shim.** The shim cannot assume the host process has a tokio runtime. All daemon communication is blocking I/O over a Unix socket (or named pipe on Windows).

- **MessagePack over length-prefixed frames.** `VfsRequest`/`VfsResponse` are serialized with `rmp-serde` and wrapped in length-prefixed frames (`read_frame`/`write_frame` in `kin-vfs-daemon::framing`).

- **Virtual file descriptors start at 10,000.** Avoids collisions with real kernel-assigned fds the host process may hold. Managed by `FdTable` in `kin-vfs-shim::fd_table` (Linux/macOS only).

- **Thread-local socket connections.** Each thread in the shimmed process gets its own connection to the daemon, avoiding lock contention on the socket.

- **Materialize-on-write.** Reads are virtual (served from blob store). Writes go to real disk fds. This ensures build tools, editors, and version control that write files work correctly without special handling.

- **Kill switch.** Set `KIN_VFS_DISABLE=1` to disable all interception instantly. The shim also disables silently if `KIN_VFS_WORKSPACE` is not set.

- **Auto-init on library load.** On Linux, the shim registers via `.init_array`; on macOS via `__DATA,__mod_init_func`. The `shim_init()` function runs before `main()` in the host process.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KIN_VFS_WORKSPACE` | yes | -- | Absolute path to the workspace root |
| `KIN_VFS_SOCK` | no | `$KIN_VFS_WORKSPACE/.kin/vfs.sock` | Path to the daemon Unix socket (Linux/macOS) |
| `KIN_VFS_PIPE` | no | `\\.\pipe\kin-vfs-{hash}` | Named pipe path (Windows) |
| `KIN_SESSION_ID` | no | -- | Session ID for session-scoped projections |
| `KIN_VFS_DISABLE` | no | -- | Set to `1` to disable all interception |
| `KIN_VFS_LOG` | no | `info` | Log level filter for kin-vfs-cli |

## Build

```bash
cd kin-vfs
cargo build --workspace
cargo test --workspace

# Build release shim (this is the cdylib you inject)
cargo build --release -p kin-vfs-shim
# Output: target/release/libkin_vfs_shim.dylib (macOS) or .so (Linux)

# Start the daemon
cargo run -p kin-vfs-cli -- start --workspace /path/to/repo

# Run any tool under the shim
# Linux:
LD_PRELOAD=target/release/libkin_vfs_shim.so cat /path/to/repo/some-file.rs
# macOS:
DYLD_INSERT_LIBRARIES=target/release/libkin_vfs_shim.dylib cat /path/to/repo/some-file.rs

# Build with FUSE support (requires macFUSE/FUSE-T or libfuse)
cargo build --release -p kin-vfs-cli --features fuse

# Mount virtual filesystem
kin-vfs mount --workspace /path/to/repo --mount-point /tmp/kin-mount
# Any tool can now read from /tmp/kin-mount/ as a normal directory.

# Unmount
kin-vfs unmount --mount-point /tmp/kin-mount

# Check FUSE availability
kin-vfs fuse-status
```

## FUSE Mount Mode

The FUSE mount mode is an alternative to the LD_PRELOAD/DYLD shim. Instead of intercepting syscalls within individual processes, it presents a real mount point visible to all processes.

### When to Use FUSE vs Shim

| | Shim (LD_PRELOAD/DYLD) | FUSE mount |
|---|---|---|
| Visibility | Per-process only | System-wide mount |
| macOS SIP | Blocked for system binaries | No SIP issues |
| Static binaries | Not supported | Fully supported |
| Requires install | Nothing | macFUSE or FUSE-T |
| Write-through | Yes (writes go to disk) | No (read-only) |
| Overhead | Very low (in-process) | Kernel round-trips |

**Use the shim** when you need write-through and per-process control.
**Use FUSE mount** when you need universal tool compatibility without SIP workarounds.

### FUSE Variants

On macOS, two FUSE implementations are supported:

- **FUSE-T** (preferred): Userspace FUSE, no kernel extension required. Install: `brew install fuse-t`
- **macFUSE**: Traditional kernel extension. Install: `brew install macfuse`

On Linux, standard libfuse (`fuse3`) is used.

### Architecture

The `kin-vfs-fuse` crate implements `fuser::Filesystem` backed by any `ContentProvider`. The FUSE event loop runs on a blocking thread. File operations:

- **lookup/getattr**: Call `provider.stat(path)`, allocate inodes lazily
- **read**: Call `provider.read_file(path)` or `provider.read_range(path, offset, len)`
- **readdir**: Call `provider.read_dir(path)`, synthesize `.` and `..` entries
- **write/mkdir/unlink/etc**: Return `EROFS` (read-only filesystem)

Inode allocation is managed by `InodeTable` — a bidirectional path-to-inode map. Root is always inode 1. Inodes are allocated on first `lookup` and cached for the lifetime of the mount.

## Debugging Guide

### Shim not intercepting reads

1. Verify `KIN_VFS_WORKSPACE` is set to the correct absolute path.
2. Verify the daemon is running: `kin-vfs status --workspace /path/to/repo`.
3. Check the socket exists: `ls -la /path/to/repo/.kin/vfs.sock`.
4. Verify the shim is loaded: on Linux, `ldd` or check `/proc/<pid>/maps`; on macOS, `DYLD_PRINT_LIBRARIES=1`.
5. Check kill switch: ensure `KIN_VFS_DISABLE` is not set to `1`.

### Daemon won't start

1. Check for stale socket: if `.kin/vfs.sock` exists but the daemon is not running, the CLI will clean it up automatically on `start`. If not, remove it manually.
2. Check PID file: `.kin/vfs.pid` records the daemon PID. If stale, remove it.
3. If using `KinDaemonProvider`, ensure kin-daemon is running on `:4219`.

### macOS SIP issues

`DYLD_INSERT_LIBRARIES` is stripped by SIP for system-protected binaries (e.g., `/usr/bin/cat`). Workarounds:
- Use Homebrew-installed binaries (e.g., `/opt/homebrew/bin/gcat`).
- Disable SIP (development machines only).
- Run the target binary from a non-SIP-protected path.

### FUSE mount issues

1. Check FUSE availability: `kin-vfs fuse-status` (requires `--features fuse`).
2. macOS: If using macFUSE, ensure the kernel extension is loaded: `kextstat | grep macfuse`. FUSE-T does not require a kernel extension.
3. Mount point must be an empty directory. If it's not empty or doesn't exist, the mount command will report an error.
4. If unmount fails with "Resource busy", check for processes with open files in the mount: `lsof +D /path/to/mount`.
5. Auto-unmount is enabled by default — when the `kin-vfs mount` process exits, the mount is cleaned up. Disable with `--no-auto-unmount`.
6. The FUSE mount is read-only. Write attempts return EROFS.

### Windows ProjFS

ProjFS support is planned but not yet fully implemented. The shim crate has `#[cfg(target_os = "windows")]` gates for ProjFS provider initialization and named pipe communication. The `shim_init_windows()` entry point creates a `ProjFsProvider` and starts virtualization.

## Platform Notes

| Platform | Interception Method | Shim Output | Status |
|----------|-------------------|-------------|--------|
| Linux | `LD_PRELOAD` shared library | `libkin_vfs_shim.so` | Primary target |
| macOS | `DYLD_INSERT_LIBRARIES` | `libkin_vfs_shim.dylib` | Primary target |
| macOS | FUSE mount (macFUSE / FUSE-T) | N/A (mount point) | Available (feature: `fuse`) |
| Linux | FUSE mount (libfuse) | N/A (mount point) | Available (feature: `fuse`) |
| Windows | ProjFS kernel callbacks | N/A (explicit init) | Planned |

- The shim uses `#[cfg(unix)]` / `#[cfg(target_os = "windows")]` gates extensively. Linux and macOS share the LD_PRELOAD/DYLD path; Windows uses the `windows` crate for ProjFS.
- Cross-compilation: the shim must be compiled for the target platform (native cdylib).
- The shim is `#![allow(clippy::missing_safety_doc)]` because the `#[no_mangle]` libc hooks are inherently unsafe FFI.

## Workspace Dependencies

```toml
rmp-serde     # MessagePack serialization
tokio         # Async runtime (daemon only)
parking_lot   # RwLock for fd table, inode table
libc          # Syscall interception
lru           # LRU blob cache (core)
sha2 + hex    # Content addressing
clap          # CLI argument parsing
fuser         # FUSE filesystem (kin-vfs-fuse only, optional)
```

## Relationship to Kin Ecosystem

- `kin-vfs-core` is depended on by the main `kin` workspace (patched via `.cargo/config.toml` to local `../kin-vfs/crates/kin-vfs-core`).
- `kin-vfs-daemon` bridges to `kin-daemon` (`:4219`) via `KinDaemonProvider` for blob resolution.
- `kin setup` and the one-line installer handle kin-vfs installation automatically.
- In native mode (`kin mode native`), kin-vfs serves all file reads from the blob store, making the filesystem fully virtual.

## License

Apache-2.0. Copyright 2026 Firelock, LLC.
