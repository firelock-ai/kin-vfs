# VFS Wire Protocol Specification

Version: **v1** (`VFS_PROTOCOL_VERSION = 1`)

Source of truth: `kin-vfs-core/src/protocol.rs`

## Overview

The VFS protocol defines communication between **shim clients** (loaded via LD_PRELOAD/DYLD_INSERT_LIBRARIES on Unix, ProjFS on Windows) and the **VFS daemon** (a tokio-based server listening on a Unix socket or Windows named pipe).

The protocol is request-response over a persistent connection, with an optional push-invalidation mode entered via the `Subscribe` request.

## Transport

| Platform | Transport | Default Path |
|----------|-----------|-------------|
| Linux | Unix domain socket | `$KIN_VFS_WORKSPACE/.kin/vfs.sock` |
| macOS | Unix domain socket | `$KIN_VFS_WORKSPACE/.kin/vfs.sock` |
| Windows | Named pipe | `\\.\pipe\kin-vfs-{workspace-hash}` |

Socket permissions are set to `0700` (owner-only) on Unix for security.

## Framing

All messages use **length-prefixed MessagePack** encoding:

```
+------------------+----------------------------+
| 4 bytes (BE u32) | N bytes (MessagePack)      |
| payload length   | serialized request/response |
+------------------+----------------------------+
```

- **Byte order:** Big-endian (network byte order) for the 4-byte length prefix.
- **Serialization:** MessagePack via `rmp-serde`.
- **Max frame size:** 16 MiB (`16 * 1024 * 1024 = 16,777,216` bytes). Frames exceeding this limit are rejected with a protocol error.

Implementation: `kin-vfs-daemon/src/framing.rs` (`read_frame` / `write_frame`)

## Connection Lifecycle

1. **Connect:** Client opens a Unix socket (or named pipe on Windows).
2. **Request-response loop:** Client sends `VfsRequest` frames; daemon responds with `VfsResponse` frames. Multiple requests may be sent on a single connection sequentially.
3. **Optional subscription:** Client sends `Subscribe`; daemon acknowledges with `Pong`, then enters push mode: the daemon sends `Invalidate` frames whenever content changes. No further requests are accepted on this connection.
4. **Disconnect:** Client closes the connection. The daemon cleans up the connection handler.

Connection limit: **256 concurrent connections** (enforced by a tokio `Semaphore`). Connections beyond this limit are dropped immediately.

## Request Types

All requests are variants of the `VfsRequest` enum, serialized as MessagePack.

### `Stat { path: String }`

Get metadata for a virtual path.

**Response:** `VfsResponse::Stat(VirtualStat)` or `VfsResponse::Error`

### `ReadDir { path: String }`

List the contents of a virtual directory.

**Response:** `VfsResponse::DirEntries(Vec<DirEntry>)` or `VfsResponse::Error`

### `Read { path: String, offset: u64, len: u64 }`

Read file content. If `offset == 0 && len == 0`, reads the entire file. Otherwise reads the specified byte range.

**Response:** `VfsResponse::Content { data: Vec<u8>, total_size: u64 }` or `VfsResponse::Error`

### `ReadLink { path: String }`

Read the target of a symbolic link.

**Response:** `VfsResponse::LinkTarget(String)` or `VfsResponse::Error`

### `Access { path: String, mode: u32 }`

Check if a path is accessible. The `mode` field mirrors POSIX access modes (F_OK=0, R_OK=4, W_OK=2, X_OK=1).

**Response:** `VfsResponse::Accessible(bool)` or `VfsResponse::Error`

### `Ping`

Keepalive/health check.

**Response:** `VfsResponse::Pong`

### `Subscribe`

Enter push-invalidation mode. After the daemon acknowledges with `Pong`, it sends `Invalidate` frames whenever content changes. No further requests are accepted on this connection.

**Response:** `VfsResponse::Pong` (then push mode begins)

## Response Types

### `Stat(VirtualStat)`

File or directory metadata:

| Field | Type | Description |
|-------|------|-------------|
| `size` | `u64` | File size in bytes (0 for directories) |
| `is_file` | `bool` | True if regular file |
| `is_dir` | `bool` | True if directory |
| `is_symlink` | `bool` | True if symbolic link |
| `mode` | `u32` | Unix permissions (0o644 for files, 0o755 for dirs) |
| `mtime` | `u64` | Last modification time (epoch seconds) |
| `ctime` | `u64` | Creation time (epoch seconds) |
| `nlink` | `u64` | Number of hard links |
| `content_hash` | `Option<[u8; 32]>` | SHA-256 content hash (files only) |

### `DirEntries(Vec<DirEntry>)`

Directory listing. Each `DirEntry`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Entry name (not full path) |
| `file_type` | `FileType` | One of: `File`, `Directory`, `Symlink` |

### `Content { data: Vec<u8>, total_size: u64 }`

File content (full or range). `total_size` is the full file size regardless of the range requested.

### `LinkTarget(String)`

Symbolic link target path.

### `Accessible(bool)`

Result of an access check.

### `Pong`

Response to `Ping` or acknowledgement of `Subscribe`.

### `Error { code: ErrorCode, message: String }`

Error response. Error codes:

| Code | Meaning |
|------|---------|
| `NotFound` | Path does not exist |
| `PermissionDenied` | Access denied |
| `IsDirectory` | Expected file, got directory |
| `NotDirectory` | Expected directory, got file |
| `IoError` | I/O failure |
| `Internal` | Provider/server internal error |

## Invalidation Mechanism

The daemon runs a **version poller** that checks the content provider's version counter every 500ms. When the version changes:

1. The daemon broadcasts an `Invalidate { paths: Vec<String> }` frame to all subscribed connections.
2. An empty `paths` vector means "everything may have changed" (full invalidation).
3. Shim clients receiving invalidation events flush their local caches.

Clients that lag behind the broadcast channel are warned but not disconnected (the channel capacity is 64 messages).

## Session-Scoped Projections

The shim reads `KIN_SESSION_ID` from the environment. When set, the `KinDaemonProvider` appends `?session_id=<id>` to all HTTP requests to `kin-daemon`. This enables session-scoped overlay projections where different sessions may see different file trees.

## Versioning

The protocol version is defined as `VFS_PROTOCOL_VERSION = 1` in `kin-vfs-core/src/protocol.rs`. Breaking wire-format changes require bumping this constant. Clients and servers should negotiate or reject incompatible versions.
