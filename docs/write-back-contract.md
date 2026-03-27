# Write-Back Integration Contract

How the VFS shim handles write operations: materialize-on-write, atomic rename, and daemon notification.

## Principle

Reads are virtual (served from the blob store via the daemon). Writes go to real disk. This ensures all tools -- editors, build systems, version control -- work correctly without special handling.

## Write Detection

The shim detects write intent by inspecting `open(2)` / `openat(2)` flags:

```rust
fn is_write_flags(flags: c_int) -> bool {
    (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0
}
```

Any of these flags triggers the materialize-on-write path.

## Materialize-on-Write Flow

When a tool opens a workspace file for writing:

```
1. open("/workspace/src/main.rs", O_WRONLY)
      │
      ▼
2. materialize_file("src/main.rs")
   ├─ Fetch current content from daemon (client_read_file)
   ├─ Write to temp file: "src/main.rs.kin_tmp_{pid}"
   └─ Return temp path
      │
      ▼
3. real_open(temp_path, O_WRONLY)
   ├─ Track fd -> target_path mapping in FdTable
   └─ Track fd -> (target_path, temp_path) as atomic write
      │
      ▼
4. Tool writes to the fd normally (write/pwrite/writev)
      │
      ▼
5. close(fd)
   ├─ Flush: real_close(fd) to ensure data hits disk
   ├─ Atomic rename: rename(temp_path, target_path)
   ├─ Notify daemon: POST /vfs/file-changed { path: target_path }
   └─ Return close result
```

## Temp File Naming Convention

```
{target_path}.kin_tmp_{pid}
```

Example: `/workspace/src/main.rs.kin_tmp_12345`

The `.kin_tmp_` infix is excluded from VFS interception (`is_workspace_path` returns false for these paths) to prevent re-entrance when `materialize_file` calls `std::fs::write`.

## Atomic Rename

The temp-then-rename pattern ensures that:

- The target file is never partially written (crash safety).
- Other processes reading the target see either the old or new content, never a torn write.
- If the rename fails, the temp file stays on disk but the original is not corrupted.

## Stale Temp Cleanup

On each `open()` with write flags, the shim calls `cleanup_stale_temps(path_str)` which:

1. Scans the parent directory for files matching `{filename}.kin_tmp_*`
2. Removes any found (leftovers from crashed processes)

This prevents temp file accumulation from abnormal terminations.

## Daemon Notification

After a successful write (close with or without atomic rename), the shim notifies `kin-daemon` that a file changed:

```
POST http://127.0.0.1:4219/vfs/file-changed
Content-Type: application/json

{"path": "src/main.rs"}
```

Notifications are fire-and-forget via a bounded channel (capacity 64) to a single worker thread. The worker coalesces rapid writes within a 50ms window, deduplicating by path. If the channel is full, notifications are dropped -- the daemon's reconciliation cycle will detect the change.

## FdTable Tracking

The `FdTable` (in `fd_table.rs`) maintains two tracking maps:

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `write_fds` | kernel fd | target workspace path | Notify daemon on close |
| `atomic_writes` | kernel fd | `{ target_path, temp_path }` | Rename temp to target on close |

Both entries are inserted on write-mode `open` and consumed on `close`.

## mmap Write-Back

When `mmap(2)` is called on a virtual fd:

1. Content is materialized to a temp file
2. The temp file is mmap'd using the real `mmap`
3. The temp file is unlinked immediately (auto-cleanup on last close)
4. OS page cache handles lazy fault-in (only accessed pages consume RAM)

This is important for large files where tools (e.g., tree-sitter) mmap the file but only read a header region.

## Invariants

1. **Reads are virtual, writes are real.** The shim never writes to the daemon; it only reads content for materialization.
2. **Write-through to disk.** After a write-mode open, all I/O (write, pwrite, writev) goes to a real kernel fd. The shim does not buffer or intercept write data.
3. **Notification is best-effort.** Dropped notifications are caught by the daemon's reconciliation loop. The system is eventually consistent.
4. **Temp files are transient.** They exist only between open and close. Stale temps from crashes are cleaned on next open.
5. **No re-entrance.** Temp file paths contain `.kin_tmp_` which is explicitly excluded from workspace path matching.
