# VFS Authority and Write-Notify Contract

This note documents the runtime authority guarantees of the `kin-vfs` shim and
its daemon client: how a write is confirmed into the graph, how close-time
materialization surfaces errors, what happens when the daemon is unreachable,
and how reads and stats stay bounded and honest. It describes behavior as
implemented in `crates/kin-vfs-shim/src/{client,intercept,lib}.rs` and
`crates/kin-vfs-daemon/src/{kin_provider,async_kin_provider}.rs`.

The governing principle is the graph-first thesis: **the graph is the authority;
disk is a projection surface.** Once a path is inside the configured workspace,
raw filesystem contents never answer read, stat, directory, access, or readlink
requests. A graph absence or authority failure is surfaced to the caller.

## 1. Write-notify is acknowledged, not fire-and-forget

After a write lands on disk, the shim POSTs `/vfs/write-notify` to the repo's kin
daemon so the graph re-indexes immediately (the daemon's file watcher is only a
backstop). The POST runs on a dedicated worker thread (`kin-vfs-notify`), never
inside an interposed syscall, so it may block and allocate freely.

The worker **requires and parses** the daemon's reply rather than discarding it:

| Daemon reply | Meaning | Shim action |
|---|---|---|
| `200 {"reindexed":true,…}` | Re-indexed | Acknowledged — success, silent |
| `200 {"reindexed":false,…}` | Reached but soft-blocked / reconcile failed | Surfaced (warn-once) |
| non-2xx `401` / `409` | Auth failure / write-veto | Surfaced (warn-once), not retried |
| `5xx` or mid-exchange I/O error | Possibly transient | Retried once, then surfaced |
| connect refused / timeout | Daemon unreachable | Warn-once; the already-landed projection write remains visibly unreconciled |

Only `200 {reindexed:true}` counts as success. Everything else is surfaced once
(distinct diagnostics for *unreachable* vs *reached-but-declined*) so a divergence
between disk and graph is observable, never hidden behind a best-effort send. The
reconcile signal itself remains lossless (unbounded queue): the change here is
that delivery is now *verified*, not merely *attempted*.

## 2. Close-time materialization surfaces errors before notifying

A write-flagged `open` materializes an atomic temp file from graph truth; on
`close` the shim promotes it to the target and notifies the graph. The graph is
told about the write **only when the bytes actually landed**:

- If the temp `close` returns non-zero (buffered data may not have flushed), the
  shim does **not** rename over the target and does **not** notify — it returns
  the real errno. A close-after-write error can never become a phantom
  "graph converged" signal.
- If the atomic `rename` fails (target left untouched, temp reclaimed on a later
  open), the shim does **not** notify and returns `EIO`.
- A plain (non-atomic) tracked write notifies only if its `close` succeeded.

The gate is the pure, unit-tested predicate `atomic_write_should_notify`.

## 3. Workspace reads fail loud without graph authority

The daemon client records a precise per-thread failure class for every request.
Workspace hooks map those classes directly to syscall errors:

| Graph result | Syscall result |
|---|---|
| exact entry absent | `ENOENT` |
| permission denied | `EACCES` |
| file/directory kind mismatch | `EISDIR` / `ENOTDIR` |
| `readlink` of a non-link | `EINVAL` |
| daemon unreachable | `EIO` |
| malformed response or size/hash/range disagreement | `EIO` |

This behavior is unconditional; there is no runtime compatibility mode that
allows a workspace read miss to consult raw disk. `KIN_VFS_CANARY` remains a
separate launch-time proof that interposition loaded. Launcher policy may refuse
to start a process when that proof is absent, but it does not change authority
semantics after the shim is active.

## 4. Reads and stats are bounded and honest

- **Bounded prefetch.** A read-only `open` pulls a file whole into the per-fd
  cache only when it is at or under `SMALL_FILE_THRESHOLD` (64 KiB). A larger
  file is left uncached and served by range reads, so the shim never loads a
  large file wholesale — nor fetches bytes the fd table would immediately
  discard. The decision keys on the exact graph-owned size; even an empty small
  file is fetched once so its hash and size are verified before open succeeds.
- **Universal entry metadata.** `/vfs/tree` supplies one `kin_model::TreeEntry`
  and one exact size for every tracked path, including unsupported-language
  source, configuration, binary, executable, and symbolic-link entries. A
  missing or extra size, non-canonical path, or file/directory collision rejects
  the entire snapshot.
- **Exact full reads.** A full `/vfs/read/<path>` response is exposed only after
  its byte length and SHA-256 identity match the tree entry.
- **Bound ranged reads.** A `206` response must carry both
  `X-Kin-Blob-Hash` matching the tree entry and an exact
  `Content-Range: bytes start-end/total` matching the requested range and tree
  size. A server that answers `200` is accepted only after the complete body
  passes the same size and hash verification, then the requested slice is
  returned.
- **Metadata-only stat.** `stat` reads kind, executable mode, symlink size,
  content identity, and size from the exact tree snapshot. It never downloads a
  large body merely to discover its length.
