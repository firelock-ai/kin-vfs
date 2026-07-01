# VFS Authority and Write-Notify Contract

This note documents the runtime authority guarantees of the `kin-vfs` shim and
its daemon client: how a write is confirmed into the graph, how close-time
materialization surfaces errors, what happens when the daemon is unreachable,
and how reads and stats stay bounded and honest. It describes behavior as
implemented in `crates/kin-vfs-shim/src/{client,intercept,lib}.rs` and
`crates/kin-vfs-daemon/src/{kin_provider,async_kin_provider}.rs`.

The governing principle is the graph-first thesis: **the graph is the authority;
disk is a projection surface.** Where the graph cannot answer, the shim either
fails loud or takes a *labeled* compatibility pass-through — it never lets raw
disk silently masquerade as graph truth.

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
| connect refused / timeout | Daemon unreachable | Warn-once, labeled pass-through |

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

## 3. Daemon-unreachable behavior is explicit

The shim's daemon client distinguishes a *genuinely unreachable* daemon (connect
retries exhausted) from a *reachable "not in graph"* answer, tracked per-thread
and exposed as `client::last_call_unreachable()`. Behavior on an
authority-path miss (open/stat of a workspace file):

- **Default (`KIN_VFS_STRICT` unset):** labeled compatibility pass-through — the
  hook falls through to the real filesystem, warned once. This keeps adoption
  transparent (the Trojan-horse property).
- **Strict (`KIN_VFS_STRICT=1`):** an *unreachable*-daemon miss fails loud with
  `EIO` instead of reading raw disk, so proof and benchmark harnesses can never
  let stale disk stand in for graph truth. A plain not-found still passes through
  even in strict mode — strict only hardens the unreachable case.

This is orthogonal to the interposition canary (`KIN_VFS_CANARY`), which proves
the shim *loaded*; strict mode governs what happens when it is loaded but the
daemon is down.

## 4. Reads and stats are bounded and honest

- **Bounded prefetch.** A read-only `open` pulls a file whole into the per-fd
  cache only when it is at or under `SMALL_FILE_THRESHOLD` (64 KiB). A larger
  file is left uncached and served by range reads, so the shim never loads a
  large file wholesale — nor fetches bytes the fd table would immediately
  discard. The decision keys on the stat size.
- **No misleading metadata on failure.** The kin daemon's tree endpoint carries
  only `path → hash`, so the provider derives a file's size from its content. If
  that content read fails, `stat` now returns an **error** rather than a
  misleading `size: 0`: a zero would make the shim serve the file as empty,
  silently truncating real content. A clean error surfaces the miss instead.

Deriving size from content is a known cost of the current tree endpoint (it does
not report sizes); it is disclosed here rather than hidden, and remains a
candidate for a future daemon-side size field.
