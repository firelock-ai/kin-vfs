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

## 0. Path identity is byte-exact

Unix paths are byte sequences, not strings. Every path identity in this system
— `ContentProvider` lookups, cache keys, the VFS protocol, directory-entry
names, and write notifications — is a validated `VfsPath`/`VfsName` of exact
bytes. There is no UTF-8 requirement anywhere on the authority path and no
lossy conversion.

This is a correctness property, not a nicety. When interception borrowed
`CStr` contents as `&str`, a repository path containing invalid UTF-8 failed
the conversion and the hook passed the call through to the real syscall — raw
disk silently answered for a graph-owned file. A lossy decode is worse still:
it addresses a *different* artifact than the caller named.

Malformed paths are rejected at the boundary rather than normalized: absolute
paths, `.`/`..` components, empty components, and NUL bytes are refused at
decode time, so a malformed peer cannot inject them through the wire.

Windows has no byte-path API. Rather than coerce, it refuses: a graph name that
cannot be represented is reported as an error and the repository is unsupported
on that platform, never silently mangled.

## 1. Write-notify is acknowledged, not fire-and-forget

After a write lands on disk, the shim POSTs `/vfs/write-notify` to the repo's kin
daemon so the graph re-indexes immediately (the daemon's file watcher is only a
backstop). The POST runs on a dedicated worker thread (`kin-vfs-notify`), never
inside an interposed syscall, so it may block and allocate freely.

The body carries the **canonical repo-relative path bytes**, hex-encoded in the
same `{"bytes_hex": …}` envelope `kin_model::RepoPath` serializes to:

```json
{"path": {"bytes_hex": "7372632f6d61696e2e7273"}, "session_id": "…"}
```

A JSON string could not represent a non-UTF8 Unix path without lossy
substitution, which would attribute the write to a different (or nonexistent)
artifact. The exact body is pinned by `tests/fixtures/write-notify.json`.

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
| nested-repository (gitlink) boundary | `ENOTSUP` |
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
- **Universal entry metadata.** `/vfs/tree` returns one schema-versioned
  `kin_model::WorkspaceTreeSnapshot`. Its binding names the exact repository,
  workspace, symbolic or detached head, resolved base target/tree, dirty
  workspace tree, complete authority roots, workspace generation, and active
  admission-policy stamps. It then carries one exact resolved artifact per
  tracked leaf — stable `artifact_id`, byte-exact `RepoPath`, `TreeEntry`,
  exact size, and timestamp. That covers unsupported-language source,
  configuration, lockfiles, binary, executable, symbolic-link, non-UTF8, and
  gitlink entries alike. Unknown fields, non-canonical identity order,
  duplicate artifact IDs, duplicate paths, prefix collisions, invalid
  encodings, non-zero gitlink sizes, inconsistent authority bindings, and
  unsupported schema versions reject the whole document **before** any cache
  state changes.
- **Atomic, race-free refresh.** Freshness is one conditional
  `If-None-Match` request. The strong HTTP `ETag` is the canonical identity of
  the complete model-owned document; it is recomputed independently by the
  consumer and is not a caller-supplied JSON field. A separate version probe
  followed by a tree fetch would leave a window in which the tree changes under
  the check. A refresh installs one fully validated snapshot or retains the
  prior one unchanged; a regressed authority generation never installs, and
  two different snapshots claiming one generation fail loud as a ref race.
  A refresh failure also retains the last installed version counter rather
  than reporting zero, so invalidation clocks never move backward.
- **Graph-derived directory mutation metadata.** Every derived directory,
  including the always-present root, is indexed from byte-exact descendant
  paths and their stable artifact IDs, exact `TreeEntry` facets, sizes, and
  projection timestamps. Its mutation identity pairs that deterministic
  membership digest with the snapshot's workspace and repository authority
  generations. Directory `mtime` uses the monotonic repository generation,
  which is also the provider cache-invalidation version. Child add, remove,
  rename, mode/type change, and empty/nonempty transitions therefore advance
  rather than inheriting or regressing to the largest remaining leaf
  timestamp. Reopening the same snapshot reproduces the same identity and
  listing; no host-filesystem stat participates. Because schema 3 has no
  per-directory tombstone clock, an advancing repository snapshot
  conservatively advances all extant directory mtimes; the membership digest
  still identifies exactly which directory views changed.
- **Content-addressed reads.** Blob and symlink content is fetched by the exact
  `Hash256` the validated tree advertises (`/vfs/blob/<hash>`), never by a raw
  path URL. A full body is exposed only after its byte length and SHA-256
  identity match the tree entry. Because the cache is keyed by content hash, a
  path reuse or ref race can never return bytes belonging to another artifact.
- **Bound ranged reads.** A `206` response must carry both
  `X-Kin-Blob-Hash` matching the tree entry and an exact
  `Content-Range: bytes start-end/total` matching the requested range and tree
  size. A server that answers `200` is accepted only after the complete body
  passes the same size and hash verification, then the requested slice is
  returned.
- **Gitlinks are carried, never faked.** A nested-repository boundary appears
  in listings as its own entry kind. Every per-path operation on it fails with
  a typed unsupported-repository-boundary error (`ENOTSUP` on Unix,
  `NFS3ERR_NOTSUPP` over NFS) unless an actual child projection exists. It is
  never presented as a blob, a symlink, or an ordinary directory whose contents
  could be fabricated.
- **Metadata-only stat.** `stat` reads kind, executable mode, symlink size,
  content identity, and size from the exact tree snapshot. It never downloads a
  large body merely to discover its length.

## 5. The peer contract is pinned by shared fixtures

`tests/fixtures/` holds golden JSON for the `/vfs/tree` document and the
write-notify body. The VFS side asserts the shared `kin-model` types encode to
exactly those bytes *and* that the fixture survives full validation, so the
shared contract and the enforced contract cannot drift apart. The Kin daemon
should assert the same files. A change to either fixture is a peer-contract
change and must land on both sides together.
