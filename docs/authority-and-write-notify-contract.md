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
bytes, with no lossy conversion. The scoped provider's repository root is the
narrow representability boundary: daemon health identifies that canonical root
as text, so a non-UTF-8 root fails local preflight before any request or bearer
token leaves the process. That boundary does not decode or weaken byte-exact
artifact paths and names inside a representable repository root.

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

Containment is decided on **absolute** bytes, so a relative argument is resolved
against the intercepted process's current working directory before the workspace
check. `getcwd` is not an interposed symbol, so reading it from inside a hook
reaches real libc without re-entering the shim, and it is read per call because
the host may `chdir` at any point in its lifetime. Skipping that resolution is
the same authority hole as a lossy decode: `open("main.rs")` from inside the
workspace would never match the root, and raw disk would answer for a graph-owned
file while every absolute spelling of the same path went to the graph.

Parent traversal is classified before that containment check. A spelling such
as `../workspace/file` from a sibling directory can kernel-resolve into the
workspace even though its unresolved bytes do not begin with the workspace
root. A leading relative `..` is applied directly to the already-resolved cwd or
directory descriptor, so the shim can normalize it exactly and route an
outside-to-inside candidate to graph authority. A `..` after a caller-supplied
component is different: that component may be a symlink, so the spelling alone
cannot say where the path lands.

What the shim must not do is let raw disk answer for a graph-owned path, and
that danger exists only when a workspace-owned destination is reachable. So
workspace relevance is decided first, and every mode refuses the ambiguous
spelling whenever the answer is yes. Relevance is settled by asking the kernel
where the traversal's deepest resolvable ancestor actually is, the same
consultation used to place a live directory descriptor. That is path structure,
never file content, and a destination inside the workspace is still refused
rather than read from disk. `ENOENT` alone is not treated as proof that a
component is absent, because a dangling symlink fails identically while still
redirecting; each unresolvable component is re-checked with `lstat` and anything
the kernel cannot place keeps the refusal.

A traversal whose destination is provably outside every workspace root has no
graph-owned candidate to protect and is passed to libc unchanged. Embedded `..`
is how autotools, cmake, libtool, pkg-config, node module resolution and rustc
`-L` arguments spell their own directories; refusing those would leave a
shim-enabled process unable to open its own toolchain.

If `getcwd` or a valid directory `dirfd` cannot be resolved, the shim returns
`EIO` rather than handing an authority-ambiguous relative path to libc. A
definitively invalid descriptor retains native `EBADF`, while a proven valid
non-directory descriptor is passed back for libc's native `ENOTDIR`. The
`getcwd` buffer grows on `ERANGE`, so a valid long cwd is not mistaken for a
resolution failure.

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

| Graph result | Syscall result | Under `KIN_VFS_STRICT=1` |
|---|---|---|
| exact entry absent | `ENOENT` | `EIO` |
| permission denied | `EACCES` | `EACCES` |
| file/directory kind mismatch | `EISDIR` / `ENOTDIR` | unchanged |
| `readlink` of a non-link | `EINVAL` | `EINVAL` |
| nested-repository (gitlink) boundary | `ENOTSUP` | `ENOTSUP` |
| daemon unreachable | `EIO` | `EIO` |
| malformed response or size/hash/range disagreement | `EIO` | `EIO` |

This behavior is unconditional; there is no runtime compatibility mode that
allows a workspace read miss to consult raw disk. Strict mode does not add the
refusal — it changes what the refusal is *called*. By default a path the graph
does not hold is an absence, which is what an ordinary tool expects; under strict
it is a refusal on the same `EIO` path as unavailable authority, so a caller that
must stay inside graph truth cannot mistake "the graph does not hold this" for
"this file does not exist". Answers about an entry the graph *does* hold keep
their exact meaning in both modes.

Strict mode is read once at shim init and fixed for the process lifetime, so a
tool cannot relax the boundary by mutating its own environment. `KIN_VFS_CANARY`
remains a separate launch-time proof that interposition loaded. Launcher policy
may refuse to start a process when that proof is absent, but it does not change
authority semantics after the shim is active.

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
- **Endpoint identity is revalidated.** A repo-scoped provider re-reads the
  current `KIN_DAEMON_URL` / `.kin/daemon.port` advertisement before every
  request. If no endpoint is currently advertised it refuses the request
  instead of dialing a cached port, because the OS may already have reassigned
  that port to another repository's daemon. Before **any** scoped HTTP request,
  the local root must be representable by the daemon's textual identity contract
  and `.kin/manifest.json` must carry both `repo_id` and the repository-v6
  `workspace_id`. A legacy manifest without `workspace_id` fails locally and
  must be migrated; neither `/health`, `/vfs/tree`, nor a bearer token is sent.
  `/health` availability then matches both the manifest `repo_id` and canonical
  local root. Every `200 /vfs/tree` additionally matches both manifest
  identifiers before the snapshot can install. This applies to direct, FUSE,
  and NFS providers rather than relying on a separate CLI availability probe.
  That local preflight repeats before every transport or authentication retry.
  A `304 Not Modified` also revalidates the exact cached tree binding against
  the current manifest, so an old endpoint cannot carry a prior workspace cache
  across a local authority change.
  A blob is fetched only after that exact workspace-bound tree handshake and is
  verified by its content hash, so an endpoint replacement cannot substitute
  another repository's bytes. Endpoint and bearer-token changes have separate
  one-use retry budgets:
  a port move followed by a `401` from a rotated token may take one retry for
  each, but neither can loop without bound.
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
  listing; no host-filesystem stat participates. Because the current schema has
  no per-directory tombstone clock, an advancing repository snapshot
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
