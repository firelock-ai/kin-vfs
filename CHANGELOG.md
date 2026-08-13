# Changelog

All notable changes to kin-vfs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are tagged `v<version>`, minted automatically once a version bump
reaches `main`. Versions 0.1.1 through 0.1.4 predate that automation and were
never tagged; their dates below reflect the commit that bumped the workspace
version and are marked `(untagged)`.

Five tagged and published releases have no entry here: 0.2.0, 0.2.3, 0.3.1,
0.3.2, and 0.3.3. They are undocumented rather than nonexistent, and a reader
comparing this file against the tag list should expect the gap. Dates are the
tag's local date, so a release tagged just after midnight UTC carries the
previous calendar day.

## [Unreleased]

### Changed

- The workspace declares `rust-version = "1.85"` and every member inherits it.
  This makes legible a floor v0.4.2 already shipped: `lru` 0.18.2 and the
  `hashbrown` 0.17.1 it pulls in both declare 1.85.0, and `kin-vfs-core`
  depends on `lru`. Before that bump the published crate's floor was 1.71. A
  consumer now reads the floor from metadata instead of meeting it as a build
  failure.

## [0.4.2] - 2026-08-12

### Security

- `lru` moves from 0.16.4 to 0.18.2, resolving RUSTSEC-2026-0253, a
  use-after-free in `LruCache::pop` when a stored key's `Drop` panics. No
  kin-vfs cache key implements `Drop` and the release profile aborts on panic,
  so the shipped artifacts were not reachable by it. The bump was still urgent:
  `cargo-deny` is a required status context, so the advisory blocked every pull
  request in the repository until it cleared. Nothing kin-vfs uses from `lru`
  changed behavior.

## [0.4.1] - 2026-08-07

### Changed

- `kin-model` moves from 0.7.7 to 0.7.8. A registry pin refresh with no
  kin-vfs behavior change.

## [0.4.0] - 2026-08-07

A minor bump rather than a patch: `VfsResponse::Stat` changes shape and
`VfsResponse::Error` gains a field, so both the Rust API and the wire format
break. Consumers pinned to `0.3` stay there until they opt in, which is the
point — a shim and a daemon from different minors do not interoperate, and
nothing negotiates the protocol version at connect time to say so.

### Changed

- Resolving a workspace path costs one daemon round trip instead of one per
  path component. The shim asks about the whole path first; the component walk
  now runs only for a symlink or to classify an absence. A tool that stats a
  tree paid depth × files for prefixes it had already been told about, which is
  the cost `git status`, language servers and build tools carry.

- Protocol v4: `VfsResponse::Stat` and `VfsResponse::Error` carry the
  repository-authority generation of the snapshot that produced them, taken
  under the same read guard as the answer. Absence carries it too, so a client
  can key an absence as well as a presence.

- The shim remembers path-prefix facts per process, bounded and evicting, each
  stamped with the generation that produced it. It is consulted while resolving
  intermediate components and never to produce the attribute a caller receives:
  every intercepted stat still makes one live daemon call, so a caller cannot
  observe a remembered answer, and an answer carrying a newer generation
  discards everything remembered before the next path resolves. No clock, no
  TTL.

## [0.3.0] - 2026-08-01

### Added

- The interposition canary can now contradict its own load handshake. A shim
  that loads and is then routed around a workspace read reports the surface
  that served raw disk, and the launch verdict becomes `Bypassed`, named by
  surface, instead of `Active`. `fopen` and `freopen` are interposed for this
  purpose: they are not served from the graph, but they refuse under
  `KIN_VFS_STRICT=1` and report the bypass in every mode.
- The VFS daemon records every path-bearing lookup with its operation, its
  byte-exact path, how it was answered, and which backend answered it. Every
  lookup logs at `debug`; the first lookup of each outcome class logs at a
  visible level, so default output stays bounded while `KIN_VFS_LOG=debug`
  yields the full trace. Outcome classes distinguish a graph miss from an
  unreachable authority.
- Defaulted `ContentProvider` lookup-provenance hooks let remote providers name
  the request-local backend that answered without reconstructing provenance
  from mutable shared endpoint state.
- The daemon announces when the kin-daemon endpoint it re-resolves moves,
  vanishes, or comes back, once per transition rather than once per request.

### Fixed

- The interposition load announce is sent synchronously instead of on a
  detached thread. A process that read one file and exited could race its own
  announce and be reported `Stripped` despite having loaded the shim and read
  from the graph, which under strict mode made the launcher refuse a valid run.
  The process latch now commits only after the daemon acknowledges this process
  token. A best-effort short-lived announce may establish it; otherwise the
  first graph request connection must obtain acknowledgement before returning
  bytes, and later connections reuse that process evidence. Likewise, a
  canary-bearing raw-disk bypass fails closed if its red report is not
  acknowledged.
- `access()` responses for paths absent from graph authority now log as
  `not-in-graph`, rather than as graph-served successes.
- `kin-vfs status` distinguishes a repo with no advertised kin-daemon from one
  whose advertised daemon is unreachable, instead of naming the default port
  that no request would dial and that may belong to another repository.

### Release intent and installer/channel impact

- This is an intentional **v0.3.0 minor release**. `kin-vfs-core`'s published
  API gains variants on `InterposeStatus`, `VfsRequest`, and `VfsResponse`;
  consumers matching those enums exhaustively must add the new arms. The new
  `ContentProvider` provenance methods are defaulted and require no implementor
  change.
- `kin setup` and one-line installer channels must advance the Kin VFS CLI,
  daemon, and shim artifacts together: a shim that reports bypasses needs a
  daemon that records them and a launcher that reads them back.

## [0.2.2] - 2026-07-28

### Changed

- Scoped daemon providers now require a repository-v6 manifest with a non-empty
  `workspace_id`. Legacy manifests and non-UTF-8 scoped roots fail locally
  before any health, tree, blob, or bearer-token request. Existing legacy
  materializations must be migrated to repository-v6 before Kin VFS can serve
  them; v0.2.2 performs no implicit migration.
- Repo-scoped requests re-read the current daemon advertisement and bind every
  installed tree to the exact local repository and workspace identity. A
  concurrent endpoint move cannot relabel an in-flight response or install a
  wrong-workspace tree. Every transport or authentication retry repeats the
  local authority preflight, and a `304 Not Modified` revalidates the cached
  tree's binding against the current manifest before serving it.

### Fixed

- Corrected the macOS `__DATA,__interpose` table so all 23 linked replacement
  tuples bind to their matching libSystem functions, and made the runtime
  interception proofs fail instead of self-skipping when the shim is absent.
- Hardened workspace path resolution so ambiguous parent traversal, invalid
  directory descriptors, symlink aliases, and graph misses retain their
  fail-closed errno and graph-authority boundaries.

### Release intent and installer/channel impact

- This is an intentional **v0.2.2 patch release**. The published
  `kin-vfs-core` API is unchanged; the release corrects daemon-provider trust
  and projection behavior in the versioned CLI, daemon, and shim artifacts.
- `kin setup` and one-line installer channels must advance the Kin VFS CLI,
  daemon, platform shim, and any FUSE-enabled CLI build together to v0.2.2. No
  new flag or configuration is required, but a mixed or older channel does not
  carry these authority and macOS interposition corrections.
- Repository-v6 workspaces continue without operator action. A pre-v6
  materialization is intentionally refused until the owning Kin migration or
  re-admission flow writes its `workspace_id`.

## [0.2.1] - 2026-07-28

### Fixed

- Resolved relative paths against the intercepted process's working directory
  before the workspace check, so a relative read inside the workspace is served
  from the graph exactly like its absolute spelling instead of falling through
  to the raw filesystem.
- Re-resolved the kin-daemon endpoint once after a transport failure, so a VFS
  daemon follows kin-daemon across a restart onto a new ephemeral port instead
  of dialing a dead URL for the rest of its life.

### Changed

- `KIN_VFS_STRICT=1` now names a definitive graph miss a refusal (`EIO`) rather
  than an absence (`ENOENT`). Neither mode consults raw disk, and answers about
  entries the graph does hold are unchanged.

## [0.1.5] - 2026-07-13

### Fixed

- Fixed Linux arm64 `stat` passthrough.

### Changed

- Polished the README and clarified per-platform VFS support status.
- Clarified the platform boundaries between the shim and FUSE projection modes.
- Aligned the project tagline with Kin's "proves the change" positioning.

## [0.1.4] - 2026-07-11 (untagged)

### Fixed

- Translated host paths to graph keys in the shim.

## [0.1.3] - 2026-07-09 (untagged)

Version bump only; no functional changes.

## [0.1.2] - 2026-07-03 (untagged)

### Added

- Hermetic provider↔daemon wire-contract test coverage for `kin-vfs-daemon`.

### Changed

- Corrected the macOS interception docs to reference the `__interpose` table.
- Aligned the public one-liner and category noun across docs.

### Fixed

- Applied clippy 1.97 lints.

## [0.1.1] - 2026-07-02 (untagged)

### Added

- Documented release metadata and the compatibility policy.

### Changed

- CI now runs PR-branch commits once and cancels superseded runs.
- CI retired the no-op notify-downstream job and bumped kin-actions to v0.1.9.

### Fixed

- Imported test-helper std deps on all targets.

## [0.1.0] - 2026-03-28

Initial public release: the shim, FUSE, and NFS projection modes, plus the
CI and docs hardening that landed before the first version bump.

### Added

- Initial `kin-vfs` workspace: the `ContentProvider` trait, Unix-socket
  daemon, and LD_PRELOAD/DYLD interception shim.
- FUSE mount mode (macFUSE / FUSE-T / libfuse) as a system-wide alternative
  to the per-process shim.
- Multi-workspace NFS adapter with auto-mount and auto-discovery.
- Write-back, session scoping, and push invalidation.

### Changed

- Added CONTRIBUTING, CODE_OF_CONDUCT, and SECURITY docs, and polished the
  README with badges and ecosystem links.

### Fixed

- Made macOS DYLD interposition actually intercept file I/O, with lossless
  write-notify.
- Hardened the shim's cdylib FFI boundary to be panic-safe, with a re-entry
  guard and errno preservation for interposed hooks.
