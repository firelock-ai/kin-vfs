# Changelog

All notable changes to kin-vfs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions after 0.1.0 have not been tagged in this repository; their dates
below reflect the commit that bumped the workspace version and are marked
`(untagged)`.

## [Unreleased]

### Changed

- Polished the README and clarified per-platform VFS support status.
- Clarified the platform boundaries between the shim and FUSE projection modes.
- Aligned the project tagline with Kin's "proves the change" positioning.

## [0.1.5] - 2026-07-13 (untagged)

### Fixed

- Fixed Linux arm64 `stat` passthrough.

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
