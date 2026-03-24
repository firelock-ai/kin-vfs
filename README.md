# kin-vfs

**Purpose-built virtual filesystem for serving files from a content-addressed store.**

kin-vfs eliminates file duplication by serving files directly from a blob store. Working trees appear as normal directories, but every file is backed by content-addressed storage -- zero extra disk usage, instant checkouts, and transparent reads for any tool that opens a file.

> **Alpha** -- APIs will evolve. The daemon, shim, and CLI are functional but still hardening.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)

---

## How It Works

```
 ┌──────────┐     LD_PRELOAD / DYLD / ProjFS     ┌────────────┐
 │   Tool   │ ──────────────────────────────────► │    Shim    │
 │ (editor, │   intercepts open/read/stat/etc.    │  (cdylib)  │
 │  build,  │                                     └─────┬──────┘
 │  grep…)  │                                           │ msgpack
 └──────────┘                                           │ over
                                                        │ unix socket
                                                  ┌─────▼──────┐
                                                  │   Daemon    │
                                                  │ (tokio srv) │
                                                  └─────┬──────┘
                                                        │
                                                  ┌─────▼──────┐
                                                  │ Blob Store  │
                                                  │ (CAS / kin) │
                                                  └─────────────┘
```

| Platform | Interception Method | Status |
|----------|-------------------|--------|
| Linux    | `LD_PRELOAD` shared library | Primary target |
| macOS    | `DYLD_INSERT_LIBRARIES` | Primary target |
| Windows  | Projected File System (ProjFS) | Planned |

---

## Quick Start

```bash
# Prerequisites: Rust stable
git clone https://github.com/firelock-ai/kin-vfs.git
cd kin-vfs
cargo build --workspace

# Run tests
cargo test --workspace

# Start the daemon (serves a blob store at a mount point)
cargo run -p kin-vfs-cli -- start --root /path/to/workdir --store /path/to/blobstore

# In another shell, run any tool under the shim
LD_PRELOAD=target/debug/libkin_vfs_shim.so cat /path/to/workdir/some-file.rs
# On macOS: DYLD_INSERT_LIBRARIES=target/debug/libkin_vfs_shim.dylib
```

---

## Crate Layout

```
crates/kin-vfs-core/     ContentProvider trait, virtual file tree, LRU cache
crates/kin-vfs-daemon/   Tokio daemon: serves file content over Unix socket
crates/kin-vfs-shim/     cdylib shim: intercepts libc calls via LD_PRELOAD / DYLD
crates/kin-vfs-cli/      CLI binary: start, stop, status
tests/integration/       End-to-end tests across daemon + shim
```

---

## Ecosystem

| Component | Description |
|-----------|-------------|
| **[kin](https://github.com/firelock-ai/kin)** | Semantic VCS -- primary consumer of kin-vfs |
| **[kin-db](https://github.com/firelock-ai/kin-db)** | Graph engine substrate |
| **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** | Virtual filesystem (this repo) |

---

## Contributing

Contributions welcome. Please open an issue before submitting large changes.

## License

Apache-2.0.

---

Created by [Troy Fortin](https://www.linkedin.com/in/troy-fortin-jr/) at [Firelock, LLC](https://firelock.ai).
