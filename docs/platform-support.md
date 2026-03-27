# Platform Support

Status of kin-vfs across operating systems, including interception method, build artifacts, and known limitations.

## Support Matrix

| Platform | Method | Artifact | Status | Notes |
|----------|--------|----------|--------|-------|
| **Linux** | `LD_PRELOAD` shared library | `libkin_vfs_shim.so` | Fully supported | Primary target. glibc and musl compatible. |
| **Linux** | FUSE mount (libfuse/fuse3) | N/A (mount point) | Available (`--features fuse`) | Requires `fuse3` installed. |
| **macOS** | `DYLD_INSERT_LIBRARIES` | `libkin_vfs_shim.dylib` | Fully supported | Primary target. SIP restrictions apply. |
| **macOS** | FUSE mount (FUSE-T) | N/A (mount point) | Available (`--features fuse`) | Preferred macOS FUSE variant. Userspace, no kext. |
| **macOS** | FUSE mount (macFUSE) | N/A (mount point) | Available (`--features fuse`) | Kernel extension required. |
| **Windows** | ProjFS (Projected File System) | N/A (explicit init) | Structurally complete, not CI-tested | Community preview. |

## Linux

### LD_PRELOAD Shim

The shim is loaded into any process via `LD_PRELOAD`. It hooks libc symbols (`open`, `read`, `stat`, `close`, etc.) using `dlsym(RTLD_NEXT)` and routes workspace file access to the VFS daemon over a Unix socket.

**Build:**
```bash
cargo build --release -p kin-vfs-shim
# Output: target/release/libkin_vfs_shim.so
```

**Use:**
```bash
export KIN_VFS_WORKSPACE=/path/to/repo
export LD_PRELOAD=/path/to/libkin_vfs_shim.so
your-command
```

**libc compatibility:**
- **glibc:** Fully supported. The shim hooks both versioned (`__xstat`, `__fxstat`) and unversioned (`stat`, `fstat`) symbols.
- **musl:** Supported. musl uses unversioned symbols only; the shim handles this.

**SELinux:** May block `LD_PRELOAD`. See `docs/troubleshooting.md` for policy module instructions.

### FUSE Mount (libfuse)

Presents a read-only mount point visible to all processes. No `LD_PRELOAD` needed.

**Requirements:** `fuse3` (`apt install fuse3 libfuse3-dev` or equivalent)

**Build:**
```bash
cargo build --release -p kin-vfs-cli --features fuse
```

## macOS

### DYLD_INSERT_LIBRARIES Shim

Same mechanism as Linux `LD_PRELOAD`, using macOS's `DYLD_INSERT_LIBRARIES`.

**Build:**
```bash
cargo build --release -p kin-vfs-shim
# Output: target/release/libkin_vfs_shim.dylib
```

**Use:**
```bash
export KIN_VFS_WORKSPACE=/path/to/repo
export DYLD_INSERT_LIBRARIES=/path/to/libkin_vfs_shim.dylib
your-command
```

**SIP (System Integrity Protection):**

SIP strips `DYLD_INSERT_LIBRARIES` from processes launched from SIP-protected paths (`/usr/bin`, `/System`, `/sbin`). This affects system binaries like `/usr/bin/cat` and `/usr/bin/grep`.

**Workarounds:**
- Use Homebrew binaries: `/opt/homebrew/bin/gcat`, `/opt/homebrew/bin/ggrep`
- Copy target binaries to a non-SIP path (e.g., `/usr/local/bin`)
- Disable SIP (development machines only; `csrutil disable` in Recovery Mode)

**Code signing:** Hardened-runtime binaries reject unsigned injected libraries. Ad-hoc sign the shim:
```bash
codesign -s - target/release/libkin_vfs_shim.dylib
```

### FUSE Mount

Two FUSE implementations are supported:

**FUSE-T** (preferred): Userspace FUSE implementation. No kernel extension required.
```bash
brew install fuse-t
```

**macFUSE**: Traditional kernel extension. Requires allowing the kext in System Preferences > Security.
```bash
brew install macfuse
```

**Build and use:**
```bash
cargo build --release -p kin-vfs-cli --features fuse
kin-vfs mount --workspace /path/to/repo --mount-point /tmp/kin-mount
```

The FUSE mount is **read-only**. Write attempts return `EROFS`. Use the shim mode for write-through support.

## Windows

### ProjFS (Projected File System)

Windows support uses ProjFS, a kernel-mode filesystem virtualization provider. Unlike `LD_PRELOAD` which piggybacks on the host process, ProjFS requires an active process to service kernel callbacks.

**Status:** Structurally complete. The codebase includes:
- `kin-vfs-shim/src/platform/windows.rs` — `ProjFsProvider` with callback implementations
- `kin-vfs-shim/src/client.rs` — `NamedPipeClient` for Windows named pipe communication
- `kin-vfs-shim/src/lib.rs` — `shim_init_windows()` entry point

**Not yet tested in CI.** Windows ProjFS support has the code path complete but has not been validated in automated testing. It is available as a community preview for early adopters.

**Requirements:**
- Windows 10 version 1809+ or Windows Server 2019+
- ProjFS optional feature enabled: `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`

**Architecture differences from Unix:**
- Uses named pipes (`\\.\pipe\kin-vfs-{hash}`) instead of Unix sockets
- ProjFS callbacks are serviced by the daemon process, not injected into host processes
- Path normalization handles backslash/forward-slash conversion
- `shim_init_windows()` is called explicitly from the daemon, not via a constructor attribute

## Choosing Between Shim and FUSE

| | Shim (LD_PRELOAD/DYLD) | FUSE mount |
|---|---|---|
| **Visibility** | Per-process only | System-wide mount point |
| **macOS SIP** | Blocked for system binaries | No SIP issues |
| **Static binaries** | Not intercepted | Fully supported |
| **Requires install** | Nothing (shim is a .so/.dylib) | macFUSE, FUSE-T, or libfuse |
| **Write-through** | Yes (writes go to real disk) | No (read-only, returns EROFS) |
| **Overhead** | Very low (in-process) | Kernel round-trips per operation |
| **Setup** | Environment variables per process | Single mount command |

**Use the shim** when you need write-through and per-process control.

**Use FUSE** when you need universal tool compatibility, including static binaries and SIP-protected programs.
