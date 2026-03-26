# Deployment Guide

How to install, configure, and auto-start the kin-vfs daemon and shim.

## Prerequisites

- `kin-vfs` CLI binary (`cargo build --release -p kin-vfs-cli`)
- `libkin_vfs_shim.dylib` (macOS) or `libkin_vfs_shim.so` (Linux) built with `cargo build --release -p kin-vfs-shim`
- A workspace with `.kin/` initialized (`kin init`)

## Daemon Configuration

The daemon binds a Unix socket at `<workspace>/.kin/vfs.sock` and writes its PID to `<workspace>/.kin/vfs.pid`. Override the socket path with `KIN_VFS_SOCK`.

If `kin-daemon` is running on `:4219`, the VFS daemon uses `KinDaemonProvider` for blob resolution. Otherwise it falls back to a placeholder provider.

## macOS: launchd

Create `~/Library/LaunchAgents/com.firelock.kin-vfs.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.firelock.kin-vfs</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/kin-vfs</string>
    <string>start</string>
    <string>--workspace</string>
    <string>/Users/you/project</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/kin-vfs.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/kin-vfs.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>KIN_VFS_LOG</key>
    <string>info</string>
  </dict>
</dict>
</plist>
```

Load and start:

```bash
launchctl load ~/Library/LaunchAgents/com.firelock.kin-vfs.plist
launchctl start com.firelock.kin-vfs
```

Stop and unload:

```bash
launchctl stop com.firelock.kin-vfs
launchctl unload ~/Library/LaunchAgents/com.firelock.kin-vfs.plist
```

## Linux: systemd

Create `~/.config/systemd/user/kin-vfs.service`:

```ini
[Unit]
Description=Kin VFS daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kin-vfs start --workspace %h/project
ExecStop=/usr/local/bin/kin-vfs stop --workspace %h/project
Restart=on-failure
RestartSec=3
Environment=KIN_VFS_LOG=info

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable kin-vfs
systemctl --user start kin-vfs
systemctl --user status kin-vfs
```

## Loading the Shim via Shell Hooks

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.config/fish/config.fish`):

### bash / zsh

```bash
# kin-vfs shim auto-load
export KIN_VFS_WORKSPACE="$HOME/project"

# macOS
export DYLD_INSERT_LIBRARIES="/usr/local/lib/libkin_vfs_shim.dylib"

# Linux
# export LD_PRELOAD="/usr/local/lib/libkin_vfs_shim.so"
```

### fish

```fish
set -gx KIN_VFS_WORKSPACE "$HOME/project"
set -gx DYLD_INSERT_LIBRARIES "/usr/local/lib/libkin_vfs_shim.dylib"
```

### Per-command loading (no global injection)

If you prefer not to inject the shim globally, wrap individual commands:

```bash
KIN_VFS_WORKSPACE=/path/to/repo \
  DYLD_INSERT_LIBRARIES=/usr/local/lib/libkin_vfs_shim.dylib \
  your-command
```

## Socket Path Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KIN_VFS_SOCK` | `$KIN_VFS_WORKSPACE/.kin/vfs.sock` | Unix socket path (Linux/macOS) |
| `KIN_VFS_PIPE` | `\\.\pipe\kin-vfs-{hash}` | Named pipe (Windows) |

The daemon removes stale socket files on startup automatically. Socket permissions are set to `0700` (owner-only access).

## Multiple Workspaces

Each workspace needs its own daemon instance. For multiple repos, create one launchd plist or systemd unit per workspace, adjusting the `--workspace` argument and using distinct socket paths.
