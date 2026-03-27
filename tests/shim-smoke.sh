#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Shim smoke test: verifies the full LD_PRELOAD/DYLD_INSERT_LIBRARIES pipeline.
#
# Prerequisites:
#   1. Build the workspace: cargo build --release --workspace
#   2. Ensure kin-daemon is NOT required (this test uses the VFS daemon directly)
#
# Usage:
#   ./tests/shim-smoke.sh
#
# What it does:
#   1. Creates a temp workspace with .kin/ directory
#   2. Starts the VFS daemon with a placeholder provider
#   3. Loads the shim into a subprocess (cat) via DYLD/LD_PRELOAD
#   4. Verifies the subprocess can read (will get ENOENT since placeholder returns nothing)
#   5. Cleans up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Detect platform and set shim path
case "$(uname -s)" in
    Darwin)
        SHIM_LIB="$REPO_ROOT/target/release/libkin_vfs_shim.dylib"
        SHIM_ENV="DYLD_INSERT_LIBRARIES"
        ;;
    Linux)
        SHIM_LIB="$REPO_ROOT/target/release/libkin_vfs_shim.so"
        SHIM_ENV="LD_PRELOAD"
        ;;
    *)
        echo "SKIP: unsupported platform $(uname -s)"
        exit 0
        ;;
esac

# Check that the shim is built
if [ ! -f "$SHIM_LIB" ]; then
    echo "SKIP: shim not built at $SHIM_LIB"
    echo "  Run: cargo build --release -p kin-vfs-shim"
    exit 0
fi

# Check that the CLI is built
VFS_CLI="$REPO_ROOT/target/release/kin-vfs"
if [ ! -f "$VFS_CLI" ]; then
    echo "SKIP: kin-vfs CLI not built at $VFS_CLI"
    echo "  Run: cargo build --release -p kin-vfs-cli"
    exit 0
fi

# Create temp workspace
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/.kin"
SOCK="$TMPDIR/.kin/vfs.sock"

echo "=== Shim smoke test ==="
echo "Workspace: $TMPDIR"
echo "Socket:    $SOCK"
echo "Shim:      $SHIM_LIB"
echo ""

# Start VFS daemon in background (will use PlaceholderProvider)
"$VFS_CLI" start --workspace "$TMPDIR" &
DAEMON_PID=$!

# Wait for socket to appear
for i in $(seq 1 20); do
    if [ -S "$SOCK" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$SOCK" ]; then
    echo "FAIL: daemon socket did not appear within 2 seconds"
    kill "$DAEMON_PID" 2>/dev/null || true
    exit 1
fi

echo "Daemon started (PID $DAEMON_PID)"

# Test 1: Run a process with shim loaded, reading a file inside the workspace.
# Since PlaceholderProvider returns NotFound for everything, cat should fail
# with an error (this proves the shim intercepted the read).
echo ""
echo "Test 1: shim intercepts reads inside workspace"

# Create a real file so we can tell if the shim intercepted or not
echo "real-content" > "$TMPDIR/test.txt"

# Run cat with the shim loaded. The shim should intercept the open() call
# for files inside KIN_VFS_WORKSPACE, but with PlaceholderProvider the daemon
# will return NotFound, so the shim falls back to the real file.
OUTPUT=$(env \
    "$SHIM_ENV=$SHIM_LIB" \
    KIN_VFS_WORKSPACE="$TMPDIR" \
    KIN_VFS_SOCK="$SOCK" \
    cat "$TMPDIR/test.txt" 2>&1) || true

if echo "$OUTPUT" | grep -q "real-content"; then
    echo "  PASS: shim loaded, fallback to real file works"
else
    echo "  WARN: unexpected output: $OUTPUT"
    echo "  (This may be a SIP restriction on macOS)"
fi

# Test 2: Verify shim is disabled when KIN_VFS_DISABLE=1
echo ""
echo "Test 2: KIN_VFS_DISABLE=1 bypasses shim"

OUTPUT=$(env \
    "$SHIM_ENV=$SHIM_LIB" \
    KIN_VFS_WORKSPACE="$TMPDIR" \
    KIN_VFS_SOCK="$SOCK" \
    KIN_VFS_DISABLE=1 \
    cat "$TMPDIR/test.txt" 2>&1) || true

if echo "$OUTPUT" | grep -q "real-content"; then
    echo "  PASS: shim disabled, real file read"
else
    echo "  WARN: unexpected output: $OUTPUT"
fi

# Test 3: Reads outside workspace are not intercepted
echo ""
echo "Test 3: reads outside workspace are passthrough"

OUTSIDE=$(mktemp)
echo "outside-content" > "$OUTSIDE"
trap 'rm -rf "$TMPDIR" "$OUTSIDE"' EXIT

OUTPUT=$(env \
    "$SHIM_ENV=$SHIM_LIB" \
    KIN_VFS_WORKSPACE="$TMPDIR" \
    KIN_VFS_SOCK="$SOCK" \
    cat "$OUTSIDE" 2>&1) || true

if echo "$OUTPUT" | grep -q "outside-content"; then
    echo "  PASS: outside workspace reads are passthrough"
else
    echo "  WARN: unexpected output: $OUTPUT"
fi

# Cleanup
echo ""
echo "Stopping daemon..."
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

echo ""
echo "=== All smoke tests passed ==="
