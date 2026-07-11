#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Bounded opt-in smoke for the production bridge:
#
#   intercepted host path -> shim MessagePack -> kin-vfs daemon
#   -> KinDaemonProvider HTTP -> real kin-daemon repo-relative graph key
#
# This is intentionally not part of the default unit suite because it requires
# binaries from both the kin and kin-vfs repositories. CI/release captains can
# provide exact binaries through the environment variables documented below.

set -euo pipefail

TIMEOUT_SECONDS="${KIN_VFS_SMOKE_TIMEOUT_SECONDS:-90}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

resolve_binary() {
    local explicit="$1"
    local fallback="$2"
    local command_name="$3"

    if [ -n "$explicit" ]; then
        printf '%s\n' "$explicit"
    elif [ -x "$fallback" ]; then
        printf '%s\n' "$fallback"
    elif command -v "$command_name" >/dev/null 2>&1; then
        command -v "$command_name"
    else
        printf 'missing %s; set its explicit smoke environment variable\n' "$command_name" >&2
        return 1
    fi
}

KIN_BIN="$(resolve_binary "${KIN_BIN:-}" "" kin)"
KIN_DAEMON_BIN="$(resolve_binary "${KIN_DAEMON_BIN:-}" "" kin-daemon)"
KIN_VFS_BIN="$(resolve_binary "${KIN_VFS_BIN:-}" "$TARGET_DIR/release/kin-vfs" kin-vfs)"
VFS_PROBE_BIN="$(resolve_binary "${VFS_PROBE_BIN:-}" "$TARGET_DIR/release/vfs_open_probe" vfs_open_probe)"

for binary in "$KIN_BIN" "$KIN_DAEMON_BIN" "$KIN_VFS_BIN" "$VFS_PROBE_BIN"; do
    if [ ! -x "$binary" ]; then
        printf 'required binary is not executable: %s\n' "$binary" >&2
        exit 1
    fi
done

run_bounded() {
    # Perl is part of the default macOS and Linux environments. `alarm` keeps a
    # wedged child from pinning either daemon after the outer cleanup trap fires.
    perl -e '$timeout = shift @ARGV; alarm($timeout); exec @ARGV' "$TIMEOUT_SECONDS" "$@"
}

WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/kin-vfs-real-daemon.XXXXXX")"
KIN_DAEMON_PID=""
VFS_DAEMON_PID=""

dump_failure_logs() {
    local diagnostics_dir="${WORKSPACE}.failure-logs"
    local log_path=""

    mkdir -p "$diagnostics_dir"
    for log_path in kin-daemon.log kin-vfs-daemon.log probe.stdout probe.stderr; do
        if [ ! -f "$WORKSPACE/$log_path" ]; then
            continue
        fi
        cp "$WORKSPACE/$log_path" "$diagnostics_dir/$log_path"
        printf '\n===== %s =====\n' "$log_path" >&2
        sed -n '1,240p' "$WORKSPACE/$log_path" >&2 || true
    done
    printf '\nsmoke failure logs preserved at %s\n' "$diagnostics_dir" >&2
}

cleanup() {
    local status=$?
    set +e
    if [ -n "$VFS_DAEMON_PID" ]; then
        kill "$VFS_DAEMON_PID" 2>/dev/null || true
        wait "$VFS_DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "$KIN_DAEMON_PID" ]; then
        kill "$KIN_DAEMON_PID" 2>/dev/null || true
        wait "$KIN_DAEMON_PID" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        dump_failure_logs
    fi
    chmod u+rw "$WORKSPACE/probe.rs" 2>/dev/null || true
    rm -rf "$WORKSPACE"
    return "$status"
}
trap cleanup EXIT INT TERM

GRAPH_BYTES='pub fn graph_authority_probe() -> u64 { 42 }'
printf '%s\n' "$GRAPH_BYTES" > "$WORKSPACE/probe.rs"
run_bounded "$KIN_BIN" init "$WORKSPACE" --force --no-lsp --git-history off >/dev/null

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
"$KIN_DAEMON_BIN" --repo "$WORKSPACE" --port "$PORT" \
    >"$WORKSPACE/kin-daemon.log" 2>&1 &
KIN_DAEMON_PID=$!

ready=0
for _ in $(seq 1 150); do
    if curl -fsS "http://127.0.0.1:$PORT/readiness" >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$KIN_DAEMON_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    printf 'real kin-daemon did not become ready\n' >&2
    exit 1
fi

TOKEN="$(tr -d '\r\n' < "$WORKSPACE/.kin/daemon.token")"
TREE="$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/vfs/tree")"
if ! printf '%s' "$TREE" | grep -q '"probe.rs"'; then
    printf 'real daemon tree did not expose repo-relative probe.rs\n' >&2
    exit 1
fi

KIN_DAEMON_URL="http://127.0.0.1:$PORT" \
    "$KIN_VFS_BIN" start --workspace "$WORKSPACE" \
    >"$WORKSPACE/kin-vfs-daemon.log" 2>&1 &
VFS_DAEMON_PID=$!

socket_ready=0
for _ in $(seq 1 100); do
    if [ -S "$WORKSPACE/.kin/vfs.sock" ]; then
        socket_ready=1
        break
    fi
    if ! kill -0 "$VFS_DAEMON_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [ "$socket_ready" -ne 1 ]; then
    printf 'kin-vfs daemon did not bind its socket\n' >&2
    exit 1
fi

# Make raw-disk fallback observably impossible without changing file content
# (and therefore without racing the daemon's content watcher). A direct probe is
# the negative control; only graph-backed VFS serving can make the next probe pass.
chmod 000 "$WORKSPACE/probe.rs"
if run_bounded "$VFS_PROBE_BIN" "$WORKSPACE/probe.rs" >/dev/null 2>&1; then
    printf 'negative control could still read the chmod-000 disk file\n' >&2
    exit 1
fi

set +e
{
    KIN_DAEMON_URL="http://127.0.0.1:$PORT" \
    KIN_VFS_STRICT=1 \
        run_bounded "$KIN_VFS_BIN" exec --workspace "$WORKSPACE" -- \
        "$VFS_PROBE_BIN" "$WORKSPACE/probe.rs"
} >"$WORKSPACE/probe.stdout" 2>"$WORKSPACE/probe.stderr"
PROBE_STATUS=$?
set -e

if [ "$PROBE_STATUS" -ne 0 ]; then
    printf 'shim exec failed with status %s\n' "$PROBE_STATUS" >&2
    exit "$PROBE_STATUS"
fi

OUTPUT="$(cat "$WORKSPACE/probe.stdout")"

if [ "$OUTPUT" != "$GRAPH_BYTES" ]; then
    printf 'shim did not return exact graph bytes\n' >&2
    exit 1
fi

printf 'PASS: absolute host path resolved through the real daemon as repo-relative probe.rs\n'
