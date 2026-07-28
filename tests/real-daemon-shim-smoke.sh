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
#
# The kin binaries must be new enough to admit a Git repository and to serve the
# schema-versioned `/vfs/tree` document this checkout's kin-model accepts; both
# preconditions are asserted below rather than surfacing as opaque read errors.

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
    for log_path in "$WORKSPACE"/*.log "$WORKSPACE"/*.stdout "$WORKSPACE"/*.stderr; do
        if [ ! -f "$log_path" ]; then
            continue
        fi
        cp "$log_path" "$diagnostics_dir/"
        printf '\n===== %s =====\n' "$(basename "$log_path")" >&2
        sed -n '1,240p' "$log_path" >&2 || true
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

# Admission derives authority from Git, never from loose filesystem contents, so
# the fixture is a real commit. Repo-local hooks are bypassed: this is a
# throwaway fixture, not history anyone publishes.
GRAPH_BYTES='pub fn graph_authority_probe() -> u64 { 42 }'
printf '%s\n' "$GRAPH_BYTES" > "$WORKSPACE/probe.rs"
git init -q "$WORKSPACE"
git -C "$WORKSPACE" add probe.rs
git -C "$WORKSPACE" \
    -c core.hooksPath=/dev/null \
    -c user.email=smoke@example.invalid \
    -c user.name=smoke \
    commit -q -s -m "Add graph authority probe"
run_bounded "$KIN_BIN" init "$WORKSPACE" >/dev/null

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
# Reads are served only from the schema-versioned tree document. A daemon that
# still answers with the legacy path->hash map, or with a schema this checkout's
# kin-model does not accept, fails every read as an authority error; say that
# here instead of leaving an operator to decode EIO from a probe.
if ! printf '%s' "$TREE" | grep -q '"schema"'; then
    printf 'daemon served a pre-versioned /vfs/tree; this checkout requires the schema-versioned document\n' >&2
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

# A file written after import exists on disk and nowhere in the graph. It stays
# readable on disk on purpose: any raw-disk answer for it is observable as a
# successful read, which is exactly what the miss controls below must refuse.
MISS_PATH="$WORKSPACE/disk-only-probe.rs"
printf 'pub fn disk_only_never_in_graph() -> u64 { 7 }\n' > "$MISS_PATH"
TREE="$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/vfs/tree")"
if printf '%s' "$TREE" | grep -q 'disk-only-probe.rs'; then
    printf 'daemon ingested the miss probe; the control needs a path the graph does not hold\n' >&2
    exit 1
fi

# The launcher prefers an installed ~/.kin/lib shim over the one built beside the
# CLI under test. Point HOME at a scratch directory so the smoke exercises this
# checkout's interposition library rather than whatever the host has installed.
SHIM_HOME="$WORKSPACE/launcher-home"
mkdir -p "$SHIM_HOME"
case "$(uname -s)" in
    Darwin) SHIM_LIB="libkin_vfs_shim.dylib" ;;
    *) SHIM_LIB="libkin_vfs_shim.so" ;;
esac
if [ ! -f "$(dirname "$KIN_VFS_BIN")/$SHIM_LIB" ]; then
    printf 'no %s beside %s; build the shim into the same directory as the CLI\n' \
        "$SHIM_LIB" "$KIN_VFS_BIN" >&2
    exit 1
fi

# Run the probe under interposition. `label` names its captured streams, `cwd`
# decides whether `arg` is read as an absolute or a relative path, and `strict`
# selects the refusal mode under test.
run_probe() { # <label> <cwd> <arg> <strict>
    local label="$1" cwd="$2" arg="$3" strict="$4" status=0
    set +e
    (
        cd "$cwd" || exit 111
        HOME="$SHIM_HOME" \
        KIN_DAEMON_URL="http://127.0.0.1:$PORT" \
        KIN_VFS_STRICT="$strict" \
            run_bounded "$KIN_VFS_BIN" exec --workspace "$WORKSPACE" -- \
            "$VFS_PROBE_BIN" "$arg"
    ) >"$WORKSPACE/$label.stdout" 2>"$WORKSPACE/$label.stderr"
    status=$?
    set -e
    return "$status"
}

# `path` is served from the graph, byte for byte. The on-disk copy is
# unreadable, so exact bytes can only have come through the daemon.
assert_graph_served() { # <label> <cwd> <arg>
    local label="$1" status=0
    run_probe "$1" "$2" "$3" 1 || status=$?
    if [ "$status" -ne 0 ]; then
        printf '%s: shim exec failed with status %s\n' "$label" "$status" >&2
        exit "$status"
    fi
    if [ "$(cat "$WORKSPACE/$label.stdout")" != "$GRAPH_BYTES" ]; then
        printf '%s: shim did not return exact graph bytes\n' "$label" >&2
        exit 1
    fi
}

# A path the graph does not hold is refused, never answered from raw disk. The
# exact errno is load-bearing: EIO (5) is the strict refusal, ENOENT (2) the
# default absence. Serving the disk bytes would exit 0 with content on stdout.
assert_graph_miss() { # <label> <cwd> <arg> <strict> <expected-errno>
    local label="$1" strict="$4" expected="$5" status=0
    run_probe "$1" "$2" "$3" "$strict" || status=$?
    if [ "$status" -eq 0 ]; then
        printf '%s: shim served a path the graph does not hold\n' "$label" >&2
        exit 1
    fi
    if [ -s "$WORKSPACE/$label.stdout" ]; then
        printf '%s: miss leaked file content to stdout\n' "$label" >&2
        exit 1
    fi
    if ! grep -q "os error $expected" "$WORKSPACE/$label.stderr"; then
        printf '%s: expected os error %s, got: %s\n' \
            "$label" "$expected" "$(cat "$WORKSPACE/$label.stderr")" >&2
        exit 1
    fi
}

assert_graph_served probe "$PWD" "$WORKSPACE/probe.rs"
printf 'PASS: absolute host path resolved through the real daemon as repo-relative probe.rs\n'

# Containment is decided on absolute bytes, so a relative argument must be
# resolved against the process cwd before the workspace check. Without that, the
# hook passes it through and the raw filesystem answers for a graph-owned file.
assert_graph_served relative "$WORKSPACE" probe.rs
printf 'PASS: relative host path served identically to its absolute twin\n'

assert_graph_miss strict-miss-absolute "$PWD" "$MISS_PATH" 1 5
assert_graph_miss strict-miss-relative "$WORKSPACE" disk-only-probe.rs 1 5
printf 'PASS: strict mode refused an absolute and a relative graph miss with EIO\n'

assert_graph_miss default-miss-absolute "$PWD" "$MISS_PATH" "" 2
assert_graph_miss default-miss-relative "$WORKSPACE" disk-only-probe.rs "" 2
printf 'PASS: default mode reported the same miss absent without reading raw disk\n'
