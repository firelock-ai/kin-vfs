#!/bin/bash
# Prove that a write through the Kin NFS mount becomes graph truth.
#
# Mounts a fresh Kin repository, writes a file with `cat >`, edits one with
# `sed -i`, deletes one with `rm`, and then asks the graph what it holds. The
# assertions are on `kin log` and the graph's own view of the files, never on
# the working copy: bytes on disk are the admission's input, not its result,
# and a proof that read them back would pass with no graph involved at all.
#
# Usage: nfs-mount-proof.sh <kin-vfs binary> [kin binary] [kin-daemon binary]
set -u

KINVFS=${1:?usage: nfs-mount-proof.sh <kin-vfs> [kin] [kin-daemon]}
KIN=${2:-$HOME/.kin/bin/kin}
KIND=${3:-$HOME/.kin/bin/kin-daemon}
PORT=${KIN_PROOF_DAEMON_PORT:-4319}

RUN=$(mktemp -d "${TMPDIR:-/tmp}/kin-nfs-proof.XXXXXX")
# Resolve symlinks now. On macOS $TMPDIR is /var/folders/... which is a symlink
# to /private/var/folders/..., and `mount` reports the resolved path. Comparing
# the unresolved one against the mount table finds nothing, which reads exactly
# like a mount that never happened.
RUN=$(cd "$RUN" && pwd -P)
export HOME="$RUN/home"
REPO="$RUN/repo"
MNT="$RUN/mnt"
WS=$(basename "$REPO")
mkdir -p "$HOME/.kin" "$REPO" "$MNT"
unset KIN_HOME KIN_DIR DYLD_INSERT_LIBRARIES LD_PRELOAD
export KIN_NO_VFS=1
# Admit promptly so the proof measures the write path rather than a window
# chosen for interactive editing.
export KIN_VFS_ADMIT_DEBOUNCE_MS=300

FAILURES=0
DAEMON_PID=""
SERVER_PID=""

say() { printf '\n=== %s ===\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1; printf '[rc=%s]\n' "$?"; }
check() {
  local label="$1"; shift
  if "$@"; then
    printf 'PASS  %s\n' "$label"
  else
    printf 'FAIL  %s\n' "$label"
    FAILURES=$((FAILURES + 1))
  fi
}

cleanup() {
  say "teardown"
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  sleep 3
  umount -f "$MNT" 2>/dev/null
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  mount | grep -F " on $MNT " && printf 'WARNING: %s is still mounted\n' "$MNT"
  printf 'run directory: %s\n' "$RUN"
}
trap cleanup EXIT

say "0. what is under test"
run "$KINVFS" --help
run "$KIN" --version
printf 'repo=%s mount=%s workspace=%s\n' "$REPO" "$MNT" "$WS"

say "1. a fresh Kin repository"
cd "$REPO" || exit 1
printf 'fn main() { println!("hello"); }\n' > main.rs
printf 'pub fn add(a: i32, b: i32) -> i32 { a + b }\n' > lib.rs
printf '# doomed\n' > doomed.md
run git init -q .
run git config user.email proof@example.com
run git config user.name "Kin Proof"
run git add -A
run git -c commit.gpgsign=false commit -q -m seed
run "$KIN" init

say "2. kin-daemon on port $PORT"
"$KIND" --repo "$REPO" --port "$PORT" > "$RUN/kin-daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 90); do
  curl -sf --connect-timeout 1 "http://127.0.0.1:$PORT/health" > /dev/null 2>&1 && break
  sleep 1
done
run curl -s "http://127.0.0.1:$PORT/health"

say "3. mount it writable"
"$KINVFS" nfs-start --repo "$REPO" --port 0 --mount-point "$MNT" > "$RUN/nfs.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  mount | grep -qF " on $MNT " && break
  sleep 1
done
cat "$RUN/nfs.log"
run "$KINVFS" nfs-status

# Nothing below can mean anything if the mount is not there. Without this the
# run reads as a partial pass: `test ! -e` on a missing mount point reports the
# deleted file absent, and a failed tree fetch reports it gone from the graph,
# so two checks pass for the same reason everything else failed.
if ! mount | grep -qF " on $MNT "; then
  printf '\nFATAL: %s is not mounted; every check below would be vacuous\n' "$MNT"
  printf 'nfs-start log:\n'
  cat "$RUN/nfs.log"
  exit 1
fi
printf 'mount confirmed: %s\n' "$(mount | grep -F " on $MNT ")"

say "4. read the graph through the mount"
run ls -la "$MNT/$WS"
run cat "$MNT/$WS/main.rs"

# The positive control for every read below. If the mount cannot serve a file
# the graph certainly holds, a later absence proves nothing about the graph.
check "the mount serves a file the graph already held" \
  grep -q "pub fn add" "$MNT/$WS/lib.rs"

BEFORE=$("$KIN" log 2>/dev/null | grep -c .)
printf 'kin log lines before any write: %s\n' "$BEFORE"

say "5. write through the mount the way a person would"
printf '$ cat > %s/%s/created.rs\n' "$MNT" "$WS"
cat > "$MNT/$WS/created.rs" <<'EOF'
pub fn created_through_the_mount() -> &'static str {
    "written by cat, admitted by kin"
}
EOF
printf '[rc=%s]\n' "$?"

printf '$ sed -i %s s/hello/goodbye/ %s/%s/main.rs\n' "''" "$MNT" "$WS"
sed -i '' 's/hello/goodbye/' "$MNT/$WS/main.rs"
printf '[rc=%s]\n' "$?"

run rm "$MNT/$WS/doomed.md"

say "5b. read-your-writes: the mount serves what was just written"
run cat "$MNT/$WS/created.rs"
run cat "$MNT/$WS/main.rs"
check "the mount serves the created file" \
  grep -q "written by cat, admitted by kin" "$MNT/$WS/created.rs"
check "the mount serves the edit" grep -q goodbye "$MNT/$WS/main.rs"
check "the mount reports the deleted file absent" \
  test ! -e "$MNT/$WS/doomed.md"

say "6. admit the writes into graph truth"
run "$KINVFS" nfs-sync
"$KINVFS" nfs-sync > "$RUN/sync.txt" 2>&1
SYNC_RC=$?
cat "$RUN/sync.txt"
check "nfs-sync exits clean" test "$SYNC_RC" -eq 0
run "$KINVFS" nfs-status

say "7. what the graph now holds"
run "$KIN" log
run "$KIN" graph status

"$KIN" log > "$RUN/log.txt" 2>&1
AFTER=$(grep -c . < "$RUN/log.txt")
printf 'kin log lines after: %s (was %s)\n' "$AFTER" "$BEFORE"
check "kin log grew, so the mount's writes minted a change" test "$AFTER" -gt "$BEFORE"
check "kin log names the mount as the source of the change" \
  grep -qi "from the Kin mount" "$RUN/log.txt"

# The graph, not the disk, is asked what the repository contains. Reading the
# working copy here would pass even if no admission had ever run.
say "8. ask the graph itself, not the working copy"
# /vfs/tree is not a public route: without the repository's bearer token the
# daemon answers 401, and an absence read from an empty body is true of every
# document that does not exist.
TOKEN=$(cat "$REPO/.kin/daemon.token" 2>/dev/null)
curl -sf -H "Authorization: Bearer ${TOKEN}" \
  "http://127.0.0.1:$PORT/vfs/tree" > "$RUN/tree.json" 2>&1
TREE_RC=$?
TREE_BYTES=$(wc -c < "$RUN/tree.json" | tr -d ' ')
printf '[tree fetch rc=%s, %s bytes]\n' "$TREE_RC" "$TREE_BYTES"
# An absence assertion over an empty or failed fetch is the same trap as above:
# "doomed.md is gone" is true of every document that does not exist. The fetch
# must succeed and must carry a file the graph is known to hold before any
# absence read from it counts.
if [ "$TREE_RC" -ne 0 ] || [ "$TREE_BYTES" -lt 2 ]; then
  printf 'FAIL  the graph tree could not be read, so nothing can be concluded from it\n'
  FAILURES=$((FAILURES + 1))
else
  check "the graph's tree carries a file it already held (control)" \
    grep -q "lib.rs" "$RUN/tree.json"
  check "the graph's tree carries the created file" grep -q "created.rs" "$RUN/tree.json"
  check "the graph's tree no longer carries the deleted file" \
    bash -c '! grep -q "doomed.md" "$0"' "$RUN/tree.json"
fi

say "RESULT"
if [ "$FAILURES" -eq 0 ]; then
  printf 'ALL CHECKS PASSED\n'
else
  printf '%s CHECK(S) FAILED\n' "$FAILURES"
fi
exit "$FAILURES"
