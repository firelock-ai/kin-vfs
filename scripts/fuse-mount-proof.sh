#!/usr/bin/env bash
# Prove that a FUSE mount is a writable, graph-authoritative projection.
#
# Runs inside a Linux container that already has, on PATH: `kin`, `kin-daemon`,
# a `kin-vfs` built with `--features fuse`, and the `fuse3` package. The
# container needs `--cap-add SYS_ADMIN --device /dev/fuse`.
#
# The proof is deliberately end to end and asserts against Kin, not against the
# mount: after each change it reads `kin log` and `kin graph status`, because
# the mount reporting success proves only that the mount is happy. Two guards
# are falsified at the end by breaking the behavior they defend and confirming
# the failure is the named one.
#
# Exit status is the number of failed checks, so a caller can key on it.

set -uo pipefail

WORK="${WORK:-${HOME:-/tmp}/kin-fuse-proof}"
REPO="$WORK/repo"
MNT="$WORK/mnt"
FAILURES=0
CHECKS=0

say() { printf '\n=== %s ===\n' "$*"; }

# Assert that `haystack` contains `needle`, printing both on failure. Reads a
# captured value rather than a pipeline, because a pipeline's exit status is
# its last stage's and `grep -q` inside one inverts the guard.
check_contains() {
  local label="$1" needle="$2" haystack="$3"
  CHECKS=$((CHECKS + 1))
  if [ "${haystack#*"$needle"}" != "$haystack" ]; then
    printf 'PASS  %s\n' "$label"
  else
    printf 'FAIL  %s\n      expected to find: %s\n      actual output:\n%s\n' \
      "$label" "$needle" "$haystack"
    FAILURES=$((FAILURES + 1))
  fi
}

check_absent() {
  local label="$1" needle="$2" haystack="$3"
  CHECKS=$((CHECKS + 1))
  if [ "${haystack#*"$needle"}" = "$haystack" ]; then
    printf 'PASS  %s\n' "$label"
  else
    printf 'FAIL  %s\n      expected NOT to find: %s\n      actual output:\n%s\n' \
      "$label" "$needle" "$haystack"
    FAILURES=$((FAILURES + 1))
  fi
}

check_status() {
  local label="$1" want="$2" got="$3"
  CHECKS=$((CHECKS + 1))
  if [ "$want" = "$got" ]; then
    printf 'PASS  %s (exit %s)\n' "$label" "$got"
  else
    printf 'FAIL  %s: wanted exit %s, got %s\n' "$label" "$want" "$got"
    FAILURES=$((FAILURES + 1))
  fi
}

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null
  [ -n "${MOUNT_PID:-}" ] && kill "$MOUNT_PID" 2>/dev/null
  [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
  return 0
}
trap cleanup EXIT

say "environment"
uname -srm
kin --version
kin-vfs --help 2>&1 | head -3
fusermount3 --version
ls -l /dev/fuse

say "a repository with no Kin in it"
rm -rf "$WORK"
mkdir -p "$REPO" "$MNT"
cd "$REPO"
git init -q
git config user.name "Fuse Proof"
git config user.email "fuse-proof@firelock.io"
mkdir -p src
printf 'fn main() {\n    println!("one");\n}\n' > src/main.rs
printf '# proof repo\n' > README.md
git add -A
git commit -qm "Add the proof sources"

kin init > /dev/null 2>&1
check_status "kin init" 0 $?

kin-daemon > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 40); do
  [ -f "$REPO/.kin/daemon.port" ] && break
  sleep 0.25
done
PORT="$(cat "$REPO/.kin/daemon.port" 2>/dev/null || echo 4219)"
HEALTH="$(curl -s -m 5 "http://127.0.0.1:$PORT/health")"
check_contains "kin-daemon is serving" '"status":"ok"' "$HEALTH"

say "mount"
kin-vfs mount --workspace "$REPO" --mount-point "$MNT" > "$WORK/mount.log" 2>&1 &
MOUNT_PID=$!
for _ in $(seq 1 40); do
  mount | grep -Fq "$MNT" && break
  sleep 0.25
done
MOUNT_TABLE="$(mount | grep -F "$MNT")"
check_contains "the mount is present and read-write" "rw," "$MOUNT_TABLE"

STATUS="$(kin-vfs fuse-status --workspace "$REPO" --mount-point "$MNT" 2>&1)"
printf '%s\n' "$STATUS"
check_contains "fuse-status reports it readable and writable" "mounted, readable, writable" "$STATUS"

say "read: the mount serves graph truth"
BODY="$(cat "$MNT/src/main.rs")"
check_contains "the committed body reads through the mount" 'println!("one");' "$BODY"

say "edit an existing file through the mount"
printf 'fn main() {\n    println!("two");\n}\n\npub fn added() {}\n' > "$MNT/src/main.rs"
check_status "the write itself" 0 $?
THROUGH="$(cat "$MNT/src/main.rs")"
# Reading back through the mount is the real assertion: the mount answers from
# the graph, so seeing the new body here means the graph took the write. A read
# of the workspace path would only prove the bytes reached disk.
check_contains "the graph serves the edited body" 'println!("two");' "$THROUGH"

say "create a new file through the mount"
printf 'pub fn helper() -> u8 { 7 }\n' > "$MNT/src/helper.rs"
check_status "the create itself" 0 $?
LISTING="$(ls "$MNT/src")"
check_contains "the new file is listed by the graph" "helper.rs" "$LISTING"
NEWBODY="$(cat "$MNT/src/helper.rs")"
check_contains "the new file's body reads back" "helper() -> u8" "$NEWBODY"

say "delete through the mount"
rm "$MNT/README.md"
check_status "the delete itself" 0 $?
ROOTLIST="$(ls "$MNT")"
check_absent "the deleted file is gone from the graph listing" "README.md" "$ROOTLIST"

say "kin graph status sees the new entity"
GRAPH="$(kin graph status 2>&1)"
printf '%s\n' "$GRAPH" | head -4
# `added` and `helper` are new definitions that existed nowhere before the
# mount wrote them, so the live graph's entity count must have grown past the
# single function the repository was created with.
check_absent "the graph is no longer at its one original entity" "Entities: 1 " "$GRAPH"

say "kin log records the work done through the mount"
COMMIT="$(kin commit -m "Work done entirely through the FUSE mount" 2>&1)"
printf '%s\n' "$COMMIT"
check_contains "kin committed a semantic change" "Created semantic change" "$COMMIT"
LOG="$(kin log 2>&1)"
printf '%s\n' "$LOG" | head -8
check_contains "kin log shows the change" "Work done entirely through the FUSE mount" "$LOG"

say "FALSIFICATION 1: the convergence gate must refuse a write the graph has not taken"
# The gate is the claim that a write reports success only once the graph itself
# reports the new content back. Forcing the deadline to zero removes the gate's
# ability to ever observe convergence while leaving everything else identical,
# so a write that succeeds under A and fails under B can only have been gated
# on the graph. Without this the gate could be doing nothing and the writes
# above would look exactly the same.
fusermount3 -u "$MNT" 2>/dev/null
kill "$MOUNT_PID" 2>/dev/null
wait "$MOUNT_PID" 2>/dev/null
KIN_VFS_FUSE_CONVERGE_MS=0 kin-vfs mount --workspace "$REPO" --mount-point "$MNT" \
  > "$WORK/mount-nogate.log" 2>&1 &
MOUNT_PID=$!
for _ in $(seq 1 40); do
  mount | grep -Fq "$MNT" && break
  sleep 0.25
done

printf 'this must not be accepted\n' 2>"$WORK/blocked.err" > "$MNT/src/blocked.rs"
BLOCKED_RC=$?
BLOCKED_ERR="$(cat "$WORK/blocked.err" 2>/dev/null)"
printf 'write exit=%s\nstderr: %s\n' "$BLOCKED_RC" "$BLOCKED_ERR"
CHECKS=$((CHECKS + 1))
if [ "$BLOCKED_RC" -ne 0 ]; then
  printf 'PASS  an unconverged write is refused\n'
else
  printf 'FAIL  an unconverged write reported success, so the gate does nothing\n'
  FAILURES=$((FAILURES + 1))
fi
check_contains "the refusal reaches the caller as an I/O error" \
  "Input/output error" "$BLOCKED_ERR"
NOGATE_LOG="$(cat "$WORK/mount-nogate.log")"
check_contains "the mount log names what did not converge" \
  "the graph did not take a write through the mount" "$NOGATE_LOG"

say "FALSIFICATION 2: the mount must fail closed when graph authority is unreachable"
# A mount whose authority has gone away must refuse rather than answer from the
# disk underneath it. That is the whole graph-first claim, and it is the one
# failure a projection could most easily paper over.
fusermount3 -u "$MNT" 2>/dev/null
kill "$MOUNT_PID" 2>/dev/null
wait "$MOUNT_PID" 2>/dev/null
kin-vfs mount --workspace "$REPO" --mount-point "$MNT" > "$WORK/mount-closed.log" 2>&1 &
MOUNT_PID=$!
for _ in $(seq 1 40); do
  mount | grep -Fq "$MNT" && break
  sleep 0.25
done
# The body is on the projection surface underneath the mount, so a mount that
# ever fell back to raw disk would still serve it here.
DISK_BODY="$(cat "$REPO/src/main.rs")"
check_contains "the workspace path still holds the body on disk" "println!" "$DISK_BODY"

kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
sleep 2

CLOSED_BODY="$(cat "$MNT/src/main.rs" 2>"$WORK/closed.err")"
CLOSED_RC=$?
CLOSED_ERR="$(cat "$WORK/closed.err" 2>/dev/null)"
printf 'read exit=%s\nstderr: %s\n' "$CLOSED_RC" "$CLOSED_ERR"
CHECKS=$((CHECKS + 1))
if [ "$CLOSED_RC" -ne 0 ]; then
  printf 'PASS  a read with no graph authority is refused\n'
else
  printf 'FAIL  a read with no graph authority was answered: %s\n' "$CLOSED_BODY"
  FAILURES=$((FAILURES + 1))
fi
check_absent "the mount did not serve the body from raw disk" "println!" "$CLOSED_BODY"

say "result"
printf '%s checks, %s failed\n' "$CHECKS" "$FAILURES"
exit "$FAILURES"
