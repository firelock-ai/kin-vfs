# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs zsh integration — auto-activates the VFS overlay when entering
# a Kin workspace (any directory tree containing .kin/).
#
# Installation:
#   Add to your ~/.zshrc:
#     source /path/to/kin-vfs/shell/kin-vfs.zsh
#
# Environment variables set when inside a workspace:
#   KIN_VFS_WORKSPACE  — absolute path to the workspace root
#   KIN_VFS_WORKSPACE_ALIASES — cleared on workspace switch and deactivation
#   KIN_VFS_SOCK       — path to the daemon Unix socket
#   DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux) — VFS shim library

# ---------------------------------------------------------------------------
# Walk up from a directory to find the nearest .kin/ marker.
# Prints the workspace root (parent of .kin/) or nothing.
# ---------------------------------------------------------------------------
_kin_vfs_find_workspace() {
    local dir="$1"
    while [[ "$dir" != "/" ]]; do
        if [[ -d "$dir/.kin" ]]; then
            printf '%s' "$dir"
            return 0
        fi
        dir="${dir:h}"  # zsh dirname — parent directory
    done
    # Check root just in case
    if [[ -d "/.kin" ]]; then
        printf '%s' "/"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Resolve the path to the VFS shim library for the current platform.
# Returns empty string if not found.
# ---------------------------------------------------------------------------
_kin_vfs_shim_path() {
    local base="${0:A:h:h}"  # directory containing shell/ → repo root
    local lib
    case "$(uname -s)" in
        Darwin) lib="$base/target/release/libkin_vfs_shim.dylib"
                [[ -f "$lib" ]] || lib="$base/target/debug/libkin_vfs_shim.dylib"
                ;;
        Linux)  lib="$base/target/release/libkin_vfs_shim.so"
                [[ -f "$lib" ]] || lib="$base/target/debug/libkin_vfs_shim.so"
                ;;
        *)      lib="" ;;
    esac
    [[ -f "$lib" && -s "$lib" ]] && printf '%s' "$lib"
}

_kin_vfs_clear_preload() {
    unset DYLD_INSERT_LIBRARIES
    unset LD_PRELOAD
}

_kin_vfs_refresh_preload() {
    local shim
    shim="$(_kin_vfs_shim_path)"
    if [[ -z "$shim" ]]; then
        _kin_vfs_clear_preload
        return
    fi
    case "$(uname -s)" in
        Darwin)
            export DYLD_INSERT_LIBRARIES="$shim"
            unset LD_PRELOAD
            ;;
        Linux)
            export LD_PRELOAD="$shim"
            unset DYLD_INSERT_LIBRARIES
            ;;
        *)
            _kin_vfs_clear_preload
            ;;
    esac
}

_kin_vfs_exec_without_preload() {
    DYLD_INSERT_LIBRARIES= LD_PRELOAD= command "$@"
}

# ---------------------------------------------------------------------------
# Enter a kin workspace: start daemon if needed, set env.
# ---------------------------------------------------------------------------
_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"

    # Aliases are repo-specific and this hook does not independently verify
    # them. Never carry an alias inherited from another workspace.
    unset KIN_VFS_WORKSPACE_ALIASES
    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"

    # Auto-start the daemon if the socket does not exist.
    if [[ ! -S "$sock" ]]; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" &>/dev/null &!
            # Give the daemon a moment to bind the socket.
            local attempts=0
            while [[ ! -S "$sock" ]] && (( attempts < 10 )); do
                sleep 0.1
                (( attempts++ ))
            done
        fi
    fi

    _kin_vfs_refresh_preload
}

# ---------------------------------------------------------------------------
# Leave a kin workspace: unset all VFS env vars.
# ---------------------------------------------------------------------------
_kin_vfs_deactivate() {
    unset KIN_VFS_WORKSPACE
    unset KIN_VFS_WORKSPACE_ALIASES
    unset KIN_VFS_SOCK
    _kin_vfs_clear_preload
}

# ---------------------------------------------------------------------------
# chpwd hook — runs every time the working directory changes.
# ---------------------------------------------------------------------------
_kin_vfs_chpwd() {
    local ws
    ws="$(_kin_vfs_find_workspace "$PWD")"

    if [[ -n "$ws" ]]; then
        # Inside a workspace. Only re-activate if we switched workspaces.
        if [[ "$ws" != "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_activate "$ws"
        else
            _kin_vfs_refresh_preload
        fi
    else
        # Outside any workspace. Deactivate if we were previously inside one.
        if [[ -n "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_deactivate
        else
            _kin_vfs_clear_preload
        fi
    fi
}

# Kin-family control-plane binaries must not be injected with the shim.
# External tools keep the overlay via the global preload environment.
kin() { _kin_vfs_exec_without_preload kin "$@"; }
kin-real() { _kin_vfs_exec_without_preload kin-real "$@"; }
kin-daemon() { _kin_vfs_exec_without_preload kin-daemon "$@"; }
kin-mcp() { _kin_vfs_exec_without_preload kin-mcp "$@"; }
kin-vfs() { _kin_vfs_exec_without_preload kin-vfs "$@"; }
kin-bench-prep() { _kin_vfs_exec_without_preload kin-bench-prep "$@"; }
kin-bench-eval() { _kin_vfs_exec_without_preload kin-bench-eval "$@"; }
kin-bench-target() { _kin_vfs_exec_without_preload kin-bench-target "$@"; }

# Register the hook.
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _kin_vfs_chpwd

# Run once on source so the current directory is handled immediately.
_kin_vfs_chpwd
