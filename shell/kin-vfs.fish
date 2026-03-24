# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs shell integration for fish
# Add to config.fish: source /path/to/kin-vfs/shell/kin-vfs.fish

set -g _KIN_VFS_WORKSPACE ""

function _kin_vfs_find_workspace
    set -l dir $argv[1]
    while test "$dir" != "/"
        if test -d "$dir/.kin"
            echo $dir
            return 0
        end
        set dir (dirname $dir)
    end
    return 1
end

function _kin_vfs_activate
    set -l ws $argv[1]
    set -l sock "$ws/.kin/vfs.sock"
    set -gx KIN_VFS_WORKSPACE $ws
    set -gx KIN_VFS_SOCK $sock

    if not test -S $sock
        if command -sq kin-vfs
            kin-vfs start --workspace $ws &>/dev/null &
            disown
            set -l attempts 0
            while not test -S $sock; and test $attempts -lt 10
                sleep 0.1
                set attempts (math $attempts + 1)
            end
        end
    end

    set -l shim "$HOME/.kin/lib/libkin_vfs_shim"
    switch (uname -s)
        case Darwin
            set shim "$shim.dylib"
            if test -f $shim
                set -gx DYLD_INSERT_LIBRARIES $shim
            end
        case Linux
            set shim "$shim.so"
            if test -f $shim
                set -gx LD_PRELOAD $shim
            end
    end
end

function _kin_vfs_deactivate
    set -e KIN_VFS_WORKSPACE
    set -e KIN_VFS_SOCK
    set -e DYLD_INSERT_LIBRARIES
    set -e LD_PRELOAD
    set -g _KIN_VFS_WORKSPACE ""
end

function _kin_vfs_chpwd --on-variable PWD
    set -l ws (_kin_vfs_find_workspace $PWD)
    if test -n "$ws"
        if test "$_KIN_VFS_WORKSPACE" != "$ws"
            _kin_vfs_activate $ws
            set -g _KIN_VFS_WORKSPACE $ws
        end
    else
        if test -n "$_KIN_VFS_WORKSPACE"
            _kin_vfs_deactivate
        end
    end
end

# Run once on source
_kin_vfs_chpwd
