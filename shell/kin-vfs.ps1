# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs shell integration for PowerShell
# Add to your $PROFILE: . /path/to/kin-vfs/shell/kin-vfs.ps1
#
# When you cd into a directory containing .kin/, the VFS daemon is
# auto-started and the ProjFS provider is activated. When you leave,
# it deactivates.

$script:KinVfsActive = -not [string]::IsNullOrEmpty($env:KIN_VFS_WORKSPACE)
$script:KinVfsWorkspace = if ($script:KinVfsActive) { $env:KIN_VFS_WORKSPACE } else { "" }

function Find-KinWorkspace {
    param([string]$StartDir)
    $dir = $StartDir
    while ($dir -and $dir -ne [System.IO.Path]::GetPathRoot($dir)) {
        if (Test-Path (Join-Path $dir ".kin")) {
            return $dir
        }
        $dir = Split-Path $dir -Parent
    }
    return $null
}

function Test-KinVfsWorkspaceMatchesCurrent {
    param([string]$Workspace)
    if ($Workspace -eq $env:KIN_VFS_WORKSPACE) {
        return $true
    }
    if ($env:KIN_VFS_WORKSPACE_ALIASES) {
        $separator = [regex]::Escape([string][System.IO.Path]::PathSeparator)
        foreach ($alias in ($env:KIN_VFS_WORKSPACE_ALIASES -split $separator)) {
            if ($alias -and $Workspace -eq $alias) {
                return $true
            }
        }
    }
    return $false
}

function Enable-KinVfs {
    param([string]$Workspace)
    $sock = Join-Path $Workspace ".kin\vfs.sock"
    $pipe = "\\.\pipe\kin-vfs-$([System.IO.Path]::GetFileName($Workspace))"

    # This hook does not independently verify repo aliases. Never carry one
    # from a parent process or a previously active workspace.
    Remove-Item Env:\KIN_VFS_WORKSPACE_ALIASES -ErrorAction SilentlyContinue

    # Auto-start daemon if not running.
    $daemonCmd = Get-Command "kin-vfs" -ErrorAction SilentlyContinue
    if ($daemonCmd) {
        # Check if daemon is reachable via named pipe.
        $pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*kin-vfs*" }
        if (-not $pipeExists) {
            Start-Process -FilePath "kin-vfs" -ArgumentList "start", "--workspace", $Workspace -WindowStyle Hidden
            # Brief wait for daemon startup.
            $retries = 0
            while ($retries -lt 10) {
                Start-Sleep -Milliseconds 50
                $pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*kin-vfs*" }
                if ($pipeExists) { break }
                $retries++
            }
        }
    }

    $env:KIN_VFS_WORKSPACE = $Workspace
    $env:KIN_VFS_PIPE = $pipe
    $script:KinVfsActive = $true
    $script:KinVfsWorkspace = $Workspace
}

function Disable-KinVfs {
    Remove-Item Env:\KIN_VFS_WORKSPACE -ErrorAction SilentlyContinue
    Remove-Item Env:\KIN_VFS_WORKSPACE_ALIASES -ErrorAction SilentlyContinue
    Remove-Item Env:\KIN_VFS_PIPE -ErrorAction SilentlyContinue
    $script:KinVfsActive = $false
    $script:KinVfsWorkspace = ""
}

function Invoke-KinVfsLocationCheck {
    $ws = Find-KinWorkspace -StartDir $PWD.Path
    if ($ws) {
        if (-not (Test-KinVfsWorkspaceMatchesCurrent -Workspace $ws)) {
            Enable-KinVfs -Workspace $ws
        }
    }
    else {
        if ($script:KinVfsActive -or $env:KIN_VFS_WORKSPACE -or $env:KIN_VFS_WORKSPACE_ALIASES) {
            Disable-KinVfs
        }
    }
}

# Override the default prompt to check directory on every command.
# Preserve the user's existing prompt function.
if (-not (Get-Variable -Name KinVfsOriginalPrompt -Scope Script -ErrorAction SilentlyContinue)) {
    $script:KinVfsOriginalPrompt = $function:prompt
}

function prompt {
    Invoke-KinVfsLocationCheck
    & $script:KinVfsOriginalPrompt
}

# Run once on source to handle current directory.
Invoke-KinVfsLocationCheck
