# Troubleshooting

Common issues with kin-vfs and how to resolve them.

## macOS: DYLD_INSERT_LIBRARIES stripped by SIP

**Symptom:** The shim has no effect on system binaries (`/usr/bin/cat`, `/usr/bin/grep`).

**Cause:** System Integrity Protection strips `DYLD_INSERT_LIBRARIES` from processes launched from SIP-protected paths (`/usr/bin`, `/System`, etc.).

**Fix:**
- Use Homebrew-installed binaries instead (`/opt/homebrew/bin/gcat`, `ggrep`).
- Run the target binary from a non-SIP-protected location (e.g., copy it to `/usr/local/bin`).
- On development machines only: disable SIP via Recovery Mode (`csrutil disable`). Not recommended for production.

**Verify SIP status:** `csrutil status`

## macOS: code signing conflicts

**Symptom:** Process crashes or `dyld: code signature invalid` when injecting the shim.

**Cause:** Hardened runtime binaries reject unsigned injected libraries.

**Fix:**
- Ad-hoc sign the shim: `codesign -s - target/release/libkin_vfs_shim.dylib`
- Or sign with your developer identity for distribution.

## Linux: LD_PRELOAD blocked by SELinux

**Symptom:** Shim not loaded; `dmesg` shows AVC denials.

**Cause:** SELinux may prevent `LD_PRELOAD` for processes running in restricted domains.

**Fix:**
- Check for denials: `ausearch -m avc -ts recent | grep kin_vfs`
- Create a policy module: `audit2allow -a -M kin-vfs && semodule -i kin-vfs.pp`
- Or set the shim library context: `chcon -t lib_t /usr/local/lib/libkin_vfs_shim.so`

## Linux: musl libc compatibility

**Symptom:** Shim loads but file operations are not intercepted.

**Cause:** musl libc does not use the `__xstat` / `__fxstat` versioned symbols that glibc uses. The shim hooks both forms, but some musl distributions may require additional symbol interception.

**Fix:** Verify which stat symbols your binary uses: `nm -D /path/to/binary | grep stat`. If only `stat` / `fstat` / `lstat` appear (no `__xstat`), the shim should work. File a bug if interception fails on musl.

## Daemon won't start

**Symptom:** `kin-vfs start` exits immediately or reports socket bind failure.

**Checks:**
1. **Stale socket:** If `.kin/vfs.sock` exists from a crashed daemon, the CLI cleans it automatically. If cleanup fails, remove manually: `rm .kin/vfs.sock`
2. **Stale PID file:** Remove `.kin/vfs.pid` if the recorded process is no longer running.
3. **Port conflict:** Ensure no other process holds the socket path: `lsof .kin/vfs.sock`
4. **Missing .kin/:** The daemon requires an initialized workspace. Run `kin init` first.
5. **kin-daemon for blob resolution:** If using `KinDaemonProvider`, ensure `kin-daemon` is running on `:4219`. Otherwise the VFS daemon starts with a placeholder provider.

## Shim not loading

**Symptom:** File reads go to disk instead of through VFS.

**Checks:**
1. Verify `KIN_VFS_WORKSPACE` is set to the correct absolute path.
2. Verify the daemon is running: `kin-vfs status --workspace /path/to/repo`
3. Verify the socket exists: `ls -la .kin/vfs.sock`
4. Verify the shim is injected:
   - Linux: check `/proc/<pid>/maps` for `libkin_vfs_shim.so`
   - macOS: `DYLD_PRINT_LIBRARIES=1 your-command 2>&1 | grep kin_vfs`
5. Check the kill switch: ensure `KIN_VFS_DISABLE` is not set to `1`.

## Stale socket files

**Symptom:** `kin-vfs start` says daemon is already running, but it is not.

**Cause:** The daemon crashed or was killed without cleanup.

**Fix:** The CLI detects stale sockets by attempting a connection. If the connection fails, it removes the socket and proceeds. If auto-cleanup does not work:

```bash
rm /path/to/repo/.kin/vfs.sock
rm /path/to/repo/.kin/vfs.pid
kin-vfs start --workspace /path/to/repo
```

## Connection timeouts

**Symptom:** Commands hang for 5 seconds then fall through to disk reads.

**Cause:** The shim's I/O timeout is 5 seconds (`IO_TIMEOUT` in `client.rs`). If the daemon is overloaded or the socket is unresponsive, operations will time out and passthrough to real syscalls.

**Fix:**
- Check daemon health: `kin-vfs status`
- Check for file descriptor exhaustion on the daemon: `lsof -p <daemon-pid> | wc -l`
- Restart the daemon: `kin-vfs stop && kin-vfs start`

## Windows: ProjFS not available

**Symptom:** VFS fails to initialize on Windows.

**Cause:** ProjFS is an optional Windows feature that must be enabled.

**Fix:** Enable ProjFS via Settings > Apps > Optional Features > Windows Projected File System, or run: `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`
