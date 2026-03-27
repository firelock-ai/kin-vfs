# Read Path Analysis

Profiling analysis of the hot read path: shim request through daemon to provider and back.

## Request Flow

```
Tool (read syscall)
  │
  ▼  [in-process]
Shim intercept.rs: open() / read()
  │
  ▼  [IPC: Unix socket, MessagePack]
Daemon server.rs: handle_connection()
  │  read_frame() → dispatch_request() → write_frame()
  │
  ▼  [local method call]
ContentProvider.read_file()
  │
  ▼  [HTTP to kin-daemon, for KinDaemonProvider]
kin-daemon :4219
```

## Copy Count Analysis (Full File Read)

For a file of size N bytes:

### Daemon Side (server + provider)

| Step | Operation | Allocation | Peak Memory |
|------|-----------|-----------|-------------|
| 1 | `read_frame`: read 4-byte len, then `vec![0u8; len]` | recv buffer (request, small) | ~100 bytes |
| 2 | `rmp_serde::from_slice`: deserialize `VfsRequest` | request struct (small) | ~100 bytes |
| 3 | `provider.read_file()`: HTTP GET, `resp.bytes().to_vec()` | **N bytes** (file content) | N |
| 4 | Construct `VfsResponse::Content { data, total_size }` | Move, no copy | N |
| 5 | `rmp_serde::to_vec(response)`: serialize | **N bytes** (serialized payload) | 2N |
| 6 | `stream.write_all(payload)`: send to socket | No alloc (writes from buffer) | 2N |
| 7 | Payload dropped after write | | N |

**Peak daemon memory per request: ~2N** (content + serialized payload).

### Shim Side (client)

| Step | Operation | Allocation | Peak Memory |
|------|-----------|-----------|-------------|
| 1 | `recv()`: read 4-byte len, then `vec![0u8; len]` | **N bytes** (recv buffer) | N |
| 2 | `rmp_serde::from_slice`: deserialize `VfsResponse` | **N bytes** (deserialized content) | 2N |
| 3 | Recv buffer dropped | | N |
| 4 | Content stored in VFD's content buffer | Move, no copy | N |

**Peak shim memory per request: ~2N** (recv buffer + deserialized content, briefly).

### Total Copies (End-to-End)

For a single full-file read of N bytes:

1. HTTP response body -> `Vec<u8>` (provider) -- **copy 1**
2. Content -> MessagePack serialization (daemon) -- **copy 2**
3. Socket write -> kernel buffer (zero-copy via write_all) -- no user-space copy
4. Kernel buffer -> recv `Vec<u8>` (shim) -- **copy 3**
5. MessagePack deserialization -> `Vec<u8>` (shim) -- **copy 4**

**Total: 4 copies of the file content across the full path.**

## Optimization Opportunities

### Low-hanging fruit

1. **Daemon: avoid double serialization for Content responses.**
   Currently `write_frame` serializes the entire `VfsResponse` including the file data into a new `Vec<u8>`. For large files, this doubles the memory. A streaming serializer that writes the MessagePack header + data directly to the socket would eliminate copy 2.

   **Impact:** Reduces daemon peak memory from 2N to N per request.
   **Complexity:** Medium. Requires a custom MessagePack writer or switching to a streaming framing format for Content responses.

2. **Shim: pre-allocated recv buffer pool.**
   The shim allocates a new `Vec<u8>` for every response. A thread-local buffer pool (reusing allocations) would reduce allocator pressure for rapid sequential reads.

   **Impact:** Reduces allocation overhead, not copy count. Most benefit for workloads with many small file reads (e.g., tree-sitter parsing hundreds of headers).
   **Complexity:** Low. Thread-local `Vec<u8>` that grows to high-water mark.

3. **Provider: use `reqwest::Response::bytes()` without `.to_vec()`.**
   `bytes()` returns a `Bytes` (reference-counted, zero-copy from the HTTP body). Converting to `Vec<u8>` copies. If the `ContentProvider` trait accepted `Bytes` or a borrowed slice, this copy could be avoided.

   **Impact:** Eliminates copy 1.
   **Complexity:** Medium. Requires trait signature change (`read_file` returning `Bytes` or a cow type).

### Structural (future)

4. **Shared memory / mmap for large files.**
   For files above a threshold (e.g., 1 MiB), the daemon could write content to a shared memory region and return a handle. The shim would mmap the shared region directly.

   **Impact:** Eliminates all IPC copies for large files.
   **Complexity:** High. Requires shared memory management, cleanup, and platform-specific code.

5. **Sendfile / splice for socket-to-socket transfer.**
   If the daemon had the file content in a kernel-accessible form (e.g., a file fd), `sendfile(2)` could transfer directly from the daemon's fd to the socket without user-space copies.

   **Impact:** Eliminates copies 2-3 for files backed by real fds.
   **Complexity:** High. Content is typically in-memory (blob store), not file-backed.

## Current Assessment

The 4-copy path is acceptable for development workloads. Typical file sizes in source code are < 100 KiB, making the overhead negligible (microseconds). The LRU cache in both `VirtualFileTree` and `KinDaemonProvider` means hot files are served from memory without daemon round-trips after the first access.

**Bottleneck is latency, not throughput.** The Unix socket round-trip (~50-100us) dominates over copy overhead for typical file sizes. The thread-local connection design eliminates lock contention.

**Recommended near-term action:** None. The current implementation is correct and performant for the target workload. Optimization #1 (streaming serializer) is worth considering if profiling reveals memory pressure during large-file reads in production.
