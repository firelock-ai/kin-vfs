// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end integration tests for kin-vfs.
//!
//! These tests spin up a real `VfsDaemonServer` on a temp Unix socket,
//! backed by an in-memory `ContentProvider`, and verify correct behavior
//! over the socket protocol.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use kin_vfs_core::{ContentProvider, DirEntry, FileType, VfsError, VfsResult, VirtualStat};
    use kin_vfs_daemon::protocol::{ErrorCode, VfsRequest, VfsResponse};
    use kin_vfs_daemon::{DaemonError, VfsDaemonServer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---------------------------------------------------------------
    // Test ContentProvider
    // ---------------------------------------------------------------

    struct TestProvider {
        files: Mutex<HashMap<String, Vec<u8>>>,
        dirs: Mutex<HashMap<String, Vec<DirEntry>>>,
        version: AtomicU64,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                dirs: Mutex::new(HashMap::new()),
                version: AtomicU64::new(1),
            }
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_string(), content.to_vec());
        }

        fn add_dir(&self, path: &str, entries: Vec<DirEntry>) {
            self.dirs
                .lock()
                .unwrap()
                .insert(path.to_string(), entries);
        }
    }

    impl ContentProvider for TestProvider {
        fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            let end = std::cmp::min(start + len as usize, data.len());
            if start >= data.len() {
                return Ok(vec![]);
            }
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
            let files = self.files.lock().unwrap();
            if let Some(data) = files.get(path) {
                let hash = [0u8; 32];
                Ok(VirtualStat::file(data.len() as u64, hash, 1000))
            } else {
                let dirs = self.dirs.lock().unwrap();
                if dirs.contains_key(path) {
                    Ok(VirtualStat::directory(1000))
                } else {
                    Err(VfsError::NotFound {
                        path: path.to_string(),
                    })
                }
            }
        }

        fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
            self.dirs
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn exists(&self, path: &str) -> VfsResult<bool> {
            let files = self.files.lock().unwrap();
            let dirs = self.dirs.lock().unwrap();
            Ok(files.contains_key(path) || dirs.contains_key(path))
        }

        fn version(&self) -> u64 {
            self.version.load(Ordering::Relaxed)
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    fn temp_socket_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        // Leak the tempdir so the path remains valid for the test duration.
        std::mem::forget(dir);
        path
    }

    /// Send a single request to the daemon and return the response.
    async fn send_request(
        socket_path: &Path,
        request: &VfsRequest,
    ) -> Result<VfsResponse, DaemonError> {
        let stream = tokio::net::UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = stream.into_split();

        let payload =
            rmp_serde::to_vec(request).map_err(|e| DaemonError::Serialization(e.to_string()))?;
        writer.write_u32(payload.len() as u32).await?;
        writer.write_all(&payload).await?;
        writer.flush().await?;

        let len = reader.read_u32().await?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;
        rmp_serde::from_slice(&buf).map_err(|e| DaemonError::Serialization(e.to_string()))
    }

    /// Start a server in the background and return the shutdown handle + join handle.
    async fn start_server(
        provider: TestProvider,
        socket_path: &Path,
    ) -> (
        kin_vfs_daemon::server::ShutdownHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let server = VfsDaemonServer::new(provider, socket_path);
        let handle = server.shutdown_handle();
        let join = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        // Wait for the server to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (handle, join)
    }

    // ---------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn read_file_returns_correct_content() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        provider.add_file("/src/main.rs", b"fn main() { println!(\"hello\"); }");
        provider.add_file("/README.md", b"# My Project\nThis is a readme.");

        let (shutdown, join) = start_server(provider, &socket).await;

        // Read first file
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/src/main.rs".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(data, b"fn main() { println!(\"hello\"); }");
                assert_eq!(total_size, 32);
            }
            other => panic!("expected Content, got {other:?}"),
        }

        // Read second file
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/README.md".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(data, b"# My Project\nThis is a readme.");
                assert_eq!(total_size, 30);
            }
            other => panic!("expected Content, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn stat_returns_correct_size() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        let content = b"Hello, world! This has exactly 43 bytes!!!";
        provider.add_file("/test.txt", content);

        let (shutdown, join) = start_server(provider, &socket).await;

        let resp = send_request(
            &socket,
            &VfsRequest::Stat {
                path: "/test.txt".into(),
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Stat(stat) => {
                assert!(stat.is_file);
                assert!(!stat.is_dir);
                assert_eq!(stat.size, content.len() as u64);
            }
            other => panic!("expected Stat, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn read_nonexistent_file_returns_error() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();

        let (shutdown, join) = start_server(provider, &socket).await;

        // Read a file that doesn't exist
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/does/not/exist.rs".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Error { code, message } => {
                assert!(matches!(code, ErrorCode::NotFound));
                assert!(message.contains("/does/not/exist.rs"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Stat a nonexistent file
        let resp = send_request(
            &socket,
            &VfsRequest::Stat {
                path: "/ghost.txt".into(),
            },
        )
        .await
        .unwrap();

        assert!(matches!(resp, VfsResponse::Error { code: ErrorCode::NotFound, .. }));

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_reads_from_multiple_threads() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();

        // Add 20 files with distinct content
        for i in 0..20 {
            let path = format!("/file_{i}.txt");
            let content = format!("content of file {i} with unique data {}", i * 31337);
            provider.add_file(&path, content.as_bytes());
        }

        let (shutdown, join) = start_server(provider, &socket).await;

        // Spawn 20 concurrent readers, each reading their own file
        let mut handles = Vec::new();
        for i in 0..20 {
            let sp = socket.clone();
            handles.push(tokio::spawn(async move {
                let path = format!("/file_{i}.txt");
                let expected = format!("content of file {i} with unique data {}", i * 31337);

                let resp = send_request(
                    &sp,
                    &VfsRequest::Read {
                        path,
                        offset: 0,
                        len: 0,
                    },
                )
                .await
                .unwrap();

                match resp {
                    VfsResponse::Content { data, .. } => {
                        assert_eq!(data, expected.as_bytes(), "file {i} content mismatch");
                    }
                    other => panic!("file {i}: expected Content, got {other:?}"),
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn large_file_round_trip() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();

        // Create a 1 MiB file with a recognizable pattern
        let size = 1024 * 1024;
        let mut large_content = Vec::with_capacity(size);
        for i in 0..size {
            large_content.push((i % 256) as u8);
        }
        provider.add_file("/large.bin", &large_content);

        let (shutdown, join) = start_server(provider, &socket).await;

        // Full read
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/large.bin".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(total_size, size as u64);
                assert_eq!(data.len(), size);
                assert_eq!(data, large_content);
            }
            other => panic!("expected Content, got {other:?}"),
        }

        // Stat to verify size
        let resp = send_request(
            &socket,
            &VfsRequest::Stat {
                path: "/large.bin".into(),
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Stat(stat) => {
                assert_eq!(stat.size, size as u64);
            }
            other => panic!("expected Stat, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn binary_file_content_preserved() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();

        // Binary content with all 256 byte values, null bytes, and high bytes
        let mut binary_content: Vec<u8> = (0..=255u8).collect();
        // Add some specific patterns that could trip up text-mode handling
        binary_content.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFE]); // BOM-like
        binary_content.extend_from_slice(&[0x0D, 0x0A, 0x0A, 0x0D]); // CRLF/LF patterns
        binary_content.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // UTF-8 BOM
        binary_content.extend_from_slice(b"\x00\x01\x02\x03"); // Low control chars

        provider.add_file("/image.png", &binary_content);

        let (shutdown, join) = start_server(provider, &socket).await;

        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/image.png".into(),
                offset: 0,
                len: 0,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(total_size, binary_content.len() as u64);
                assert_eq!(data, binary_content, "binary content must be byte-identical");
            }
            other => panic!("expected Content, got {other:?}"),
        }

        // Also verify via range read that binary offsets are correct
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/image.png".into(),
                offset: 0,
                len: 4,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, .. } => {
                assert_eq!(data, &[0x00, 0x01, 0x02, 0x03]);
            }
            other => panic!("expected Content, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_requests_on_single_connection() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        provider.add_file("/a.txt", b"aaa");
        provider.add_file("/b.txt", b"bbb");

        let (shutdown, join) = start_server(provider, &socket).await;

        // Open a single connection and send multiple sequential requests
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();

        let requests: Vec<VfsRequest> = vec![
            VfsRequest::Ping,
            VfsRequest::Read {
                path: "/a.txt".into(),
                offset: 0,
                len: 0,
            },
            VfsRequest::Stat {
                path: "/b.txt".into(),
            },
            VfsRequest::Read {
                path: "/b.txt".into(),
                offset: 0,
                len: 0,
            },
            VfsRequest::Access {
                path: "/a.txt".into(),
                mode: 4,
            },
            VfsRequest::Ping,
        ];

        for req in &requests {
            let payload = rmp_serde::to_vec(req).unwrap();
            writer.write_u32(payload.len() as u32).await.unwrap();
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();

            let len = reader.read_u32().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf).await.unwrap();
            let resp: VfsResponse = rmp_serde::from_slice(&buf).unwrap();

            match req {
                VfsRequest::Ping => {
                    assert!(matches!(resp, VfsResponse::Pong));
                }
                VfsRequest::Read { path, .. } => match resp {
                    VfsResponse::Content { data, .. } => {
                        if path == "/a.txt" {
                            assert_eq!(data, b"aaa");
                        } else {
                            assert_eq!(data, b"bbb");
                        }
                    }
                    other => panic!("expected Content, got {other:?}"),
                },
                VfsRequest::Stat { .. } => {
                    assert!(matches!(resp, VfsResponse::Stat(_)));
                }
                VfsRequest::Access { .. } => {
                    assert!(matches!(resp, VfsResponse::Accessible(true)));
                }
                _ => {}
            }
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn read_range_within_file() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        provider.add_file("/data.txt", b"0123456789abcdef");

        let (shutdown, join) = start_server(provider, &socket).await;

        // Read middle range
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/data.txt".into(),
                offset: 4,
                len: 6,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, total_size } => {
                assert_eq!(data, b"456789");
                assert_eq!(total_size, 16);
            }
            other => panic!("expected Content, got {other:?}"),
        }

        // Read past end (should return available bytes only)
        let resp = send_request(
            &socket,
            &VfsRequest::Read {
                path: "/data.txt".into(),
                offset: 14,
                len: 100,
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Content { data, .. } => {
                assert_eq!(data, b"ef");
            }
            other => panic!("expected Content, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn directory_stat_and_listing() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        provider.add_file("/project/src/main.rs", b"fn main() {}");
        provider.add_dir(
            "/project/src",
            vec![
                DirEntry {
                    name: "main.rs".into(),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "lib.rs".into(),
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "tests".into(),
                    file_type: FileType::Directory,
                },
            ],
        );

        let (shutdown, join) = start_server(provider, &socket).await;

        // Stat the directory
        let resp = send_request(
            &socket,
            &VfsRequest::Stat {
                path: "/project/src".into(),
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::Stat(stat) => {
                assert!(stat.is_dir);
                assert!(!stat.is_file);
            }
            other => panic!("expected Stat, got {other:?}"),
        }

        // ReadDir
        let resp = send_request(
            &socket,
            &VfsRequest::ReadDir {
                path: "/project/src".into(),
            },
        )
        .await
        .unwrap();

        match resp {
            VfsResponse::DirEntries(entries) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0].name, "main.rs");
                assert!(matches!(entries[0].file_type, FileType::File));
                assert_eq!(entries[2].name, "tests");
                assert!(matches!(entries[2].file_type, FileType::Directory));
            }
            other => panic!("expected DirEntries, got {other:?}"),
        }

        shutdown.shutdown();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn access_check_existing_and_missing() {
        let socket = temp_socket_path();
        let provider = TestProvider::new();
        provider.add_file("/exists.txt", b"yes");

        let (shutdown, join) = start_server(provider, &socket).await;

        let resp = send_request(
            &socket,
            &VfsRequest::Access {
                path: "/exists.txt".into(),
                mode: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, VfsResponse::Accessible(true)));

        let resp = send_request(
            &socket,
            &VfsRequest::Access {
                path: "/missing.txt".into(),
                mode: 4,
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, VfsResponse::Accessible(false)));

        shutdown.shutdown();
        join.await.unwrap();
    }
}
