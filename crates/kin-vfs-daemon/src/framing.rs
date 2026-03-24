// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Length-prefixed MessagePack framing for the Unix socket protocol.
//!
//! Wire format: 4-byte big-endian u32 length prefix followed by an rmp-serde
//! encoded payload. Max frame size is 16 MiB to prevent runaway allocations.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{VfsRequest, VfsResponse};
use crate::DaemonError;

/// Maximum frame payload: 16 MiB.
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Read a length-prefixed MessagePack frame and deserialize it as a `VfsRequest`.
pub async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<VfsRequest, DaemonError> {
    let len = stream.read_u32().await?;
    if len > MAX_FRAME_SIZE {
        return Err(DaemonError::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    rmp_serde::from_slice(&buf).map_err(|e| DaemonError::Serialization(e.to_string()))
}

/// Serialize a `VfsResponse` and write it as a length-prefixed MessagePack frame.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    response: &VfsResponse,
) -> Result<(), DaemonError> {
    let payload = rmp_serde::to_vec(response)
        .map_err(|e| DaemonError::Serialization(e.to_string()))?;
    let len = payload.len() as u32;
    stream.write_u32(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ErrorCode;
    use kin_vfs_core::VirtualStat;

    #[tokio::test]
    async fn round_trip_ping_pong() {
        // Serialize a Ping request through framing
        let request = VfsRequest::Ping;
        let payload = rmp_serde::to_vec(&request).unwrap();
        let len = (payload.len() as u32).to_be_bytes();
        let mut wire = Vec::new();
        wire.extend_from_slice(&len);
        wire.extend_from_slice(&payload);

        let mut cursor = std::io::Cursor::new(wire);
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert!(matches!(decoded, VfsRequest::Ping));
    }

    #[tokio::test]
    async fn round_trip_stat_response() {
        let stat = VirtualStat::directory(1234567890);
        let response = VfsResponse::Stat(stat);

        let mut buf = Vec::new();
        write_frame(&mut buf, &response).await.unwrap();

        // Now read it back as raw bytes and deserialize
        let mut cursor = std::io::Cursor::new(buf);
        let len = {
            use tokio::io::AsyncReadExt;
            cursor.read_u32().await.unwrap()
        };
        let mut payload = vec![0u8; len as usize];
        cursor.read_exact(&mut payload).await.unwrap();
        let decoded: VfsResponse = rmp_serde::from_slice(&payload).unwrap();
        assert!(matches!(decoded, VfsResponse::Stat(_)));
    }

    #[tokio::test]
    async fn round_trip_error_response() {
        let response = VfsResponse::Error {
            code: ErrorCode::NotFound,
            message: "file not found".to_string(),
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &response).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let len = {
            use tokio::io::AsyncReadExt;
            cursor.read_u32().await.unwrap()
        };
        let mut payload = vec![0u8; len as usize];
        cursor.read_exact(&mut payload).await.unwrap();
        let decoded: VfsResponse = rmp_serde::from_slice(&payload).unwrap();
        assert!(matches!(decoded, VfsResponse::Error { .. }));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        // Craft a frame header claiming 32 MiB
        let len = (32u32 * 1024 * 1024).to_be_bytes();
        let mut wire = Vec::new();
        wire.extend_from_slice(&len);
        wire.extend_from_slice(&[0u8; 64]); // some garbage payload

        let mut cursor = std::io::Cursor::new(wire);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("frame too large"));
    }

    #[tokio::test]
    async fn round_trip_all_request_variants() {
        let requests = vec![
            VfsRequest::Stat { path: "/a".into() },
            VfsRequest::ReadDir { path: "/b".into() },
            VfsRequest::Read { path: "/c".into(), offset: 10, len: 100 },
            VfsRequest::ReadLink { path: "/d".into() },
            VfsRequest::Access { path: "/e".into(), mode: 4 },
            VfsRequest::Ping,
            VfsRequest::Subscribe,
        ];
        for req in requests {
            let payload = rmp_serde::to_vec(&req).unwrap();
            let len = (payload.len() as u32).to_be_bytes();
            let mut wire = Vec::new();
            wire.extend_from_slice(&len);
            wire.extend_from_slice(&payload);

            let mut cursor = std::io::Cursor::new(wire);
            let decoded = read_frame(&mut cursor).await.unwrap();
            // Just check it didn't panic/error
            let _ = format!("{decoded:?}");
        }
    }
}
