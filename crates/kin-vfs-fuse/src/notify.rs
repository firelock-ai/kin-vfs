// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Write-notify client: how a mounted write is confirmed into the graph.
//!
//! A FUSE write lands on the projection surface (the real workspace path) and
//! is then announced to the repo's kin daemon at `/vfs/write-notify`, which
//! reconciles it into graph truth. This is the same acknowledged contract the
//! LD_PRELOAD shim uses, documented in
//! `docs/authority-and-write-notify-contract.md` and pinned byte-for-byte by
//! `tests/fixtures/write-notify.json`. Only `200 {"reindexed":true}` counts as
//! success; every other outcome is reported to the caller rather than
//! swallowed, so a divergence between the projection and the graph is never
//! hidden.
//!
//! The request is written straight onto a `TcpStream` rather than through an
//! HTTP client crate. The body is one short JSON object to a loopback port, and
//! keeping this module dependency-free lets the mount crate build on its own,
//! outside the workspace, wherever libfuse happens to be installed.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use kin_vfs_core::VfsPath;

/// Environment override for the loopback bearer token, matching the daemon
/// client's resolution order.
const AUTH_TOKEN_ENV: &str = "KIN_DAEMON_AUTH_TOKEN";

/// Per-attempt connect/read/write budget. The daemon is on loopback and the
/// reply is a few dozen bytes, so a write blocked on this is a stuck daemon,
/// not a slow one.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on response bytes read, so a misbehaving peer cannot make a
/// mount thread read without end.
const MAX_NOTIFY_RESPONSE: usize = 2048;

/// Why a write could not be confirmed into the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// The daemon could not be reached at all.
    Unreachable(String),
    /// The daemon is running but serves no write-notify route.
    ///
    /// This is the ordinary answer from a repository-v6 daemon, which dropped
    /// the route as pre-v6 authority. It is separated from a decline because it
    /// says something permanent about the daemon rather than something about
    /// this write: there is no point sending the next one.
    RouteAbsent,
    /// The daemon answered, but did not confirm the re-index: a non-2xx status
    /// such as `401`/`409`, or `200 {"reindexed":false}`.
    Declined(String),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(detail) => {
                write!(f, "kin-daemon unreachable: {detail}")
            }
            Self::RouteAbsent => write!(
                f,
                "this kin-daemon serves no /vfs/write-notify route; \
                 reconcile falls to its file watcher"
            ),
            Self::Declined(detail) => {
                write!(f, "kin-daemon did not confirm the re-index: {detail}")
            }
        }
    }
}

impl std::error::Error for NotifyError {}

/// Where the write-notify POST goes, and what it authenticates with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyTarget {
    host: String,
    port: u16,
    token: Option<String>,
}

impl NotifyTarget {
    /// Build a target from the daemon base URL the mount is already using and
    /// the served workspace root.
    ///
    /// The token resolves exactly as the daemon client and the shim resolve it:
    /// `KIN_DAEMON_AUTH_TOKEN` first, then `<root>/.kin/daemon.token`. Reading
    /// the file here rather than accepting a pre-read secret keeps a rotated
    /// token working across a daemon restart without remounting.
    pub fn resolve(base_url: &str, workspace_root: &Path) -> Self {
        let (host, port) = parse_host_port(base_url);
        Self {
            host,
            port,
            token: resolve_token(workspace_root),
        }
    }

    /// The `Host:` header value.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Split `host:port` out of a base URL, defaulting to the daemon's documented
/// loopback port when the URL carries none.
fn parse_host_port(base_url: &str) -> (String, u16) {
    let rest = base_url
        .strip_prefix("http://")
        .or_else(|| base_url.strip_prefix("https://"))
        .unwrap_or(base_url);
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_end_matches('/');

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => match port.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (authority.to_string(), 4219),
        },
        _ => (authority.to_string(), 4219),
    }
}

/// Read the loopback bearer token: environment override first, then the
/// per-repo `.kin/daemon.token` file.
fn resolve_token(workspace_root: &Path) -> Option<String> {
    if let Some(from_env) = std::env::var(AUTH_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some(from_env);
    }

    std::fs::read_to_string(workspace_root.join(".kin").join("daemon.token"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Build the raw HTTP/1.1 write-notify request for `path`.
///
/// The path travels as canonical bytes in the `{"bytes_hex": …}` envelope that
/// `kin_model::RepoPath` serializes to. A JSON string could not carry a
/// non-UTF8 Unix path without lossy substitution, which would attribute the
/// write to a different artifact than the one the caller actually saved.
pub fn build_notify_request(
    path: &VfsPath,
    target: &NotifyTarget,
    session_id: Option<&str>,
) -> String {
    let body = match session_id {
        Some(session) => format!(
            r#"{{"path":{{"bytes_hex":"{}"}},"session_id":"{}"}}"#,
            hex_encode(path.as_bytes()),
            escape_json_string(session)
        ),
        None => format!(
            r#"{{"path":{{"bytes_hex":"{}"}}}}"#,
            hex_encode(path.as_bytes())
        ),
    };

    // A bare `Bearer ` with no secret is rejected, and the daemon accepts
    // tokenless requests while enforcement is off, so the header is attached
    // only when a token actually resolves. With enforcement on and no token the
    // daemon answers 401, which surfaces as a declined write rather than a
    // silent bypass.
    let auth_header = match &target.token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };

    format!(
        "POST /vfs/write-notify HTTP/1.1\r\n\
         Host: {host}\r\n\
         {auth}Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        host = target.authority(),
        auth = auth_header,
        len = body.len(),
    )
}

/// Lowercase-hex encode `bytes`. The daemon rejects any other encoding.
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Escape a session id for embedding in a JSON string literal.
fn escape_json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// What the daemon said about one write.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NotifyResponse {
    /// `200` with `"reindexed":true`. The graph re-indexed the write.
    Acked,
    /// `2xx` without `"reindexed":true`. The daemon was reached, but the
    /// reconcile did not happen.
    NotReindexed,
    /// Any other status.
    Rejected(u16),
}

/// Classify a raw HTTP reply. Both the status line and the body matter: a soft
/// block is a `200` carrying `"reindexed":false`, so bytes coming back is not
/// on its own evidence that anything reconciled.
fn parse_notify_response(raw: &[u8]) -> NotifyResponse {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    if !(200..300).contains(&status) {
        return NotifyResponse::Rejected(status);
    }

    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    if body.replace(' ', "").contains("\"reindexed\":true") {
        NotifyResponse::Acked
    } else {
        NotifyResponse::NotReindexed
    }
}

/// Outcome of one transport attempt, before retry classification.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NotifyAttempt {
    Responded(NotifyResponse),
    /// Could not connect at all.
    Unreachable,
    /// Connected, but the exchange failed part-way through.
    Transient,
}

/// Whether an attempt is worth exactly one more try.
fn notify_is_retryable(attempt: &NotifyAttempt) -> bool {
    match attempt {
        NotifyAttempt::Transient => true,
        NotifyAttempt::Responded(NotifyResponse::Rejected(code)) => (500..600).contains(code),
        _ => false,
    }
}

/// Perform one POST and classify the outcome.
fn attempt_notify(request: &str, target: &NotifyTarget) -> NotifyAttempt {
    let addrs = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return NotifyAttempt::Unreachable,
    };

    let stream = addrs
        .into_iter()
        .find_map(|addr| TcpStream::connect_timeout(&addr, NOTIFY_TIMEOUT).ok());
    let mut stream = match stream {
        Some(stream) => stream,
        None => return NotifyAttempt::Unreachable,
    };

    let _ = stream.set_write_timeout(Some(NOTIFY_TIMEOUT));
    let _ = stream.set_read_timeout(Some(NOTIFY_TIMEOUT));

    if stream.write_all(request.as_bytes()).is_err() {
        return NotifyAttempt::Transient;
    }

    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= MAX_NOTIFY_RESPONSE {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if buf.is_empty() {
        return NotifyAttempt::Transient;
    }
    NotifyAttempt::Responded(parse_notify_response(&buf))
}

/// Announce a landed write and require the daemon's acknowledgement.
///
/// Returns `Ok(())` only for `200 {"reindexed":true}`. A transient transport
/// failure or a `5xx` is retried exactly once; nothing else is retried, so a
/// rejected write cannot loop.
pub fn notify_write(
    path: &VfsPath,
    target: &NotifyTarget,
    session_id: Option<&str>,
) -> Result<(), NotifyError> {
    let request = build_notify_request(path, target, session_id);

    let mut attempt = attempt_notify(&request, target);
    if notify_is_retryable(&attempt) {
        attempt = attempt_notify(&request, target);
    }

    match attempt {
        NotifyAttempt::Responded(NotifyResponse::Acked) => Ok(()),
        NotifyAttempt::Unreachable => Err(NotifyError::Unreachable(format!(
            "no daemon answering at {}",
            target.authority()
        ))),
        NotifyAttempt::Transient => Err(NotifyError::Unreachable(format!(
            "the exchange with {} did not complete",
            target.authority()
        ))),
        NotifyAttempt::Responded(NotifyResponse::NotReindexed) => Err(NotifyError::Declined(
            "the daemon answered 200 but reported reindexed=false".to_string(),
        )),
        NotifyAttempt::Responded(NotifyResponse::Rejected(404)) => Err(NotifyError::RouteAbsent),
        NotifyAttempt::Responded(NotifyResponse::Rejected(code)) => Err(NotifyError::Declined(
            format!("the daemon answered HTTP {code}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> NotifyTarget {
        NotifyTarget {
            host: "127.0.0.1".to_string(),
            port: 4219,
            token: None,
        }
    }

    fn vpath(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).expect("valid test path")
    }

    #[test]
    fn body_matches_the_pinned_peer_fixture() {
        // tests/fixtures/write-notify.json is the shared peer contract: the
        // same bytes the shim sends and the Kin daemon parses. A change here
        // that the fixture does not carry is a silent protocol fork.
        let request = build_notify_request(&vpath("src/main.rs"), &target(), Some("sess-42"));
        let body = request
            .split("\r\n\r\n")
            .nth(1)
            .expect("request has a body");
        assert_eq!(
            body,
            r#"{"path":{"bytes_hex":"7372632f6d61696e2e7273"},"session_id":"sess-42"}"#
        );
    }

    #[test]
    fn body_omits_session_when_absent() {
        let request = build_notify_request(&vpath("src/main.rs"), &target(), None);
        let body = request
            .split("\r\n\r\n")
            .nth(1)
            .expect("request has a body");
        assert_eq!(body, r#"{"path":{"bytes_hex":"7372632f6d61696e2e7273"}}"#);
    }

    #[test]
    fn non_utf8_path_survives_as_exact_bytes() {
        // A JSON string could not carry these bytes without substitution, and a
        // substituted path names a different artifact than the caller saved.
        let raw = VfsPath::from_bytes(b"logs/x-\xff\xfe.log".to_vec()).unwrap();
        let request = build_notify_request(&raw, &target(), None);
        assert!(
            request.contains("6c6f67732f782dfffe2e6c6f67"),
            "expected exact hex of the raw name, got: {request}"
        );
    }

    #[test]
    fn content_length_counts_the_body_bytes() {
        let request = build_notify_request(&vpath("src/main.rs"), &target(), Some("sess-42"));
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        assert!(
            request.contains(&format!("Content-Length: {}\r\n", body.len())),
            "declared length must match the body it describes: {request}"
        );
    }

    #[test]
    fn bearer_header_appears_only_with_a_token() {
        let without = build_notify_request(&vpath("a.rs"), &target(), None);
        assert!(!without.contains("Authorization:"));

        let with = build_notify_request(
            &vpath("a.rs"),
            &NotifyTarget {
                token: Some("secret".to_string()),
                ..target()
            },
            None,
        );
        assert!(with.contains("Authorization: Bearer secret\r\n"));
    }

    #[test]
    fn session_id_is_json_escaped() {
        let request =
            build_notify_request(&vpath("a.rs"), &target(), Some("has\"quote\\and\nnewline"));
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        assert!(body.contains(r#"has\"quote\\and\nnewline"#), "body: {body}");
    }

    #[test]
    fn only_reindexed_true_is_an_acknowledgement() {
        assert_eq!(
            parse_notify_response(
                b"HTTP/1.1 200 OK\r\n\r\n{\"reindexed\":true,\"entity_count\":3}"
            ),
            NotifyResponse::Acked
        );
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 200 OK\r\n\r\n{\"reindexed\":false}"),
            NotifyResponse::NotReindexed
        );
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 401 Unauthorized\r\n\r\n{}"),
            NotifyResponse::Rejected(401)
        );
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 409 Conflict\r\n\r\n{\"reindexed\":true}"),
            NotifyResponse::Rejected(409),
            "a write-veto stays a veto even when the body claims a re-index"
        );
    }

    #[test]
    fn whitespace_in_the_body_does_not_hide_the_acknowledgement() {
        assert_eq!(
            parse_notify_response(b"HTTP/1.1 200 OK\r\n\r\n{ \"reindexed\" : true }"),
            NotifyResponse::Acked
        );
    }

    #[test]
    fn only_transient_and_5xx_are_retried() {
        assert!(notify_is_retryable(&NotifyAttempt::Transient));
        assert!(notify_is_retryable(&NotifyAttempt::Responded(
            NotifyResponse::Rejected(503)
        )));
        assert!(!notify_is_retryable(&NotifyAttempt::Unreachable));
        assert!(!notify_is_retryable(&NotifyAttempt::Responded(
            NotifyResponse::Rejected(401)
        )));
        assert!(!notify_is_retryable(&NotifyAttempt::Responded(
            NotifyResponse::NotReindexed
        )));
    }

    #[test]
    fn host_port_parsing_covers_the_shapes_a_daemon_url_takes() {
        assert_eq!(
            parse_host_port("http://127.0.0.1:5050"),
            ("127.0.0.1".to_string(), 5050)
        );
        assert_eq!(
            parse_host_port("http://127.0.0.1:5050/"),
            ("127.0.0.1".to_string(), 5050)
        );
        assert_eq!(
            parse_host_port("http://localhost"),
            ("localhost".to_string(), 4219)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:9999"),
            ("127.0.0.1".to_string(), 9999)
        );
    }
}
