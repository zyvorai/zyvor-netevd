// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Minimal HTTP/1.0 client for the CLI to talk to the local REST API. HTTP/1.0
//! makes the server close the connection after the body and never use chunked
//! encoding, so a plain read-to-end is a complete parser. Plain `http://` only.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 16 * 1024 * 1024;

/// `http://host:port[/]` or bare `host:port` to `host:port`.
pub fn parse_endpoint(endpoint: &str) -> Result<String> {
    let e = endpoint.trim();
    if e.starts_with("https://") {
        bail!("https endpoints are not supported by the CLI client; use an http:// address");
    }
    let e = e.strip_prefix("http://").unwrap_or(e).trim_end_matches('/');
    if e.is_empty() || e.contains('/') || e.contains(' ') {
        bail!("invalid endpoint '{endpoint}': expected http://host:port");
    }
    Ok(if e.contains(':') && !e.ends_with(']') {
        e.to_string()
    } else {
        format!("{e}:80")
    })
}

/// Percent-encode a query value.
pub fn encode(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn request(method: &str, host: &str, path: &str, body: Option<&str>) -> String {
    let host = host.to_string();
    match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => format!(
            "{method} {path} HTTP/1.0\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ),
    }
}

async fn connect(endpoint: &str) -> Result<(TcpStream, String)> {
    let addr = parse_endpoint(endpoint)?;
    let s = tokio::time::timeout(TIMEOUT, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("timed out connecting to {addr}"))?
        .with_context(|| {
            format!(
                "cannot connect to netevd at {addr} (is the daemon running with the API enabled?)"
            )
        })?;
    Ok((s, addr))
}

fn split_response(raw: &[u8]) -> Result<(u16, &[u8])> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let head = std::str::from_utf8(&raw[..pos]).context("non-UTF-8 HTTP header")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .context("malformed HTTP status line")?;
    Ok((status, &raw[pos + 4..]))
}

async fn roundtrip(
    endpoint: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Vec<u8>> {
    let (mut s, addr) = connect(endpoint).await?;
    s.write_all(request(method, &addr, path, body).as_bytes())
        .await?;
    let mut raw = Vec::new();
    tokio::time::timeout(
        TIMEOUT,
        (&mut s).take(MAX_BODY as u64).read_to_end(&mut raw),
    )
    .await
    .context("timed out waiting for the response")??;
    let (status, body) = split_response(&raw)?;
    if !(200..300).contains(&status) {
        bail!(
            "{method} {path} failed with HTTP {status}: {}",
            String::from_utf8_lossy(body).trim()
        );
    }
    Ok(body.to_vec())
}

/// GET `path` (with query) and parse the JSON body.
pub async fn get_json<T: serde::de::DeserializeOwned>(endpoint: &str, path: &str) -> Result<T> {
    let body = roundtrip(endpoint, "GET", path, None).await?;
    serde_json::from_slice(&body).with_context(|| format!("unexpected response from {path}"))
}

/// POST a JSON body and parse the JSON response.
pub async fn post_json<T: serde::de::DeserializeOwned>(
    endpoint: &str,
    path: &str,
    body: &str,
) -> Result<T> {
    let body = roundtrip(endpoint, "POST", path, Some(body)).await?;
    serde_json::from_slice(&body).with_context(|| format!("unexpected response from {path}"))
}

/// The payload of an SSE `data:` line, if it is one.
pub fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:").map(str::trim_start)
}

/// GET an SSE stream and call `on_data` for each `data:` payload until the
/// server closes the connection or `on_data` returns false.
pub async fn stream_sse(
    endpoint: &str,
    path: &str,
    mut on_data: impl FnMut(&str) -> bool,
) -> Result<()> {
    let (mut s, addr) = connect(endpoint).await?;
    s.write_all(request("GET", &addr, path, None).as_bytes())
        .await?;
    let mut lines = BufReader::new(s).lines();
    let status_line = lines
        .next_line()
        .await?
        .context("connection closed before a response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .context("malformed HTTP status line")?;
    if status != 200 {
        bail!("GET {path} failed with HTTP {status}");
    }
    while let Some(line) = lines.next_line().await? {
        if let Some(d) = sse_data(&line) {
            if !on_data(d) {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_forms() {
        assert_eq!(
            parse_endpoint("http://localhost:9090").unwrap(),
            "localhost:9090"
        );
        assert_eq!(
            parse_endpoint("http://localhost:9090/").unwrap(),
            "localhost:9090"
        );
        assert_eq!(parse_endpoint("127.0.0.1:1").unwrap(), "127.0.0.1:1");
        assert_eq!(parse_endpoint("http://example").unwrap(), "example:80");
        assert_eq!(parse_endpoint("http://[::1]:9").unwrap(), "[::1]:9");
        assert!(parse_endpoint("https://x:1").is_err());
        assert!(parse_endpoint("http://x:1/path").is_err());
        assert!(parse_endpoint("").is_err());
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode("eth0"), "eth0");
        assert_eq!(encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn response_split_and_sse_lines() {
        let (st, body) = split_response(b"HTTP/1.0 200 OK\r\nX: y\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!((st, body), (200, &b"{\"a\":1}"[..]));
        assert!(split_response(b"garbage").is_err());
        assert_eq!(sse_data("data: {\"x\":1}"), Some("{\"x\":1}"));
        assert_eq!(sse_data("id: 4"), None);
        assert_eq!(sse_data(": keep-alive"), None);
    }
}
