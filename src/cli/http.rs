// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Minimal HTTP/1.0 client for the CLI to talk to the REST API, over plain TCP
//! or TLS, optionally with a bearer token. HTTP/1.0 makes the server close the
//! connection after the body and never use chunked encoding, so reading to the
//! end (checked against `Content-Length`) is a complete parser.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 16 * 1024 * 1024;

/// A parsed API address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Host name or IP address, without IPv6 brackets.
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Accepts `http://host[:port][/]`, `https://host[:port][/]` and a bare
    /// `host[:port]` (plain HTTP). IPv6 addresses go in brackets.
    pub fn parse(text: &str) -> Result<Self> {
        let bad =
            || format!("invalid endpoint '{text}': expected a URL like https://localhost:9090");
        let t = text.trim();
        let (tls, rest) = if let Some(r) = t.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = t.strip_prefix("http://") {
            (false, r)
        } else if t.contains("://") {
            bail!(bad());
        } else {
            (false, t)
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/?#@".contains(c))
        {
            bail!(bad());
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(r) = rest.strip_prefix('[') {
            let (host, after) = r.split_once(']').with_context(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().ok().with_context(bad)?,
                None if after.is_empty() => default_port,
                None => bail!(bad()),
            };
            (host, port)
        } else {
            match rest.split_once(':') {
                Some((h, p)) => (h, p.parse().ok().with_context(bad)?),
                None => (rest, default_port),
            }
        };
        if host.is_empty() {
            bail!(bad());
        }
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
        })
    }

    /// `host:port` as used to connect and in the `Host` header.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
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

/// How to reach and authenticate to the API.
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    pub endpoint: String,
    /// File holding the bearer token (first token line is used).
    pub token_file: Option<PathBuf>,
    /// Bearer token given directly (from `NETEVD_API_TOKEN`).
    pub token: Option<String>,
    /// Trust only the certificates in this PEM file instead of the system's.
    pub ca_file: Option<PathBuf>,
}

pub struct Client {
    endpoint: Endpoint,
    token: Option<String>,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn read_token(path: &Path) -> Result<String> {
    // The server decides how strict the file mode must be; the client only
    // needs one usable token.
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read token file {}", path.display()))?;
    let tokens = crate::api::security::parse_tokens(&text)
        .with_context(|| format!("token file {}", path.display()))?;
    Ok(tokens[0].to_string())
}

fn tls_connector(ca_file: Option<&Path>) -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let ctx = || format!("CA file {}", path.display());
            for cert in CertificateDer::pem_file_iter(path).with_context(ctx)? {
                roots.add(cert.with_context(ctx)?).with_context(ctx)?;
            }
            if roots.is_empty() {
                bail!("{}: no PEM certificate found", ctx());
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
            if roots.is_empty() {
                bail!("no system CA certificates found; pass --ca-file");
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// Status code, headers and body of a complete response.
struct Response<'a> {
    status: u16,
    content_length: Option<usize>,
    body: &'a [u8],
}

fn split_response(raw: &[u8]) -> Result<Response<'_>> {
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
    let content_length = head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse().ok())
            .flatten()
    });
    Ok(Response {
        status,
        content_length,
        body: &raw[pos + 4..],
    })
}

fn status_error(method: &str, path: &str, status: u16, body: &[u8]) -> anyhow::Error {
    if status == 401 {
        return anyhow::anyhow!(
            "{method} {path} failed with HTTP 401: the API requires a token \
             (--token-file, NETEVD_API_TOKEN_FILE or NETEVD_API_TOKEN)"
        );
    }
    anyhow::anyhow!(
        "{method} {path} failed with HTTP {status}: {}",
        String::from_utf8_lossy(body).trim()
    )
}

impl Client {
    pub fn new(options: &ClientOptions) -> Result<Self> {
        let endpoint = Endpoint::parse(&options.endpoint)?;
        let token = match (&options.token_file, &options.token) {
            (Some(f), _) => Some(read_token(f)?),
            (None, Some(t)) if !t.trim().is_empty() => {
                let t = t.trim();
                if !t.bytes().all(|b| b.is_ascii_graphic()) {
                    bail!("NETEVD_API_TOKEN must be printable ASCII without spaces");
                }
                Some(t.to_string())
            }
            _ => None,
        };
        if token.is_some() && !endpoint.tls && !endpoint.is_loopback() {
            bail!(
                "refusing to send the API token unencrypted to {}; use https",
                endpoint.authority()
            );
        }
        let tls = if endpoint.tls {
            let name = ServerName::try_from(endpoint.host.clone())
                .with_context(|| format!("invalid TLS server name '{}'", endpoint.host))?;
            Some((tls_connector(options.ca_file.as_deref())?, name))
        } else if options.ca_file.is_some() {
            bail!("--ca-file only applies to https endpoints");
        } else {
            None
        };
        Ok(Self {
            endpoint,
            token,
            tls,
        })
    }

    /// An unauthenticated client for `endpoint`.
    pub fn plain(endpoint: &str) -> Result<Self> {
        Self::new(&ClientOptions {
            endpoint: endpoint.to_string(),
            ..Default::default()
        })
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> String {
        let mut r = format!(
            "{method} {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n",
            self.endpoint.authority()
        );
        if let Some(t) = &self.token {
            r.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        if let Some(b) = body {
            r.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        r.push_str("\r\n");
        r.push_str(body.unwrap_or(""));
        r
    }

    /// Connect, finish the TLS handshake if any, and send the request.
    async fn send(&self, method: &str, path: &str, body: Option<&str>) -> Result<Box<dyn Io>> {
        let addr = self.endpoint.authority();
        let open = async {
            let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
                .await
                .with_context(|| {
                    format!(
                        "cannot connect to netevd at {addr} \
                         (is the daemon running with the API enabled?)"
                    )
                })?;
            let mut s: Box<dyn Io> = match &self.tls {
                Some((connector, name)) => Box::new(
                    connector
                        .connect(name.clone(), tcp)
                        .await
                        .with_context(|| format!("TLS handshake with {addr} failed"))?,
                ),
                None => Box::new(tcp),
            };
            s.write_all(self.request(method, path, body).as_bytes())
                .await?;
            s.flush().await?;
            anyhow::Ok(s)
        };
        tokio::time::timeout(TIMEOUT, open)
            .await
            .with_context(|| format!("timed out connecting to {addr}"))?
    }

    /// Perform a request and return the status and complete body.
    pub async fn exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut s = self.send(method, path, body).await?;
        let mut raw = Vec::new();
        let read = tokio::time::timeout(
            TIMEOUT,
            (&mut s).take(MAX_BODY as u64).read_to_end(&mut raw),
        )
        .await
        .context("timed out waiting for the response")?;
        // A peer may close TLS without `close_notify`; that is acceptable only
        // when Content-Length proves nothing is missing.
        let unclean = match read {
            Ok(_) => None,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Some(e),
            Err(e) => return Err(e.into()),
        };
        let r = split_response(&raw)?;
        match r.content_length {
            Some(n) if r.body.len() < n => {
                bail!("truncated response: {} of {n} bytes", r.body.len())
            }
            None => {
                if let Some(e) = unclean {
                    return Err(anyhow::Error::new(e).context("truncated response"));
                }
            }
            Some(_) => {}
        }
        Ok((r.status, r.body.to_vec()))
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<T> {
        let (status, body) = self.exchange(method, path, body).await?;
        if !(200..300).contains(&status) {
            return Err(status_error(method, path, status, &body));
        }
        serde_json::from_slice(&body).with_context(|| format!("unexpected response from {path}"))
    }

    /// GET `path` (with query) and parse the JSON body.
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.json("GET", path, None).await
    }

    /// POST a JSON body and parse the JSON response.
    pub async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &str,
    ) -> Result<T> {
        self.json("POST", path, Some(body)).await
    }

    /// GET an SSE stream and call `on_data` for each `data:` payload until the
    /// server closes the connection or `on_data` returns false.
    pub async fn stream_sse(
        &self,
        path: &str,
        mut on_data: impl FnMut(&str) -> bool,
    ) -> Result<()> {
        let s = self.send("GET", path, None).await?;
        let mut lines = BufReader::new(s).lines();
        let status_line = tokio::time::timeout(TIMEOUT, lines.next_line())
            .await
            .context("timed out waiting for the response")??
            .context("connection closed before a response")?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .context("malformed HTTP status line")?;
        if status != 200 {
            return Err(status_error("GET", path, status, b""));
        }
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(d) = sse_data(&line) {
                        if !on_data(d) {
                            return Ok(());
                        }
                    }
                }
                Ok(None) => return Ok(()),
                // The stream has no defined end, so an unclean TLS close is
                // just the end of it.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// The payload of an SSE `data:` line, if it is one.
pub fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:").map(str::trim_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(text: &str) -> (bool, String, u16) {
        let e = Endpoint::parse(text).unwrap();
        (e.tls, e.host, e.port)
    }

    #[test]
    fn endpoint_forms() {
        let h = |s: &str| s.to_string();
        assert_eq!(ep("http://localhost:9090"), (false, h("localhost"), 9090));
        assert_eq!(ep("http://localhost:9090/"), (false, h("localhost"), 9090));
        assert_eq!(ep("127.0.0.1:1"), (false, h("127.0.0.1"), 1));
        assert_eq!(ep("http://localhost"), (false, h("localhost"), 80));
        assert_eq!(ep("https://localhost"), (true, h("localhost"), 443));
        assert_eq!(ep("https://[::1]:9"), (true, h("::1"), 9));
        assert_eq!(ep("http://[::1]"), (false, h("::1"), 80));
        assert_eq!(
            Endpoint::parse("http://[::1]:9").unwrap().authority(),
            "[::1]:9"
        );
        for bad in [
            "",
            "https://",
            "ftp://localhost",
            "http://localhost:9090/path",
            "http://localhost:port",
            "http://localhost:99999",
            "http://user@localhost",
            "http://localhost\r\nX: y",
            "http://[::1",
            "http://[::1]9",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn token_is_not_sent_in_clear_off_host() {
        let opts = |endpoint: &str| ClientOptions {
            endpoint: endpoint.into(),
            token: Some("0123456789abcdef".into()),
            ..Default::default()
        };
        for ok in ["http://localhost:1", "http://127.0.0.1:1", "http://[::1]:1"] {
            Client::new(&opts(ok)).unwrap();
        }
        let e = Client::new(&opts("http://192.0.2.1:9090")).err().unwrap();
        assert!(e.to_string().contains("unencrypted"), "{e}");
        assert!(!e.to_string().contains("0123456789abcdef"));
        let mut bad = opts("http://localhost:1");
        bad.token = Some("a\r\nX-Evil: 1".into());
        assert!(Client::new(&bad).is_err());
    }

    #[test]
    fn token_file_wins_and_ca_file_needs_https() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("t");
        std::fs::write(&f, "# c\nfrom-the-file-0123456789\n").unwrap();
        let c = Client::new(&ClientOptions {
            endpoint: "http://localhost:1".into(),
            token_file: Some(f.clone()),
            token: Some("from-the-environment-0123".into()),
            ca_file: None,
        })
        .unwrap();
        assert!(c
            .request("GET", "/x", None)
            .contains("Authorization: Bearer from-the-file-0123456789\r\n"));
        assert!(Client::new(&ClientOptions {
            endpoint: "http://localhost:1".into(),
            ca_file: Some(f.clone()),
            ..Default::default()
        })
        .is_err());
        // A CA file without a certificate is an error, not an empty trust set.
        assert!(Client::new(&ClientOptions {
            endpoint: "https://localhost:1".into(),
            ca_file: Some(f),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode("eth0"), "eth0");
        assert_eq!(encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn response_split_and_sse_lines() {
        let r = split_response(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(
            (r.status, r.content_length, r.body),
            (200, Some(7), &b"{\"a\":1}"[..])
        );
        assert!(split_response(b"garbage").is_err());
        assert_eq!(sse_data("data: {\"x\":1}"), Some("{\"x\":1}"));
        assert_eq!(sse_data("id: 4"), None);
        assert_eq!(sse_data(": keep-alive"), None);
    }

    #[tokio::test]
    async fn short_body_is_reported_as_truncated() {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\n{}")
                .await
                .unwrap();
        });
        let c = Client::plain(&format!("http://{addr}")).unwrap();
        let e = c.get_json::<serde_json::Value>("/x").await.err().unwrap();
        assert!(e.to_string().contains("truncated"), "{e}");
    }
}
