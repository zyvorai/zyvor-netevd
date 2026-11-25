// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! API access control: bearer-token authentication and TLS.
//!
//! Everything is loaded once at start-up, before the daemon drops privileges
//! (when it was started as root). Any problem with configured
//! security material is an error: the API is then not served at all, never
//! served without the protection that was asked for.

use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use subtle::{Choice, ConstantTimeEq};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::api::models::ApiResponse;
use crate::config::ApiConfig;

/// Shortest accepted token.
pub const MIN_TOKEN_LEN: usize = 16;
const MAX_TOKEN_FILE: u64 = 64 * 1024;
/// A client must finish the TLS handshake within this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight at once; further connections wait in the backlog.
const MAX_HANDSHAKES: usize = 128;

/// Paths that never need a token, so liveness and readiness probes work.
pub const PUBLIC_PATHS: &[&str] = &["/health", "/health/ready"];

/// Accepted bearer tokens, kept only as SHA-256 digests.
pub struct TokenSet {
    digests: Vec<[u8; 32]>,
}

fn digest(token: &str) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Tokens from the file format: one per line, `#` comments and blank lines
/// ignored. Error messages never contain a token.
pub fn parse_tokens(text: &str) -> Result<Vec<&str>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.len() < MIN_TOKEN_LEN {
            bail!(
                "line {}: token is shorter than {MIN_TOKEN_LEN} characters",
                i + 1
            );
        }
        if !t.bytes().all(|b| b.is_ascii_graphic()) {
            bail!(
                "line {}: token must be printable ASCII without spaces",
                i + 1
            );
        }
        out.push(t);
    }
    if out.is_empty() {
        bail!("no token found");
    }
    Ok(out)
}

impl TokenSet {
    pub fn new<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            digests: tokens.into_iter().map(digest).collect(),
        }
    }

    /// Load a token file. It must be a regular file that is neither
    /// world-accessible nor group-writable.
    pub fn from_file(path: &Path) -> Result<Self> {
        let ctx = || format!("token file {}", path.display());
        let file = std::fs::File::open(path).with_context(ctx)?;
        let meta = file.metadata().with_context(ctx)?;
        if !meta.is_file() {
            bail!("{}: not a regular file", ctx());
        }
        if meta.mode() & 0o027 != 0 {
            bail!(
                "{}: mode {:o} is too open (use 0600 or 0640)",
                ctx(),
                meta.mode() & 0o7777
            );
        }
        let mut text = String::new();
        file.take(MAX_TOKEN_FILE + 1)
            .read_to_string(&mut text)
            .with_context(ctx)?;
        if text.len() as u64 > MAX_TOKEN_FILE {
            bail!("{}: larger than 64 KiB", ctx());
        }
        let tokens = parse_tokens(&text).with_context(ctx)?;
        Ok(Self::new(tokens))
    }

    /// Constant-time comparison against every accepted token.
    pub fn verify(&self, candidate: &str) -> bool {
        let d = digest(candidate);
        self.digests
            .iter()
            .fold(Choice::from(0), |acc, x| acc | x.ct_eq(&d))
            .into()
    }
}

/// Server TLS configuration from PEM files (TLS 1.2 and 1.3, HTTP/1.1).
pub fn load_tls(cert_file: &Path, key_file: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let certs = CertificateDer::pem_file_iter(cert_file)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .with_context(|| format!("TLS certificate {}", cert_file.display()))?;
    if certs.is_empty() {
        bail!(
            "TLS certificate {}: no PEM certificate found",
            cert_file.display()
        );
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .with_context(|| format!("TLS private key {}", key_file.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and key do not form a usable pair")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// What protects the API. The default is no authentication and plain HTTP.
#[derive(Clone, Default)]
pub struct ApiSecurity {
    pub tokens: Option<Arc<TokenSet>>,
    pub public_metrics: bool,
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

impl ApiSecurity {
    pub fn load(cfg: &ApiConfig) -> Result<Self> {
        let tokens = match cfg.auth.token_file.as_deref() {
            None => None,
            Some("") => bail!("api.auth.token_file is empty"),
            Some(p) => Some(Arc::new(TokenSet::from_file(Path::new(p))?)),
        };
        let tls = if cfg.tls.enabled {
            let need = |v: &Option<String>, key: &str| -> Result<String> {
                match v.as_deref() {
                    None | Some("") => bail!("api.tls is enabled but {key} is empty"),
                    Some(p) => Ok(p.to_string()),
                }
            };
            let cert = need(&cfg.tls.cert_file, "api.tls.cert_file")?;
            let key = need(&cfg.tls.key_file, "api.tls.key_file")?;
            Some(load_tls(Path::new(&cert), Path::new(&key))?)
        } else {
            None
        };
        Ok(Self {
            tokens,
            public_metrics: cfg.auth.public_metrics,
            tls,
        })
    }

    fn is_public(&self, path: &str) -> bool {
        PUBLIC_PATHS.contains(&path) || (self.public_metrics && path == "/metrics")
    }
}

/// The token of an `Authorization: Bearer <token>` header value.
pub fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Middleware rejecting requests without a valid token.
pub async fn require_token(
    State(sec): State<ApiSecurity>,
    request: Request,
    next: Next,
) -> Response {
    let Some(tokens) = &sec.tokens else {
        return next.run(request).await;
    };
    if sec.is_public(request.uri().path()) {
        return next.run(request).await;
    }
    let ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .is_some_and(|t| tokens.verify(t));
    if ok {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"netevd\"")],
        Json(ApiResponse::<()>::error("unauthorized".into())),
    )
        .into_response()
}

/// TCP listener that performs TLS handshakes off the accept path, so a slow or
/// silent client cannot stall other connections.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, ready) = mpsc::channel(MAX_HANDSHAKES);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        let task = tokio::spawn(async move {
            loop {
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        // Typically fd exhaustion: back off instead of spinning.
                        tracing::warn!("API accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!("TLS handshake with {peer} failed: {e}"),
                        Err(_) => tracing::debug!("TLS handshake with {peer} timed out"),
                    }
                    drop(permit);
                });
            }
        });
        Ok(Self { ready, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(x) => x,
            // The accept task never ends while the listener is alive.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const T1: &str = "0123456789abcdef-one";
    const T2: &str = "0123456789abcdef-two";

    fn file(dir: &Path, name: &str, body: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn token_file_supports_rotation_and_comments() {
        let d = tempfile::tempdir().unwrap();
        let p = file(
            d.path(),
            "t",
            &format!("# old\n{T1}\n\n  {T2}  \r\n"),
            0o600,
        );
        let set = TokenSet::from_file(&p).unwrap();
        assert!(set.verify(T1) && set.verify(T2));
        assert!(!set.verify(&T1[..T1.len() - 1]));
        assert!(!set.verify(""));
        assert!(!set.verify("# old"));
        TokenSet::from_file(&file(d.path(), "g", T1, 0o640)).unwrap();
    }

    #[test]
    fn unsafe_token_files_are_rejected_without_leaking() {
        let d = tempfile::tempdir().unwrap();
        for mode in [0o644, 0o604, 0o660, 0o602] {
            let p = file(d.path(), "m", T1, mode);
            assert!(TokenSet::from_file(&p).is_err(), "mode {mode:o}");
        }
        for body in [
            "",
            "# only a comment\n",
            "short",
            "has space inside the token",
        ] {
            let p = file(d.path(), "b", body, 0o600);
            let e = format!("{:#}", TokenSet::from_file(&p).err().unwrap());
            assert!(!e.contains("short\n") && !e.contains("inside"), "{e}");
        }
        assert!(TokenSet::from_file(d.path()).is_err());
        assert!(TokenSet::from_file(&d.path().join("missing")).is_err());
    }

    #[test]
    fn bearer_header_forms() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("abc"), None);
    }

    #[test]
    fn configured_but_broken_security_is_an_error() {
        let mut cfg = ApiConfig::default();
        assert!(ApiSecurity::load(&cfg).unwrap().tls.is_none());
        cfg.tls.enabled = true;
        assert!(ApiSecurity::load(&cfg).is_err(), "empty cert path");
        cfg.tls.cert_file = Some("/nonexistent/cert".into());
        cfg.tls.key_file = Some("/nonexistent/key".into());
        assert!(ApiSecurity::load(&cfg).is_err(), "missing files");
        let d = tempfile::tempdir().unwrap();
        let junk = file(d.path(), "junk.pem", "not pem", 0o600);
        cfg.tls.cert_file = Some(junk.display().to_string());
        cfg.tls.key_file = Some(junk.display().to_string());
        assert!(ApiSecurity::load(&cfg).is_err(), "no certificate in file");
        let mut cfg = ApiConfig::default();
        cfg.auth.token_file = Some(String::new());
        assert!(ApiSecurity::load(&cfg).is_err());
    }

    #[test]
    fn mismatched_certificate_and_key_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let a = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = file(d.path(), "c.pem", &a.cert.pem(), 0o644);
        let good = file(d.path(), "a.key", &a.signing_key.serialize_pem(), 0o600);
        let bad = file(d.path(), "b.key", &b.signing_key.serialize_pem(), 0o600);
        load_tls(&cert, &good).unwrap();
        assert!(load_tls(&cert, &bad).is_err());
    }
}
