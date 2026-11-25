// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

use crate::api::handlers::AppState;
use crate::api::routes::{create_api_routes_with, ApiContext};
use crate::api::security::{require_token, ApiSecurity, TlsListener};
use crate::network::NetworkState;
use anyhow::{Context, Result};
use axum::http::{header, HeaderValue, Method};
use axum::Router;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub struct ApiServer {
    addr: SocketAddr,
    state: AppState,
    context: ApiContext,
    security: ApiSecurity,
}

impl ApiServer {
    pub fn new(port: u16, state: Arc<RwLock<NetworkState>>) -> Self {
        Self::at(SocketAddr::from(([127, 0, 0, 1], port)), state)
    }

    fn at(addr: SocketAddr, state: AppState) -> Self {
        Self {
            addr,
            state,
            context: ApiContext::default(),
            security: ApiSecurity::default(),
        }
    }

    /// Build a server bound to `bind_address:port`. `bind_address` must be an
    /// IP literal (IPv4 or IPv6); anything else is an error.
    pub fn with_bind_address(
        bind_address: &str,
        port: u16,
        state: Arc<RwLock<NetworkState>>,
    ) -> Result<Self> {
        let ip: IpAddr = bind_address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .with_context(|| format!("invalid api.bind_address '{bind_address}'"))?;
        Ok(Self::at(SocketAddr::new(ip, port), state))
    }

    /// Require tokens and/or serve TLS.
    pub fn with_security(mut self, security: ApiSecurity) -> Self {
        self.security = security;
        self
    }

    /// Daemon facts and event log the handlers report on.
    pub fn with_context(mut self, context: ApiContext) -> Self {
        self.context = context;
        self
    }

    /// The complete application: routes, authentication, CORS and tracing.
    pub fn router(state: AppState, context: ApiContext, security: ApiSecurity) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
                origin.to_str().is_ok_and(is_local_origin)
            }))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

        // Later layers wrap earlier ones: CORS answers preflights before the
        // token check sees them.
        create_api_routes_with(state, context)
            .layer(axum::middleware::from_fn_with_state(
                security,
                require_token,
            ))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr)
            .await
            .with_context(|| format!("cannot listen on {}", self.addr))?;
        self.serve(listener).await
    }

    /// Serve on an already bound listener (the bind address is ignored).
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let addr = listener.local_addr()?;
        let tls = self.security.tls.clone();
        let auth = self.security.tokens.is_some();
        if !addr.ip().is_loopback() {
            if !auth {
                tracing::warn!("API on {addr} accepts unauthenticated requests");
            }
            if tls.is_none() {
                tracing::warn!("API on {addr} is not encrypted");
            }
        }
        tracing::info!(
            "Starting API server on {}://{addr} (authentication {})",
            if tls.is_some() { "https" } else { "http" },
            if auth { "required" } else { "off" }
        );
        let app = Self::router(self.state, self.context, self.security);
        match tls {
            Some(cfg) => axum::serve(TlsListener::new(listener, cfg)?, app).await?,
            None => axum::serve(listener, app).await?,
        }
        Ok(())
    }
}

fn is_local_origin(s: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        s.strip_prefix(scheme).is_some_and(|rest| {
            ["127.0.0.1", "localhost", "[::1]"].iter().any(|host| {
                rest == *host
                    || rest
                        .strip_prefix(host)
                        .is_some_and(|port| port.starts_with(':'))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::security::TokenSet;
    use crate::network::NetworkState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const TOKEN: &str = "unit-test-token-0123456789";

    fn state() -> Arc<RwLock<NetworkState>> {
        Arc::new(RwLock::new(NetworkState::new()))
    }

    fn app(public_metrics: bool) -> Router {
        let security = ApiSecurity {
            tokens: Some(Arc::new(TokenSet::new([TOKEN]))),
            public_metrics,
            tls: None,
        };
        ApiServer::router(state(), ApiContext::default(), security)
    }

    async fn status(app: Router, method: &str, uri: &str, auth: Option<&str>) -> StatusCode {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        app.oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[test]
    fn bind_address_is_honoured() {
        let s = ApiServer::with_bind_address("0.0.0.0", 9090, state()).unwrap();
        assert_eq!(s.addr, "0.0.0.0:9090".parse().unwrap());
        let s = ApiServer::with_bind_address("[::1]", 1234, state()).unwrap();
        assert_eq!(s.addr, "[::1]:1234".parse().unwrap());
        assert!(ApiServer::with_bind_address("not-an-ip", 1, state()).is_err());
    }

    #[test]
    fn only_loopback_origins_are_allowed() {
        for ok in [
            "http://localhost",
            "https://localhost:9090",
            "http://127.0.0.1:1",
            "http://[::1]",
        ] {
            assert!(is_local_origin(ok), "{ok}");
        }
        for bad in [
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://evil.example",
            "null",
        ] {
            assert!(!is_local_origin(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn health_route_responds() {
        let app = ApiServer::router(state(), ApiContext::default(), ApiSecurity::default());
        assert_eq!(status(app, "GET", "/health", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn token_protects_everything_but_probes() {
        let good = format!("Bearer {TOKEN}");
        for uri in [
            "/api/v1/status",
            "/api/v1/interfaces",
            "/api/v1/events",
            "/api/v1/events/stream",
            "/metrics",
            "/does-not-exist",
            "/health/../api/v1/status",
        ] {
            for auth in [None, Some("Bearer wrong-token-0123456789"), Some(TOKEN)] {
                assert_eq!(
                    status(app(false), "GET", uri, auth).await,
                    StatusCode::UNAUTHORIZED,
                    "{uri} {auth:?}"
                );
            }
        }
        assert_eq!(
            status(app(false), "POST", "/api/v1/reload", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(app(false), "GET", "/api/v1/status", Some(&good)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app(false), "GET", "/health", None).await,
            StatusCode::OK
        );
        assert_ne!(
            status(app(false), "GET", "/health/ready", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(app(true), "GET", "/metrics", None).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app(true), "GET", "/api/v1/status", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn rejection_names_the_scheme_and_preflight_passes() {
        let r = app(false)
            .oneshot(Request::get("/api/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.headers()["www-authenticate"], "Bearer realm=\"netevd\"");
        let r = app(false)
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/status")
                    .header("origin", "http://localhost:3000")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers()["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .contains("authorization"));
    }
}
