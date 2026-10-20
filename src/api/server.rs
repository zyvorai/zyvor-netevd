// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::handlers::AppState;
use crate::api::routes::create_api_routes;
use crate::network::NetworkState;
use anyhow::{Context, Result};
use axum::http::{HeaderValue, Method};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub struct ApiServer {
    addr: SocketAddr,
    state: AppState,
}

impl ApiServer {
    pub fn new(port: u16, state: Arc<RwLock<NetworkState>>) -> Self {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        Self { addr, state }
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
        Ok(Self {
            addr: SocketAddr::new(ip, port),
            state,
        })
    }

    pub async fn run(self) -> Result<()> {
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
                origin.to_str().is_ok_and(|s| {
                    s == "http://127.0.0.1"
                        || s.starts_with("http://127.0.0.1:")
                        || s == "http://localhost"
                        || s.starts_with("http://localhost:")
                        || s == "http://[::1]"
                        || s.starts_with("http://[::1]:")
                })
            }))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE]);

        let app = create_api_routes(self.state)
            .layer(cors)
            .layer(TraceLayer::new_for_http());

        tracing::info!("Starting API server on {}", self.addr);

        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn state() -> Arc<RwLock<NetworkState>> {
        Arc::new(RwLock::new(NetworkState::new()))
    }

    #[test]
    fn bind_address_is_honoured() {
        let s = ApiServer::with_bind_address("0.0.0.0", 9090, state()).unwrap();
        assert_eq!(s.addr, "0.0.0.0:9090".parse().unwrap());
        let s = ApiServer::with_bind_address("[::1]", 1234, state()).unwrap();
        assert_eq!(s.addr, "[::1]:1234".parse().unwrap());
        assert!(ApiServer::with_bind_address("not-an-ip", 1, state()).is_err());
    }

    #[tokio::test]
    async fn health_route_responds() {
        let app = create_api_routes(state());
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
