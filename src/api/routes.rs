// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

use crate::api::handlers::*;
use crate::api::health::{health_check, readiness_check, HealthProbe};
use crate::hooks::journal::EventLog;
use axum::{
    routing::{get, post},
    Extension, Router,
};
use std::sync::Arc;

/// What the handlers report on besides the shared network state.
#[derive(Clone)]
pub struct ApiContext {
    pub log: Arc<EventLog>,
    pub probe: Arc<HealthProbe>,
}

impl Default for ApiContext {
    fn default() -> Self {
        Self {
            log: crate::hooks::journal::global(),
            probe: Arc::new(HealthProbe::default()),
        }
    }
}

pub fn create_api_routes(state: AppState) -> Router {
    create_api_routes_with(state, ApiContext::default())
}

pub fn create_api_routes_with_log(state: AppState, log: Arc<EventLog>) -> Router {
    create_api_routes_with(
        state,
        ApiContext {
            log,
            ..ApiContext::default()
        },
    )
}

/// All routes, without authentication (see `ApiServer::router`).
pub fn create_api_routes_with(state: AppState, context: ApiContext) -> Router {
    Router::new()
        // API v1 routes
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/interfaces", get(list_interfaces))
        .route("/api/v1/interfaces/{name}", get(get_interface))
        .route("/api/v1/routes", get(list_routes))
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/events/stream", get(stream_events))
        .route("/api/v1/reload", post(reload_config))
        // Health and metrics
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics))
        .layer(Extension(context.log))
        .layer(Extension(context.probe))
        .with_state(state)
}
