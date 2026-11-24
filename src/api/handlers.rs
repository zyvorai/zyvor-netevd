// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

use crate::api::models::*;
use crate::hooks::journal::{EventFilter, EventLog, JournalRecord};
use crate::network::NetworkState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Extension, Json,
};
use futures::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type AppState = Arc<RwLock<NetworkState>>;

/// GET /api/v1/status
pub async fn get_status(
    State(state): State<AppState>,
    Extension(log): Extension<Arc<EventLog>>,
) -> Json<ApiResponse<DaemonStatus>> {
    let state = state.read().await;

    let status = DaemonStatus {
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: log.uptime().as_secs(),
        interfaces_count: state.links_by_name.len(),
        routing_rules_count: state.routing_rules_from.len() + state.routing_rules_to.len(),
        events_processed: log.total(),
        backend: "systemd-networkd".to_string(), // TODO: Get from config
        dry_run: false,                          // TODO: Get from config
    };

    Json(ApiResponse::success(status))
}

/// GET /api/v1/interfaces
pub async fn list_interfaces(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<InterfaceInfo>>> {
    let state = state.read().await;

    let interfaces: Vec<InterfaceInfo> = state
        .links_by_name
        .iter()
        .map(|(name, index)| InterfaceInfo {
            name: name.clone(),
            index: *index,
            state: "up".to_string(), // TODO: Get actual state
            addresses: vec![],       // TODO: Get addresses
            mac_address: None,       // TODO: Get MAC
            mtu: None,               // TODO: Get MTU
            flags: vec![],           // TODO: Get flags
        })
        .collect();

    Json(ApiResponse::success(interfaces))
}

/// GET /api/v1/interfaces/:name
pub async fn get_interface(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<InterfaceInfo>>, StatusCode> {
    let state = state.read().await;

    let interface = state.links_by_name.get(&name).map(|index| InterfaceInfo {
        name: name.clone(),
        index: *index,
        state: "up".to_string(),
        addresses: vec![],
        mac_address: None,
        mtu: None,
        flags: vec![],
    });

    match interface {
        Some(iface) => Ok(Json(ApiResponse::success(iface))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// GET /api/v1/routes
pub async fn list_routes(State(_state): State<AppState>) -> Json<ApiResponse<Vec<RouteInfo>>> {
    // TODO: Implement route listing
    let routes = vec![];
    Json(ApiResponse::success(routes))
}

/// GET /api/v1/rules
pub async fn list_rules(State(state): State<AppState>) -> Json<ApiResponse<Vec<RoutingRuleInfo>>> {
    let state = state.read().await;

    let mut rules: Vec<RoutingRuleInfo> = Vec::new();

    // Add "from" rules
    for (addr, rule) in state.routing_rules_from.iter() {
        rules.push(RoutingRuleInfo {
            priority: 32765, // TODO: Get actual priority
            source: Some(addr.to_string()),
            destination: None,
            table: rule.table,
            interface: None,
        });
    }

    // Add "to" rules
    for (addr, rule) in state.routing_rules_to.iter() {
        rules.push(RoutingRuleInfo {
            priority: 32766, // TODO: Get actual priority
            source: None,
            destination: Some(addr.to_string()),
            table: rule.table,
            interface: None,
        });
    }

    Json(ApiResponse::success(rules))
}

/// Query string shared by `/api/v1/events` and `/api/v1/events/stream`.
#[derive(Debug, Deserialize, Default)]
pub struct EventQuery {
    pub interface: Option<String>,
    pub event: Option<String>,
    /// Only events with a sequence number above this (resume cursor).
    pub since: Option<u64>,
    /// Newest N events (default 100, max 1000).
    pub limit: Option<usize>,
}

impl EventQuery {
    fn filter(&self) -> EventFilter {
        EventFilter {
            interface: self.interface.clone(),
            event: self.event.clone(),
            since: self.since,
        }
    }
}

/// Convert a journal record to the public API shape.
pub fn to_network_event(r: &JournalRecord) -> NetworkEvent {
    NetworkEvent {
        id: r.seq.to_string(),
        timestamp: chrono::DateTime::parse_from_rfc3339(&r.event.ts)
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        event_type: r.event.event.clone(),
        interface: r.event.link.clone(),
        details: serde_json::to_value(r).unwrap_or_default(),
    }
}

/// GET /api/v1/events
pub async fn list_events(
    Extension(log): Extension<Arc<EventLog>>,
    Query(q): Query<EventQuery>,
) -> Json<ApiResponse<Vec<NetworkEvent>>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let events = log
        .recent(limit, &q.filter())
        .iter()
        .map(|r| to_network_event(r))
        .collect();
    Json(ApiResponse::success(events))
}

/// GET /api/v1/events/stream (Server-Sent Events, one `NetworkEvent` per message)
pub async fn stream_events(
    Extension(log): Extension<Arc<EventLog>>,
    Query(q): Query<EventQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let filter = q.filter();
    let rx = log.subscribe();
    let stream = futures::stream::unfold((rx, filter), |(mut rx, filter)| async move {
        loop {
            match rx.recv().await {
                Ok(rec) if filter.matches(&rec) => {
                    let ev = Event::default()
                        .id(rec.seq.to_string())
                        .event("netevd")
                        .json_data(to_network_event(&rec))
                        .unwrap_or_else(|_| Event::default().comment("encode error"));
                    return Some((Ok(ev), (rx, filter)));
                }
                Ok(_) => continue,
                // Slow consumer: skip what was dropped and keep going.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// POST /api/v1/reload
pub async fn reload_config(
    State(_state): State<AppState>,
    Json(_payload): Json<ReloadRequest>,
) -> Json<ReloadResponse> {
    // TODO: Implement config reload
    Json(ReloadResponse {
        success: false,
        message: "Configuration reload not yet implemented".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

/// GET /health
pub async fn health_check() -> Json<HealthStatus> {
    Json(HealthStatus {
        status: "unknown".to_string(),
        checks: HealthChecks {
            dbus: false,
            netlink: false,
            config: false,
        },
    })
}

/// GET /metrics
pub async fn metrics() -> String {
    let info_line = format!(
        "# HELP netevd_info netevd daemon information\n\
         # TYPE netevd_info gauge\n\
         netevd_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    );

    if let Some(handle) = crate::metrics::get_global_metrics() {
        format!("{}{}", info_line, handle.gather())
    } else {
        info_line
    }
}

#[cfg(test)]
mod tests {
    use crate::api::routes::create_api_routes_with_log;
    use crate::hooks::{EventLog, HookEventV1};
    use crate::network::NetworkState;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn app(log: Arc<EventLog>) -> axum::Router {
        create_api_routes_with_log(Arc::new(RwLock::new(NetworkState::new())), log)
    }

    async fn get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let r = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let st = r.status();
        let b = to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or_default())
    }

    fn log_with(n: usize) -> Arc<EventLog> {
        let log = Arc::new(EventLog::new(50));
        for i in 0..n {
            let link = if i % 2 == 0 { "eth0" } else { "eth1" };
            log.record(
                &HookEventV1::new("routable", link, 2, "netlink"),
                "dispatched",
                Duration::ZERO,
                None,
            );
        }
        log
    }

    #[tokio::test]
    async fn events_endpoint_filters_limits_and_resumes() {
        let log = log_with(6);
        let (st, v) = get(app(log.clone()), "/api/v1/events").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["data"].as_array().unwrap().len(), 6);
        let (_, v) = get(app(log.clone()), "/api/v1/events?interface=eth1").await;
        assert_eq!(v["data"].as_array().unwrap().len(), 3);
        let (_, v) = get(app(log.clone()), "/api/v1/events?limit=2").await;
        let ids: Vec<_> = v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].clone())
            .collect();
        assert_eq!(ids, ["5", "6"]);
        let (_, v) = get(app(log.clone()), "/api/v1/events?since=4").await;
        assert_eq!(v["data"].as_array().unwrap().len(), 2);
        let (_, v) = get(app(log.clone()), "/api/v1/events?event=nothing").await;
        assert!(v["data"].as_array().unwrap().is_empty());
        let (_, v) = get(app(log), "/api/v1/events?limit=0").await;
        assert_eq!(
            v["data"].as_array().unwrap().len(),
            1,
            "limit is clamped to >= 1"
        );
    }

    #[tokio::test]
    async fn bad_query_is_rejected() {
        let (st, _) = get(app(log_with(1)), "/api/v1/events?limit=abc").await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn status_uses_the_event_log() {
        let (_, v) = get(app(log_with(4)), "/api/v1/status").await;
        assert_eq!(v["data"]["events_processed"], 4);
    }

    #[tokio::test]
    async fn stream_route_is_event_stream() {
        let r = app(log_with(0))
            .oneshot(
                Request::get("/api/v1/events/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()["content-type"].to_str().unwrap(),
            "text/event-stream"
        );
    }
}
