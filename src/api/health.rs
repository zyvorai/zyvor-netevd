// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Liveness (`/health`) and readiness (`/health/ready`).
//!
//! Both report the same live checks. `/health` answers 200 whenever the daemon
//! can answer at all; `/health/ready` answers 503 while a check fails.
//! Results are cached briefly because the endpoints need no token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::{Extension, Json};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;

use crate::api::models::{HealthChecks, HealthStatus};
use crate::hooks::HookEventV1;

const CACHE_FOR: Duration = Duration::from_secs(2);
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// What to check. The default checks netlink only.
#[derive(Default)]
pub struct HealthProbe {
    /// Configured backend, reported by `/api/v1/status`.
    pub backend: Option<String>,
    /// Require a reachable D-Bus system bus.
    pub needs_dbus: bool,
    /// The hook dispatch queue; closed means events are no longer handled.
    pub hooks: Option<UnboundedSender<HookEventV1>>,
    cache: Mutex<Option<(Instant, HealthChecks)>>,
}

impl HealthProbe {
    pub fn for_daemon(backend: &str, hooks: UnboundedSender<HookEventV1>) -> Self {
        Self {
            backend: Some(backend.to_string()),
            // dhclient is followed through its lease file.
            needs_dbus: backend != "dhclient",
            hooks: Some(hooks),
            cache: Mutex::new(None),
        }
    }

    pub async fn checks(&self) -> HealthChecks {
        let mut cache = self.cache.lock().await;
        if let Some((at, c)) = cache.as_ref() {
            if at.elapsed() < CACHE_FOR {
                return c.clone();
            }
        }
        let netlink = matches!(
            tokio::time::timeout(CHECK_TIMEOUT, crate::network::query::interfaces()).await,
            Ok(Ok(_))
        );
        let dbus = if self.needs_dbus {
            Some(matches!(
                tokio::time::timeout(CHECK_TIMEOUT, zbus::Connection::system()).await,
                Ok(Ok(_))
            ))
        } else {
            None
        };
        let hooks = self.hooks.as_ref().map(|tx| !tx.is_closed());
        let checks = HealthChecks {
            netlink,
            dbus,
            hooks,
            // The daemon does not start without a usable configuration.
            config: true,
        };
        *cache = Some((Instant::now(), checks.clone()));
        checks
    }
}

fn status_of(checks: HealthChecks) -> HealthStatus {
    HealthStatus {
        status: if checks.all_ok() { "ok" } else { "degraded" }.to_string(),
        checks,
    }
}

/// GET /health
pub async fn health_check(Extension(probe): Extension<Arc<HealthProbe>>) -> Json<HealthStatus> {
    Json(status_of(probe.checks().await))
}

/// GET /health/ready
pub async fn readiness_check(
    Extension(probe): Extension<Arc<HealthProbe>>,
) -> (StatusCode, Json<HealthStatus>) {
    let status = status_of(probe.checks().await);
    let code = if status.checks.all_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_hook_queue_makes_the_daemon_not_ready() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let probe = Arc::new(HealthProbe::for_daemon("dhclient", tx.clone()));
        let (code, Json(body)) = readiness_check(Extension(probe)).await;
        assert_eq!(code, StatusCode::OK, "{body:?}");
        assert_eq!(body.checks.dbus, None, "dhclient needs no D-Bus");
        assert_eq!(body.checks.hooks, Some(true));

        drop(rx);
        let probe = Arc::new(HealthProbe::for_daemon("dhclient", tx));
        let (code, Json(body)) = readiness_check(Extension(probe.clone())).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "degraded");
        assert_eq!(body.checks.hooks, Some(false));
        // Liveness still answers, with the same checks.
        let Json(live) = health_check(Extension(probe)).await;
        assert_eq!(live.status, "degraded");
    }

    #[tokio::test]
    async fn results_are_cached() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let probe = HealthProbe::for_daemon("dhclient", tx);
        assert_eq!(probe.checks().await.hooks, Some(true));
        drop(rx);
        assert_eq!(probe.checks().await.hooks, Some(true));
    }
}
