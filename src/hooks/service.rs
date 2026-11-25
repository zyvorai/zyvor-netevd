// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Connects watchers to [`dispatch_event`]: a channel to push raw events
//! into, and a background task that debounces and dispatches them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::debounce::HookDebouncer;
use super::dispatch::{dispatch_event, HookDispatchOpts};
use super::event::HookEventV1;
use super::journal::EventLog;
use super::ratelimit::{RateLimitConfig, RateLimiter};
use crate::metrics::MetricsHandle;

/// Spawn the hook dispatch service. Returns a sender watchers can clone and
/// push events into, plus the background task's join handle.
pub fn spawn(
    opts: HookDispatchOpts,
    debounce: Duration,
    metrics: Option<MetricsHandle>,
    rate_limit: RateLimitConfig,
    max_pending: usize,
) -> (UnboundedSender<HookEventV1>, JoinHandle<()>) {
    spawn_with_log(opts, debounce, metrics, rate_limit, max_pending, None)
}

/// Like [`spawn`], additionally recording every dispatch in `log`.
pub fn spawn_with_log(
    opts: HookDispatchOpts,
    debounce: Duration,
    metrics: Option<MetricsHandle>,
    rate_limit: RateLimitConfig,
    max_pending: usize,
    log: Option<Arc<EventLog>>,
) -> (UnboundedSender<HookEventV1>, JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(run(
        rx,
        opts,
        debounce,
        metrics,
        rate_limit,
        max_pending,
        log,
    ));
    (tx, handle)
}

async fn run(
    mut rx: UnboundedReceiver<HookEventV1>,
    opts: HookDispatchOpts,
    debounce: Duration,
    metrics: Option<MetricsHandle>,
    rate_limit: RateLimitConfig,
    max_pending: usize,
    log: Option<Arc<EventLog>>,
) {
    let log = &log;
    let mut debouncer = HookDebouncer::new(debounce).with_max_pending(max_pending);
    let mut limiter = RateLimiter::new(rate_limit);
    let mut last_coalesced: u64 = 0;
    let flush_every = if debounce.is_zero() {
        Duration::from_millis(50)
    } else {
        (debounce / 2).max(Duration::from_millis(1))
    };
    let mut ticker = tokio::time::interval(flush_every);

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(event) => {
                        if let Some(displaced) = debouncer.push(event) {
                            dispatch(&displaced, &opts, &metrics, &mut limiter, log).await;
                        }
                        report_coalesced(&debouncer, &metrics, &mut last_coalesced);
                    }
                    None => {
                        // All senders dropped (shutdown): flush what remains.
                        for event in debouncer.take_all() {
                            dispatch(&event, &opts, &metrics, &mut limiter, log).await;
                        }
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                for event in debouncer.take_ready() {
                    dispatch(&event, &opts, &metrics, &mut limiter, log).await;
                }
            }
        }
    }
}

async fn dispatch(
    event: &HookEventV1,
    opts: &HookDispatchOpts,
    metrics: &Option<MetricsHandle>,
    limiter: &mut RateLimiter,
    log: &Option<Arc<EventLog>>,
) {
    let key = format!("{}:{}", event.link, event.event);
    if !limiter.allow(&key, std::time::Instant::now()) {
        warn!(event = %event.event, link = %event.link, "hook dispatch rate-limited");
        if let Some(ref m) = metrics {
            m.hooks_rate_limited_total.inc();
        }
        if let Some(l) = log {
            l.record(event, "rate-limited", Duration::ZERO, None);
        }
        return;
    }
    if let Some(ref m) = metrics {
        m.hooks_dispatched_total
            .with_label_values(&[event.event.as_str(), event.link.as_str()])
            .inc();
    }
    let started = Instant::now();
    let result = dispatch_event(event, opts).await;
    let took = started.elapsed();
    match &result {
        Err(e) => warn!(event = %event.event, link = %event.link, "hook dispatch failed: {}", e),
        Ok(_) => debug!(event = %event.event, link = %event.link, "hook dispatched"),
    }
    if let Some(l) = log {
        match result {
            Ok(runs) => l.record_run(event, took, runs.into_iter().map(|r| r.result).collect()),
            Err(e) => l.record(event, "failed", took, Some(e.to_string())),
        };
    }
}

/// `HookDebouncer::coalesced_total` is cumulative, so report only the delta
/// since the last check.
fn report_coalesced(debouncer: &HookDebouncer, metrics: &Option<MetricsHandle>, last: &mut u64) {
    let total = debouncer.coalesced_total();
    if total > *last {
        if let Some(ref m) = metrics {
            m.hooks_coalesced_total.inc_by((total - *last) as f64);
        }
        *last = total;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn dispatches_are_journaled_with_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("routable.d");
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("01-ok.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let log = Arc::new(EventLog::new(10));
        let opts = HookDispatchOpts {
            config_root: tmp.path().to_path_buf(),
            timeout: Duration::from_secs(5),
        };
        let (tx, handle) = spawn_with_log(
            opts,
            Duration::ZERO,
            None,
            RateLimitConfig::default(),
            16,
            Some(log.clone()),
        );
        tx.send(HookEventV1::new("routable", "eth0", 2, "netlink"))
            .unwrap();
        // Unknown state is rejected without an error, still journaled.
        tx.send(HookEventV1::new("bogus", "eth0", 2, "netlink"))
            .unwrap();
        drop(tx);
        handle.await.unwrap();

        let recs = log.recent(10, &Default::default());
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.outcome == "dispatched"));
        assert!(recs.iter().any(|r| r.event.event == "routable"));
        assert_eq!(log.total(), 2);
    }

    #[tokio::test]
    async fn failing_script_is_journaled_as_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("routable.d");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, code) in [("01-ok.sh", 0), ("02-bad.sh", 7)] {
            let script = dir.join(name);
            std::fs::write(&script, format!("#!/bin/sh\nexit {code}\n")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let log = Arc::new(EventLog::new(10));
        let opts = HookDispatchOpts {
            config_root: tmp.path().to_path_buf(),
            timeout: Duration::from_secs(5),
        };
        let (tx, handle) = spawn_with_log(
            opts,
            Duration::ZERO,
            None,
            RateLimitConfig::default(),
            16,
            Some(log.clone()),
        );
        tx.send(HookEventV1::new("routable", "eth0", 2, "netlink"))
            .unwrap();
        drop(tx);
        handle.await.unwrap();
        let recs = log.recent(10, &Default::default());
        assert_eq!(recs[0].outcome, "failed");
        assert_eq!(recs[0].scripts.len(), 2);
        assert_eq!(
            recs[0].error.as_deref(),
            Some("1 of 2 scripts failed: 02-bad.sh (exit 7)")
        );
    }

    #[tokio::test]
    async fn rate_limited_events_are_journaled() {
        let tmp = tempfile::tempdir().unwrap();
        let log = Arc::new(EventLog::new(10));
        let opts = HookDispatchOpts {
            config_root: tmp.path().to_path_buf(),
            timeout: Duration::from_secs(5),
        };
        let rl = RateLimitConfig {
            burst: 1,
            per_minute: 1,
            ..Default::default()
        };
        let (tx, handle) = spawn_with_log(opts, Duration::ZERO, None, rl, 16, Some(log.clone()));
        for _ in 0..3 {
            tx.send(HookEventV1::new("mtu", "eth0", 2, "netlink"))
                .unwrap();
        }
        drop(tx);
        handle.await.unwrap();
        let outcomes: Vec<String> = log
            .recent(10, &Default::default())
            .iter()
            .map(|r| r.outcome.clone())
            .collect();
        assert!(outcomes.contains(&"dispatched".to_string()), "{outcomes:?}");
        assert!(
            outcomes.contains(&"rate-limited".to_string()),
            "{outcomes:?}"
        );
    }
}
