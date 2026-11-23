// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Connects watchers to [`dispatch_event`]: a channel to push raw events
//! into, and a background task that debounces and dispatches them.

use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::debounce::HookDebouncer;
use super::dispatch::{dispatch_event, HookDispatchOpts};
use super::event::HookEventV1;
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
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(run(rx, opts, debounce, metrics, rate_limit, max_pending));
    (tx, handle)
}

async fn run(
    mut rx: UnboundedReceiver<HookEventV1>,
    opts: HookDispatchOpts,
    debounce: Duration,
    metrics: Option<MetricsHandle>,
    rate_limit: RateLimitConfig,
    max_pending: usize,
) {
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
                            dispatch(&displaced, &opts, &metrics, &mut limiter).await;
                        }
                        report_coalesced(&debouncer, &metrics, &mut last_coalesced);
                    }
                    None => {
                        // All senders dropped (shutdown): flush what remains.
                        for event in debouncer.take_all() {
                            dispatch(&event, &opts, &metrics, &mut limiter).await;
                        }
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                for event in debouncer.take_ready() {
                    dispatch(&event, &opts, &metrics, &mut limiter).await;
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
) {
    let key = format!("{}:{}", event.link, event.event);
    if !limiter.allow(&key, std::time::Instant::now()) {
        warn!(event = %event.event, link = %event.link, "hook dispatch rate-limited");
        if let Some(ref m) = metrics {
            m.hooks_rate_limited_total.inc();
        }
        return;
    }
    if let Some(ref m) = metrics {
        m.hooks_dispatched_total
            .with_label_values(&[event.event.as_str(), event.link.as_str()])
            .inc();
    }
    if let Err(e) = dispatch_event(event, opts).await {
        warn!(event = %event.event, link = %event.link, "hook dispatch failed: {}", e);
    } else {
        debug!(event = %event.event, link = %event.link, "hook dispatched");
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
