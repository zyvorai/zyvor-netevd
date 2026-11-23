// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Per-key token-bucket rate limit for hook dispatch.
//!
//! The debouncer merges bursts inside one window; a flapping link still
//! produces one dispatch per window, forever. The limiter caps the long-run
//! rate per `(link, event)` key so a flapping NIC or a hostile DHCP/RA
//! source cannot turn into an unbounded stream of script runs.
//!
//! Time is passed in, so tests need no sleeping.

use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RateLimitConfig {
    /// Dispatches allowed in a burst per key. 0 disables the limiter.
    #[serde(default)]
    pub burst: u32,
    /// Sustained refill rate, dispatches per minute per key.
    #[serde(default = "default_per_minute")]
    pub per_minute: u32,
    /// Maximum distinct keys tracked; the least recently used is evicted.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
}

fn default_per_minute() -> u32 {
    30
}
fn default_max_keys() -> usize {
    2048
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 0,
            per_minute: default_per_minute(),
            max_keys: default_max_keys(),
        }
    }
}

impl RateLimitConfig {
    pub fn enabled(&self) -> bool {
        self.burst > 0
    }

    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.burst > 0 && self.per_minute == 0 {
            out.push(
                "hooks.rate_limit.per_minute is 0: after the burst, events for a key are never dispatched again"
                    .to_string(),
            );
        }
        if self.max_keys == 0 {
            out.push("hooks.rate_limit.max_keys must be at least 1".to_string());
        }
        out
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: HashMap<String, Bucket>,
    limited_total: u64,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            buckets: HashMap::new(),
            limited_total: 0,
        }
    }

    /// True if one dispatch for `key` is allowed now (and consumes a token).
    pub fn allow(&mut self, key: &str, now: Instant) -> bool {
        if !self.cfg.enabled() {
            return true;
        }
        let burst = f64::from(self.cfg.burst);
        let per_sec = f64::from(self.cfg.per_minute) / 60.0;

        if !self.buckets.contains_key(key) {
            if self.buckets.len() >= self.cfg.max_keys.max(1) {
                self.evict_lru();
            }
            self.buckets.insert(
                key.to_string(),
                Bucket {
                    tokens: burst,
                    last_refill: now,
                    last_used: now,
                },
            );
        }
        let b = self.buckets.get_mut(key).expect("just inserted");
        let elapsed = now.saturating_duration_since(b.last_refill);
        b.tokens = (b.tokens + elapsed.as_secs_f64() * per_sec).min(burst);
        b.last_refill = now;
        b.last_used = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            self.limited_total += 1;
            false
        }
    }

    fn evict_lru(&mut self) {
        if let Some(k) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last_used)
            .map(|(k, _)| k.clone())
        {
            self.buckets.remove(&k);
        }
    }

    pub fn limited_total(&self) -> u64 {
        self.limited_total
    }

    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    /// How long until `key` could be dispatched again (zero if allowed now).
    pub fn retry_after(&self, key: &str, now: Instant) -> Duration {
        let Some(b) = self.buckets.get(key) else {
            return Duration::ZERO;
        };
        let per_sec = f64::from(self.cfg.per_minute) / 60.0;
        let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
        let tokens = (b.tokens + elapsed * per_sec).min(f64::from(self.cfg.burst));
        if tokens >= 1.0 || per_sec <= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64((1.0 - tokens) / per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(burst: u32, per_minute: u32, max_keys: usize) -> RateLimitConfig {
        RateLimitConfig {
            burst,
            per_minute,
            max_keys,
        }
    }

    #[test]
    fn disabled_allows_everything() {
        let mut rl = RateLimiter::new(RateLimitConfig::default());
        let t = Instant::now();
        for _ in 0..10_000 {
            assert!(rl.allow("eth0:routable", t));
        }
        assert_eq!(rl.tracked_keys(), 0);
    }

    #[test]
    fn burst_then_block_then_refill() {
        let mut rl = RateLimiter::new(cfg(3, 60, 16)); // 1 token / second
        let t0 = Instant::now();
        assert!(rl.allow("k", t0));
        assert!(rl.allow("k", t0));
        assert!(rl.allow("k", t0));
        assert!(!rl.allow("k", t0));
        assert_eq!(rl.limited_total(), 1);
        assert!(rl.retry_after("k", t0) > Duration::from_millis(900));
        assert!(!rl.allow("k", t0 + Duration::from_millis(500)));
        assert!(rl.allow("k", t0 + Duration::from_millis(1500)));
        assert!(!rl.allow("k", t0 + Duration::from_millis(1500)));
    }

    #[test]
    fn keys_are_independent() {
        let mut rl = RateLimiter::new(cfg(1, 1, 16));
        let t = Instant::now();
        assert!(rl.allow("eth0:routable", t));
        assert!(!rl.allow("eth0:routable", t));
        assert!(rl.allow("eth1:routable", t));
        assert!(rl.allow("eth0:mtu", t));
    }

    #[test]
    fn refill_never_exceeds_burst() {
        let mut rl = RateLimiter::new(cfg(2, 600, 16));
        let t = Instant::now();
        assert!(rl.allow("k", t));
        let later = t + Duration::from_secs(3600);
        assert!(rl.allow("k", later));
        assert!(rl.allow("k", later));
        assert!(!rl.allow("k", later));
    }

    #[test]
    fn key_table_is_bounded_under_hostile_key_churn() {
        let mut rl = RateLimiter::new(cfg(1, 1, 64));
        let t = Instant::now();
        for i in 0..100_000u32 {
            rl.allow(&format!("veth{i}:link-added"), t + Duration::from_micros(u64::from(i)));
        }
        assert!(rl.tracked_keys() <= 64);
    }

    #[test]
    fn clock_going_backwards_is_harmless() {
        let mut rl = RateLimiter::new(cfg(1, 60, 4));
        let t = Instant::now();
        assert!(rl.allow("k", t + Duration::from_secs(10)));
        assert!(!rl.allow("k", t));
    }

    #[test]
    fn config_problems() {
        assert!(cfg(0, 0, 0).problems().len() == 1); // disabled: only max_keys
        assert_eq!(cfg(5, 0, 10).problems().len(), 1);
        assert!(cfg(5, 30, 10).problems().is_empty());
    }
}
