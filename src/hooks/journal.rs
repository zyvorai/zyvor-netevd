// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Event journal: a bounded in-memory history of dispatched hook events, a
//! live broadcast for streaming, and an optional size-rotated JSONL file.
//!
//! Each journal line is a `netevd.event.v1` object plus `seq`, `outcome`,
//! `duration_ms` and `error`, so `netevd explain --from-file <journal>` can
//! replay it unchanged (extra keys are ignored by the event parser).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::event::HookEventV1;
use crate::system::execute::{ScriptResult, ScriptStatus};

pub const DEFAULT_HISTORY: usize = 1000;
pub const DEFAULT_JOURNAL_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// One dispatched (or rate-limited) event and what happened to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalRecord {
    pub seq: u64,
    #[serde(flatten)]
    pub event: HookEventV1,
    /// `dispatched`, `failed` or `rate-limited`.
    pub outcome: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Per-script results, in execution order (empty if nothing ran).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<ScriptResult>,
}

/// Query filter shared by the REST API and the CLI.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub interface: Option<String>,
    pub event: Option<String>,
    /// Only records with `seq` greater than this.
    pub since: Option<u64>,
    /// `dispatched`, `failed` or `rate-limited`.
    pub outcome: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, r: &JournalRecord) -> bool {
        self.interface.as_deref().is_none_or(|i| r.event.link == i)
            && self.event.as_deref().is_none_or(|e| r.event.event == e)
            && self.since.is_none_or(|s| r.seq > s)
            && self.outcome.as_deref().is_none_or(|o| r.outcome == o)
    }
}

struct JournalFile {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
}

impl JournalFile {
    fn open(path: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        let file = open_append(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            file,
            size,
            max_bytes,
        })
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        if self.max_bytes > 0 && self.size > 0 && self.size + line.len() as u64 + 1 > self.max_bytes
        {
            self.rotate()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.size += line.len() as u64 + 1;
        Ok(())
    }

    /// Keep exactly one previous generation (`<path>.1`).
    fn rotate(&mut self) -> std::io::Result<()> {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        std::fs::rename(&self.path, PathBuf::from(old))?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

fn open_append(path: &std::path::Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

struct Inner {
    ring: VecDeque<Arc<JournalRecord>>,
    next_seq: u64,
    file: Option<JournalFile>,
}

pub struct EventLog {
    inner: Mutex<Inner>,
    capacity: usize,
    tx: broadcast::Sender<Arc<JournalRecord>>,
    total: AtomicU64,
    started: Instant,
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (tx, _) = broadcast::channel(256);
        Self {
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(capacity.min(4096)),
                next_seq: 1,
                file: None,
            }),
            capacity,
            tx,
            total: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    /// Also append every record to `path` (mode 0600), rotating once the file
    /// would exceed `max_bytes` (0 = never rotate).
    pub fn with_journal_file(self, path: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        let jf = JournalFile::open(path, max_bytes)?;
        self.inner.lock().unwrap().file = Some(jf);
        Ok(self)
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Records ever logged since start (not just those still in the ring).
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<JournalRecord>> {
        self.tx.subscribe()
    }

    pub fn record(
        &self,
        event: &HookEventV1,
        outcome: &str,
        duration: Duration,
        error: Option<String>,
    ) -> Arc<JournalRecord> {
        self.push(event, outcome, duration, error, Vec::new())
    }

    /// Record a dispatch that ran scripts. The outcome is `failed` when any
    /// script did not succeed, with `error` naming them.
    pub fn record_run(
        &self,
        event: &HookEventV1,
        duration: Duration,
        scripts: Vec<ScriptResult>,
    ) -> Arc<JournalRecord> {
        let bad: Vec<String> = scripts
            .iter()
            .filter(|s| s.status != ScriptStatus::Ok)
            .map(ScriptResult::describe)
            .collect();
        let (outcome, error) = if bad.is_empty() {
            ("dispatched", None)
        } else {
            let msg = format!(
                "{} of {} scripts failed: {}",
                bad.len(),
                scripts.len(),
                bad.join(", ")
            );
            ("failed", Some(msg))
        };
        self.push(event, outcome, duration, error, scripts)
    }

    fn push(
        &self,
        event: &HookEventV1,
        outcome: &str,
        duration: Duration,
        error: Option<String>,
        scripts: Vec<ScriptResult>,
    ) -> Arc<JournalRecord> {
        let rec = {
            let mut g = self.inner.lock().unwrap();
            let rec = Arc::new(JournalRecord {
                seq: g.next_seq,
                event: event.clone(),
                outcome: outcome.to_string(),
                duration_ms: duration.as_millis() as u64,
                error,
                scripts,
            });
            g.next_seq += 1;
            if g.ring.len() == self.capacity {
                g.ring.pop_front();
            }
            g.ring.push_back(rec.clone());
            if let Some(f) = g.file.as_mut() {
                if let Ok(line) = serde_json::to_string(&*rec) {
                    if let Err(e) = f.write_line(&line) {
                        tracing::warn!("event journal write failed: {e}");
                    }
                }
            }
            rec
        };
        self.total.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(rec.clone());
        rec
    }

    /// Newest `limit` matching records, oldest first.
    pub fn recent(&self, limit: usize, filter: &EventFilter) -> Vec<Arc<JournalRecord>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<_> = g
            .ring
            .iter()
            .rev()
            .filter(|r| filter.matches(r))
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }
}

static GLOBAL: OnceLock<Arc<EventLog>> = OnceLock::new();

/// Install the daemon-wide log. Returns false if one was already installed.
pub fn set_global(log: Arc<EventLog>) -> bool {
    GLOBAL.set(log).is_ok()
}

/// The daemon-wide log (an empty default one if none was installed).
pub fn global() -> Arc<EventLog> {
    GLOBAL
        .get_or_init(|| Arc::new(EventLog::new(DEFAULT_HISTORY)))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, link: &str) -> HookEventV1 {
        HookEventV1::new(name, link, 2, "netlink")
    }

    #[test]
    fn ring_is_bounded_and_seq_monotonic() {
        let log = EventLog::new(3);
        for i in 0..5 {
            log.record(
                &ev("mtu", &format!("eth{i}")),
                "dispatched",
                Duration::ZERO,
                None,
            );
        }
        let all = log.recent(100, &EventFilter::default());
        assert_eq!(all.iter().map(|r| r.seq).collect::<Vec<_>>(), [3, 4, 5]);
        assert_eq!(log.total(), 5);
    }

    #[test]
    fn filters_and_limit_return_newest_oldest_first() {
        let log = EventLog::new(10);
        log.record(&ev("mtu", "eth0"), "dispatched", Duration::ZERO, None);
        log.record(&ev("routable", "eth1"), "dispatched", Duration::ZERO, None);
        log.record(
            &ev("mtu", "eth0"),
            "failed",
            Duration::ZERO,
            Some("boom".into()),
        );
        let f = EventFilter {
            interface: Some("eth0".into()),
            ..Default::default()
        };
        assert_eq!(log.recent(10, &f).len(), 2);
        assert_eq!(log.recent(1, &f)[0].seq, 3);
        let f = EventFilter {
            event: Some("routable".into()),
            ..Default::default()
        };
        assert_eq!(log.recent(10, &f)[0].event.link, "eth1");
        let f = EventFilter {
            since: Some(2),
            ..Default::default()
        };
        assert_eq!(log.recent(10, &f).len(), 1);
    }

    #[test]
    fn journal_file_lines_replay_as_events_and_rotate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.jsonl");
        let log = EventLog::new(10)
            .with_journal_file(path.clone(), 400)
            .unwrap();
        for _ in 0..6 {
            log.record(
                &ev("routable", "eth0"),
                "dispatched",
                Duration::from_millis(7),
                None,
            );
        }
        let current = std::fs::read_to_string(&path).unwrap();
        let rotated = std::fs::read_to_string(tmp.path().join("events.jsonl.1")).unwrap();
        assert!(!rotated.is_empty());
        assert!(current.len() as u64 <= 400);
        // explain --from-file must accept journal lines.
        let (events, errors) = crate::hooks::explain::load_events(&current);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!events.is_empty());
        let rec: JournalRecord = serde_json::from_str(current.lines().next().unwrap()).unwrap();
        assert_eq!(rec.outcome, "dispatched");
        assert_eq!(rec.duration_ms, 7);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn script_failures_set_outcome_and_survive_replay() {
        let log = EventLog::new(4);
        let res = |name: &str, status, exit_code| ScriptResult {
            name: name.into(),
            status,
            exit_code,
            duration_ms: 1,
        };
        let ok = log.record_run(
            &ev("mtu", "eth0"),
            Duration::ZERO,
            vec![res("01-a", ScriptStatus::Ok, Some(0))],
        );
        assert_eq!((ok.outcome.as_str(), &ok.error), ("dispatched", &None));
        let bad = log.record_run(
            &ev("mtu", "eth0"),
            Duration::ZERO,
            vec![
                res("01-a", ScriptStatus::Ok, Some(0)),
                res("02-b", ScriptStatus::Failed, Some(4)),
            ],
        );
        assert_eq!(bad.outcome, "failed");
        assert_eq!(
            bad.error.as_deref(),
            Some("1 of 2 scripts failed: 02-b (exit 4)")
        );
        let f = EventFilter {
            outcome: Some("failed".into()),
            ..Default::default()
        };
        assert_eq!(log.recent(10, &f).len(), 1);
        let line = serde_json::to_string(&*bad).unwrap();
        let back: JournalRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(&back, &*bad);
        let (events, errors) = crate::hooks::explain::load_events(&line);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn subscribers_receive_records() {
        let log = EventLog::new(4);
        let mut rx = log.subscribe();
        log.record(&ev("mtu", "eth0"), "dispatched", Duration::ZERO, None);
        assert_eq!(rx.recv().await.unwrap().event.event, "mtu");
    }
}
