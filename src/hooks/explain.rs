// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! `netevd explain`: show what the daemon would do for a synthetic or
//! recorded event, without running anything.
//!
//! The report is built from the same functions the executor uses
//! (`hook_dir`, `InterfaceSelector`, `plan_directory`, `prepare_env`), so it
//! cannot drift from real behaviour.

use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::dispatch::hook_dir;
use super::event::HookEventV1;
use super::match_iface::InterfaceSelector;
use crate::config::Config;
use crate::filters::{FilterAction, NetworkEvent};
use crate::system::execute::plan_directory;
use crate::system::sandbox::{self, Verdict};

/// Longest value printed for one variable.
const SHOW_VALUE_MAX: usize = 120;
/// Longest JSONL line `load_events` will parse.
pub const MAX_EVENT_LINE: usize = 1 << 20;
/// Most events `load_events` returns.
pub const MAX_EVENTS: usize = 10_000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScriptLine {
    pub name: String,
    /// `run` or `skip: <reason>`
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EnvLine {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Explanation {
    pub event: String,
    pub link: String,
    pub backend: String,
    pub hook_dir: Option<String>,
    pub interface_selected: bool,
    pub interface_reason: String,
    pub filter_decision: String,
    pub debounce_ms: u64,
    pub rate_limit: String,
    pub scripts: Vec<ScriptLine>,
    pub env: Vec<EnvLine>,
    pub env_rejected: Vec<EnvLine>,
    /// True when at least one script would be executed.
    pub would_run: bool,
    pub notes: Vec<String>,
}

fn shorten(v: &str) -> String {
    let flat: String = v
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if flat.chars().count() > SHOW_VALUE_MAX {
        let cut: String = flat.chars().take(SHOW_VALUE_MAX).collect();
        format!("{cut}... ({} bytes)", v.len())
    } else {
        flat
    }
}

fn interface_decision(sel: &InterfaceSelector, link: &str) -> (bool, String) {
    use super::match_iface::glob_matches;
    if let Some(p) = sel.exclude.iter().find(|p| glob_matches(p, link)) {
        return (false, format!("excluded by pattern '{p}'"));
    }
    if sel.include.is_empty() {
        return (true, "no include list; not excluded".into());
    }
    match sel.include.iter().find(|p| glob_matches(p, link)) {
        Some(p) => (true, format!("matches include pattern '{p}'")),
        None => (false, "matches no include pattern".into()),
    }
}

fn filter_decision(config: &Config, ev: &HookEventV1) -> String {
    if ev.backend == "netlink" {
        return "not applied (filters only apply to backend events, not netlink hooks)".into();
    }
    let addresses: Vec<IpAddr> = ev.addresses.iter().filter_map(|a| a.parse().ok()).collect();
    let ne = NetworkEvent {
        interface: ev.link.clone(),
        event_type: ev.event.clone(),
        backend: ev.backend.clone(),
        addresses,
        has_gateway: ev.gateway.is_some(),
        dns_servers: ev.dns.iter().filter_map(|a| a.parse().ok()).collect(),
    };
    for (i, f) in config.filters.iter().enumerate() {
        if f.matches(&ne) {
            match f.action {
                FilterAction::Execute => return format!("execute (filter #{})", i + 1),
                FilterAction::Ignore => return format!("ignore (filter #{})", i + 1),
                FilterAction::Log => continue,
            }
        }
    }
    "execute (no filter matched; default)".into()
}

/// Build the explanation. `daemon_uid` and `daemon_env` are injected so the
/// result is reproducible in tests.
pub fn explain_event(
    ev: &HookEventV1,
    config: &Config,
    config_root: &Path,
    daemon_uid: u32,
    daemon_env: &dyn Fn(&str) -> Option<String>,
) -> Explanation {
    let mut notes = Vec::new();
    let sandbox_cfg = &config.hooks.sandbox;

    let dir = hook_dir(config_root, &ev.event);
    if dir.is_none() {
        notes.push(format!(
            "'{}' is not a known hook state; the daemon rejects it and runs nothing",
            shorten(&ev.event)
        ));
    }

    let selector = InterfaceSelector::from_lists(
        config.monitoring.match_patterns.clone(),
        config.monitoring.exclude.clone(),
    )
    .with_default_excludes();
    let (selected, interface_reason) = if ev.backend == "netlink" {
        interface_decision(&selector, &ev.link)
    } else {
        (
            true,
            "interface selector only applies to netlink hooks".to_string(),
        )
    };
    if !selected {
        notes.push("netlink watchers drop this event before dispatch".into());
    }

    let filter = filter_decision(config, ev);

    let mut scripts = Vec::new();
    if let Some(d) = &dir {
        match plan_directory(d, sandbox_cfg, daemon_uid) {
            Ok(plan) => {
                for p in plan {
                    scripts.push(ScriptLine {
                        name: shorten(&p.name),
                        outcome: match p.verdict {
                            Verdict::Run => "run".into(),
                            Verdict::Skip(why) => format!("skip: {why}"),
                        },
                    });
                }
                if scripts.is_empty() {
                    notes.push(format!("{} is missing or empty", d.display()));
                }
            }
            Err(e) => notes.push(format!("cannot read {}: {e}", d.display())),
        }
    }

    let raw_env = ev.to_env();
    let prepared = sandbox::prepare_env(&raw_env, sandbox_cfg, daemon_env);
    let env = prepared
        .vars
        .iter()
        .map(|(k, v)| EnvLine {
            name: k.clone(),
            value: shorten(v),
        })
        .collect();
    let env_rejected = prepared
        .rejected
        .iter()
        .map(|(k, why)| EnvLine {
            name: shorten(k),
            value: why.clone(),
        })
        .collect();

    let rl = &config.hooks.rate_limit;
    let rate_limit = if rl.enabled() {
        format!(
            "burst {} then {}/min per (link, event)",
            rl.burst, rl.per_minute
        )
    } else {
        "off".into()
    };

    let gate_open = selected && !filter.starts_with("ignore");
    let would_run = gate_open && scripts.iter().any(|s| s.outcome == "run");

    Explanation {
        event: shorten(&ev.event),
        link: shorten(&ev.link),
        backend: shorten(&ev.backend),
        hook_dir: dir.map(|d| d.display().to_string()),
        interface_selected: selected,
        interface_reason,
        filter_decision: filter,
        debounce_ms: config.hooks.debounce_ms,
        rate_limit,
        scripts,
        env,
        env_rejected,
        would_run,
        notes,
    }
}

impl Explanation {
    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut o = String::new();
        let _ = writeln!(
            o,
            "Event     : {} on {} ({})",
            self.event, self.link, self.backend
        );
        let _ = writeln!(
            o,
            "Hook dir  : {}",
            self.hook_dir.as_deref().unwrap_or("(none: unknown state)")
        );
        let _ = writeln!(
            o,
            "Interface : {} ({})",
            if self.interface_selected {
                "selected"
            } else {
                "dropped"
            },
            self.interface_reason
        );
        let _ = writeln!(o, "Filters   : {}", self.filter_decision);
        let _ = writeln!(o, "Debounce  : {} ms", self.debounce_ms);
        let _ = writeln!(o, "Rate limit: {}", self.rate_limit);
        let _ = writeln!(o, "Scripts   :");
        if self.scripts.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for s in &self.scripts {
            let _ = writeln!(o, "  {:<32} {}", s.name, s.outcome);
        }
        let _ = writeln!(o, "Environment ({} variables):", self.env.len());
        for e in &self.env {
            let _ = writeln!(o, "  {}={}", e.name, e.value);
        }
        if !self.env_rejected.is_empty() {
            let _ = writeln!(o, "Rejected variables:");
            for e in &self.env_rejected {
                let _ = writeln!(o, "  {} ({})", e.name, e.value);
            }
        }
        for n in &self.notes {
            let _ = writeln!(o, "Note      : {n}");
        }
        let _ = writeln!(
            o,
            "Result    : {}",
            if self.would_run {
                "scripts WOULD run (nothing was executed)"
            } else {
                "no script would run"
            }
        );
        o
    }
}

/// Parse a JSON-lines file of `netevd.event.v1` events. Malformed, oversized
/// or wrong-schema lines are reported, never fatal; the result is capped.
pub fn load_events(text: &str) -> (Vec<HookEventV1>, Vec<String>) {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        if events.len() >= MAX_EVENTS {
            errors.push(format!("line {n}: stopped after {MAX_EVENTS} events"));
            break;
        }
        if line.len() > MAX_EVENT_LINE {
            errors.push(format!(
                "line {n}: longer than {MAX_EVENT_LINE} bytes, skipped"
            ));
            continue;
        }
        match serde_json::from_str::<HookEventV1>(line) {
            Ok(e) if e.schema == super::event::SCHEMA_V1 => events.push(e),
            Ok(e) => errors.push(format!(
                "line {n}: unsupported schema '{}'",
                shorten(&e.schema)
            )),
            Err(e) => errors.push(format!("line {n}: {e}")),
        }
    }
    (events, errors)
}

/// Build a synthetic event from CLI-style parts.
pub fn synthetic_event(
    event: &str,
    link: &str,
    index: u32,
    backend: &str,
    addresses: Vec<String>,
) -> HookEventV1 {
    HookEventV1::new(event, link, index, backend).with_addresses(addresses)
}

pub fn default_root() -> PathBuf {
    PathBuf::from(crate::system::paths::CONFIG_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, Config) {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("routable.d");
        std::fs::create_dir(&d).unwrap();
        for (n, m) in [("02-b.sh", 0o755), ("01-a.sh", 0o755), ("03-off", 0o644)] {
            let p = d.join(n);
            std::fs::write(&p, "#!/bin/sh\ntouch /tmp/SHOULD_NEVER_EXIST_netevd\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
        }
        (t, Config::default())
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn lists_scripts_in_order_and_never_executes() {
        let (t, cfg) = setup();
        let ev = synthetic_event("routable", "eth0", 2, "netlink", vec!["10.0.0.5".into()]);
        let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
        let names: Vec<_> = x
            .scripts
            .iter()
            .map(|s| (s.name.as_str(), s.outcome.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("01-a.sh", "run"),
                ("02-b.sh", "run"),
                ("03-off", "skip: not executable")
            ]
        );
        assert!(x.would_run);
        assert!(x.interface_selected);
        assert!(!Path::new("/tmp/SHOULD_NEVER_EXIST_netevd").exists());
        assert!(x.render_text().contains("nothing was executed"));
    }

    #[test]
    fn excluded_interface_is_dropped() {
        let (t, cfg) = setup();
        let ev = synthetic_event("routable", "docker0", 9, "netlink", vec![]);
        let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
        assert!(!x.interface_selected);
        assert!(x.interface_reason.contains("docker*"));
        assert!(!x.would_run);
    }

    #[test]
    fn unknown_and_traversal_states_run_nothing() {
        let (t, cfg) = setup();
        for bad in ["../routable", "routable/../..", "rm -rf", "", "ROUTABLE"] {
            let ev = synthetic_event(bad, "eth0", 2, "netlink", vec![]);
            let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
            assert!(x.hook_dir.is_none(), "{bad:?}");
            assert!(!x.would_run);
            assert!(x.notes.iter().any(|n| n.contains("not a known hook state")));
        }
    }

    #[test]
    fn hostile_link_and_addresses_are_reported_as_rejected() {
        let (t, cfg) = setup();
        let ev = synthetic_event(
            "routable",
            "eth0;id",
            2,
            "netlink",
            vec!["10.0.0.1; reboot".into(), "$(id)".into()],
        );
        let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
        let rej: Vec<_> = x.env_rejected.iter().map(|e| e.name.as_str()).collect();
        assert!(rej.contains(&"LINK") && rej.contains(&"ADDRESSES"));
        assert!(!x.env.iter().any(|e| e.name == "LINK"));
    }

    #[test]
    fn huge_and_control_values_are_shortened_in_output() {
        let (t, cfg) = setup();
        let long = "x".repeat(500_000);
        let mut ev = synthetic_event("routable", "eth0", 2, "netlink", vec![]);
        ev.backend = format!("evil\x1b[31m{long}");
        let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
        let text = x.render_text();
        assert!(text.len() < 4000, "{}", text.len());
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn filters_apply_to_backend_events_only() {
        let (t, _) = setup();
        let cfg: Config = serde_yaml::from_str(
            "filters:\n  - match_rule:\n      interface: eth0\n    action: ignore\n",
        )
        .unwrap();
        let be = synthetic_event("routable", "eth0", 2, "systemd-networkd", vec![]);
        let x = explain_event(&be, &cfg, t.path(), 0, &no_env);
        assert!(x.filter_decision.starts_with("ignore"));
        assert!(!x.would_run);
        let nl = synthetic_event("routable", "eth0", 2, "netlink", vec![]);
        assert!(explain_event(&nl, &cfg, t.path(), 0, &no_env).would_run);
    }

    #[test]
    fn missing_dir_is_noted() {
        let t = tempfile::tempdir().unwrap();
        let ev = synthetic_event("mtu", "eth0", 2, "netlink", vec![]);
        let x = explain_event(&ev, &Config::default(), t.path(), 0, &no_env);
        assert!(!x.would_run);
        assert!(x.notes.iter().any(|n| n.contains("missing or empty")));
    }

    #[test]
    fn explanation_serializes_to_json() {
        let (t, cfg) = setup();
        let ev = synthetic_event("routable", "eth0", 2, "netlink", vec![]);
        let x = explain_event(&ev, &cfg, t.path(), 0, &no_env);
        let j = serde_json::to_string(&x).unwrap();
        assert!(j.contains("\"would_run\":true"));
    }

    #[test]
    fn load_events_survives_garbage() {
        let good = synthetic_event("routable", "eth0", 2, "netlink", vec![])
            .to_json()
            .unwrap();
        let wrong = good.replace("netevd.event.v1", "netevd.event.v9");
        let huge = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_EVENT_LINE + 1));
        let text = format!(
            "{good}\n\nnot json\n{{\"schema\":1}}\n{wrong}\n{huge}\n\u{0}\u{0}\n[1,2]\n{good}\n"
        );
        let (events, errors) = load_events(&text);
        assert_eq!(events.len(), 2);
        assert_eq!(errors.len(), 6, "{errors:?}");
        assert!(errors[0].starts_with("line 3"));
    }

    #[test]
    fn load_events_is_capped() {
        let good = synthetic_event("mtu", "eth0", 2, "netlink", vec![])
            .to_json()
            .unwrap();
        let text = vec![good; MAX_EVENTS + 50].join("\n");
        let (events, errors) = load_events(&text);
        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(errors.len(), 1);
    }
}
