// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! `netevd check-config`: line-numbered configuration diagnostics.
//!
//! serde silently ignores unknown keys, so a typo such as `timout_sec`
//! would run with the default. This module finds those, validates values
//! the daemon would otherwise only trip over at runtime, and attaches a
//! source line to every finding.
//!
//! Line numbers come from a small indentation-based scanner, not a full
//! YAML parser: it understands block mappings, block lists and block
//! scalars. Keys inside flow style (`{a: 1}`) are not located, so unknown
//! keys there are not reported (values are still validated).

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use super::Config;
use crate::system::validation::validate_interface_name;

/// Refuse to scan configuration files larger than this.
pub const MAX_CONFIG_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Diagnostic {
    pub level: Level,
    pub line: Option<usize>,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Report {
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    fn push(
        &mut self,
        level: Level,
        line: Option<usize>,
        path: Option<&str>,
        msg: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic {
            level,
            line,
            path: path.map(str::to_string),
            message: msg.into(),
        });
    }

    pub fn errors(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.level == Level::Error)
            .count()
    }

    pub fn warnings(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.level == Level::Warning)
            .count()
    }

    /// `strict` turns warnings into failures.
    pub fn ok(&self, strict: bool) -> bool {
        self.errors() == 0 && (!strict || self.warnings() == 0)
    }

    pub fn render_text(&self, file: &str) -> String {
        let mut o = String::new();
        for d in &self.diagnostics {
            let lvl = match d.level {
                Level::Error => "error",
                Level::Warning => "warning",
            };
            match d.line {
                Some(l) => o.push_str(&format!("{file}:{l}: {lvl}: {}\n", d.message)),
                None => o.push_str(&format!("{file}: {lvl}: {}\n", d.message)),
            }
        }
        o.push_str(&format!(
            "{} error(s), {} warning(s)\n",
            self.errors(),
            self.warnings()
        ));
        o
    }
}

/// Known configuration key paths. Lists are written `name[]`.
const KNOWN: &[&str] = &[
    "system",
    "system.log_level",
    "system.backend",
    "monitoring",
    "monitoring.interfaces",
    "monitoring.match_patterns",
    "monitoring.exclude",
    "routing",
    "routing.policy_rules",
    "backends",
    "backends.systemd_networkd",
    "backends.systemd_networkd.emit_json",
    "backends.dhclient",
    "backends.dhclient.use_dns",
    "backends.dhclient.use_domain",
    "backends.dhclient.use_hostname",
    "backends.networkmanager",
    "api",
    "api.enabled",
    "api.bind_address",
    "api.port",
    "api.tls",
    "api.tls.enabled",
    "api.tls.cert_file",
    "api.tls.key_file",
    "api.auth",
    "api.auth.token_file",
    "api.auth.public_metrics",
    "metrics",
    "metrics.enabled",
    "metrics.port",
    "audit",
    "audit.enabled",
    "audit.path",
    "audit.retention_days",
    "filters",
    "hooks",
    "hooks.debounce_ms",
    "hooks.timeout_sec",
    "hooks.max_parallel",
    "hooks.max_pending",
    "hooks.history_size",
    "hooks.journal_path",
    "hooks.journal_max_bytes",
    "hooks.startup_triggers",
    "hooks.sandbox",
    "hooks.sandbox.workdir",
    "hooks.sandbox.pass_env",
    "hooks.sandbox.max_env_bytes",
    "hooks.sandbox.max_output_bytes",
    "hooks.sandbox.umask",
    "hooks.sandbox.strict_script_perms",
    "hooks.sandbox.rlimit_nofile",
    "hooks.sandbox.rlimit_cpu_sec",
    "hooks.sandbox.rlimit_as_mb",
    "hooks.sandbox.rlimit_fsize_mb",
    "hooks.sandbox.no_core_dumps",
    "hooks.rate_limit",
    "hooks.rate_limit.burst",
    "hooks.rate_limit.per_minute",
    "hooks.rate_limit.max_keys",
    "ebpf",
    "ebpf.enabled",
    "ebpf.drops",
    "ebpf.tcp_retransmit",
    "ebpf.tcp_reset",
    "ebpf.debounce_ms",
    "ebpf.min_count",
    "ebpf.object_path",
    "ebpf.skip_unknown_ifindex",
    "ebpf.reasons_allow",
    "ebpf.reasons_deny",
];

/// Subtrees whose inner keys are not checked here.
const OPAQUE: &[&str] = &["filters", "backends.networkmanager"];

/// `(path, 1-based line)` for every mapping key found in block style.
pub fn scan_keys(text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    // (indent of the key / dash, path component)
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut block_scalar_indent: Option<usize> = None;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let trimmed_end = raw.trim_end();
        let indent = trimmed_end.len() - trimmed_end.trim_start_matches(' ').len();
        let body = strip_comment(trimmed_end.trim_start_matches(' '));
        let body = body.trim_end();
        if body.is_empty() {
            continue;
        }
        if let Some(bi) = block_scalar_indent {
            if indent > bi {
                continue;
            }
            block_scalar_indent = None;
        }
        if body == "---" || body == "..." {
            stack.clear();
            continue;
        }

        let mut ind = indent;
        let mut content = body;
        let mut is_item = false;
        while let Some(rest) =
            content
                .strip_prefix("- ")
                .or(if content == "-" { Some("") } else { None })
        {
            if !is_item {
                while stack.last().is_some_and(|(si, _)| *si >= ind) {
                    stack.pop();
                }
                stack.push((ind, "[]".to_string()));
                is_item = true;
            }
            let trimmed = rest.trim_start_matches(' ');
            ind += 2 + (rest.len() - trimmed.len());
            content = trimmed;
            if content.is_empty() {
                break;
            }
        }
        if content.is_empty() {
            continue;
        }
        let Some((key, value)) = split_key(content) else {
            continue;
        };
        while stack.last().is_some_and(|(si, _)| *si >= ind) {
            stack.pop();
        }
        let mut path = String::new();
        for name in stack
            .iter()
            .map(|(_, n)| n.as_str())
            .chain(std::iter::once(key.as_str()))
        {
            if name == "[]" {
                path.push_str("[]");
            } else {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(name);
            }
        }
        out.push((path, line_no));
        let v = value.trim();
        if v.starts_with('|') || v.starts_with('>') {
            block_scalar_indent = Some(ind);
        }
        stack.push((ind, key));
    }
    out
}

fn strip_comment(s: &str) -> &str {
    let mut in_s = false;
    let mut in_d = false;
    let mut prev_ws = true;
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            '#' if !in_s && !in_d && prev_ws => return &s[..i],
            _ => {}
        }
        prev_ws = c.is_whitespace();
    }
    s
}

/// Split `key: value`. Returns None for scalars and flow collections.
fn split_key(content: &str) -> Option<(String, String)> {
    if content.starts_with('{') || content.starts_with('[') {
        return None;
    }
    let (key_part, rest) = if let Some(q) = content.strip_prefix('"') {
        let end = q.find('"')?;
        (&q[..end], q[end + 1..].strip_prefix(':')?)
    } else if let Some(q) = content.strip_prefix('\'') {
        let end = q.find('\'')?;
        (&q[..end], q[end + 1..].strip_prefix(':')?)
    } else {
        let mut idx = None;
        let bytes = content.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ') {
                idx = Some(i);
                break;
            }
        }
        let i = idx?;
        (&content[..i], &content[i + 1..])
    };
    if key_part.is_empty() {
        return None;
    }
    Some((key_part.to_string(), rest.to_string()))
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur.push((prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn suggest(path: &str) -> Option<String> {
    let (parent, key) = match path.rfind('.') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    };
    KNOWN
        .iter()
        .filter(|k| {
            let kp = match k.rfind('.') {
                Some(i) => &k[..i],
                None => "",
            };
            kp == parent
        })
        .map(|k| (levenshtein(key, k.rsplit('.').next().unwrap_or(k)), *k))
        .filter(|(d, _)| *d <= 3)
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k.rsplit('.').next().unwrap_or(k).to_string())
}

struct Lines(HashMap<String, usize>);

impl Lines {
    fn get(&self, path: &str) -> Option<usize> {
        self.0.get(path).copied()
    }
}

fn pattern_problem(p: &str) -> Option<String> {
    if p.is_empty() {
        return Some("empty pattern".into());
    }
    if p.len() > 64 {
        return Some(format!(
            "pattern '{}...' is longer than 64 characters",
            &p[..16]
        ));
    }
    if p.contains('?') || p.contains('[') {
        return Some(format!(
            "pattern '{p}': only '*' is supported as a wildcard"
        ));
    }
    if !p
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*'))
    {
        return Some(format!(
            "pattern '{p}' contains characters that cannot occur in an interface name"
        ));
    }
    None
}

/// Check YAML text. Pure: no filesystem access.
pub fn check_yaml(text: &str) -> Report {
    let mut r = Report::default();
    if text.len() > MAX_CONFIG_BYTES {
        r.push(
            Level::Error,
            None,
            None,
            format!("configuration larger than {MAX_CONFIG_BYTES} bytes"),
        );
        return r;
    }
    if text.contains('\0') {
        r.push(
            Level::Error,
            None,
            None,
            "configuration contains a NUL byte",
        );
        return r;
    }

    let cfg: Config = match serde_yaml::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            let line = e.location().map(|l| l.line());
            r.push(Level::Error, line, None, e.to_string());
            return r;
        }
    };

    let keys = scan_keys(text);
    let mut lines = Lines(HashMap::new());
    for (p, l) in &keys {
        lines.0.entry(p.clone()).or_insert(*l);
    }

    // Unknown keys (and duplicates, which serde_yaml already rejects, so only
    // the former is needed).
    for (path, line) in &keys {
        if OPAQUE.iter().any(|o| {
            path == o || path.starts_with(&format!("{o}.")) || path.starts_with(&format!("{o}[]"))
        }) {
            continue;
        }
        if !KNOWN.contains(&path.as_str()) {
            let hint = suggest(path)
                .map(|s| format!(" (did you mean '{s}'?)"))
                .unwrap_or_default();
            r.push(
                Level::Warning,
                Some(*line),
                Some(path),
                format!("unknown key '{path}' is ignored by netevd{hint}"),
            );
        }
    }

    let at = |p: &str| lines.get(p);

    // system
    match cfg.system.backend.as_str() {
        "systemd-networkd" | "NetworkManager" | "dhclient" => {}
        other => r.push(
            Level::Error,
            at("system.backend"),
            Some("system.backend"),
            format!("invalid backend '{other}'; use systemd-networkd, NetworkManager or dhclient"),
        ),
    }
    if !matches!(
        cfg.system.log_level.to_ascii_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        r.push(
            Level::Warning,
            at("system.log_level"),
            Some("system.log_level"),
            format!(
                "log_level '{}' is not one of trace, debug, info, warn, error",
                cfg.system.log_level
            ),
        );
    }

    // monitoring / routing
    for name in &cfg.monitoring.interfaces {
        if !validate_interface_name(name) {
            r.push(
                Level::Error,
                at("monitoring.interfaces"),
                Some("monitoring.interfaces"),
                format!("'{name}' is not a valid interface name"),
            );
        }
    }
    for (key, list) in [
        ("monitoring.match_patterns", &cfg.monitoring.match_patterns),
        ("monitoring.exclude", &cfg.monitoring.exclude),
    ] {
        for p in list {
            if let Some(msg) = pattern_problem(p) {
                r.push(Level::Error, at(key), Some(key), msg);
            }
        }
    }
    for name in &cfg.routing.policy_rules {
        if !validate_interface_name(name) {
            r.push(
                Level::Error,
                at("routing.policy_rules"),
                Some("routing.policy_rules"),
                format!("'{name}' is not a valid interface name"),
            );
        } else if !cfg.monitoring.interfaces.is_empty() && !cfg.monitoring.interfaces.contains(name)
        {
            r.push(
                Level::Warning,
                at("routing.policy_rules"),
                Some("routing.policy_rules"),
                format!("policy rule interface '{name}' is not listed in monitoring.interfaces"),
            );
        }
    }

    // api / metrics
    match cfg.api.bind_address.parse::<IpAddr>() {
        Err(_) => r.push(
            Level::Error,
            at("api.bind_address"),
            Some("api.bind_address"),
            format!(
                "bind_address '{}' is not an IP address",
                cfg.api.bind_address
            ),
        ),
        Ok(ip) if cfg.api.enabled && !ip.is_loopback() => {
            if !cfg.api.tls.enabled {
                r.push(
                    Level::Warning,
                    at("api.bind_address"),
                    Some("api.bind_address"),
                    format!("API listens on non-loopback {ip} without TLS"),
                );
            }
            if cfg.api.auth.token_file.is_none() {
                r.push(
                    Level::Warning,
                    at("api.bind_address"),
                    Some("api.bind_address"),
                    format!(
                        "API listens on non-loopback {ip} without authentication (set api.auth.token_file)"
                    ),
                );
            }
        }
        Ok(_) => {}
    }
    match cfg.api.auth.token_file.as_deref() {
        Some("") => r.push(
            Level::Error,
            at("api.auth.token_file"),
            Some("api.auth.token_file"),
            "api.auth.token_file is empty; the API will not start",
        ),
        Some(p) if !p.starts_with('/') => r.push(
            Level::Warning,
            at("api.auth.token_file"),
            Some("api.auth.token_file"),
            format!("api.auth.token_file '{p}' is not an absolute path"),
        ),
        None if cfg.api.auth.public_metrics => r.push(
            Level::Warning,
            at("api.auth.public_metrics"),
            Some("api.auth.public_metrics"),
            "public_metrics has no effect without api.auth.token_file",
        ),
        _ => {}
    }
    if cfg.api.port == 0 {
        r.push(
            Level::Error,
            at("api.port"),
            Some("api.port"),
            "port 0 is not a usable port",
        );
    }
    if cfg.metrics.port == 0 {
        r.push(
            Level::Error,
            at("metrics.port"),
            Some("metrics.port"),
            "port 0 is not a usable port",
        );
    }
    if cfg.api.enabled && cfg.metrics.enabled && cfg.api.port == cfg.metrics.port {
        r.push(
            Level::Warning,
            at("metrics.port"),
            Some("metrics.port"),
            "metrics.port equals api.port; the second listener will fail to bind",
        );
    }
    if cfg.api.tls.enabled {
        for (key, v) in [
            ("api.tls.cert_file", &cfg.api.tls.cert_file),
            ("api.tls.key_file", &cfg.api.tls.key_file),
        ] {
            match v.as_deref() {
                None | Some("") => r.push(
                    Level::Error,
                    at("api.tls.enabled"),
                    Some(key),
                    format!("tls is enabled but {key} is empty"),
                ),
                Some(p) if !p.starts_with('/') => r.push(
                    Level::Warning,
                    at(key),
                    Some(key),
                    format!("{key} '{p}' is not an absolute path"),
                ),
                _ => {}
            }
        }
    }

    // audit
    if cfg.audit.enabled {
        if !cfg.audit.path.starts_with('/') {
            r.push(
                Level::Error,
                at("audit.path"),
                Some("audit.path"),
                "audit.path must be absolute",
            );
        }
        if cfg.audit.retention_days == 0 {
            r.push(
                Level::Warning,
                at("audit.retention_days"),
                Some("audit.retention_days"),
                "retention_days 0 keeps nothing",
            );
        }
    }

    // hooks
    let h = &cfg.hooks;
    if h.timeout_sec == 0 {
        r.push(
            Level::Error,
            at("hooks.timeout_sec"),
            Some("hooks.timeout_sec"),
            "timeout_sec 0 would kill every script immediately",
        );
    } else if h.timeout_sec > 3600 {
        r.push(
            Level::Warning,
            at("hooks.timeout_sec"),
            Some("hooks.timeout_sec"),
            format!(
                "timeout_sec {} is over an hour; scripts run one at a time",
                h.timeout_sec
            ),
        );
    }
    if h.debounce_ms > 10_000 {
        r.push(
            Level::Warning,
            at("hooks.debounce_ms"),
            Some("hooks.debounce_ms"),
            format!(
                "debounce_ms {} delays every hook by that long",
                h.debounce_ms
            ),
        );
    }
    if h.max_parallel != 1 {
        r.push(
            Level::Warning,
            at("hooks.max_parallel"),
            Some("hooks.max_parallel"),
            "max_parallel is reserved; scripts always run sequentially",
        );
    }
    if h.max_pending == 0 {
        r.push(
            Level::Error,
            at("hooks.max_pending"),
            Some("hooks.max_pending"),
            "max_pending must be at least 1",
        );
    }
    if h.history_size == 0 {
        r.push(
            Level::Error,
            at("hooks.history_size"),
            Some("hooks.history_size"),
            "history_size must be at least 1",
        );
    } else if h.history_size > 100_000 {
        r.push(
            Level::Warning,
            at("hooks.history_size"),
            Some("hooks.history_size"),
            format!(
                "history_size {} keeps that many events in memory",
                h.history_size
            ),
        );
    }
    if let Some(p) = &h.journal_path {
        if !p.starts_with('/') {
            r.push(
                Level::Error,
                at("hooks.journal_path"),
                Some("hooks.journal_path"),
                "journal_path must be an absolute path",
            );
        } else if p.ends_with('/') || p.split('/').any(|c| c == "..") {
            r.push(
                Level::Error,
                at("hooks.journal_path"),
                Some("hooks.journal_path"),
                "journal_path must name a file and not contain '..'",
            );
        }
    }
    for msg in h.sandbox.problems() {
        r.push(
            Level::Error,
            at("hooks.sandbox"),
            Some("hooks.sandbox"),
            msg,
        );
    }
    for msg in h.rate_limit.problems() {
        r.push(
            Level::Error,
            at("hooks.rate_limit"),
            Some("hooks.rate_limit"),
            msg,
        );
    }
    if h.rate_limit.enabled() && u64::from(h.rate_limit.burst) < 2 {
        r.push(
            Level::Warning,
            at("hooks.rate_limit.burst"),
            Some("hooks.rate_limit.burst"),
            "burst 1 drops the second of any two quick events for a key",
        );
    }

    // ebpf
    if cfg.ebpf.enabled && !(cfg.ebpf.drops || cfg.ebpf.tcp_retransmit || cfg.ebpf.tcp_reset) {
        r.push(
            Level::Warning,
            at("ebpf.enabled"),
            Some("ebpf.enabled"),
            "ebpf.enabled is true but no source (drops, tcp_retransmit, tcp_reset) is on",
        );
    }
    if cfg.ebpf.min_count == 0 {
        r.push(
            Level::Warning,
            at("ebpf.min_count"),
            Some("ebpf.min_count"),
            "min_count 0 never coalesces",
        );
    }

    // filters
    for (n, f) in cfg.filters.iter().enumerate() {
        for s in &f.scripts {
            if s.contains('/') || s.contains("..") || s.is_empty() || s.starts_with('.') {
                r.push(
                    Level::Error,
                    at("filters"),
                    Some("filters"),
                    format!(
                        "filter #{} script name '{s}' must be a plain file name (no '/', no '..')",
                        n + 1
                    ),
                );
            }
        }
        if let Some(p) = &f.match_rule.interface_pattern {
            if let Some(msg) = pattern_problem(p) {
                r.push(
                    Level::Error,
                    at("filters"),
                    Some("filters"),
                    format!("filter #{}: {msg}", n + 1),
                );
            }
        }
    }

    r.diagnostics
        .sort_by_key(|d| (d.line.unwrap_or(usize::MAX), d.level == Level::Warning));
    r
}

/// Check a file: the YAML plus file-level hygiene.
pub fn check_file(path: &Path) -> Report {
    use std::os::unix::fs::MetadataExt;
    let mut r = Report::default();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            r.push(
                Level::Error,
                None,
                None,
                format!("cannot read {}: {e}", path.display()),
            );
            return r;
        }
    };
    if !meta.is_file() {
        r.push(
            Level::Error,
            None,
            None,
            format!("{} is not a regular file", path.display()),
        );
        return r;
    }
    if meta.len() as usize > MAX_CONFIG_BYTES {
        r.push(
            Level::Error,
            None,
            None,
            format!("{} is larger than {MAX_CONFIG_BYTES} bytes", path.display()),
        );
        return r;
    }
    let text = match std::fs::read(path) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => {
                r.push(Level::Error, None, None, "configuration is not valid UTF-8");
                return r;
            }
        },
        Err(e) => {
            r.push(
                Level::Error,
                None,
                None,
                format!("cannot read {}: {e}", path.display()),
            );
            return r;
        }
    };
    let mut inner = check_yaml(&text);
    if meta.mode() & 0o002 != 0 {
        inner.push(
            Level::Warning,
            None,
            None,
            "configuration file is world-writable (SECURITY.md: chmod 640)",
        );
    }
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(r: &Report) -> Vec<String> {
        r.diagnostics
            .iter()
            .map(|d| format!("{:?}:{:?}:{}", d.level, d.line, d.message))
            .collect()
    }

    #[test]
    fn example_config_is_clean() {
        let text = include_str!("../../config/netevd.example.yaml");
        let r = check_yaml(text);
        assert_eq!(r.errors(), 0, "{:#?}", msgs(&r));
        let unknown: Vec<_> = r
            .diagnostics
            .iter()
            .filter(|d| d.message.contains("unknown key"))
            .collect();
        assert!(unknown.is_empty(), "{unknown:#?}");
    }

    #[test]
    fn default_empty_config_is_valid() {
        assert!(check_yaml("").ok(true));
        assert!(check_yaml("# nothing\n").ok(true));
    }

    #[test]
    fn typo_gets_line_number_and_suggestion() {
        let r =
            check_yaml("system:\n  backend: dhclient\nhooks:\n  debounce_ms: 5\n  timout_sec: 5\n");
        let d = &r.diagnostics[0];
        assert_eq!(d.line, Some(5));
        assert!(
            d.message.contains("did you mean 'timeout_sec'"),
            "{}",
            d.message
        );
        assert_eq!(r.errors(), 0);
        assert!(!r.ok(true));
        assert!(r.ok(false));
    }

    #[test]
    fn journal_settings_are_validated() {
        let r = check_yaml("hooks:\n  journal_path: events.jsonl\n  history_size: 0\n");
        assert_eq!(r.errors(), 2);
        let r = check_yaml(
            "hooks:\n  journal_path: /var/log/netevd/events.jsonl\n  history_size: 50\n  startup_triggers: true\n",
        );
        assert!(r.ok(true), "{:?}", r.diagnostics);
    }

    #[test]
    fn api_auth_settings_are_validated() {
        let r = check_yaml(
            "api:\n  bind_address: 0.0.0.0\n  tls:\n    enabled: true\n    cert_file: /c\n    key_file: /k\n  auth:\n    token_file: /etc/netevd/api.token\n    public_metrics: true\n",
        );
        assert_eq!((r.errors(), r.warnings()), (0, 0), "{}", r.render_text("f"));
        let r = check_yaml("api:\n  bind_address: 0.0.0.0\n");
        assert_eq!(r.warnings(), 2, "{}", r.render_text("f"));
        assert_eq!(
            check_yaml("api:\n  auth:\n    token_file: \"\"\n").errors(),
            1
        );
        assert_eq!(
            check_yaml("api:\n  auth:\n    token_file: rel\n").warnings(),
            1
        );
        assert_eq!(
            check_yaml("api:\n  auth:\n    public_metrics: true\n").warnings(),
            1
        );
        let r = check_yaml("api:\n  auth:\n    token_fil: /t\n");
        assert!(
            r.render_text("f").contains("token_file"),
            "{}",
            r.render_text("f")
        );
    }

    #[test]
    fn shipped_kubernetes_config_has_no_unknown_keys() {
        let map = include_str!("../../kubernetes/configmap.yaml");
        let mut checked = 0;
        for doc in serde_yaml::Deserializer::from_str(map) {
            let doc = <serde_yaml::Value as serde::Deserialize>::deserialize(doc).unwrap();
            if let Some(text) = doc["data"]["netevd.yaml"].as_str() {
                let r = check_yaml(text);
                assert_eq!((r.errors(), r.warnings()), (0, 0), "{}", r.render_text("f"));
                checked += 1;
            }
        }
        assert_eq!(checked, 1);
    }

    #[test]
    fn syntax_error_has_line() {
        let r = check_yaml("system:\n  backend: [unclosed\n");
        assert_eq!(r.errors(), 1);
        assert!(r.diagnostics[0].line.is_some());
        let r = check_yaml("hooks:\n  timeout_sec: not-a-number\n");
        assert_eq!(r.diagnostics[0].line, Some(2));
    }

    #[test]
    fn semantic_errors_point_at_their_key() {
        let r = check_yaml("system:\n  backend: bogus\nhooks:\n  timeout_sec: 0\n");
        let m = msgs(&r);
        assert!(
            m.iter()
                .any(|s| s.starts_with("Error:Some(2):") && s.contains("invalid backend")),
            "{m:?}"
        );
        assert!(m.iter().any(|s| s.starts_with("Error:Some(4):")), "{m:?}");
    }

    #[test]
    fn hostile_names_and_patterns_rejected() {
        let r = check_yaml("monitoring:\n  interfaces: [\"eth0;reboot\"]\n  match_patterns: [\"$(id)\", \"\", \"a?\"]\nrouting:\n  policy_rules: [\"../x\"]\n");
        assert!(r.errors() >= 5, "{:#?}", msgs(&r));
    }

    #[test]
    fn filter_script_path_traversal_rejected() {
        let y = "filters:\n  - match_rule:\n      interface: eth0\n    action: execute\n    scripts: [\"../../bin/sh\", \"/bin/sh\", \"ok.sh\", \".hidden\"]\n";
        let r = check_yaml(y);
        assert_eq!(r.errors(), 3, "{:#?}", msgs(&r));
    }

    #[test]
    fn sandbox_and_rate_limit_validated() {
        let y = "hooks:\n  sandbox:\n    workdir: relative\n    umask: 9999\n  rate_limit:\n    burst: 5\n    per_minute: 0\n";
        let r = check_yaml(y);
        assert!(r.errors() >= 3, "{:#?}", msgs(&r));
        assert!(r
            .diagnostics
            .iter()
            .any(|d| d.line == Some(2) || d.line == Some(5)));
    }

    #[test]
    fn nested_unknown_key_and_lists() {
        let y =
            "hooks:\n  sandbox:\n    wokdir: /\nmonitoring:\n  exclude:\n    - lo\n  bogus: 1\n";
        let r = check_yaml(y);
        let lines: Vec<_> = r.diagnostics.iter().filter_map(|d| d.line).collect();
        assert_eq!(lines, [3, 7]);
        assert!(r.diagnostics[0].message.contains("did you mean 'workdir'"));
    }

    #[test]
    fn scanner_handles_comments_block_scalars_and_quotes() {
        let y = "# top\nsystem:   # c\n  backend: \"dhclient\"   # c: x\n  \"log_level\": info\nfilters:\n  - match_rule:\n      interface: eth0\n    action: ignore\n    note: |\n      fake_key: not a key\n";
        let keys = scan_keys(y);
        let paths: Vec<_> = keys.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            [
                "system",
                "system.backend",
                "system.log_level",
                "filters",
                "filters[].match_rule",
                "filters[].match_rule.interface",
                "filters[].action",
                "filters[].note"
            ]
        );
    }

    #[test]
    fn oversized_and_nul_input() {
        assert_eq!(check_yaml(&"a".repeat(MAX_CONFIG_BYTES + 1)).errors(), 1);
        assert_eq!(check_yaml("system:\n  backend: \0\n").errors(), 1);
    }

    #[test]
    fn deep_nesting_and_anchors_do_not_hang() {
        let mut y = String::new();
        for i in 0..2000 {
            y.push_str(&" ".repeat(i % 60));
            y.push_str(&format!("k{i}:\n"));
        }
        let _ = check_yaml(&y);
        let _ = check_yaml("a: &x [*x]\n");
    }

    #[test]
    fn api_exposure_warning() {
        let r = check_yaml("api:\n  bind_address: 0.0.0.0\n");
        assert!(msgs(&r).iter().any(|s| s.contains("non-loopback")));
        assert_eq!(check_yaml("api:\n  bind_address: not-an-ip\n").errors(), 1);
    }

    #[test]
    fn file_checks() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("c.yaml");
        assert_eq!(check_file(&p).errors(), 1);
        std::fs::write(&p, "system:\n  backend: dhclient\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        let r = check_file(&p);
        assert_eq!(r.errors(), 0);
        assert_eq!(r.warnings(), 1);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check_file(&p).ok(true));
        std::fs::write(&p, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(check_file(&p).errors(), 1);
        assert_eq!(check_file(t.path()).errors(), 1);
    }
}
