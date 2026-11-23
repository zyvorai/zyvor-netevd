// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Hook script sandbox profile.
//!
//! Pure, testable pieces of the script execution policy: which variables a
//! script may see, how large they may be, which script files are acceptable,
//! and which resource limits a child gets. `execute.rs` applies the profile;
//! `hooks::explain` reports it without running anything.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::system::validation;

/// Linux limits a single `KEY=value` string to 128 KiB (`MAX_ARG_STRLEN`).
pub const MAX_ENV_STRING: usize = 131_072;

/// Variables that are never taken from the daemon's own environment, even if
/// an operator lists them in `pass_env`.
const NEVER_PASS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
    "IFS",
    "PATH",
];

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SandboxConfig {
    /// Working directory for scripts. Must be absolute.
    #[serde(default = "default_workdir")]
    pub workdir: String,

    /// Variables copied from the daemon environment into the (otherwise
    /// empty) script environment.
    #[serde(default = "default_pass_env")]
    pub pass_env: Vec<String>,

    /// Cap on the total size of the script environment (bytes).
    #[serde(default = "default_max_env_bytes")]
    pub max_env_bytes: usize,

    /// Bytes of stdout and of stderr kept per script; the rest is discarded.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,

    /// `umask` applied to scripts (octal in YAML is not portable, so give it
    /// as a decimal number, e.g. 18 for 0o022, 63 for 0o077).
    #[serde(default = "default_umask")]
    pub umask: u32,

    /// Refuse scripts that are group/other-writable, setuid/setgid, or not
    /// owned by root or the daemon user. Off by default for compatibility.
    #[serde(default)]
    pub strict_script_perms: bool,

    /// RLIMIT_NOFILE for scripts (0 = leave unchanged).
    #[serde(default)]
    pub rlimit_nofile: u64,

    /// RLIMIT_CPU seconds (0 = leave unchanged).
    #[serde(default)]
    pub rlimit_cpu_sec: u64,

    /// RLIMIT_AS in MiB (0 = leave unchanged).
    #[serde(default)]
    pub rlimit_as_mb: u64,

    /// RLIMIT_FSIZE in MiB (0 = leave unchanged).
    #[serde(default)]
    pub rlimit_fsize_mb: u64,

    /// Disable core dumps for scripts (RLIMIT_CORE = 0).
    #[serde(default = "default_true")]
    pub no_core_dumps: bool,
}

fn default_workdir() -> String {
    "/".to_string()
}
fn default_pass_env() -> Vec<String> {
    ["HOME", "USER", "LANG", "TZ"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_max_env_bytes() -> usize {
    262_144
}
fn default_max_output_bytes() -> usize {
    65_536
}
fn default_umask() -> u32 {
    0o022
}
fn default_true() -> bool {
    true
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            workdir: default_workdir(),
            pass_env: default_pass_env(),
            max_env_bytes: default_max_env_bytes(),
            max_output_bytes: default_max_output_bytes(),
            umask: default_umask(),
            strict_script_perms: false,
            rlimit_nofile: 0,
            rlimit_cpu_sec: 0,
            rlimit_as_mb: 0,
            rlimit_fsize_mb: 0,
            no_core_dumps: true,
        }
    }
}

impl SandboxConfig {
    /// Problems with the profile itself (used by `check-config`).
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.workdir.starts_with('/') || self.workdir.contains('\0') {
            out.push(format!(
                "sandbox.workdir '{}' must be an absolute path",
                self.workdir
            ));
        }
        if self.umask > 0o777 {
            out.push(format!(
                "sandbox.umask {} is out of range (max 511, i.e. 0o777)",
                self.umask
            ));
        }
        for name in &self.pass_env {
            if !valid_env_name(name) {
                out.push(format!(
                    "sandbox.pass_env entry '{name}' is not a valid variable name"
                ));
            } else if NEVER_PASS.contains(&name.as_str()) {
                out.push(format!(
                    "sandbox.pass_env entry '{name}' is never passed through"
                ));
            }
        }
        if self.max_env_bytes < 4096 {
            out.push(format!(
                "sandbox.max_env_bytes {} is too small to carry the event",
                self.max_env_bytes
            ));
        }
        out
    }
}

pub fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    name.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

static GLOBAL: OnceLock<SandboxConfig> = OnceLock::new();

/// Install the profile used by every `execute_scripts*` call (first call wins).
pub fn set_global(cfg: SandboxConfig) {
    let _ = GLOBAL.set(cfg);
}

pub fn global() -> SandboxConfig {
    GLOBAL.get().cloned().unwrap_or_default()
}

/// Result of validating the variables for one script run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreparedEnv {
    /// Final variables, daemon passthrough included (PATH is fixed).
    pub vars: BTreeMap<String, String>,
    /// `(name, reason)`; values are deliberately not kept.
    pub rejected: Vec<(String, String)>,
}

/// Context-specific validation of one event variable.
fn variable_ok(key: &str, value: &str) -> bool {
    match key {
        "LINK" => validation::validate_interface_name(value),
        "DHCP_HOSTNAME" | "HOSTNAME" => validation::validate_hostname(value),
        "DHCP_DOMAIN" | "DOMAIN" => validation::validate_domain_name(value),
        "DHCP_ADDRESS" | "ADDRESSES" | "DHCP_DNS" | "DNS" | "DHCP_GATEWAY" => {
            validation::validate_ip_list(value)
        }
        "STATE" => validation::validate_state_name(value),
        "LINKINDEX" => {
            !value.is_empty() && value.len() <= 10 && value.chars().all(|c| c.is_ascii_digit())
        }
        // Serialized by our own code; shell safety is not needed because
        // scripts are exec'd directly and the value is never re-parsed.
        "JSON" => !value.contains('\0'),
        _ => validation::sanitize_env_value(value).is_some(),
    }
}

/// Build the environment a script would receive. `daemon_env` is the
/// daemon's own environment (injected so tests need no process state).
pub fn prepare_env(
    event_vars: &HashMap<String, String>,
    cfg: &SandboxConfig,
    daemon_env: &dyn Fn(&str) -> Option<String>,
) -> PreparedEnv {
    let mut out = PreparedEnv::default();
    out.vars
        .insert("PATH".into(), "/usr/sbin:/usr/bin:/sbin:/bin".into());
    for name in &cfg.pass_env {
        if !valid_env_name(name) || NEVER_PASS.contains(&name.as_str()) {
            continue;
        }
        if let Some(v) = daemon_env(name) {
            if !v.contains('\0') && v.len() < MAX_ENV_STRING - name.len() - 2 {
                out.vars.insert(name.clone(), v);
            }
        }
    }

    let mut total: usize = out.vars.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    // Deterministic order, and JSON (the bulkiest, least essential) last so
    // that it is the one dropped when the budget is exhausted.
    let mut keys: Vec<&String> = event_vars.keys().collect();
    keys.sort_by(|a, b| (*a == "JSON").cmp(&(*b == "JSON")).then(a.cmp(b)));
    for key in keys {
        let value = &event_vars[key];
        if !valid_env_name(key) {
            out.rejected
                .push((key.clone(), "invalid variable name".into()));
            continue;
        }
        if key == "PATH" {
            out.rejected
                .push((key.clone(), "PATH is fixed by the daemon".into()));
            continue;
        }
        if key.len() + value.len() + 2 > MAX_ENV_STRING {
            out.rejected.push((
                key.clone(),
                format!("value larger than {MAX_ENV_STRING} bytes"),
            ));
            continue;
        }
        if !variable_ok(key, value) {
            out.rejected
                .push((key.clone(), "failed content validation".into()));
            continue;
        }
        let cost = key.len() + value.len() + 2;
        if total + cost > cfg.max_env_bytes {
            out.rejected.push((
                key.clone(),
                format!(
                    "environment budget of {} bytes exhausted",
                    cfg.max_env_bytes
                ),
            ));
            continue;
        }
        total += cost;
        out.vars.insert(key.clone(), value.clone());
    }
    out
}

/// What we know about a candidate script file (after following symlinks).
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptMeta {
    pub is_file: bool,
    pub mode: u32,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Run,
    Skip(String),
}

/// Decide whether a file in a hook directory is run. `daemon_uid` is the
/// uid the daemon runs as.
pub fn judge_script(meta: &ScriptMeta, cfg: &SandboxConfig, daemon_uid: u32) -> Verdict {
    if !meta.is_file {
        return Verdict::Skip("not a regular file".into());
    }
    if meta.mode & 0o111 == 0 {
        return Verdict::Skip("not executable".into());
    }
    if cfg.strict_script_perms {
        if meta.mode & 0o6000 != 0 {
            return Verdict::Skip("setuid/setgid bit set".into());
        }
        if meta.mode & 0o022 != 0 {
            return Verdict::Skip("writable by group or others".into());
        }
        if meta.uid != 0 && meta.uid != daemon_uid {
            return Verdict::Skip(format!("owned by uid {}, not root or the daemon", meta.uid));
        }
    }
    Verdict::Run
}

/// A file name that is safe to run: no control characters, not hidden, not an
/// editor/package leftover.
pub fn script_name_ok(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty name".into());
    }
    if name.starts_with('.') {
        return Err("hidden file".into());
    }
    if name.contains('/') || name.contains('\0') {
        return Err("path separator in name".into());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("control character in name".into());
    }
    for suffix in [
        "~",
        ".bak",
        ".orig",
        ".rpmsave",
        ".rpmnew",
        ".dpkg-old",
        ".dpkg-new",
        ".swp",
    ] {
        if name.ends_with(suffix) {
            return Err(format!("backup/leftover suffix {suffix}"));
        }
    }
    Ok(())
}

/// Apply rlimits and umask in the child between fork and exec.
///
/// # Safety
/// Only async-signal-safe calls (`setrlimit`, `umask`).
pub fn apply_in_child(cfg: &SandboxConfig) -> std::io::Result<()> {
    fn set(res: i32, v: u64) -> std::io::Result<()> {
        let lim = libc::rlimit {
            rlim_cur: v as libc::rlim_t,
            rlim_max: v as libc::rlim_t,
        };
        // Lowering only: if the hard limit is already lower, setrlimit
        // fails with EPERM when raising, so clamp to the current maximum.
        let mut cur = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain syscalls on stack structs.
        unsafe {
            if libc::getrlimit(res as _, &mut cur) == 0
                && cur.rlim_max != libc::RLIM_INFINITY
                && lim.rlim_max > cur.rlim_max
            {
                return Ok(());
            }
            if libc::setrlimit(res as _, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
    if cfg.no_core_dumps {
        set(libc::RLIMIT_CORE as i32, 0)?;
    }
    if cfg.rlimit_nofile > 0 {
        set(libc::RLIMIT_NOFILE as i32, cfg.rlimit_nofile)?;
    }
    if cfg.rlimit_cpu_sec > 0 {
        set(libc::RLIMIT_CPU as i32, cfg.rlimit_cpu_sec)?;
    }
    if cfg.rlimit_as_mb > 0 {
        set(
            libc::RLIMIT_AS as i32,
            cfg.rlimit_as_mb.saturating_mul(1 << 20),
        )?;
    }
    if cfg.rlimit_fsize_mb > 0 {
        set(
            libc::RLIMIT_FSIZE as i32,
            cfg.rlimit_fsize_mb.saturating_mul(1 << 20),
        )?;
    }
    // SAFETY: umask is async-signal-safe and cannot fail.
    unsafe {
        libc::umask(cfg.umask as libc::mode_t);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn default_profile_matches_legacy_behaviour() {
        let c = SandboxConfig::default();
        assert_eq!(c.pass_env, ["HOME", "USER", "LANG", "TZ"]);
        assert!(!c.strict_script_perms);
        assert!(c.problems().is_empty());
    }

    #[test]
    fn injection_through_interface_name_rejected() {
        for bad in [
            "eth0;reboot",
            "$(id)",
            "eth0\nPATH=/tmp",
            "`id`",
            "a b",
            "../x",
            "..",
            ".",
            "eth0|x",
            &"a".repeat(16),
        ] {
            let p = prepare_env(&vars(&[("LINK", bad)]), &SandboxConfig::default(), &no_env);
            assert!(!p.vars.contains_key("LINK"), "accepted {bad:?}");
            assert_eq!(p.rejected.len(), 1);
        }
        let ok = prepare_env(
            &vars(&[("LINK", "eth0")]),
            &SandboxConfig::default(),
            &no_env,
        );
        assert_eq!(ok.vars["LINK"], "eth0");
    }

    #[test]
    fn injection_through_addresses_rejected() {
        for bad in [
            "10.0.0.1; rm -rf /",
            "10.0.0.1 $(id)",
            "::1\n127.0.0.1",
            "10.0.0.1/24",
        ] {
            let p = prepare_env(
                &vars(&[("ADDRESSES", bad)]),
                &SandboxConfig::default(),
                &no_env,
            );
            assert!(!p.vars.contains_key("ADDRESSES"), "accepted {bad:?}");
        }
        let ok = prepare_env(
            &vars(&[("ADDRESSES", "10.0.0.1 fe80::1")]),
            &SandboxConfig::default(),
            &no_env,
        );
        assert!(ok.vars.contains_key("ADDRESSES"));
    }

    #[test]
    fn hostile_variable_names_rejected() {
        let p = prepare_env(
            &vars(&[
                ("LD_PRELOAD=/x", "1"),
                ("A B", "1"),
                ("", "1"),
                ("1A", "1"),
                ("PATH", "/tmp"),
            ]),
            &SandboxConfig::default(),
            &no_env,
        );
        assert_eq!(p.rejected.len(), 5);
        assert_eq!(p.vars["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin");
    }

    #[test]
    fn huge_values_dropped_and_budget_enforced() {
        let huge = "1".repeat(MAX_ENV_STRING);
        let p = prepare_env(
            &vars(&[("COUNT", &huge), ("LINK", "eth0")]),
            &SandboxConfig::default(),
            &no_env,
        );
        assert!(!p.vars.contains_key("COUNT"));
        assert!(p.vars.contains_key("LINK"));

        // JSON is shed first when the total budget runs out.
        let cfg = SandboxConfig {
            max_env_bytes: 4096,
            ..Default::default()
        };
        let json = "x".repeat(5000);
        let p = prepare_env(&vars(&[("JSON", &json), ("LINK", "eth0")]), &cfg, &no_env);
        assert!(p.vars.contains_key("LINK"));
        assert!(!p.vars.contains_key("JSON"));
        assert!(p.rejected[0].1.contains("budget"));
    }

    #[test]
    fn passthrough_is_filtered() {
        let cfg = SandboxConfig {
            pass_env: vec![
                "HOME".into(),
                "LD_PRELOAD".into(),
                "BAD NAME".into(),
                "TZ".into(),
            ],
            ..Default::default()
        };
        let env = |k: &str| Some(format!("val-{k}"));
        let p = prepare_env(&HashMap::new(), &cfg, &env);
        assert_eq!(p.vars.get("HOME").unwrap(), "val-HOME");
        assert_eq!(p.vars.get("TZ").unwrap(), "val-TZ");
        assert!(!p.vars.contains_key("LD_PRELOAD"));
        assert_eq!(p.vars.len(), 3); // PATH + HOME + TZ
        assert_eq!(cfg.problems().len(), 2);
    }

    #[test]
    fn judge_script_rules() {
        let cfg = SandboxConfig::default();
        let strict = SandboxConfig {
            strict_script_perms: true,
            ..Default::default()
        };
        let m = |mode, uid| ScriptMeta {
            is_file: true,
            mode,
            uid,
        };
        assert_eq!(judge_script(&m(0o755, 0), &cfg, 999), Verdict::Run);
        assert_eq!(
            judge_script(&m(0o644, 0), &cfg, 999),
            Verdict::Skip("not executable".into())
        );
        assert_eq!(judge_script(&m(0o777, 1000), &cfg, 999), Verdict::Run);
        assert!(matches!(
            judge_script(&m(0o777, 0), &strict, 999),
            Verdict::Skip(_)
        ));
        assert!(matches!(
            judge_script(&m(0o4755, 0), &strict, 999),
            Verdict::Skip(_)
        ));
        assert!(matches!(
            judge_script(&m(0o755, 1000), &strict, 999),
            Verdict::Skip(_)
        ));
        assert_eq!(judge_script(&m(0o750, 999), &strict, 999), Verdict::Run);
        assert_eq!(
            judge_script(
                &ScriptMeta {
                    is_file: false,
                    mode: 0o755,
                    uid: 0
                },
                &cfg,
                0
            ),
            Verdict::Skip("not a regular file".into())
        );
    }

    #[test]
    fn script_names() {
        assert!(script_name_ok("01-notify.sh").is_ok());
        for bad in [
            "",
            ".hidden",
            "a/b",
            "../x",
            "x\ny",
            "x~",
            "x.bak",
            "x.dpkg-old",
            "a\u{7}b",
        ] {
            assert!(script_name_ok(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn problems_reported() {
        let cfg = SandboxConfig {
            workdir: "rel".into(),
            umask: 9999,
            max_env_bytes: 10,
            ..Default::default()
        };
        assert_eq!(cfg.problems().len(), 3);
    }
}
