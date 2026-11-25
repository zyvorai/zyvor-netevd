// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

use crate::api::models::HealthStatus;
use crate::cli::http::{encode, Client};
use crate::cli::{Cli, Commands, ListResource, OutputFormat, ShowResource};
use crate::config::Config;
use crate::hooks::HookEventV1;
use crate::system::execute::{failure_summary, run_scripts, ScriptRun};
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;

pub async fn handle_command(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Status { format, api }) => {
            handle_status(format, &Client::new(&api.options())?).await
        }
        Some(Commands::List {
            resource,
            format,
            api,
        }) => handle_list(resource, format, &Client::new(&api.options())?).await,
        Some(Commands::Show {
            resource,
            name,
            format,
            api,
        }) => handle_show(resource, &name, format, &Client::new(&api.options())?).await,
        Some(Commands::Events {
            follow,
            interface,
            event_type,
            tail,
            format,
            outcome,
            api,
        }) => {
            let filter = EventsArgs {
                interface,
                event_type,
                outcome,
            };
            handle_events(follow, filter, tail, format, &Client::new(&api.options())?).await
        }
        Some(Commands::Reload { api }) => handle_reload(&Client::new(&api.options())?).await,
        Some(Commands::Health { format, api }) => {
            handle_health(format, &Client::new(&api.options())?).await
        }
        Some(Commands::Trigger {
            event,
            link,
            index,
            backend,
            addresses,
            config_root,
            from_file,
            timeout,
            allow_root,
            format,
        }) => {
            let args = EventArgs {
                event,
                link,
                index,
                backend,
                addresses,
                from_file,
            };
            let opts = TriggerOpts {
                config_root,
                timeout,
                allow_root,
                uid: nix::unistd::Uid::effective().as_raw(),
            };
            handle_trigger(&cli.config, args, opts, format).await
        }
        Some(Commands::Validate {
            config,
            strict,
            format,
        }) => handle_check_config(&config.unwrap_or(cli.config), strict, format),
        Some(Commands::Explain {
            event,
            link,
            index,
            backend,
            addresses,
            config_root,
            from_file,
            format,
        }) => handle_explain(
            &cli.config,
            EventArgs {
                event,
                link,
                index,
                backend,
                addresses,
                from_file,
            },
            config_root,
            format,
        ),
        Some(Commands::Test {
            script,
            interface,
            event_type,
            ip,
        }) => handle_test_script(&script, &interface, &event_type, ip).await,
        Some(Commands::Version { detailed }) => handle_version(detailed),
        Some(Commands::Start { foreground: _ }) => {
            // This is handled in main.rs
            Ok(())
        }
        None => {
            // Default: start daemon
            Ok(())
        }
    }
}

async fn handle_status(format: OutputFormat, client: &Client) -> Result<()> {
    let status = get_daemon_status(client).await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&status)?);
        }
        _ => {
            println!("netevd Status:");
            println!("  Status: {}", status.status);
            println!("  Version: {}", status.version);
            println!("  Uptime: {} seconds", status.uptime_seconds);
            println!("  Interfaces: {}", status.interfaces_count);
            println!("  Routing Rules: {}", status.routing_rules_count);
            println!("  Events Processed: {}", status.events_processed);
        }
    }

    Ok(())
}

async fn handle_list(resource: ListResource, format: OutputFormat, client: &Client) -> Result<()> {
    match resource {
        ListResource::Interfaces => {
            let interfaces = get_interfaces(client).await?;
            print_list("Interfaces", &interfaces, format)?;
        }
        ListResource::Routes => {
            let routes = get_routes(client).await?;
            print_list("Routes", &routes, format)?;
        }
        ListResource::Rules => {
            let rules = get_rules(client).await?;
            print_list("Rules", &rules, format)?;
        }
        ListResource::Scripts => {
            let scripts = get_scripts(client).await?;
            print_list("Scripts", &scripts, format)?;
        }
    }

    Ok(())
}

async fn handle_show(
    resource: ShowResource,
    name: &str,
    format: OutputFormat,
    client: &Client,
) -> Result<()> {
    match resource {
        ShowResource::Interface => {
            let interface = get_interface_details(client, name).await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&interface)?),
                OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&interface)?),
                _ => print_interface_details(&interface),
            }
        }
        ShowResource::Status => {
            handle_status(format, client).await?;
        }
        _ => {
            println!("Show {} not implemented yet", name);
        }
    }

    Ok(())
}

/// Filters of the `events` command.
#[derive(Debug, Clone, Default)]
struct EventsArgs {
    interface: Option<String>,
    event_type: Option<String>,
    outcome: Option<String>,
}

async fn handle_events(
    follow: bool,
    filter: EventsArgs,
    tail: usize,
    format: OutputFormat,
    client: &Client,
) -> Result<()> {
    let recent = get_recent_events(client, tail, &filter).await?;
    print_events(&recent, format.clone())?;
    if follow {
        stream_events(client, &filter, format).await?;
    }

    Ok(())
}

async fn handle_reload(client: &Client) -> Result<()> {
    let response = send_reload_request(client).await?;

    println!("  Message: {}", response.message);

    Ok(())
}

async fn handle_health(format: OutputFormat, client: &Client) -> Result<()> {
    let (ready, health) = get_health(client).await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&health)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&health)?),
        _ => print!("{}", health_text(&health)),
    }
    if ready {
        Ok(())
    } else {
        anyhow::bail!("netevd is not ready")
    }
}

fn health_text(h: &HealthStatus) -> String {
    let show = |v: Option<bool>| match v {
        Some(true) => "ok",
        Some(false) => "FAILED",
        None => "not used",
    };
    format!(
        "Status : {}\n  netlink: {}\n  dbus   : {}\n  hooks  : {}\n  config : {}\n",
        h.status,
        show(Some(h.checks.netlink)),
        show(h.checks.dbus),
        show(h.checks.hooks),
        show(Some(h.checks.config)),
    )
}

fn handle_check_config(path: &Path, strict: bool, format: OutputFormat) -> Result<()> {
    let report = crate::config::check::check_file(path);
    let file = path.display().to_string();
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": file,
                "ok": report.ok(strict),
                "errors": report.errors(),
                "warnings": report.warnings(),
                "diagnostics": report.diagnostics,
            }))?
        ),
        _ => print!("{}", report.render_text(&file)),
    }
    if report.ok(strict) {
        Ok(())
    } else {
        anyhow::bail!(
            "configuration check failed: {} error(s), {} warning(s){}",
            report.errors(),
            report.warnings(),
            if strict { " (strict)" } else { "" }
        )
    }
}

/// Which events `explain` and `trigger` act on.
struct EventArgs {
    event: Option<String>,
    link: String,
    index: u32,
    backend: String,
    addresses: Vec<String>,
    from_file: Option<std::path::PathBuf>,
}

/// The events named on the command line, or recorded in `--from-file`.
fn events_from(a: EventArgs) -> Result<Vec<HookEventV1>> {
    use crate::hooks::explain::{load_events, synthetic_event};
    Ok(if let Some(f) = &a.from_file {
        let meta = std::fs::metadata(f)?;
        if meta.len() > 64 * 1024 * 1024 {
            anyhow::bail!("{} is larger than 64 MiB", f.display());
        }
        let text = String::from_utf8_lossy(&std::fs::read(f)?).into_owned();
        let (events, errors) = load_events(&text);
        for e in &errors {
            eprintln!("warning: {}: {e}", f.display());
        }
        events
    } else {
        let name = a.event.unwrap_or_default();
        vec![synthetic_event(
            &name,
            &a.link,
            a.index,
            &a.backend,
            a.addresses,
        )]
    })
}

fn handle_explain(
    config_path: &Path,
    a: EventArgs,
    config_root: Option<std::path::PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    use crate::hooks::explain::{default_root, explain_event};
    // A missing config file means defaults, exactly as the daemon does.
    let config = Config::parse_from_path(&config_path.to_string_lossy())?;
    let root = config_root.unwrap_or_else(default_root);
    let uid = nix::unistd::Uid::effective().as_raw();
    let env = |k: &str| std::env::var(k).ok();
    let events = events_from(a)?;

    let explained: Vec<_> = events
        .iter()
        .map(|ev| explain_event(ev, &config, &root, uid, &env))
        .collect();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&explained)?),
        _ => {
            for (i, x) in explained.iter().enumerate() {
                if explained.len() > 1 {
                    println!("--- event {} of {} ---", i + 1, explained.len());
                }
                print!("{}", x.render_text());
            }
        }
    }
    Ok(())
}

struct TriggerOpts {
    config_root: Option<std::path::PathBuf>,
    timeout: Option<u64>,
    allow_root: bool,
    /// Effective user id the scripts would run as.
    uid: u32,
}

/// What `trigger` did for one event.
#[derive(serde::Serialize)]
struct Triggered {
    event: String,
    link: String,
    /// Why no script ran, when none did.
    skipped: Option<String>,
    scripts: Vec<ScriptRun>,
}

/// Printable form of captured output: control characters other than newline
/// and tab are replaced so scripts cannot drive the terminal.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// Run the scripts the daemon would run for `ev`, after the same interface
/// selector and filter decisions that `explain` reports.
async fn trigger_event(
    ev: &HookEventV1,
    config: &Config,
    root: &Path,
    opts: &TriggerOpts,
) -> Result<Triggered> {
    use crate::hooks::explain::explain_event;
    if !HookEventV1::is_known_event(&ev.event) {
        anyhow::bail!(
            "unknown event '{}'; known: {}",
            printable(&ev.event),
            crate::hooks::event::HOOK_STATES.join(", ")
        );
    }
    let env = |k: &str| std::env::var(k).ok();
    let plan = explain_event(ev, config, root, opts.uid, &env);
    let skipped = if !plan.interface_selected {
        Some(format!("interface dropped: {}", plan.interface_reason))
    } else if !plan.would_run && plan.filter_decision.starts_with("ignore") {
        Some(format!("filters: {}", plan.filter_decision))
    } else if !plan.would_run {
        Some(format!(
            "no runnable script in {}",
            plan.hook_dir.as_deref().unwrap_or("(none)")
        ))
    } else {
        None
    };
    let scripts = if skipped.is_some() {
        Vec::new()
    } else {
        let dir =
            crate::hooks::dispatch::hook_dir(root, &ev.event).context("unknown hook state")?;
        let timeout = opts.timeout.unwrap_or(config.hooks.timeout_sec);
        run_scripts(
            &dir.to_string_lossy(),
            ev.to_env(),
            Duration::from_secs(timeout),
            &config.hooks.sandbox,
        )
        .await?
    };
    Ok(Triggered {
        event: ev.event.clone(),
        link: printable(&ev.link),
        skipped,
        scripts,
    })
}

fn trigger_text(t: &Triggered) -> String {
    use std::fmt::Write;
    let mut o = format!("Event {} on {}\n", t.event, t.link);
    if let Some(why) = &t.skipped {
        let _ = writeln!(o, "  nothing run ({why})");
    }
    for s in &t.scripts {
        let _ = writeln!(o, "  {} {} ms", s.result.describe(), s.result.duration_ms);
        for (label, text) in [("stdout", &s.stdout), ("stderr", &s.stderr)] {
            for line in printable(text).lines() {
                let _ = writeln!(o, "    {label}| {line}");
            }
        }
    }
    o
}

async fn handle_trigger(
    config_path: &Path,
    args: EventArgs,
    opts: TriggerOpts,
    format: OutputFormat,
) -> Result<()> {
    if opts.uid == 0 && !opts.allow_root {
        anyhow::bail!(
            "refusing to run hook scripts as root: the daemon runs them as 'netevd' \
             (try `sudo -u netevd netevd trigger ...`, or pass --allow-root)"
        );
    }
    let config = Config::parse_from_path(&config_path.to_string_lossy())?;
    let root = opts
        .config_root
        .clone()
        .unwrap_or_else(crate::hooks::explain::default_root);
    let mut results = Vec::new();
    for ev in events_from(args)? {
        let t = trigger_event(&ev, &config, &root, &opts).await?;
        if !matches!(format, OutputFormat::Json) {
            print!("{}", trigger_text(&t));
        }
        results.push(t);
    }
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }
    let failed: Vec<ScriptRun> = results.into_iter().flat_map(|t| t.scripts).collect();
    match failure_summary(&failed) {
        None => Ok(()),
        Some(msg) => anyhow::bail!(msg),
    }
}

async fn handle_test_script(
    script: &Path,
    interface: &str,
    event_type: &str,
    ip: Option<String>,
) -> Result<()> {
    println!("Testing script: {}", script.display());
    println!("  Interface: {}", interface);
    println!("  Event type: {}", event_type);
    if let Some(ref ip_addr) = ip {
        println!("  IP address: {}", ip_addr);
    }

    println!("\nEnvironment the script would receive (nothing is executed):");
    let mut vars = std::collections::HashMap::new();
    vars.insert("LINK".to_string(), interface.to_string());
    vars.insert("STATE".to_string(), event_type.to_string());
    vars.insert("EVENT".to_string(), event_type.to_string());
    vars.insert("BACKEND".to_string(), "test".to_string());
    if let Some(ip_addr) = ip {
        vars.insert("ADDRESSES".to_string(), ip_addr);
    }
    let config = Config::default();
    let prepared = crate::system::sandbox::prepare_env(&vars, &config.hooks.sandbox, &|k| {
        std::env::var(k).ok()
    });
    for (k, v) in &prepared.vars {
        println!("  {k}={v}");
    }
    for (k, why) in &prepared.rejected {
        println!("  rejected: {k} ({why})");
    }

    println!("\nUse `netevd explain <event>` to see which scripts would run.");

    Ok(())
}

fn handle_version(detailed: bool) -> Result<()> {
    println!("netevd {}", env!("CARGO_PKG_VERSION"));

    if detailed {
        println!("\nBuild information:");
        println!("  Compiler: rustc");
        println!("\nFeatures:");
        println!("  - systemd-networkd support");
        println!("  - NetworkManager support");
        println!("  - dhclient support");
        println!("  - REST API");
        println!("  - Prometheus metrics");
        println!("  - Event filtering");
        println!("  - IPv6 policy routing");
        println!("  - Kubernetes operator");
        println!("  - Cloud provider integrations (AWS, Azure, GCP)");
        println!("  - Audit logging");
        println!("  - Web dashboard");
    }

    Ok(())
}

// REST API client calls (see `cli::http`).

/// The API wraps every payload as `{success, data, error, timestamp}`.
#[derive(serde::Deserialize)]
struct Envelope<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

fn unwrap_envelope<T>(e: Envelope<T>, what: &str) -> Result<T> {
    match (e.success, e.data) {
        (true, Some(d)) => Ok(d),
        _ => anyhow::bail!(
            "{what}: {}",
            e.error.unwrap_or_else(|| "empty response".into())
        ),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonStatus {
    status: String,
    version: String,
    uptime_seconds: u64,
    interfaces_count: usize,
    routing_rules_count: usize,
    events_processed: u64,
}

async fn get_daemon_status(client: &Client) -> Result<DaemonStatus> {
    let e: Envelope<DaemonStatus> = client.get_json("/api/v1/status").await?;
    unwrap_envelope(e, "status")
}

/// Readiness: `true` when `/health/ready` answers 200. A 503 still carries
/// the checks.
async fn get_health(client: &Client) -> Result<(bool, HealthStatus)> {
    let path = "/health/ready";
    let (status, body) = client.exchange("GET", path, None).await?;
    if status != 200 && status != 503 {
        anyhow::bail!("GET {path} failed with HTTP {status}");
    }
    let health = serde_json::from_slice(&body)
        .with_context(|| format!("unexpected response from {path}"))?;
    Ok((status == 200, health))
}

async fn get_list(client: &Client, path: &str) -> Result<Vec<serde_json::Value>> {
    let e: Envelope<Vec<serde_json::Value>> = client.get_json(path).await?;
    unwrap_envelope(e, path)
}

async fn get_interfaces(client: &Client) -> Result<Vec<serde_json::Value>> {
    get_list(client, "/api/v1/interfaces").await
}

async fn get_routes(client: &Client) -> Result<Vec<serde_json::Value>> {
    get_list(client, "/api/v1/routes").await
}

async fn get_rules(client: &Client) -> Result<Vec<serde_json::Value>> {
    get_list(client, "/api/v1/rules").await
}

async fn get_scripts(_client: &Client) -> Result<Vec<serde_json::Value>> {
    anyhow::bail!(
        "the API does not list scripts; use `netevd explain <event>` to see what would run"
    )
}

async fn get_interface_details(client: &Client, name: &str) -> Result<serde_json::Value> {
    let e: Envelope<serde_json::Value> = client
        .get_json(&format!("/api/v1/interfaces/{}", encode(name)))
        .await?;
    unwrap_envelope(e, "interface")
}

fn events_query(limit: Option<usize>, filter: &EventsArgs) -> String {
    let mut q = Vec::new();
    if let Some(l) = limit {
        q.push(format!("limit={l}"));
    }
    for (key, value) in [
        ("interface", &filter.interface),
        ("event", &filter.event_type),
        ("outcome", &filter.outcome),
    ] {
        if let Some(v) = value {
            q.push(format!("{key}={}", encode(v)));
        }
    }
    if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    }
}

async fn get_recent_events(
    client: &Client,
    tail: usize,
    filter: &EventsArgs,
) -> Result<Vec<serde_json::Value>> {
    let q = events_query(Some(tail), filter);
    get_list(client, &format!("/api/v1/events{q}")).await
}

async fn stream_events(client: &Client, filter: &EventsArgs, format: OutputFormat) -> Result<()> {
    let q = events_query(None, filter);
    client
        .stream_sse(
            &format!("/api/v1/events/stream{q}"),
            |data| match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => print_events(std::slice::from_ref(&v), format.clone()).is_ok(),
                Err(_) => true,
            },
        )
        .await
}

#[derive(serde::Deserialize)]
struct ReloadResponse {
    message: String,
}

async fn send_reload_request(client: &Client) -> Result<ReloadResponse> {
    client.post_json("/api/v1/reload", "{}").await
}

/// One-line text form of an API event.
fn event_line(e: &serde_json::Value) -> String {
    let d = &e["details"];
    let s = |v: &serde_json::Value| v.as_str().unwrap_or("-").to_string();
    let addrs = d["addresses"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let mut line = format!(
        "{:>5} {} {:<14} {:<10} {}",
        s(&e["id"]),
        s(&d["ts"]),
        s(&e["event_type"]),
        s(&e["interface"]),
        s(&d["outcome"]),
    );
    if let Some(ms) = d["duration_ms"].as_u64() {
        line.push_str(&format!(" {ms}ms"));
    }
    if !addrs.is_empty() {
        line.push_str(&format!(" [{addrs}]"));
    }
    if let Some(err) = d["error"].as_str() {
        line.push_str(&format!(" error: {err}"));
    }
    line
}

fn print_events(events: &[serde_json::Value], format: OutputFormat) -> Result<()> {
    for e in events {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string(e)?),
            OutputFormat::Yaml => print!("---\n{}", serde_yaml::to_string(e)?),
            _ => println!("{}", event_line(e)),
        }
    }
    Ok(())
}

fn print_list(title: &str, items: &[serde_json::Value], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(items)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(items)?),
        _ => {
            println!("{title} ({})", items.len());
            for i in items {
                let fields: Vec<String> = i
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .filter(|(_, v)| !v.is_null())
                            .map(|(k, v)| match v.as_str() {
                                Some(s) => format!("{k}={s}"),
                                None => format!("{k}={v}"),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                println!("  {}", fields.join(" "));
            }
        }
    }
    Ok(())
}

fn print_interface_details(interface: &serde_json::Value) {
    if let Some(o) = interface.as_object() {
        for (k, v) in o {
            println!("  {k}: {v}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::routes::create_api_routes_with_log;
    use crate::hooks::{EventLog, HookEventV1};
    use crate::network::NetworkState;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    async fn serve(log: Arc<EventLog>) -> Client {
        let app = create_api_routes_with_log(Arc::new(RwLock::new(NetworkState::new())), log);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Client::plain(&format!("http://{addr}")).unwrap()
    }

    fn rec(log: &EventLog, ev: &str, link: &str) {
        log.record(
            &HookEventV1::new(ev, link, 2, "netlink").with_addresses(vec!["192.0.2.1".into()]),
            "dispatched",
            Duration::from_millis(3),
            None,
        );
    }

    #[tokio::test]
    async fn status_reports_real_counters_not_placeholders() {
        let log = Arc::new(EventLog::new(10));
        rec(&log, "routable", "eth0");
        rec(&log, "mtu", "eth0");
        let ep = serve(log).await;
        let st = get_daemon_status(&ep).await.unwrap();
        assert_eq!(st.events_processed, 2);
        assert_eq!(st.interfaces_count, 0);
        assert_eq!(st.version, env!("CARGO_PKG_VERSION"));
        handle_status(OutputFormat::Json, &ep).await.unwrap();
    }

    #[tokio::test]
    async fn events_tail_and_filters_over_http() {
        let log = Arc::new(EventLog::new(10));
        rec(&log, "routable", "eth0");
        rec(&log, "mtu", "eth1");
        rec(&log, "mtu", "eth0");
        let ep = serve(log).await;
        let none = EventsArgs::default();
        let all = get_recent_events(&ep, 10, &none).await.unwrap();
        assert_eq!(all.len(), 3);
        let one = get_recent_events(&ep, 1, &none).await.unwrap();
        assert_eq!(one[0]["id"], "3");
        let both = EventsArgs {
            interface: Some("eth0".into()),
            event_type: Some("mtu".into()),
            outcome: None,
        };
        let f = get_recent_events(&ep, 10, &both).await.unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["event_type"], "mtu");
        let line = event_line(&f[0]);
        assert!(
            line.contains("mtu") && line.contains("eth0") && line.contains("[192.0.2.1]"),
            "{line}"
        );
        let failed = EventsArgs {
            outcome: Some("failed".into()),
            ..Default::default()
        };
        assert!(get_recent_events(&ep, 10, &failed)
            .await
            .unwrap()
            .is_empty());
        handle_events(false, none, 5, OutputFormat::Text, &ep)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn follow_receives_live_events_and_honours_filter() {
        let log = Arc::new(EventLog::new(10));
        let ep = serve(log.clone()).await;
        let got = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let got2 = got.clone();
        let ep2 = ep;
        let task = tokio::spawn(async move {
            ep2.stream_sse("/api/v1/events/stream?interface=eth0", |d| {
                got2.lock().unwrap().push(d.to_string());
                false
            })
            .await
        });
        // Wait for the subscriber to attach, then publish a non-match and a match.
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            rec(&log, "mtu", "eth9");
            rec(&log, "routable", "eth0");
            if task.is_finished() {
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let first = got.lock().unwrap()[0].clone();
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(v["interface"], "eth0");
        assert_eq!(v["event_type"], "routable");
    }

    #[tokio::test]
    async fn unreachable_daemon_is_a_clear_error() {
        let client = Client::plain("http://127.0.0.1:1").unwrap();
        let e = get_daemon_status(&client).await.err().unwrap();
        assert!(e.to_string().contains("cannot connect"), "{e}");
    }

    #[tokio::test]
    async fn reload_and_lists_round_trip() {
        let ep = serve(Arc::new(EventLog::new(2))).await;
        let r = send_reload_request(&ep).await.unwrap();
        assert!(!r.message.is_empty());
        let interfaces = get_interfaces(&ep).await.unwrap();
        assert!(interfaces.iter().any(|i| i["name"] == "lo"));
        get_routes(&ep).await.unwrap();
        assert!(get_rules(&ep).await.unwrap().is_empty());
        assert!(get_interface_details(&ep, "nope").await.is_err());
        assert!(get_scripts(&ep).await.is_err());
    }

    #[test]
    fn query_builder_encodes() {
        assert_eq!(events_query(None, &EventsArgs::default()), "");
        let f = EventsArgs {
            interface: Some("a b".into()),
            event_type: Some("mtu".into()),
            outcome: Some("failed".into()),
        };
        assert_eq!(
            events_query(Some(5), &f),
            "?limit=5&interface=a%20b&event=mtu&outcome=failed"
        );
    }

    fn hook(root: &Path, dir: &str, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let d = root.join(dir);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn trigger_opts(root: &Path) -> TriggerOpts {
        TriggerOpts {
            config_root: Some(root.to_path_buf()),
            timeout: Some(5),
            allow_root: false,
            uid: 1000,
        }
    }

    fn event_args(event: &str, link: &str) -> EventArgs {
        EventArgs {
            event: Some(event.into()),
            link: link.into(),
            index: 2,
            backend: "netlink".into(),
            addresses: vec!["192.0.2.7".into()],
            from_file: None,
        }
    }

    #[tokio::test]
    async fn trigger_runs_scripts_and_reports_failures() {
        let t = tempfile::tempdir().unwrap();
        hook(
            t.path(),
            "routable.d",
            "01-env",
            "#!/bin/sh\necho \"$LINK $ADDRESSES\"\nprintf '\\033[2J' >&2\n",
        );
        hook(t.path(), "routable.d", "02-bad", "#!/bin/sh\nexit 5\n");
        let opts = trigger_opts(t.path());
        let ev = events_from(event_args("routable", "eth0"))
            .unwrap()
            .remove(0);
        let got = trigger_event(&ev, &Config::default(), t.path(), &opts)
            .await
            .unwrap();
        assert_eq!(got.skipped, None);
        assert_eq!(got.scripts[0].stdout, "eth0 192.0.2.7\n");
        let text = trigger_text(&got);
        assert!(text.contains("stdout| eth0 192.0.2.7"), "{text}");
        assert!(
            !text.contains('\u{1b}'),
            "escape sequences must not reach the terminal"
        );
        assert!(text.contains("02-bad (exit 5)"), "{text}");
        let e = handle_trigger(
            Path::new("/nonexistent/netevd.yaml"),
            event_args("routable", "eth0"),
            opts,
            OutputFormat::Json,
        )
        .await
        .unwrap_err();
        assert_eq!(e.to_string(), "1 of 2 scripts failed: 02-bad (exit 5)");
    }

    #[tokio::test]
    async fn trigger_honours_selector_root_guard_and_unknown_events() {
        let t = tempfile::tempdir().unwrap();
        let marker = t.path().join("ran");
        hook(
            t.path(),
            "mtu.d",
            "01",
            &format!("#!/bin/sh\n: > {}\n", marker.display()),
        );
        let opts = trigger_opts(t.path());
        // `lo` is excluded by the default selector, as in the daemon.
        let ev = events_from(event_args("mtu", "lo")).unwrap().remove(0);
        let got = trigger_event(&ev, &Config::default(), t.path(), &opts)
            .await
            .unwrap();
        assert!(got.skipped.unwrap().contains("interface dropped"));
        let ev = events_from(event_args("carrier", "eth0"))
            .unwrap()
            .remove(0);
        let got = trigger_event(&ev, &Config::default(), t.path(), &opts)
            .await
            .unwrap();
        assert!(got.skipped.unwrap().contains("no runnable script"));
        let ev = events_from(event_args("../mtu", "eth0")).unwrap().remove(0);
        assert!(trigger_event(&ev, &Config::default(), t.path(), &opts)
            .await
            .is_err());

        let mut root = trigger_opts(t.path());
        root.uid = 0;
        let e = handle_trigger(
            Path::new("/nonexistent/netevd.yaml"),
            event_args("mtu", "eth0"),
            root,
            OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("--allow-root"), "{e}");
        assert!(!marker.exists(), "nothing may have run");
    }
}
