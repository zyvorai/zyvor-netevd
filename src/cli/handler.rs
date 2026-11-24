// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

use crate::cli::{Cli, Commands, ListResource, OutputFormat, ShowResource};
use crate::config::Config;
use anyhow::Result;
use std::path::Path;

pub async fn handle_command(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Status { format, endpoint }) => handle_status(format, &endpoint).await,
        Some(Commands::List {
            resource,
            format,
            endpoint,
        }) => handle_list(resource, format, &endpoint).await,
        Some(Commands::Show {
            resource,
            name,
            format,
            endpoint,
        }) => handle_show(resource, &name, format, &endpoint).await,
        Some(Commands::Events {
            follow,
            interface,
            event_type,
            tail,
            format,
            endpoint,
        }) => handle_events(follow, interface, event_type, tail, format, &endpoint).await,
        Some(Commands::Reload { endpoint }) => handle_reload(&endpoint).await,
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
            ExplainArgs {
                event,
                link,
                index,
                backend,
                addresses,
                config_root,
                from_file,
            },
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

async fn handle_status(format: OutputFormat, endpoint: &str) -> Result<()> {
    let status = get_daemon_status(endpoint).await?;

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

async fn handle_list(resource: ListResource, format: OutputFormat, endpoint: &str) -> Result<()> {
    match resource {
        ListResource::Interfaces => {
            let interfaces = get_interfaces(endpoint).await?;
            print_list("Interfaces", &interfaces, format)?;
        }
        ListResource::Routes => {
            let routes = get_routes(endpoint).await?;
            print_list("Routes", &routes, format)?;
        }
        ListResource::Rules => {
            let rules = get_rules(endpoint).await?;
            print_list("Rules", &rules, format)?;
        }
        ListResource::Scripts => {
            let scripts = get_scripts(endpoint).await?;
            print_list("Scripts", &scripts, format)?;
        }
    }

    Ok(())
}

async fn handle_show(
    resource: ShowResource,
    name: &str,
    format: OutputFormat,
    endpoint: &str,
) -> Result<()> {
    match resource {
        ShowResource::Interface => {
            let interface = get_interface_details(endpoint, name).await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&interface)?),
                OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&interface)?),
                _ => print_interface_details(&interface),
            }
        }
        ShowResource::Status => {
            handle_status(format, endpoint).await?;
        }
        _ => {
            println!("Show {} not implemented yet", name);
        }
    }

    Ok(())
}

async fn handle_events(
    follow: bool,
    interface: Option<String>,
    event_type: Option<String>,
    tail: usize,
    format: OutputFormat,
    endpoint: &str,
) -> Result<()> {
    if follow {
        let recent =
            get_recent_events(endpoint, tail, interface.clone(), event_type.clone()).await?;
        print_events(&recent, format.clone())?;
        stream_events(endpoint, interface, event_type, format).await?;
    } else {
        let events = get_recent_events(endpoint, tail, interface, event_type).await?;
        print_events(&events, format)?;
    }

    Ok(())
}

async fn handle_reload(endpoint: &str) -> Result<()> {
    let response = send_reload_request(endpoint).await?;

    println!("  Message: {}", response.message);

    Ok(())
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

struct ExplainArgs {
    event: Option<String>,
    link: String,
    index: u32,
    backend: String,
    addresses: Vec<String>,
    config_root: Option<std::path::PathBuf>,
    from_file: Option<std::path::PathBuf>,
}

fn handle_explain(config_path: &Path, a: ExplainArgs, format: OutputFormat) -> Result<()> {
    use crate::hooks::explain::{default_root, explain_event, load_events, synthetic_event};
    // A missing config file means defaults, exactly as the daemon does.
    let config = Config::parse_from_path(&config_path.to_string_lossy())?;
    let root = a.config_root.unwrap_or_else(default_root);
    let uid = nix::unistd::Uid::effective().as_raw();
    let env = |k: &str| std::env::var(k).ok();

    let events = if let Some(f) = &a.from_file {
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
    };

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

use crate::cli::http::{encode, get_json, post_json, stream_sse};

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

async fn get_daemon_status(endpoint: &str) -> Result<DaemonStatus> {
    let e: Envelope<DaemonStatus> = get_json(endpoint, "/api/v1/status").await?;
    unwrap_envelope(e, "status")
}

async fn get_list(endpoint: &str, path: &str) -> Result<Vec<serde_json::Value>> {
    let e: Envelope<Vec<serde_json::Value>> = get_json(endpoint, path).await?;
    unwrap_envelope(e, path)
}

async fn get_interfaces(endpoint: &str) -> Result<Vec<serde_json::Value>> {
    get_list(endpoint, "/api/v1/interfaces").await
}

async fn get_routes(endpoint: &str) -> Result<Vec<serde_json::Value>> {
    get_list(endpoint, "/api/v1/routes").await
}

async fn get_rules(endpoint: &str) -> Result<Vec<serde_json::Value>> {
    get_list(endpoint, "/api/v1/rules").await
}

async fn get_scripts(_endpoint: &str) -> Result<Vec<serde_json::Value>> {
    anyhow::bail!(
        "the API does not list scripts; use `netevd explain <event>` to see what would run"
    )
}

async fn get_interface_details(endpoint: &str, name: &str) -> Result<serde_json::Value> {
    let e: Envelope<serde_json::Value> =
        get_json(endpoint, &format!("/api/v1/interfaces/{}", encode(name))).await?;
    unwrap_envelope(e, "interface")
}

fn events_query(
    limit: Option<usize>,
    interface: &Option<String>,
    event_type: &Option<String>,
) -> String {
    let mut q = Vec::new();
    if let Some(l) = limit {
        q.push(format!("limit={l}"));
    }
    if let Some(i) = interface {
        q.push(format!("interface={}", encode(i)));
    }
    if let Some(t) = event_type {
        q.push(format!("event={}", encode(t)));
    }
    if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    }
}

async fn get_recent_events(
    endpoint: &str,
    tail: usize,
    interface: Option<String>,
    event_type: Option<String>,
) -> Result<Vec<serde_json::Value>> {
    let q = events_query(Some(tail), &interface, &event_type);
    get_list(endpoint, &format!("/api/v1/events{q}")).await
}

async fn stream_events(
    endpoint: &str,
    interface: Option<String>,
    event_type: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    let q = events_query(None, &interface, &event_type);
    stream_sse(
        endpoint,
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

async fn send_reload_request(endpoint: &str) -> Result<ReloadResponse> {
    post_json(endpoint, "/api/v1/reload", "{}").await
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

    async fn serve(log: Arc<EventLog>) -> String {
        let app = create_api_routes_with_log(Arc::new(RwLock::new(NetworkState::new())), log);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
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
        let all = get_recent_events(&ep, 10, None, None).await.unwrap();
        assert_eq!(all.len(), 3);
        let one = get_recent_events(&ep, 1, None, None).await.unwrap();
        assert_eq!(one[0]["id"], "3");
        let f = get_recent_events(&ep, 10, Some("eth0".into()), Some("mtu".into()))
            .await
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["event_type"], "mtu");
        let line = event_line(&f[0]);
        assert!(
            line.contains("mtu") && line.contains("eth0") && line.contains("[192.0.2.1]"),
            "{line}"
        );
        handle_events(false, None, None, 5, OutputFormat::Text, &ep)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn follow_receives_live_events_and_honours_filter() {
        let log = Arc::new(EventLog::new(10));
        let ep = serve(log.clone()).await;
        let got = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let got2 = got.clone();
        let ep2 = ep.clone();
        let task = tokio::spawn(async move {
            stream_sse(&ep2, "/api/v1/events/stream?interface=eth0", |d| {
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
        let e = get_daemon_status("http://127.0.0.1:1").await.err().unwrap();
        assert!(e.to_string().contains("cannot connect"), "{e}");
    }

    #[tokio::test]
    async fn reload_and_lists_round_trip() {
        let ep = serve(Arc::new(EventLog::new(2))).await;
        let r = send_reload_request(&ep).await.unwrap();
        assert!(!r.message.is_empty());
        assert!(get_interfaces(&ep).await.unwrap().is_empty());
        assert!(get_rules(&ep).await.unwrap().is_empty());
        assert!(get_interface_details(&ep, "nope").await.is_err());
        assert!(get_scripts(&ep).await.is_err());
    }

    #[test]
    fn query_builder_encodes() {
        assert_eq!(events_query(None, &None, &None), "");
        assert_eq!(
            events_query(Some(5), &Some("a b".into()), &Some("mtu".into())),
            "?limit=5&interface=a%20b&event=mtu"
        );
    }
}
