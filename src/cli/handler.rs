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
    println!("Fetching status from {}...", endpoint);

    // TODO: Make HTTP request to API
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
            println!("  Uptime: {} seconds", status.uptime);
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
        println!("Following events from {}...", endpoint);
        println!("Press Ctrl+C to stop");
        // TODO: Implement event streaming via SSE or WebSocket
        stream_events(endpoint, interface, event_type, format).await?;
    } else {
        let events = get_recent_events(endpoint, tail, interface, event_type).await?;
        print_events(&events, format)?;
    }

    Ok(())
}

async fn handle_reload(endpoint: &str) -> Result<()> {
    println!("Sending reload signal to {}...", endpoint);

    // TODO: POST to /api/v1/reload
    let response = send_reload_request(endpoint).await?;

    println!("  Message: {}", response.message);
    println!("  Note: config reload not yet implemented on server side");

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
        vec![synthetic_event(&name, &a.link, a.index, &a.backend, a.addresses)]
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

// Placeholder functions for API calls
// These will be implemented when the REST API is ready

#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonStatus {
    status: String,
    uptime: u64,
    interfaces_count: usize,
    routing_rules_count: usize,
    events_processed: u64,
}

async fn get_daemon_status(_endpoint: &str) -> Result<DaemonStatus> {
    // TODO: Implement HTTP client request
    Ok(DaemonStatus {
        status: "running".to_string(),
        uptime: 3600,
        interfaces_count: 2,
        routing_rules_count: 4,
        events_processed: 150,
    })
}

async fn get_interfaces(_endpoint: &str) -> Result<Vec<serde_json::Value>> {
    // TODO: Implement
    Ok(vec![])
}

async fn get_routes(_endpoint: &str) -> Result<Vec<serde_json::Value>> {
    // TODO: Implement
    Ok(vec![])
}

async fn get_rules(_endpoint: &str) -> Result<Vec<serde_json::Value>> {
    // TODO: Implement
    Ok(vec![])
}

async fn get_scripts(_endpoint: &str) -> Result<Vec<serde_json::Value>> {
    // TODO: Implement
    Ok(vec![])
}

async fn get_interface_details(_endpoint: &str, _name: &str) -> Result<serde_json::Value> {
    // TODO: Implement
    Ok(serde_json::json!({}))
}

async fn get_recent_events(
    _endpoint: &str,
    _tail: usize,
    _interface: Option<String>,
    _event_type: Option<String>,
) -> Result<Vec<serde_json::Value>> {
    // TODO: Implement
    Ok(vec![])
}

async fn stream_events(
    _endpoint: &str,
    _interface: Option<String>,
    _event_type: Option<String>,
    _format: OutputFormat,
) -> Result<()> {
    // TODO: Implement SSE/WebSocket streaming
    Ok(())
}

#[derive(serde::Deserialize)]
struct ReloadResponse {
    message: String,
}

async fn send_reload_request(_endpoint: &str) -> Result<ReloadResponse> {
    // TODO: Implement
    Ok(ReloadResponse {
        message: "Configuration reloaded".to_string(),
    })
}

fn print_list(_title: &str, _items: &[serde_json::Value], _format: OutputFormat) -> Result<()> {
    // TODO: Implement
    Ok(())
}

fn print_interface_details(_interface: &serde_json::Value) {
    // TODO: Implement
    println!("Interface details...");
}

fn print_events(_events: &[serde_json::Value], _format: OutputFormat) -> Result<()> {
    // TODO: Implement
    Ok(())
}
