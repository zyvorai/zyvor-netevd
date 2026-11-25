// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! The `netevd` binary against a real API server on a loopback port: TLS,
//! bearer tokens, health, events and `trigger`. Nothing here needs privileges
//! or touches network configuration.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use netevd::api::health::HealthProbe;
use netevd::api::routes::ApiContext;
use netevd::api::security::ApiSecurity;
use netevd::api::ApiServer;
use netevd::config::Config;
use netevd::hooks::{EventLog, HookEventV1};
use netevd::network::NetworkState;
use netevd::system::execute::{ScriptResult, ScriptStatus};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::RwLock;

const TOKEN: &str = "integration-token-0123456789abcdef";

fn write(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

struct Server {
    dir: tempfile::TempDir,
    port: u16,
    ca: PathBuf,
    token: PathBuf,
    log: Arc<EventLog>,
    /// Dropping the receiver makes the daemon not ready.
    _hooks: Option<tokio::sync::mpsc::UnboundedReceiver<HookEventV1>>,
}

impl Server {
    /// Configure TLS and a token exactly as an operator would, through the
    /// YAML configuration.
    async fn start(hooks_alive: bool) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let ca = write(dir.path(), "cert.pem", &key.cert.pem(), 0o644);
        let key_file = write(
            dir.path(),
            "key.pem",
            &key.signing_key.serialize_pem(),
            0o600,
        );
        let token = write(dir.path(), "token", &format!("{TOKEN}\n"), 0o600);
        let yaml = format!(
            "api:\n  tls:\n    enabled: true\n    cert_file: {}\n    key_file: {}\n  auth:\n    token_file: {}\n",
            ca.display(),
            key_file.display(),
            token.display()
        );
        let config_file = write(dir.path(), "netevd.yaml", &yaml, 0o644);
        let config = Config::parse_from_path(config_file.to_str().unwrap()).unwrap();
        let security = ApiSecurity::load(&config.api).unwrap();

        let log = Arc::new(EventLog::new(20));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let context = ApiContext {
            log: log.clone(),
            probe: Arc::new(HealthProbe::for_daemon("dhclient", tx)),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = ApiServer::new(port, Arc::new(RwLock::new(NetworkState::new())))
            .with_security(security)
            .with_context(context);
        tokio::spawn(server.serve(listener));
        Server {
            dir,
            port,
            ca,
            token,
            log,
            _hooks: hooks_alive.then_some(rx),
        }
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.port)
    }

    fn client_args(&self) -> Vec<String> {
        vec![
            "--endpoint".into(),
            self.url(),
            "--ca-file".into(),
            self.ca.display().to_string(),
            "--token-file".into(),
            self.token.display().to_string(),
        ]
    }
}

fn netevd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_netevd"));
    for k in [
        "NETEVD_ENDPOINT",
        "NETEVD_API_TOKEN",
        "NETEVD_API_TOKEN_FILE",
        "NETEVD_API_CA_FILE",
    ] {
        c.env_remove(k);
    }
    c.stdin(Stdio::null()).kill_on_drop(true);
    c
}

/// (exit success, stdout, stderr)
async fn run(mut c: Command) -> (bool, String, String) {
    let out = tokio::time::timeout(Duration::from_secs(30), c.output())
        .await
        .expect("netevd did not finish")
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn record(log: &EventLog, link: &str, status: ScriptStatus) {
    log.record_run(
        &HookEventV1::new("routable", link, 2, "netlink"),
        Duration::from_millis(4),
        vec![ScriptResult {
            name: "01-notify".into(),
            status,
            exit_code: Some(i32::from(status != ScriptStatus::Ok)),
            duration_ms: 4,
        }],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_over_tls_with_a_token() {
    let s = Server::start(true).await;
    record(&s.log, "eth0", ScriptStatus::Ok);
    record(&s.log, "eth1", ScriptStatus::Failed);

    let mut c = netevd();
    c.args(["status", "-f", "json"]).args(s.client_args());
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["events_processed"], 2);

    // The token may come from the environment instead of a file.
    let mut c = netevd();
    c.args(["events", "--outcome", "failed", "--endpoint", &s.url()])
        .env("NETEVD_API_CA_FILE", &s.ca)
        .env("NETEVD_API_TOKEN", TOKEN);
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(
        out.contains("eth1") && out.contains("1 of 1 scripts failed: 01-notify (exit 1)"),
        "{out}"
    );

    let mut c = netevd();
    c.args(["show", "interface", "lo", "-f", "json"])
        .args(s.client_args());
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    assert!(out.contains("\"loopback\""), "{out}");

    let mut c = netevd();
    c.args(["list", "routes", "-f", "json"])
        .args(s.client_args());
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    serde_json::from_str::<Vec<serde_json::Value>>(&out).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_is_refused_without_trust_or_token() {
    let s = Server::start(true).await;

    let mut c = netevd();
    c.args(["status", "--endpoint", &s.url()])
        .env("NETEVD_API_CA_FILE", &s.ca);
    let (ok, _, err) = run(c).await;
    assert!(!ok);
    assert!(
        err.contains("HTTP 401") && err.contains("--token-file"),
        "{err}"
    );

    let wrong = write(s.dir.path(), "wrong", "not-the-token-0123456789\n", 0o600);
    let mut c = netevd();
    c.args(["events", "--follow", "--endpoint", &s.url()])
        .env("NETEVD_API_CA_FILE", &s.ca)
        .env("NETEVD_API_TOKEN_FILE", &wrong);
    let (ok, _, err) = run(c).await;
    assert!(!ok);
    assert!(err.contains("HTTP 401"), "{err}");
    assert!(!err.contains("not-the-token"), "{err}");

    // A certificate from someone else is not trusted.
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let other_ca = write(s.dir.path(), "other.pem", &other.cert.pem(), 0o644);
    let mut c = netevd();
    c.args(["status", "--endpoint", &s.url()])
        .arg("--ca-file")
        .arg(&other_ca)
        .env("NETEVD_API_TOKEN", TOKEN);
    let (ok, _, err) = run(c).await;
    assert!(!ok);
    assert!(err.contains("TLS handshake"), "{err}");

    // The certificate names `localhost` only.
    let mut c = netevd();
    c.args([
        "status",
        "--endpoint",
        &format!("https://127.0.0.1:{}", s.port),
    ])
    .args(["--ca-file"])
    .arg(&s.ca)
    .env("NETEVD_API_TOKEN", TOKEN);
    let (ok, _, err) = run(c).await;
    assert!(!ok);
    assert!(err.contains("TLS handshake"), "{err}");

    // Plain HTTP gets nothing from the TLS port.
    let mut c = netevd();
    c.args([
        "status",
        "--endpoint",
        &format!("http://localhost:{}", s.port),
    ])
    .env("NETEVD_API_TOKEN", TOKEN);
    let (ok, out, _) = run(c).await;
    assert!(!ok && out.is_empty(), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_clients_do_not_block_tls_and_follow_streams() {
    let s = Server::start(true).await;
    // Connections that never start a handshake.
    let mut silent = Vec::new();
    for _ in 0..8 {
        silent.push(TcpStream::connect(("127.0.0.1", s.port)).await.unwrap());
    }
    let mut c = netevd();
    c.args(["events", "--follow", "-o", "json"])
        .args(s.client_args())
        .stdout(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let log = s.log.clone();
    let publisher = tokio::spawn(async move {
        loop {
            record(&log, "eth7", ScriptStatus::Ok);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let line = tokio::time::timeout(Duration::from_secs(8), lines.next_line())
        .await
        .expect("no event streamed while other handshakes were pending")
        .unwrap()
        .unwrap();
    publisher.abort();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["interface"], "eth7");
    assert_eq!(v["details"]["scripts"][0]["status"], "ok");
    child.kill().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn health_command_exit_status() {
    let s = Server::start(true).await;
    // Probes need no token.
    let mut c = netevd();
    c.args(["health", "--endpoint", &s.url()])
        .env("NETEVD_API_CA_FILE", &s.ca);
    let (ok, out, err) = run(c).await;
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("Status : ok") && out.contains("dbus   : not used"),
        "{out}"
    );

    let s = Server::start(false).await;
    let mut c = netevd();
    c.args(["health", "-f", "json"]).args(s.client_args());
    let (ok, out, err) = run(c).await;
    assert!(!ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["checks"]["hooks"], false);
    assert!(err.contains("not ready"), "{err}");

    let mut c = netevd();
    c.args(["health", "--endpoint", "http://127.0.0.1:1"]);
    let (ok, _, err) = run(c).await;
    assert!(!ok && err.contains("cannot connect"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_need_the_token_and_report_gauges() {
    let metrics = Arc::new(netevd::metrics::Metrics::new().unwrap());
    netevd::metrics::set_global_metrics(metrics);
    let state = Arc::new(RwLock::new(NetworkState::new()));
    state.write().await.add_link("eth0".into(), 2);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let security = ApiSecurity {
        tokens: Some(Arc::new(netevd::api::security::TokenSet::new([TOKEN]))),
        ..Default::default()
    };
    tokio::spawn(
        ApiServer::new(addr.port(), state)
            .with_security(security)
            .serve(listener),
    );
    let get = |auth: String| async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET /metrics HTTP/1.0\r\n{auth}\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    };
    assert!(get(String::new()).await.starts_with("HTTP/1.0 401"));
    let body = get(format!("Authorization: Bearer {TOKEN}\r\n")).await;
    assert!(body.contains("netevd_interfaces_total 1"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn trigger_exit_status_and_json() {
    let t = tempfile::tempdir().unwrap();
    let hooks = t.path().join("routable.d");
    std::fs::create_dir(&hooks).unwrap();
    write(
        &hooks,
        "01-ok",
        "#!/bin/sh\necho \"ran for $LINK\"\n",
        0o755,
    );
    let config = write(t.path(), "netevd.yaml", "hooks:\n  timeout_sec: 5\n", 0o644);
    let trigger = || {
        let mut c = netevd();
        c.arg("-c")
            .arg(&config)
            .args(["trigger", "routable", "-l", "eth3", "--config-root"])
            .arg(t.path())
            // Test containers may run as root.
            .arg("--allow-root");
        c
    };
    let (ok, out, err) = run(trigger()).await;
    assert!(ok, "{err}");
    assert!(out.contains("stdout| ran for eth3"), "{out}");

    write(&hooks, "02-slow", "#!/bin/sh\nsleep 20\n", 0o755);
    let mut c = trigger();
    c.args(["--timeout", "3", "-f", "json"]);
    let (ok, out, err) = run(c).await;
    assert!(!ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v[0]["scripts"][0]["status"], "ok");
    assert_eq!(v[0]["scripts"][1]["status"], "timeout");
    assert!(err.contains("02-slow (timeout)"), "{err}");

    // Journal lines replay.
    let log = EventLog::new(1);
    let rec = log.record_run(
        &HookEventV1::new("routable", "eth9", 9, "netlink"),
        Duration::ZERO,
        Vec::new(),
    );
    let journal = write(
        t.path(),
        "events.jsonl",
        &format!("{}\n", serde_json::to_string(&*rec).unwrap()),
        0o600,
    );
    std::fs::remove_file(hooks.join("02-slow")).unwrap();
    let mut c = netevd();
    c.arg("-c")
        .arg(&config)
        .args(["trigger", "--allow-root", "--config-root"])
        .arg(t.path())
        .arg("--from-file")
        .arg(&journal);
    let (ok, out, err) = run(c).await;
    assert!(ok, "{err}");
    assert!(out.contains("ran for eth9"), "{out}");
}
