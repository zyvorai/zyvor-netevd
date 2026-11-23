// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Script execution with input validation
//!
//! This module executes user scripts with environment variables from potentially
//! untrusted sources (DHCP, network configurations). All environment values are
//! validated and sanitized before being passed to scripts.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::system::sandbox::{self, SandboxConfig, ScriptMeta, Verdict};

const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for output readers after the script exits (a daemonized
/// grandchild may keep the pipe open).
const OUTPUT_GRACE: Duration = Duration::from_millis(200);

/// One file found in a hook directory and what would happen to it.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedScript {
    pub name: String,
    pub path: PathBuf,
    pub verdict: Verdict,
}

/// List a hook directory in execution order, with a verdict per entry.
/// Nothing is executed. A missing directory yields an empty plan.
pub fn plan_directory(
    dir: &Path,
    cfg: &SandboxConfig,
    daemon_uid: u32,
) -> std::io::Result<Vec<PlannedScript>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let verdict = match sandbox::script_name_ok(&name) {
            Err(why) => Verdict::Skip(why),
            // metadata() follows symlinks: the target is what gets judged.
            Ok(()) => match std::fs::metadata(&path) {
                Ok(m) => sandbox::judge_script(
                    &ScriptMeta {
                        is_file: m.is_file(),
                        mode: m.mode(),
                        uid: m.uid(),
                    },
                    cfg,
                    daemon_uid,
                ),
                Err(e) => Verdict::Skip(format!("cannot stat: {e}")),
            },
        };
        out.push(PlannedScript {
            name,
            path,
            verdict,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Execute all scripts in a directory with a caller-supplied timeout.
pub async fn execute_scripts_with_timeout(
    directory: &str,
    env_vars: HashMap<String, String>,
    timeout: Duration,
) -> Result<()> {
    execute_scripts_with(directory, env_vars, timeout, &sandbox::global()).await
}

/// Execute all scripts in a directory with provided environment variables
pub async fn execute_scripts(directory: &str, env_vars: HashMap<String, String>) -> Result<()> {
    execute_scripts_with(directory, env_vars, SCRIPT_TIMEOUT, &sandbox::global()).await
}

/// Execute all scripts in a directory under an explicit sandbox profile.
pub async fn execute_scripts_with(
    directory: &str,
    env_vars: HashMap<String, String>,
    timeout: Duration,
    cfg: &SandboxConfig,
) -> Result<()> {
    let dir_path = Path::new(directory);

    if !dir_path.exists() {
        debug!("Script directory does not exist: {}", directory);
        return Ok(());
    }
    if !dir_path.is_dir() {
        warn!("Script path is not a directory: {}", directory);
        return Ok(());
    }

    let uid = nix::unistd::Uid::effective().as_raw();
    let plan = plan_directory(dir_path, cfg, uid)
        .with_context(|| format!("Failed to read directory: {}", directory))?;

    let mut scripts = Vec::new();
    for p in plan {
        match p.verdict {
            Verdict::Run => scripts.push(p.path),
            Verdict::Skip(why) => debug!("Skipping {:?}: {}", p.path, why),
        }
    }
    if scripts.is_empty() {
        debug!("No executable scripts found in: {}", directory);
        return Ok(());
    }

    info!("Executing {} scripts in: {}", scripts.len(), directory);

    for script_path in scripts {
        match execute_script(&script_path, &env_vars, timeout, cfg).await {
            Ok(_) => info!("Successfully executed script: {:?}", script_path),
            Err(e) => warn!("Failed to execute script {:?}: {}", script_path, e),
        }
    }
    Ok(())
}

/// Read a pipe to the end, keeping at most `cap` bytes.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
    sink: Arc<Mutex<Vec<u8>>>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut g = sink.lock().unwrap();
                let room = cap.saturating_sub(g.len());
                g.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}

type Captured = (Arc<Mutex<Vec<u8>>>, Option<tokio::task::JoinHandle<()>>);

fn spawn_reader<R>(r: Option<R>, cap: usize) -> Captured
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let sink = Arc::new(Mutex::new(Vec::new()));
    let handle = r.map(|r| tokio::spawn(read_capped(r, cap, sink.clone())));
    (sink, handle)
}

/// Execute a single script with environment variables
///
/// Variables are validated by `sandbox::prepare_env`; dangerous values are
/// dropped with a warning. The child runs in its own process group so a
/// timeout kills grandchildren too.
async fn execute_script(
    script_path: &Path,
    env_vars: &HashMap<String, String>,
    timeout: Duration,
    cfg: &SandboxConfig,
) -> Result<()> {
    debug!("Executing script: {:?}", script_path);

    let prepared = sandbox::prepare_env(env_vars, cfg, &|k| std::env::var(k).ok());
    if !prepared.rejected.is_empty() {
        warn!(
            "Rejected {} environment variables for script {:?}: {}",
            prepared.rejected.len(),
            script_path,
            prepared
                .rejected
                .iter()
                .map(|(k, why)| format!("{k} ({why})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut cmd = Command::new(script_path);
    cmd.env_clear();
    cmd.envs(&prepared.vars);
    cmd.current_dir(&cfg.workdir);
    cmd.process_group(0);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    let child_cfg = cfg.clone();
    // SAFETY: the closure only calls async-signal-safe functions
    // (setrlimit, umask) between fork and exec.
    unsafe {
        cmd.pre_exec(move || sandbox::apply_in_child(&child_cfg));
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn script: {:?}", script_path))?;
    let pid = child.id();
    let (out_sink, out_task) = spawn_reader(child.stdout.take(), cfg.max_output_bytes);
    let (err_sink, err_task) = spawn_reader(child.stderr.take(), cfg.max_output_bytes);

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(r) => r.with_context(|| format!("Failed to execute script: {:?}", script_path))?,
        Err(_) => {
            if let Some(pid) = pid {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = child.kill().await;
            anyhow::bail!(
                "Script {:?} timed out after {}s (process group killed)",
                script_path,
                timeout.as_secs()
            );
        }
    };

    for t in [out_task, err_task].into_iter().flatten() {
        // A grandchild may still hold the pipe; keep what we have.
        let _ = tokio::time::timeout(OUTPUT_GRACE, t).await;
    }
    let stdout = out_sink.lock().unwrap().clone();
    let stderr = err_sink.lock().unwrap().clone();

    if !stdout.is_empty() {
        debug!("Script stdout: {}", String::from_utf8_lossy(&stdout).trim());
    }
    if !stderr.is_empty() {
        let stderr = String::from_utf8_lossy(&stderr);
        if status.success() {
            debug!("Script stderr: {}", stderr.trim());
        } else {
            warn!("Script stderr: {}", stderr.trim());
        }
    }

    if !status.success() {
        anyhow::bail!("Script {:?} exited with status: {}", script_path, status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn write_script(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn plan_orders_and_flags_hostile_names() {
        let t = tempfile::tempdir().unwrap();
        write_script(t.path(), "02-b.sh", "#!/bin/sh\n", 0o755);
        write_script(t.path(), "01-a.sh", "#!/bin/sh\n", 0o755);
        write_script(t.path(), ".hidden", "#!/bin/sh\n", 0o755);
        write_script(t.path(), "03-c.sh~", "#!/bin/sh\n", 0o755);
        write_script(t.path(), "04-data", "x", 0o644);
        std::fs::create_dir(t.path().join("05-dir")).unwrap();
        symlink("/nonexistent/target", t.path().join("06-dangling")).unwrap();
        let plan = plan_directory(t.path(), &SandboxConfig::default(), 0).unwrap();
        let names: Vec<_> = plan.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                ".hidden",
                "01-a.sh",
                "02-b.sh",
                "03-c.sh~",
                "04-data",
                "05-dir",
                "06-dangling"
            ]
        );
        let runs: Vec<_> = plan
            .iter()
            .filter(|p| p.verdict == Verdict::Run)
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(runs, ["01-a.sh", "02-b.sh"]);
    }

    #[test]
    fn plan_missing_dir_is_empty() {
        let t = tempfile::tempdir().unwrap();
        assert!(
            plan_directory(&t.path().join("nope.d"), &SandboxConfig::default(), 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn strict_mode_skips_writable_scripts() {
        let t = tempfile::tempdir().unwrap();
        write_script(t.path(), "01-ok.sh", "#!/bin/sh\n", 0o750);
        write_script(t.path(), "02-bad.sh", "#!/bin/sh\n", 0o775);
        let uid = nix::unistd::Uid::effective().as_raw();
        let cfg = SandboxConfig {
            strict_script_perms: true,
            ..Default::default()
        };
        let plan = plan_directory(t.path(), &cfg, uid).unwrap();
        assert_eq!(plan[0].verdict, Verdict::Run);
        assert!(matches!(plan[1].verdict, Verdict::Skip(_)));
    }

    // The tests below run tiny shell scripts from a temporary directory;
    // they never touch network configuration.

    #[tokio::test]
    async fn script_sees_scrubbed_env_and_workdir() {
        let t = tempfile::tempdir().unwrap();
        let out = t.path().join("out");
        let hooks = t.path().join("h.d");
        std::fs::create_dir(&hooks).unwrap();
        write_script(
            &hooks,
            "01.sh",
            &format!(
                "#!/bin/sh\n{{ echo \"LINK=$LINK\"; echo \"SECRET=${{SECRET:-unset}}\"; echo \"EVIL=${{EVIL:-unset}}\"; pwd; ulimit -c; }} > {}\n",
                out.display()
            ),
            0o755,
        );
        std::env::set_var("SECRET", "leak");
        execute_scripts_with(
            hooks.to_str().unwrap(),
            env(&[("LINK", "eth0"), ("EVIL", "$(touch /tmp/pwned)")]),
            Duration::from_secs(5),
            &SandboxConfig::default(),
        )
        .await
        .unwrap();
        let got = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            got.lines().collect::<Vec<_>>(),
            ["LINK=eth0", "SECRET=unset", "EVIL=unset", "/", "0"]
        );
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        let t = tempfile::tempdir().unwrap();
        let hooks = t.path().join("h.d");
        std::fs::create_dir(&hooks).unwrap();
        let pidfile = t.path().join("pid");
        write_script(
            &hooks,
            "01.sh",
            &format!(
                "#!/bin/sh\nsleep 30 &\necho $! > {}\nwait\n",
                pidfile.display()
            ),
            0o755,
        );
        execute_scripts_with(
            hooks.to_str().unwrap(),
            env(&[]),
            Duration::from_millis(600),
            &SandboxConfig::default(),
        )
        .await
        .unwrap();
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok();
        assert!(!alive, "grandchild survived the timeout");
    }

    #[tokio::test]
    async fn output_flood_is_capped_and_does_not_hang() {
        let t = tempfile::tempdir().unwrap();
        let hooks = t.path().join("h.d");
        std::fs::create_dir(&hooks).unwrap();
        write_script(
            &hooks,
            "01.sh",
            "#!/bin/sh\nhead -c 5000000 /dev/zero | tr '\\0' x\n",
            0o755,
        );
        let cfg = SandboxConfig {
            max_output_bytes: 1024,
            ..Default::default()
        };
        execute_scripts_with(
            hooks.to_str().unwrap(),
            env(&[]),
            Duration::from_secs(10),
            &cfg,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn read_capped_keeps_only_cap() {
        let data = vec![b'a'; 10_000];
        let sink = Arc::new(Mutex::new(Vec::new()));
        read_capped(&data[..], 100, sink.clone()).await;
        assert_eq!(sink.lock().unwrap().len(), 100);
    }

    #[tokio::test]
    async fn rlimit_nofile_applies() {
        let t = tempfile::tempdir().unwrap();
        let hooks = t.path().join("h.d");
        std::fs::create_dir(&hooks).unwrap();
        let out = t.path().join("out");
        write_script(
            &hooks,
            "01.sh",
            &format!("#!/bin/sh\nulimit -n > {}\n", out.display()),
            0o755,
        );
        let cfg = SandboxConfig {
            rlimit_nofile: 64,
            ..Default::default()
        };
        execute_scripts_with(
            hooks.to_str().unwrap(),
            env(&[]),
            Duration::from_secs(5),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "64");
    }
}
