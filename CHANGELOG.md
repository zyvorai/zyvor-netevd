# Changelog

## Unreleased

### Dependency and toolchain upgrades

- Major bumps: `netlink-packet-route` 0.33 -> 0.34 (this also removes a duplicate copy: `rtnetlink` 0.24 already pulled 0.34),
  `netlink-proto` 0.13 -> 0.14, `nix` 0.31 -> 0.32. No source changes were needed.
- `cargo update` (tokio 1.54, hyper 1.12, zbus 6.5, uuid 1.29, regex 1.13, ...). Manifest floors raised to match.
- Removed unused dependencies: `ini`, `ipnetwork`, `signal-hook`, `signal-hook-tokio`, `tokio-stream`.
- MSRV 1.87 -> 1.91: forced by the transitive `notify-types` 2.3 (zbus 6.5 and uuid 1.29 need 1.89). The `msrv` CI job follows.
  The optional `ebpf` feature (aya 0.16) declares rust 1.98; the MSRV is raised to 1.98 so `cargo check --all-features` passes.
- Held back: `netlink-packet-core` stays at 0.9 (the only newer release is 1.0.0-rc2, a prerelease, and `rtnetlink` 0.24
  still depends on 0.9). `serde_yaml` 0.9 is deprecated upstream and has no drop-in successor in this tree; left as is.
- Clippy (Rust 1.100) cleanups so `-D warnings` passes: eBPF imports gated on the `ebpf` feature, `Coalescer::is_empty`,
  `ObsEvent::to_hook` by value, criterion `black_box` -> `std::hint::black_box`, redundant `homepage`.
- CI: `actions/checkout` v7, `actions/cache` v6, `github/codeql-action` v4. Unverified, left unchanged: `codecov/codecov-action`
  (latest v7), `softprops/action-gh-release` (latest v3), `trivy-action`, `lychee-action`, `typos`, `peaceiris/actions-gh-pages`.
- Docker: Alpine image base 3.23 -> 3.24 (tag verified on Docker Hub). Ubuntu stays on the 26.04 LTS (26.10 exists but is not LTS).
  `rust:1-*` builder tags float and are unchanged.
- `requirements-docs.txt` floors: mkdocs >= 1.6.1, mkdocs-material >= 9.8 (PyPI: 1.6.1 / 9.8.2). No Node pins exist in this repo.

### Added

- Event journal: every dispatched hook event (outcome `dispatched`, `failed` or `rate-limited`, duration, error) is kept in a bounded
  in-memory history (`hooks.history_size`, default 1000) and optionally appended to a 0600 JSONL file (`hooks.journal_path`,
  rotated once to `<path>.1` beyond `hooks.journal_max_bytes`). Journal lines are `netevd.event.v1` plus `seq`, `outcome`,
  `duration_ms`, `error`, so `netevd explain --from-file` replays them unchanged.
- REST: `GET /api/v1/events` now returns real history (it was an empty stub) with `interface`, `event`, `since`, `limit` filters;
  new `GET /api/v1/events/stream` (Server-Sent Events). `/api/v1/status` reports real `uptime_seconds` and `events_processed`.
- CLI: `netevd status`, `list interfaces|routes|rules`, `show interface`, `events` (tail, filters, `--follow` over SSE) and `reload`
  now talk to the API through a small built-in HTTP client. Before, they printed fabricated placeholder data (status always showed
  "3600 seconds, 150 events") or nothing. `list scripts` now says it is not served by the API and points at `netevd explain`.
- `hooks.startup_triggers` (off by default): at start, fire `link-added` and `address-added` hooks for existing links that pass the
  interface selector, like networkd-dispatcher `--run-startup-triggers` and networkd-broker `--startup-triggers`.
- Config check knows the new `hooks.*` keys and rejects `history_size: 0` and a relative or `..` `journal_path`.
- Dependencies: `notify` 8.2 -> 9.0 (no source changes; it pulls `xxhash-rust`, BSL-1.0, now allowed in deny.toml), `hyper` 1.12 -> 1.13.

- `netevd check-config` (alias `validate`): line-numbered diagnostics. Reports YAML errors with line, unknown keys (serde silently
  ignored them) with a suggestion, and invalid or risky values (backend, interface names and patterns, ports, TLS, timeouts,
  sandbox and rate-limit settings, filter script names containing `/` or `..`, world-writable config). `--strict` fails on warnings,
  `--format json` for tooling. `netevd -c FILE check-config` now honours the global `--config` (it was ignored).
- `netevd explain <event>`: shows the hook directory, interface-selector decision, filter decision, scripts in order with
  `run` or `skip: reason`, the environment the script would receive and the variables rejected by validation, without executing
  anything. `--from-file events.jsonl` replays recorded `netevd.event.v1` events (malformed lines reported, not fatal).
  `netevd test` now prints the validated environment instead of raw values.
- `hooks.sandbox`: script working directory, umask, environment passthrough list and budget, captured-output cap, optional rlimits
  (nofile, cpu, as, fsize), no core dumps, and `strict_script_perms`. See `docs/hardening.md`.
- `hooks.rate_limit` (token bucket per link and event, off by default) and `hooks.max_pending` (bound on the debouncer key table);
  metric `netevd_hooks_rate_limited_total`.
- `docs/RESEARCH.md` (field survey, ranked ideas, sources) and `docs/hardening.md`.

### Fixed

- A script timeout killed only the direct child; background children survived. The whole process group is now killed.
- Script stdout/stderr was buffered without limit; it is now capped per stream.
- Hidden files and editor/package leftovers (`~`, `.bak`, `.dpkg-old`, ...) in hook directories were executed; they are skipped.
- `ADDRESSES`/`DNS`-style lists accepted newlines and tabs as separators; only spaces separate addresses now.
- `.` and `..` passed interface-name validation.
- The debouncer pending-key table was unbounded.
- Scripts inherited the daemon working directory and umask.

### Other

- Container: `:latest` now points at the Alpine image, and the Trivy container scan covers it. The Ubuntu 26.04 image's
  base packages (`rust-coreutils`, glibc, `tar`, ...) have open CVEs with no upstream fix; `:latest-ubuntu` is still built.

## 0.4.1 — 2026-09-22

- **Observe-only eBPF** (`--features ebpf`): `kfree_skb` → `drops.d`, `tcp_retransmit_skb` → `tcp-retransmit.d`, `tcp_*_reset` → `tcp-reset.d`, with ringbuf drain, CO-RE ports/L4, coalesce, iface/reason filters, and Prometheus `netevd_ebpf_*` metrics.
- glibc container image is Ubuntu 26.04 (`ghcr.io/zyvorai/netevd:latest-ubuntu`). The Alpine image is pinned to 3.23 (`:latest-alpine`).
- `scripts/deploy-remote.sh` builds with `--features ebpf`, installs the BPF object + unit drop-in, and checks attach plus observe hooks.
- Hooks-contract sandbox: tokio 1.52.3, which includes the fix for GHSA-rr8g-9fpq-6wmg.
- Dependency updates since 0.4.0, including tokio 1.53, hyper 1.11.1, zbus 5.19, rtnetlink 0.23, and tower-http 0.7.
- Docs: README eBPF highlight; install tarball name matches the release asset; Prometheus on the API port (`:9090/metrics`).

## 0.4.0 — 2026-09-07

- Release tarball, hook contract, and the operator docs shipped with tag `v0.4.0`.
