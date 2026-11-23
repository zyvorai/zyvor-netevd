# Changelog

## Unreleased

### Dependency and toolchain upgrades

- Major bumps: `netlink-packet-route` 0.33 -> 0.34 (this also removes a duplicate copy: `rtnetlink` 0.24 already pulled 0.34),
  `netlink-proto` 0.13 -> 0.14, `nix` 0.31 -> 0.32. No source changes were needed.
- `cargo update` (tokio 1.54, hyper 1.12, zbus 6.5, uuid 1.29, regex 1.13, ...). Manifest floors raised to match.
- Removed unused dependencies: `ini`, `ipnetwork`, `signal-hook`, `signal-hook-tokio`, `tokio-stream`.
- MSRV 1.87 -> 1.91: forced by the transitive `notify-types` 2.3 (zbus 6.5 and uuid 1.29 need 1.89). The `msrv` CI job follows.
  The optional `ebpf` feature (aya 0.16) declares rust 1.98.
- Held back: `netlink-packet-core` stays at 0.9 (the only newer release is 1.0.0-rc2, a prerelease, and `rtnetlink` 0.24
  still depends on 0.9). `serde_yaml` 0.9 is deprecated upstream and has no drop-in successor in this tree; left as is.
- Clippy (Rust 1.100) cleanups so `-D warnings` passes: eBPF imports gated on the `ebpf` feature, `Coalescer::is_empty`,
  `ObsEvent::to_hook` by value, criterion `black_box` -> `std::hint::black_box`, redundant `homepage`.
- CI: `actions/checkout` v7, `actions/cache` v6, `github/codeql-action` v4. Unverified, left unchanged: `codecov/codecov-action`
  (latest v7), `softprops/action-gh-release` (latest v3), `trivy-action`, `lychee-action`, `typos`, `peaceiris/actions-gh-pages`.
- Docker: Alpine image base 3.23 -> 3.24 (tag verified on Docker Hub). Ubuntu stays on the 26.04 LTS (26.10 exists but is not LTS).
  `rust:1-*` builder tags float and are unchanged.
- `requirements-docs.txt` floors: mkdocs >= 1.6.1, mkdocs-material >= 9.8 (PyPI: 1.6.1 / 9.8.2). No Node pins exist in this repo.

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
