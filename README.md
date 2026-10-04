<div align="center">

# netevd

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://github.com/zyvorai/zyvor-netevd/actions/workflows/ci.yml/badge.svg)](https://github.com/zyvorai/zyvor-netevd/actions/workflows/ci.yml)
[![Functional Tests](https://github.com/zyvorai/zyvor-netevd/actions/workflows/functional-tests.yml/badge.svg)](https://github.com/zyvorai/zyvor-netevd/actions/workflows/functional-tests.yml)
[![codecov](https://codecov.io/gh/zyvorai/netevd/branch/main/graph/badge.svg)](https://codecov.io/gh/zyvorai/netevd)
[![Release](https://img.shields.io/github/v/release/zyvorai/zyvor-netevd?sort=semver)](https://github.com/zyvorai/zyvor-netevd/releases)
[![GHCR](https://img.shields.io/badge/GHCR-zyvorai%2Fnetevd-blue?logo=docker)](https://github.com/zyvorai/zyvor-netevd/pkgs/container/netevd)
[![Rust](https://img.shields.io/badge/Rust-tokio%20%C2%B7%20netlink%20%C2%B7%20eBPF-000000?logo=rust)](Cargo.toml)

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=netevd&utm_campaign=readme_hero)
[![30-day PoC](https://img.shields.io/badge/30--day_PoC-000000?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=netevd&utm_campaign=readme_hero)
[![Quickstart](https://img.shields.io/badge/Install_from_the_release_tarball-7d7aff?style=for-the-badge)](#quickstart)

![netevd — Linux network event daemon](docs/social/netevd-hero-dark.jpg)

### Kernel events → your scripts.

**A small Linux daemon that turns network events into drop-in hook scripts.** netevd listens to netlink (and opt-in eBPF) across systemd-networkd, NetworkManager and dhclient, runs your `/etc/netevd/<event>.d/` scripts, fixes multi-homed return paths with automatic policy routing, and exposes a REST API and Prometheus metrics.

**3 network backends** · **17 hook directories** · **Zero polling** · **Automatic policy routing** · **Opt-in eBPF drops and resets**

**[Quickstart](#quickstart)** · **[User guide](docs/user/README.md)** · **[eBPF](docs/user/ebpf.md)** · **[Config example](config/netevd.example.yaml)**

</div>

---

## What's new

Version 0.4.1 ([CHANGELOG.md](CHANGELOG.md)):

| | |
|---|---|
| **Observe-only eBPF** | `--features ebpf`: `kfree_skb` → `drops.d`, `tcp_retransmit_skb` → `tcp-retransmit.d`, `tcp_*_reset` → `tcp-reset.d`, with ringbuf drain, CO-RE ports/L4, coalescing and interface/reason filters. |
| **eBPF metrics** | Prometheus `netevd_ebpf_*` on the API port (`:9090/metrics`). |
| **Container images** | `ghcr.io/zyvorai/netevd:latest-ubuntu` (Ubuntu 26.04) and `:latest-alpine` (Alpine 3.23). |
| **Remote lab prove** | `scripts/deploy-remote.sh` builds with eBPF, installs the BPF object and unit drop-in, and checks attach plus observe hooks. |

---

## Why netevd

| You have… | netevd gives you… |
|-----------|-------------------|
| Scripts that should run when the network changes | Drop a file in `/etc/netevd/routable.d/` |
| Multi-homed return-path breakage | Automatic per-interface tables + policy rules |
| NetworkManager `dispatcher.d` only | One contract for networkd, NM, and dhclient |
| Cron polling `ip addr` | Real netlink multicast (&lt;100 ms) |
| Silent `kfree_skb` / TCP RST netlink never sees | Opt-in eBPF → `drops.d` / `tcp-reset.d` |
| Hand-rolled netlink + debounce + safe exec | Already done — with validated `$LINK` / `$JSON` |

![Capabilities at a glance: Hook, Route, Observe, Operate](docs/ux/readme-capabilities.jpg)

---

## netevd vs NetworkManager dispatcher

![netevd vs NetworkManager dispatcher: one hook contract, every backend](docs/ux/readme-vs.jpg)

| | **netevd** | **NetworkManager dispatcher** |
|---|---|---|
| Where it works | systemd-networkd, NetworkManager and dhclient hosts | Devices managed by NetworkManager |
| Event source | Netlink multicast, backend D-Bus or dhclient leases, optional eBPF ringbuf | NetworkManager's own device and connection actions |
| Script contract | `/etc/netevd/<event>.d/`, 17 directories, `$LINK`, `$STATE`, `$ADDRESSES`, versioned `$JSON` | `/etc/NetworkManager/dispatcher.d/` with interface and action arguments plus environment |
| Multi-homed return path | Automatic per-interface tables (`200 + ifindex`) and `from`/`to` rules | Write it in your scripts |
| Silent drops and TCP resets | Opt-in eBPF tracepoints → `drops.d`, `tcp-retransmit.d`, `tcp-reset.d` | Not in scope |
| API and metrics | REST `/api/v1/*`, Prometheus `/metrics` on `:9090` | Not included |
| **Choose NetworkManager dispatcher when** | | Every host runs NetworkManager and plain per-action scripts are all you need |

---

## How it fits together

![Kernel in; hooks, routes and metrics out: NetworkState, hook directories, policy routing, REST + Prometheus](docs/ux/readme-how-it-works.jpg)

| | |
|---|---|
| Backends | systemd-networkd · NetworkManager · dhclient |
| Hooks | 17 directories (carrier, routable, link/address, eBPF drops…) |
| Latency | &lt;100 ms netlink · zero polling |
| eBPF | Opt-in observe-only: drops / TCP retransmit / TCP reset |
| Ops | Policy routing · REST `:9090` · Prometheus `/metrics` |
| License | Apache-2.0 |

```mermaid
flowchart LR
  Kernel[Netlink_plus_eBPF] --> State[NetworkState]
  State --> Hooks[Hook_scripts]
  State --> Routing[Policy_routing]
  State --> API[REST_and_metrics]
```

1. **Sources** — netlink multicast, backend D-Bus (or dhclient leases), optional eBPF ringbuf  
2. **State** — one `NetworkState` behind `Arc<RwLock>`, updated by Tokio tasks  
3. **Actions** — matching `/etc/netevd/<event>.d/` scripts, policy rules, optional DNS/hostname via D-Bus  

---

## Quickstart

Linux with systemd-networkd, NetworkManager or dhclient. Release tarball (recommended):

```bash
curl -LO https://github.com/zyvorai/zyvor-netevd/releases/download/v0.4.1/netevd-0.4.1-linux-amd64.tar.gz
tar xzf netevd-*-linux-amd64.tar.gz && cd netevd-*-linux-amd64
sudo ./install.sh && sudo systemctl enable --now netevd
```

### 30-second hook

```bash
sudo tee /etc/netevd/routable.d/01-notify.sh >/dev/null <<'EOF'
#!/bin/bash
logger -t netevd "$LINK is routable: $ADDRESSES"
EOF
sudo chmod +x /etc/netevd/routable.d/01-notify.sh
```

When the interface becomes fully routable, that script runs. Same idea for carrier, link add/remove, routes — and, with eBPF, packet drops and TCP resets.

## Install


### From source

```bash
git clone https://github.com/zyvorai/zyvor-netevd.git && cd netevd
cargo build --release
# optional: make -C ebpf && cargo build --release --features ebpf
sudo install -Dm755 target/release/netevd /usr/bin/netevd
sudo install -Dm644 systemd/netevd.service /lib/systemd/system/netevd.service
sudo install -Dm644 config/netevd.example.yaml /etc/netevd/netevd.yaml
sudo systemctl enable --now netevd
```

### Container

```bash
docker pull ghcr.io/zyvorai/netevd:latest-ubuntu   # or :latest-alpine
```

Images ship on every `main` push. Hook scripts have `bash` and `ip`; D-Bus uses zbus (no `dbus`/`systemd` in the image).

### Remote lab prove

```bash
./scripts/deploy-remote.sh <host> [user]   # builds, installs, veth + eBPF attach check
```

## Observe-only eBPF

Netlink covers link, address, and route. It does **not** see silent stack drops or TCP retransmit/RST. With `--features ebpf`, the same hook contract gets three more sources — no XDP/TC deny, no DNS/SNI, no process attribution.

| Kernel source | Hook directory |
|---------------|----------------|
| `skb:kfree_skb` | `/etc/netevd/drops.d/` |
| `tcp:tcp_retransmit_skb` | `/etc/netevd/tcp-retransmit.d/` |
| `tcp:tcp_*_reset` | `/etc/netevd/tcp-reset.d/` |

```bash
make -C ebpf
cargo build --release --features ebpf
sudo install -Dm644 ebpf/netevd-ebpf.o /usr/lib/netevd/netevd-ebpf.o
sudo install -Dm644 systemd/netevd-ebpf.conf /etc/systemd/system/netevd.service.d/ebpf.conf
```

```yaml
ebpf:
  enabled: true
  drops: true
  tcp_reset: true
  min_count: 8
  reasons_deny: ["NO_SOCKET"]
```

Scripts get `$DROP_REASON`, `$PROTOCOL`, `$SPORT`/`$DPORT`, `$COUNT`, `$JSON`. Metrics: `netevd_ebpf_*`. Full guide: [docs/user/ebpf.md](docs/user/ebpf.md).

## Hooks (headline dirs)

| Directory | Fires when |
|-----------|------------|
| `carrier.d/` / `no-carrier.d/` | Link up / down |
| `routable.d/` | Full L3 connectivity |
| `link-added.d/` / `link-removed.d/` | Interface appears / disappears |
| `address-added.d/` | Address configured |
| `drops.d/` / `tcp-reset.d/` | eBPF observe-only (opt-in) |

All 17 directories, env vars, and `netevd.event.v1` JSON: [docs/hooks-contract.md](docs/hooks-contract.md). Use `01-` / `02-` prefixes for order; non-zero exits are logged and do not block siblings.

Every script gets `$LINK`, `$LINKINDEX`, `$STATE`, `$BACKEND`, `$ADDRESSES` (plus `$JSON` / DHCP fields by backend).

## Policy routing

List an interface under `routing.policy_rules` and netevd:

1. Creates table `200 + ifindex`  
2. Adds `from <ip>` / `to <ip>` lookup rules  
3. Installs a default via that interface’s gateway  
4. Tears it down when addresses leave  

```bash
$ ip rule list
32765: from 192.168.1.100 lookup 203

$ ip route show table 203
default via 192.168.1.1 dev eth1
```

## Configuration

Minimal shape — full template: [config/netevd.example.yaml](config/netevd.example.yaml).

```yaml
system:
  backend: "systemd-networkd"    # or NetworkManager | dhclient
monitoring:
  match_patterns: ["eth*", "wg*"]
  exclude: ["lo", "docker*", "veth*"]
hooks:
  debounce_ms: 50
routing:
  policy_rules: ["eth1"]
```

## Security

1. Starts as root, drops to user `netevd`  
2. `CAP_NET_ADMIN` by default; eBPF builds also keep `CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`  
3. Validated interface names / IPs / hostnames — no shell metacharacters  
4. Scripts exec’d directly (not `sh -c`)  
5. systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, …); eBPF re-allows `bpf` / `perf_event_open`  

Details: [SECURITY.md](SECURITY.md).

## Performance

| Metric | Typical |
|--------|---------|
| RSS idle | 3–5 MB |
| CPU idle | &lt;1 % |
| Netlink event latency | &lt;100 ms |
| Event → script | &lt;10 ms |
| Throughput | 1000+ events/s |

## REST API

Same port as Prometheus (default `9090`):

```bash
curl -s localhost:9090/api/v1/status
curl -s localhost:9090/api/v1/interfaces
curl -s localhost:9090/api/v1/events
curl -s localhost:9090/metrics
curl -s localhost:9090/health
```

## Development

```bash
cargo build && cargo test && cargo clippy -- -D warnings
# eBPF unit tests (no CAP_BPF): cargo test --lib ebpf::
```

## Enterprise

| | Community (this repo) | Enterprise |
|---|----------------------|------------|
| Support | [GitHub Issues](https://github.com/zyvorai/zyvor-netevd/issues) | SLA · [sales@zyvor.dev](mailto:sales@zyvor.dev) |
| Scope | Self-hosted hooks + policy routing | Production rollouts, platform integration |
| Platform | netevd | netctl, cloud-netconfig, Zyvor Platform |

[Demo](https://zyvor.dev/demo?utm_source=github&utm_medium=netevd&utm_campaign=readme_edition) · [Pricing](https://zyvor.dev/pricing?utm_source=github&utm_medium=netevd&utm_campaign=readme_edition) · [Contact](https://zyvor.dev/contact?utm_source=github&utm_medium=netevd&utm_campaign=readme_edition) · [docs/enterprise.md](docs/enterprise.md)

## Support

[Book a demo](https://zyvor.dev/schedule?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer) · [30-day PoC](https://zyvor.dev/poc?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer) · fallback: [sales@zyvor.dev](mailto:sales@zyvor.dev)

Maintained by **Susant Sahani** · [Zyvor AI Labs](https://zyvor.dev/?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer). Community help: [Issues](https://github.com/zyvorai/zyvor-netevd/issues) · [SECURITY.md](SECURITY.md).

---

## Maturity

netevd is at **0.4.1** ([CHANGELOG.md](CHANGELOG.md)); release tarballs ship from tags and container images on every `main` push.

| Area | Status |
|---|---|
| Netlink watchers, systemd-networkd / NetworkManager / dhclient backends, hook directories | Default build |
| Automatic policy routing | Default build, per interface listed in `routing.policy_rules` |
| REST API and Prometheus metrics | Default build, `:9090` |
| eBPF drops, TCP retransmit, TCP reset | Opt-in (`--features ebpf`), observe-only: no XDP/TC deny, no DNS/SNI, no process attribution |

What comes next: [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Part of the Zyvor stack

| Product | Role next to netevd |
|---|---|
| **netevd** | Linux network event daemon: netlink and eBPF events into hooks, policy routing, REST and metrics |
| **[netctl](https://github.com/zyvorai/netctl)** | Pairs with netevd: `systemctl`-style network configuration CLI over netlink and systemd D-Bus |
| **[cloud-netconfig](https://github.com/zyvorai/zyvor-cloud-netconfig)** | Pairs with netevd on cloud VMs: secondary IPs and policy routing from cloud metadata |
| **[Netra](https://github.com/zyvorai/zyvor-netra)** | Next to netevd: eBPF network observability and leased emergency network control for Linux and Kubernetes |

Enterprise rollouts cover netevd together with netctl and cloud-netconfig.

→ [zyvor.dev](https://zyvor.dev)

---

## License

netevd is **free and open source** under the [Apache License 2.0](LICENSE) (see [NOTICE](NOTICE)): use, modify and run it in production. That does not change.

**Zyvor Enterprise** adds what production teams ask for: supported releases, deployment and upgrade guidance, priority incident triage, a named technical contact and 24x7 critical intake. Plans and terms: [docs/SUBSCRIPTION-MODEL.md](docs/SUBSCRIPTION-MODEL.md) · [Pricing](https://zyvor.dev/pricing?utm_source=github&utm_medium=netevd&utm_campaign=readme_license) · [sales@zyvor.dev](mailto:sales@zyvor.dev).

Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

<div align="center">

### Let the kernel run your network playbooks

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer)
[![30-day PoC](https://img.shields.io/badge/Start_a_30--day_PoC-000000?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer)
[![Pricing](https://img.shields.io/badge/Pricing-1d1d1f?style=for-the-badge)](https://zyvor.dev/pricing?utm_source=github&utm_medium=netevd&utm_campaign=readme_footer)
[![Contact sales](https://img.shields.io/badge/Contact_sales-7d7aff?style=for-the-badge)](mailto:sales@zyvor.dev?subject=netevd)
[![Star on GitHub](https://img.shields.io/github/stars/zyvorai/zyvor-netevd?style=for-the-badge&logo=github&label=Star&color=2997ff)](https://github.com/zyvorai/zyvor-netevd)

</div>
