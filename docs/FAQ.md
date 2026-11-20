---
hero:
  eyebrow: FAQ
  title: FAQ
---

Questions people evaluating netevd actually ask. For "why netevd over X",
see the README's [Instead of...](https://github.com/zyvorai/netevd#instead-of) section — this
FAQ covers what that section doesn't.

## Licensing & cost

**Do I need a license?** Yes. Running netevd requires a commercial license under the
Zyvor Production License v1.0 (sales@zyvor.dev, https://zyvor.dev/buy; a 30-day
trial key is how to evaluate).
See the README's [License](https://github.com/zyvorai/netevd#license) section.

**What does the Enterprise license include?** See the
README's [Enterprise](https://github.com/zyvorai/netevd#enterprise) section and
[`docs/enterprise.md`](enterprise.md) —
briefly: the self-hosted daemon, SLA-backed support and the broader HyperSDK
platform (`netctl`, `cloud-netconfig`).

## Support

**What if I find a bug?** Open a GitHub issue.

**What if I find a security vulnerability?** See [`SECURITY.md`](https://github.com/zyvorai/netevd/blob/main/SECURITY.md)
for private reporting to legal@zyvor.dev — response SLA is documented
there (initial response within 48 hours; critical fixes within 7 days).

**Is there a support SLA?** SLA-backed support is part of the Enterprise
license (sales@zyvor.dev). Bugs are tracked via GitHub Issues.

## Production readiness

**Is this production-ready?** The README's own License section already
states that production use requires a commercial license, and `SECURITY.md`
documents a real defense-in-depth model (privilege drop, `CAP_NET_ADMIN`
only, input validation, systemd hardening) plus an explicit "what netevd
does NOT protect against" section — read that before deploying, since it's
the honest boundary of the security model (e.g. it does not protect
against a malicious script you've already placed in a hook directory, or a
root compromise).

**What's the current version?** 0.4.1. Notes are in [`CHANGELOG.md`](https://github.com/zyvorai/netevd/blob/main/CHANGELOG.md) and [GitHub Releases](https://github.com/zyvorai/netevd/releases).

**How do I install it on another machine?** Use the release tarball, a container (`ghcr.io/zyvorai/netevd:latest-ubuntu` is Ubuntu 26.04; `:latest-alpine` is musl), or `./scripts/deploy-remote.sh <host> [user]` from a checkout. The remote script installs the systemd unit and checks hooks with a `veth-netevd*` pair.

## Platform & compatibility

**Which network managers does it support?** systemd-networkd,
NetworkManager, and dhclient — one daemon handles all three, per the
README's "Why netevd?" table.

**Is there a web dashboard?** No shipped browser console —
[`docs/user/using-the-dashboard.md`](user/using-the-dashboard.md) is
explicit that operators use the CLI, REST API, Prometheus metrics, and the
systemd journal as the primary surfaces; a static dashboard HTML exists
but isn't the primary way to operate netevd.

## Performance

**Are the performance numbers (sub-100ms, 1000+ events/sec) benchmarked
against a specific environment?** The README's Performance table states
the figures; check `.github/workflows/benchmark.yml` for the CI benchmark
job if you need the methodology behind them before relying on the numbers
for capacity planning.
