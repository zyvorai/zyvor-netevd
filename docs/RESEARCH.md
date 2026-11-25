# Research: network-event automation and hook-script safety

Scope: what comparable tools do when a network event must trigger scripts,
what netevd lacks, and which gaps this release closes. Statements marked
**[U]** were not read from a fetched page (search-result snippets or
background knowledge) and should be verified before being relied on.

## What the field does

### NetworkManager dispatcher

Read from the NetworkManager dispatcher documentation
(<https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html>):

- Scripts live in `/etc/NetworkManager/dispatcher.d` and
  `/usr/lib/NetworkManager/dispatcher.d`; each must be a regular executable
  file **owned by root**, **not writable by group or other**, and **not
  setuid**.
- They run alphabetically, one at a time, asynchronously from the daemon.
  Once queued a script always runs, even if a later event made it obsolete.
- Scripts that run too long are killed; the page gives no figure.
  Long-running work is expected to fork and return.
- `pre-up` / `pre-down` block activation; symlinks into `no-wait.d/` run
  immediately and in parallel.
- Arguments are the interface and action; the environment carries
  `CONNECTION_*`, `DEVICE_*`, `IP4_*`, `DHCP4_*` and so on.

Gap in netevd: it ran any executable regular file, including group- or
world-writable ones, and had no ownership check.

### networkd-dispatcher

Read from the Debian man page
(<https://manpages.debian.org/bookworm/networkd-dispatcher/networkd-dispatcher.8.en.html>):
scripts live in per-state directories (`routable.d/`, `degraded.d/`, ...),
search path `/etc/networkd-dispatcher:/usr/lib/networkd-dispatcher` (earliest
wins), `--run-startup-triggers` replays pre-existing state at startup. The
page does not document ownership rules, environment or timeouts.

Security history: Ubuntu USN-5395-1
(<https://ubuntu.com/security/notices/USN-5395-1>) covers CVE-2022-29799 and
CVE-2022-29800, "incorrectly handled internal scripts", leading to a race
condition and privilege escalation (page read). That the first of the two was
a directory traversal through the unsanitised operational state, and the
second a time-of-check/time-of-use race, comes from search snippets **[U]**.
The lesson netevd already applies for state names (`validate_state_name`
allow-list); the TOCTOU lesson is still open (see caveats).

### Other NetworkManager issues

Search snippets only **[U]**: CVE-2026-10805 (command injection through a
crafted MUD URL when NetworkManager is configured to use dhclient) and
CVE-2024-9050 (libreswan VPN plugin `leftupdown` script injection). Both are
"untrusted network-supplied string reaches a script" bugs, which is exactly
netevd's threat model: DHCP and router-advertisement data into `$ADDRESSES`,
`$DNS`, hostnames.

### systemd hardening primitives

Read from systemd.exec(5)
(<https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>,
first 100k characters) and systemd-run(1)
(<https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>):
`NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`,
`PrivateDevices=`, `ReadWritePaths=`/`InaccessiblePaths=`,
`CapabilityBoundingSet=`, `LimitNOFILE=`, `ProtectProc=`, `DynamicUser=`.
`systemd-run -p Prop=value --wait --collect --pipe` runs one command as a
transient service with any of those properties, and waits for it. The page
text read did not cover `SystemCallFilter=` or `RestrictAddressFamilies=`;
they exist in systemd.exec(5) **[U]** for this read.

netevd already ships the unit-level set (SECURITY.md layer 5), which covers
the daemon and therefore every script. What it cannot do in-process is
per-script namespaces or seccomp; those need `systemd-run` or a wrapper
(documented below, not built in).

### nmstate

Read from <https://nmstate.io/>: a declarative, schema-based host network
API (desired state in, current state out), NetworkManager the only provider.
It *configures*; netevd *reacts*. The page did not describe verification or
rollback, so nothing is claimed about them. Relevance: netevd hooks could
call `nmstatectl`, but the daemon itself should stay event-driven and not
grow a state reconciler.

### Kubernetes / Cilium node agents

A search for Cilium node-init and netlink debouncing returned only Cilium
API rate-limiting documentation and workqueue issues, none specific to
netlink **[U]**. The transferable idea (not verified against Cilium code) is
the standard controller pattern: coalesce events per key, then rate limit per
key with a token bucket. That is what the new `hooks.rate_limit` does.

### Event de-duplication, debounce, rate limiting

Background knowledge **[U]**: debounce (trailing edge) merges a burst;
a token bucket bounds the long-run rate of what remains; both need bounded
key tables or a hostile source can exhaust memory by inventing keys.

## What netevd lacked (before this change)

| Gap | Evidence in code | Risk |
|---|---|---|
| No way to ask "what would run for this event?" | `Test` command was a stub; `--dry-run` unused | Operators test by changing the network |
| Config typos silently ignored | serde ignores unknown keys; `validate` printed no line numbers | A misspelt `timout_sec` runs with the default |
| Script policy: any executable ran, hidden/backup files included | `execute_scripts_inner` | Editor backups and group-writable scripts execute as the daemon user |
| Timeout killed only the direct child | `kill_on_drop` on one pid | Grandchildren survive and accumulate |
| Unbounded script output buffered in memory | `wait_with_output` | A chatty script can exhaust memory |
| Daemon `cwd`, `umask`, rlimits inherited | no `pre_exec` | Scripts write into the daemon's working directory |
| Debounce is per window only; unbounded key table | `HookDebouncer` | A flapping link dispatches forever; key churn grows memory |
| `ADDRESSES` accepted newline/tab separators; `.` and `..` accepted as interface names | `split_whitespace`, character-class check | Line smuggling into line-oriented scripts; odd path behaviour in `/sys/class/net/$LINK` |

## Ranked ideas

1. **Script sandbox profile** (built). Closes the most real gaps for the
   least code: environment budget, workdir, umask, rlimits, process-group
   kill, output cap, strict permission mode. Rationale: NM dispatcher's own
   rules (root-owned, not group/other-writable) are the accepted baseline.
2. **`netevd explain` (dry-run and replay)** (built). Highest operator value
   per line; built on the same planning functions as the executor so it
   cannot drift. Replay of a recorded JSONL file doubles as a regression
   test for a configuration.
3. **`netevd check-config`** (built). Cheap, catches the silent-typo class,
   gives line numbers.
4. **Rate limit and bounded key tables** (built). Closes the flapping-link
   and key-churn amplification.
5. Event journal writer (record every dispatched event to JSONL for later
   `explain --from-file`). Not built: the audit module already records
   activity; the replay half is delivered, a writer can follow. Needs
   rotation and permission design.
6. Per-script `systemd-run` execution mode. Not built: pulls in a systemd
   dependency the daemon does not otherwise have at runtime and cannot be
   exercised without systemd. Documented as a wrapper recipe instead.
7. In-process seccomp. Rejected: a filter strict enough to matter breaks
   arbitrary user scripts; the right layer is the unit file or `systemd-run`.
8. nmstate-style desired-state reconciliation. Rejected: different product
   identity (configure vs react).
9. NM-style `pre-up` blocking hooks and `no-wait.d` parallelism. Not built:
   netevd observes; blocking activation would change its role. `max_parallel`
   remains reserved.

## Sources

- <https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html>
- <https://manpages.debian.org/bookworm/networkd-dispatcher/networkd-dispatcher.8.en.html>
- <https://ubuntu.com/security/notices/USN-5395-1>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>
- <https://nmstate.io/>
- <https://nvd.nist.gov/vuln/detail/CVE-2022-29799> **[U]** (search result, not fetched)
- <https://nvd.nist.gov/vuln/detail/CVE-2026-10805> **[U]** (search result, not fetched)
- <https://access.redhat.com/security/cve/CVE-2024-9050> **[U]** (search result, not fetched)
- <https://docs.cilium.io/en/latest/configuration/api-rate-limiting/> **[U]** (search result, not fetched)

## Third round: operating the daemon

Pages fetched for this round:

- networkd-broker (<https://github.com/bpetlert/networkd-broker>): per-state directories, root-owned executables, 20 s
  default timeout, `-nowait` scripts, `--startup-triggers`. The README mentions no network API.
- networkd-dispatcher man page (<https://manpages.debian.org/unstable/networkd-dispatcher/networkd-dispatcher.8.en.html>):
  options are script directories, startup triggers and verbosity; no way to fire an event by hand is listed.
- NetworkManager dispatcher (<https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html>): script stdout
  is consumed by the dispatcher, so debugging output goes to stderr and the journal; `connectivity-change` and `dns-change`
  actions exist.
- Prometheus exporter-toolkit web configuration
  (<https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md>): the shared expectation for
  exporters is optional TLS (minimum TLS 1.2), client certificates and bcrypt basic auth.
- Kubernetes, API server bypass risks (<https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/>): node
  agent APIs should refuse anonymous access, restrict the network path, and never expose an unauthenticated port.
- adnanh/webhook rules (<https://github.com/adnanh/webhook/blob/master/docs/Hook-Rules.md>): HMAC payload checks and IP
  allow-lists for event receivers.

| Idea | Decision |
|---|---|
| TLS and token authentication on the API | Built. `api.tls` existed in the configuration but did nothing, which was the larger problem. Bearer tokens rather than bcrypt basic auth: machine clients, no password hashing cost, supported by Prometheus. |
| HTTPS and token support in the CLI | Built, so the secured API stays usable. |
| Truthful liveness and readiness | Built. |
| Per-script results in journal, API and metrics | Built. Without them "did my hook work?" needed debug logs. |
| Fire an event by hand (`netevd trigger`) | Built, local only. A remote trigger endpoint was rejected: it would turn API access into code execution. |
| Client certificates, roles | Not built; a reverse proxy covers them. |
| Outgoing signed webhooks | Not built; a hook script with `curl` and `openssl` does it without new network code in the daemon. |
| `-nowait` / parallel scripts | Not built; `hooks.max_parallel` remains reserved. |
