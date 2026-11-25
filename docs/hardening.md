# Script sandbox, rate limiting, explain and check-config

Operator reference for the hook-safety features. For the event payload and
directories see [the hook contract](hooks-contract.md); for the reasoning see
[RESEARCH.md](RESEARCH.md).

## Script sandbox profile (`hooks.sandbox`)

Every hook script runs directly (never through a shell) with an empty
environment plus validated event variables. The profile tunes the rest. All
keys are optional; defaults keep the previous behaviour except where noted.

```yaml
hooks:
  sandbox:
    workdir: "/"                  # was: the daemon's cwd
    pass_env: [HOME, USER, LANG, TZ]   # copied from the daemon; LD_*, PATH, IFS never are
    max_env_bytes: 262144         # total environment budget; JSON is shed first
    max_output_bytes: 65536       # kept per stream (stdout, stderr); the rest is discarded
    umask: 18                     # decimal; 18 = 0o022, 63 = 0o077
    strict_script_perms: false    # true: refuse group/other-writable, setuid, foreign-owned scripts
    rlimit_nofile: 0              # 0 = leave unchanged
    rlimit_cpu_sec: 0
    rlimit_as_mb: 0
    rlimit_fsize_mb: 0
    no_core_dumps: true
```

Behaviour that is always on:

- Hidden files (`.x`), editor and package leftovers (`~`, `.bak`, `.orig`,
  `.dpkg-old`, `.rpmsave`, ...) and names with control characters are skipped.
  Before, an executable `.foo` in a hook directory ran.
- Symlinks are followed and the **target** is judged.
- On timeout the whole process group is killed, not just the script, so
  background children do not accumulate. Scripts that intentionally daemonize
  must detach (`setsid`) themselves.
- Output beyond `max_output_bytes` is discarded while the pipe is still
  drained, so a chatty script cannot grow daemon memory or block.

`strict_script_perms: true` follows the NetworkManager dispatcher rule:
regular file, not setuid/setgid, not writable by group or others, owned by
root or the daemon user. It is off by default so existing installs do not
change behaviour; turn it on once `check-config` and `explain` show your
scripts pass.

Caveat: the check happens when the directory is listed, shortly before the
script is executed. A local attacker who can already write to the hook
directory can win that race; protect the directory (SECURITY.md checklist).

### Per-script isolation beyond this

The daemon does not create namespaces or install seccomp filters. If a
script needs more, put a small wrapper in the hook directory and let
systemd do it (verified against the systemd-run man page; adjust properties
to your needs):

```sh
#!/bin/sh
# /etc/netevd/routable.d/50-isolated.sh  (root:root 0750)
exec systemd-run --quiet --wait --collect --pipe \
  -p PrivateTmp=yes -p ProtectHome=yes -p ProtectSystem=strict \
  -p NoNewPrivileges=yes -p MemoryMax=64M -p RuntimeMaxSec=20 \
  /usr/local/libexec/real-hook "$LINK"
```

`systemd-run` needs access to the system bus, which the stock unit's
hardening may block; test it with `netevd explain` first and on a lab host.

## Rate limiting (`hooks.rate_limit`)

Debounce merges a burst inside one window; the limiter bounds the long-run
rate per `(link, event)` so a flapping link cannot run your script forever.

```yaml
hooks:
  max_pending: 4096        # distinct keys waiting in the debouncer; past it, new keys dispatch at once
  rate_limit:
    burst: 5               # 0 = off (default)
    per_minute: 30         # sustained refill per key
    max_keys: 2048         # table bound; least recently used key is evicted
```

Dropped dispatches are logged and counted in
`netevd_hooks_rate_limited_total`.

## `netevd explain`

Shows what the daemon would do for an event and executes nothing.

```console
$ netevd explain routable --link eth0 --address 192.168.1.10
$ netevd explain address-added --link docker0           # shows the selector drop
$ netevd explain mtu --config-root ./staging --format json
$ netevd explain --from-file recorded-events.jsonl      # replay netevd.event.v1 lines
```

The report covers: whether the state name is valid (path traversal such as
`../x` is rejected), the hook directory, the interface-selector decision and
the pattern responsible, the configured filter decision (backend events
only), scripts in order with `run` or `skip: <reason>`, the exact
environment the script would receive, and variables rejected by validation
(for example an interface name containing `;`). `--from-file` tolerates
malformed lines (reported on stderr), caps lines at 1 MiB, files at 64 MiB, and the replay at
10,000 events.

## `netevd check-config`

```console
$ netevd check-config -c /etc/netevd/netevd.yaml
/etc/netevd/netevd.yaml:12: warning: unknown key 'hooks.timout_sec' is ignored by netevd (did you mean 'timeout_sec'?)
/etc/netevd/netevd.yaml:15: error: hooks.rate_limit.per_minute is 0: ...
1 error(s), 1 warning(s)
```

- Exit status 1 on any error; `--strict` also fails on warnings (use it in CI).
- `--format json` for tooling. `validate` is kept as an alias.
- Checks: YAML syntax with line, unknown keys with suggestion, backend and
  log level, interface names and glob patterns, bind address, ports, TLS
  files, hook timeout/debounce/limits, sandbox and rate-limit values, eBPF
  switches, filter script names (no `/` or `..`), and a world-writable
  config file.
- Line numbers for unknown keys come from an indentation scanner: block
  style is fully covered, flow style (`{a: 1}`) is not located.

## API access control

The REST API shares one port with `/metrics`. Defaults: bind `127.0.0.1`, no authentication, plain HTTP. Any local user can
then read interface, route and event data, so enable a token on multi-user hosts, and a token plus TLS before binding to
another address.

| Setting | Effect |
|---|---|
| `api.auth.token_file` | Every request needs `Authorization: Bearer <token>`, except `/health` and `/health/ready` (CORS preflights are answered without one). |
| `api.auth.public_metrics` | Also exempt `/metrics`. |
| `api.tls.enabled`, `cert_file`, `key_file` | HTTPS only on `api.port`, TLS 1.2 or 1.3. |

- Token file: one token per line (several allow rotation), `#` comments, at least 16 printable characters, not
  world-accessible and not group-writable. Generate with
  `(umask 027; openssl rand -hex 32 > /etc/netevd/api.token) && chgrp netevd /etc/netevd/api.token`.
- The token file and TLS key are read once at start; restart to pick up changes. The packaged systemd unit runs as user
  `netevd`, so both must be readable by that user (for example `root:netevd`, mode 0640). Only a daemon started as root
  (containers) reads them before dropping privileges.
- Fail closed: if any configured item cannot be loaded, the daemon logs an error and does not serve the API at all. The
  hooks keep running. **Check this after upgrading if you had set `api.tls.enabled`: earlier releases ignored it and served
  plain HTTP.**
- Tokens are compared as SHA-256 digests in constant time. Failed attempts are not rate limited.
- There are no roles: a valid token grants every endpoint. There are no client certificates.
- Prometheus: use `scheme: https`, `authorization: { credentials_file: ... }` and `tls_config: { ca_file: ... }`.
- Kubernetes probes use `/health` (liveness) and `/health/ready` (readiness) with `scheme: HTTPS` when TLS is on.

## Running hooks by hand

`netevd trigger <event>` applies the same interface selector, filter decision, script policy and sandbox as `explain`, then
runs the scripts and prints each status and captured output. It exits non-zero if any script failed or timed out. Scripts run
as the invoking user, so it refuses to run as root unless `--allow-root` is given; use `sudo -u netevd` to match the daemon.
`--from-file` replays journal lines, which **runs the scripts again** for every recorded event.
