---
hero:
  eyebrow: USER GUIDE
  title: REST API (:9090)
---

## Purpose

Query status, interfaces, routes, policy rules, and recent events over HTTP — the same data backing `netevd status`, `list`, `show`, and `events` without SSH or `ip(8)`.

## When to use it

- Automation and config-management probes from a bastion
- Quick inspection when CLI is not installed on a jump host (curl only)
- Integrate with internal dashboards (JSON responses)

## How to get there

- Base URL: `http://127.0.0.1:9090` (default bind **localhost**)
- Config: `api.enabled`, `api.bind_address`, `api.port` in `/etc/netevd/netevd.yaml`
- Remote access: tunnel, or set `bind_address: "0.0.0.0"` together with `api.auth.token_file` and `api.tls`
- With a token configured add `-H "Authorization: Bearer $TOKEN"` to `curl`; the CLI takes `--token-file` (and `--ca-file` for a private CA)

## Operate from CLI

1. Health and version smoke test:

```bash
curl -sf http://127.0.0.1:9090/health | jq .
curl -sf http://127.0.0.1:9090/api/v1/status | jq .
```

2. List interfaces and drill into one:

```bash
curl -sf http://127.0.0.1:9090/api/v1/interfaces | jq .
curl -sf http://127.0.0.1:9090/api/v1/interfaces/eth0 | jq .
```

3. Routes and policy rules:

```bash
curl -sf http://127.0.0.1:9090/api/v1/routes | jq .
curl -sf http://127.0.0.1:9090/api/v1/rules | jq .
```

4. Recent events:

```bash
curl -sf 'http://127.0.0.1:9090/api/v1/events' | jq .
```

5. Request config reload (same as `netevd reload`):

```bash
curl -X POST http://127.0.0.1:9090/api/v1/reload \
  -H 'Content-Type: application/json' \
  -d '{"force":false}' | jq .
```

6. Remote host via SSH tunnel (keeps API on localhost):

```bash
ssh -L 9090:127.0.0.1:9090 root@<host>
curl -sf http://127.0.0.1:9090/api/v1/status | jq .
```

7. CLI equivalents:

```bash
netevd status -f json
netevd list interfaces -f json
netevd events --tail 20 -o json
```

8. **Empty / fail:** `Connection refused` → unit down or `api.enabled: false`; empty event history → normal on fresh install until links change; reload returns `success: false` → restart with `systemctl restart netevd`.

9. **Success:** JSON `success: true` with populated `data`; interface count matches `netevd list interfaces`; `netevd health` exits 0 when the netlink, D-Bus (not used by `dhclient`), hook-service and config checks pass.

## Endpoint reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness: 200 with `status` `ok` or `degraded` and the checks. No token needed |
| GET | `/health/ready` | Readiness: same body, 503 while a check fails. No token needed |
| GET | `/metrics` | Prometheus text on the API port |
| GET | `/api/v1/status` | Daemon summary |
| GET | `/api/v1/interfaces` | All interfaces |
| GET | `/api/v1/interfaces/{name}` | One interface |
| GET | `/api/v1/routes` | Kernel IPv4 and IPv6 routes (all tables but `local`; `?table=N` for one; at most 10000) |
| GET | `/api/v1/rules` | Policy rules |
| GET | `/api/v1/events` | Dispatched-event history. Query: `interface`, `event`, `outcome`, `since` (sequence cursor), `limit` (1-1000, default 100). `details.scripts` lists each script result |
| GET | `/api/v1/events/stream` | Server-Sent Events, one event per message (`id` = sequence). Same `interface` / `event` / `outcome` filters; live only, resume with `since` on `/api/v1/events` |
| POST | `/api/v1/reload` | Config reload request |

## Related pages

- [CLI: status](../cli/status.md)
- [CLI: list / show](../cli/list-show.md)
- [Prometheus metrics](prometheus.md)
