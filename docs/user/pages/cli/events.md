---
hero:
  eyebrow: USER GUIDE
  title: 'CLI: events'
---

## Purpose

Tail normalized carrier, routable, routes, and manager events from the daemon API — the same stream hooks react to, but for operators debugging link flaps or missing scripts.

## When to use it

- A hook did not fire and you need to see whether netevd saw the event
- You are validating filters in `/etc/netevd/netevd.yaml` while bouncing an interface
- You want a live feed during a change window instead of parsing `journalctl`

## How to get there

- Command: `netevd events`
- Default API: `http://127.0.0.1:9090` (override with `--endpoint http://<host>:9090`)
- Requires `api.enabled: true` in `/etc/netevd/netevd.yaml` and a running `netevd.service`

## Operate from CLI

1. Confirm the daemon and API are up:

```bash
systemctl is-active netevd
curl -sf http://127.0.0.1:9090/health | jq .
```

2. Show the last 20 events (text table):

```bash
netevd events --tail 20
```

3. Follow live events (like `tail -f`):

```bash
netevd events -f
```

4. Filter by interface and event type while testing a link bounce:

```bash
netevd events -f -i eth0 -t routable
```

5. Machine-readable output for automation:

```bash
netevd events --tail 50 -f json --endpoint http://<host>:9090
```

6. Cross-check hook side effects in the journal:

```bash
journalctl -u netevd -f
```

7. **Empty / fail:** API unreachable → check `api.enabled`, bind address, and firewall; events list empty → confirm `system.backend` matches the host (`systemd-networkd`, `NetworkManager`, or `dhclient`) and the interface is not ignored by a YAML filter.

8. **Success:** Events appear within ~100 ms of a link or address change; filtered `-i`/`-t` flags narrow the stream to the interface under test.

## Related pages

- [CLI: status](status.md)
- [Hook: routable](../hooks/routable.md)
- [REST API](../ops/rest-api.md)
- [Common workflows](../../workflows.md)

## Journal and replay

Set `hooks.journal_path` to keep every dispatched event in a JSONL file (mode 0600, rotated once to `<path>.1`). Each line is a
`netevd.event.v1` object plus `seq`, `outcome` (`dispatched`, `failed`, `rate-limited`), `duration_ms` and `error`:

```bash
netevd explain --from-file /var/lib/netevd/events.jsonl
```

`hooks.startup_triggers: true` additionally fires `link-added` and `address-added` hooks for links that already exist when the daemon starts.
