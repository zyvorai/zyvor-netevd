// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Startup triggers: synthesise `link-added` / `address-added` hook events for
//! what already exists when the daemon starts, so scripts do not miss links
//! that were configured before netevd (networkd-dispatcher's
//! `--run-startup-triggers`). Enabled by `hooks.startup_triggers`.

use std::net::IpAddr;

use rtnetlink::Handle;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

use super::address::get_ipv4_addresses;
use super::NetworkState;
use crate::hooks::{HookEventV1, InterfaceSelector};

/// Build the startup events. `links` is `(name, ifindex)`; `addrs` yields the
/// addresses present on a link. Links are ordered by ifindex so the result is
/// deterministic; loopback and excluded links are dropped by `selector`.
pub fn build_startup_events(
    links: &[(String, u32)],
    addrs: impl Fn(u32) -> Vec<IpAddr>,
    selector: &InterfaceSelector,
) -> Vec<HookEventV1> {
    let mut links: Vec<&(String, u32)> = links.iter().collect();
    links.sort_by_key(|(_, idx)| *idx);
    let mut out = Vec::new();
    for (name, idx) in links {
        if !selector.allows(name) {
            continue;
        }
        out.push(HookEventV1::new("link-added", name, *idx, "netlink"));
        let a: Vec<String> = addrs(*idx).iter().map(|a| a.to_string()).collect();
        if !a.is_empty() {
            out.push(HookEventV1::new("address-added", name, *idx, "netlink").with_addresses(a));
        }
    }
    out
}

/// Query current addresses and push the startup events into the hook service.
/// Returns how many events were queued.
pub async fn fire_startup_triggers(
    handle: &Handle,
    state: &NetworkState,
    selector: &InterfaceSelector,
    hook_tx: &UnboundedSender<HookEventV1>,
) -> usize {
    let links: Vec<(String, u32)> = state
        .links_by_name
        .iter()
        .map(|(n, i)| (n.clone(), *i))
        .collect();
    let mut by_index = std::collections::HashMap::new();
    for (name, idx) in &links {
        if !selector.allows(name) {
            continue;
        }
        match get_ipv4_addresses(handle, *idx).await {
            Ok(a) => {
                by_index.insert(*idx, a);
            }
            Err(e) => warn!("startup trigger: cannot read addresses of {name}: {e}"),
        }
    }
    let events = build_startup_events(
        &links,
        |i| by_index.get(&i).cloned().unwrap_or_default(),
        selector,
    );
    let n = events.len();
    for e in events {
        let _ = hook_tx.send(e);
    }
    info!("Startup triggers queued {n} hook events");
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel() -> InterfaceSelector {
        InterfaceSelector::from_lists(vec![], vec![]).with_default_excludes()
    }

    #[test]
    fn emits_link_and_address_events_in_ifindex_order() {
        let links = vec![
            ("eth1".to_string(), 3),
            ("eth0".to_string(), 2),
            ("lo".to_string(), 1),
        ];
        let ev = build_startup_events(
            &links,
            |i| match i {
                2 => vec!["192.0.2.10".parse().unwrap()],
                _ => vec![],
            },
            &sel(),
        );
        let seq: Vec<(&str, &str)> = ev
            .iter()
            .map(|e| (e.event.as_str(), e.link.as_str()))
            .collect();
        assert_eq!(
            seq,
            [
                ("link-added", "eth0"),
                ("address-added", "eth0"),
                ("link-added", "eth1"),
            ]
        );
        assert_eq!(ev[1].addresses, ["192.0.2.10"]);
    }

    #[test]
    fn excluded_links_produce_nothing() {
        let links = vec![("docker0".to_string(), 5), ("veth12".to_string(), 6)];
        assert!(build_startup_events(&links, |_| vec![], &sel()).is_empty());
    }
}
