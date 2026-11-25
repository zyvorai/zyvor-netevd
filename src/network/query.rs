// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//! Read-only netlink dumps of interfaces and routes for the REST API. They
//! need no privileges and change nothing.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, RouteMessageBuilder};
use serde::{Deserialize, Serialize};

use crate::api::models::{InterfaceInfo, RouteInfo};

/// Upper bound on routes returned (a full BGP table would be huge).
pub const MAX_ROUTES: usize = 10_000;

fn connect() -> Result<(Handle, tokio::task::JoinHandle<()>)> {
    let (conn, handle, _) = rtnetlink::new_connection().context("cannot open a netlink socket")?;
    Ok((handle, tokio::spawn(conn)))
}

/// Serde form of an operational state, e.g. `up`, `down`, `unknown`.
fn lower<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}").to_ascii_lowercase()
}

fn flag_names(flags: LinkFlags) -> Vec<String> {
    [
        (LinkFlags::Up, "up"),
        (LinkFlags::Broadcast, "broadcast"),
        (LinkFlags::Loopback, "loopback"),
        (LinkFlags::Pointopoint, "pointopoint"),
        (LinkFlags::Running, "running"),
        (LinkFlags::Noarp, "noarp"),
        (LinkFlags::Promisc, "promisc"),
        (LinkFlags::Multicast, "multicast"),
        (LinkFlags::LowerUp, "lower-up"),
    ]
    .into_iter()
    .filter(|(f, _)| flags.contains(*f))
    .map(|(_, n)| n.to_string())
    .collect()
}

fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// All interfaces with their addresses, ordered by index.
pub async fn interfaces() -> Result<Vec<InterfaceInfo>> {
    let (handle, task) = connect()?;
    let result = dump_interfaces(&handle).await;
    task.abort();
    result
}

async fn dump_interfaces(handle: &Handle) -> Result<Vec<InterfaceInfo>> {
    let mut out = Vec::new();
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await.context("link dump failed")? {
        let mut info = InterfaceInfo {
            name: format!("link{}", link.header.index),
            index: link.header.index,
            state: "unknown".into(),
            addresses: Vec::new(),
            mac_address: None,
            mtu: None,
            flags: flag_names(link.header.flags),
        };
        for attr in &link.attributes {
            match attr {
                LinkAttribute::IfName(n) => info.name = n.clone(),
                LinkAttribute::Mtu(m) => info.mtu = Some(*m),
                LinkAttribute::OperState(s) => info.state = lower(s),
                LinkAttribute::Address(a) if !a.is_empty() => info.mac_address = Some(mac(a)),
                _ => {}
            }
        }
        out.push(info);
    }

    let mut addresses: HashMap<u32, Vec<String>> = HashMap::new();
    let mut dump = handle.address().get().execute();
    while let Some(msg) = dump.try_next().await.context("address dump failed")? {
        let mut local = None;
        let mut address = None;
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Local(a) => local = Some(*a),
                AddressAttribute::Address(a) => address = Some(*a),
                _ => {}
            }
        }
        // On point-to-point links `Address` is the peer; `Local` is ours.
        if let Some(ip) = local.or(address) {
            addresses
                .entry(msg.header.index)
                .or_default()
                .push(format!("{ip}/{}", msg.header.prefix_len));
        }
    }
    for i in &mut out {
        i.addresses = addresses.remove(&i.index).unwrap_or_default();
    }
    out.sort_by_key(|i| i.index);
    Ok(out)
}

/// Which routing tables [`routes`] returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteQuery {
    /// Only this table. Without it, every table except `local` (255).
    pub table: Option<u32>,
}

fn route_ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

fn route_info(msg: &RouteMessage, names: &HashMap<u32, String>, v6: bool) -> RouteInfo {
    let mut destination = None;
    let mut gateway = None;
    let mut out_if = None;
    let mut metric = None;
    let mut table = u32::from(msg.header.table);
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Destination(d) => destination = route_ip(d),
            RouteAttribute::Gateway(g) => gateway = route_ip(g),
            RouteAttribute::Oif(i) => out_if = Some(*i),
            RouteAttribute::Priority(p) => metric = Some(*p),
            RouteAttribute::Table(t) => table = *t,
            _ => {}
        }
    }
    let destination = match destination {
        Some(d) => format!("{d}/{}", msg.header.destination_prefix_length),
        None if v6 => "::/0".to_string(),
        None => "0.0.0.0/0".to_string(),
    };
    RouteInfo {
        destination,
        gateway,
        interface: out_if
            .map(|i| names.get(&i).cloned().unwrap_or_else(|| format!("if{i}")))
            .unwrap_or_default(),
        metric,
        table,
    }
}

/// IPv4 and IPv6 routes (at most [`MAX_ROUTES`]).
pub async fn routes(query: &RouteQuery) -> Result<Vec<RouteInfo>> {
    let (handle, task) = connect()?;
    let result = dump_routes(&handle, query).await;
    task.abort();
    result
}

async fn dump_routes(handle: &Handle, query: &RouteQuery) -> Result<Vec<RouteInfo>> {
    let names: HashMap<u32, String> = dump_interfaces(handle)
        .await?
        .into_iter()
        .map(|i| (i.index, i.name))
        .collect();
    let mut out = Vec::new();
    let requests = [
        (
            false,
            RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
        ),
        (
            true,
            RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
        ),
    ];
    for (v6, mut request) in requests {
        // A dump request must not narrow by the builder's default table,
        // protocol, scope or type.
        request.header.table = 0;
        request.header.protocol = Default::default();
        request.header.scope = Default::default();
        request.header.kind = Default::default();
        let mut dump = handle.route().get(request).execute();
        while let Some(msg) = dump.try_next().await.context("route dump failed")? {
            let r = route_info(&msg, &names, v6);
            let wanted = match query.table {
                Some(t) => r.table == t,
                None => r.table != 255,
            };
            if wanted {
                out.push(r);
                if out.len() >= MAX_ROUTES {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every Linux network namespace has a loopback interface, and reading it
    // needs no privileges.

    #[tokio::test]
    async fn loopback_is_reported_from_the_kernel() {
        let all = interfaces().await.unwrap();
        let lo = all.iter().find(|i| i.name == "lo").expect("no lo");
        assert!(lo.flags.contains(&"loopback".to_string()), "{lo:?}");
        assert!(lo.mtu.is_some_and(|m| m > 0));
        assert!(lo.index > 0);
        if lo.flags.contains(&"up".to_string()) {
            assert!(lo.addresses.contains(&"127.0.0.1/8".to_string()), "{lo:?}");
        }
    }

    #[tokio::test]
    async fn route_table_filter() {
        let local = routes(&RouteQuery { table: Some(255) }).await.unwrap();
        assert!(local.iter().all(|r| r.table == 255));
        let main = routes(&RouteQuery::default()).await.unwrap();
        assert!(main.iter().all(|r| r.table != 255));
        let lo_up = interfaces()
            .await
            .unwrap()
            .iter()
            .any(|i| i.name == "lo" && i.flags.contains(&"up".to_string()));
        if lo_up {
            assert!(
                local.iter().any(|r| r.destination.starts_with("127.")),
                "{local:?}"
            );
        }
    }

    #[test]
    fn mac_and_default_route_forms() {
        assert_eq!(mac(&[0, 1, 0xab]), "00:01:ab");
        let msg = RouteMessage::default();
        assert_eq!(
            route_info(&msg, &HashMap::new(), false).destination,
            "0.0.0.0/0"
        );
        assert_eq!(route_info(&msg, &HashMap::new(), true).destination, "::/0");
    }
}
