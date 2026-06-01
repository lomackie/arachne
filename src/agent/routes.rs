use anyhow::{Context, Result};
use futures::TryStreamExt;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use k8s_openapi::api::core::v1::Node;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, IpVersion};

// ── Node route watcher ────────────────────────────────────────────────────────

pub async fn watch_node_routes(client: &Client, my_node: &str) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .context("failed to open netlink connection")?;
    tokio::spawn(connection);

    let nodes: Api<Node> = Api::all(client.clone());
    let stream = watcher::watcher(nodes, watcher::Config::default());
    tokio::pin!(stream);

    while let Some(event) = stream.try_next().await.context("node watch error")? {
        match event {
            Event::Apply(node) | Event::InitApply(node) => {
                let Some(name) = node.metadata.name.as_deref() else { continue };
                if name == my_node { continue }

                let Some(cidr_str) = node.spec.as_ref().and_then(|s| s.pod_cidr.as_deref()) else { continue };
                let net: Ipv4Net = cidr_str.parse().context("invalid podCIDR")?;

                if node_is_ready(&node) {
                    let Some(node_ip) = node_internal_ip(&node) else { continue };
                    upsert_route(&handle, net, node_ip).await
                        .with_context(|| format!("upsert route {net} via {node_ip}"))?;
                } else {
                    delete_route(&handle, net).await
                        .with_context(|| format!("delete route for NotReady node {name}: {net}"))?;
                }
            }
            Event::Delete(node) => {
                let Some(cidr_str) = node.spec.and_then(|s| s.pod_cidr) else { continue };
                let net: Ipv4Net = cidr_str.parse().context("invalid podCIDR")?;
                delete_route(&handle, net).await
                    .with_context(|| format!("delete route {net}"))?;
            }
            Event::Init | Event::InitDone => {}
        }
    }
    Ok(())
}

fn node_is_ready(node: &Node) -> bool {
    node.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conds| conds.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
        .unwrap_or(false)
}

fn node_internal_ip(node: &Node) -> Option<Ipv4Addr> {
    node.status.as_ref()?
        .addresses.as_ref()?
        .iter()
        .find(|a| a.type_ == "InternalIP")
        .and_then(|a| a.address.parse().ok())
}

async fn upsert_route(handle: &Handle, net: Ipv4Net, via: Ipv4Addr) -> Result<()> {
    handle.route().add()
        .v4()
        .destination_prefix(net.network(), net.prefix_len())
        .gateway(via)
        .replace()
        .execute()
        .await
        .with_context(|| format!("netlink route replace {net} via {via}"))?;
    Ok(())
}

async fn delete_route(handle: &Handle, net: Ipv4Net) -> Result<()> {
    let mut routes = handle.route().get(IpVersion::V4).execute();
    while let Some(route) = routes.try_next().await.context("enumerate routes")? {
        if route_matches_net(&route, net) {
            handle.route().del(route).execute().await
                .with_context(|| format!("netlink route del {net}"))?;
            return Ok(());
        }
    }
    Ok(())
}

fn route_matches_net(route: &RouteMessage, net: Ipv4Net) -> bool {
    route.header.destination_prefix_length == net.prefix_len()
        && route.attributes.iter().any(|attr| {
            matches!(attr, RouteAttribute::Destination(RouteAddress::Inet(ip)) if *ip == net.network())
        })
}
