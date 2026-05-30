use anyhow::{Context, Result};
use futures::TryStreamExt;
use ipnet::Ipv4Net;
use k8s_openapi::api::core::v1::Node;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, IpVersion};
use std::net::Ipv4Addr;

const CNI_CONF_PATH: &str = "/etc/cni/net.d/10-arachne.conflist";
const CNI_VERSION: &str = "1.1.0";

#[tokio::main]
async fn main() -> Result<()> {
    let node_name = std::env::var("NODE_NAME").context("NODE_NAME not set")?;
    let client = Client::try_default().await.context("failed to create Kubernetes client")?;

    let pod_cidr = fetch_pod_cidr(&client, &node_name).await?;
    arachne::bpf::ensure_bpffs().context("failed to mount bpffs")?;
    arachne::bpf::attach_node("eth0").context("failed to attach TC to eth0")?;
    write_conflist(&pod_cidr).context("failed to write conflist")?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;

    tokio::select! {
        _ = sigterm.recv() => {},
        res = watch_node_routes(&client, &node_name) => {
            res.context("node route watcher failed")?;
        }
    }
    Ok(())
}

async fn watch_node_routes(client: &Client, my_node: &str) -> Result<()> {
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

                let node_ip = node_internal_ip(&node);
                let cidr_str = node.spec.and_then(|s| s.pod_cidr);
                let (Some(cidr_str), Some(node_ip)) = (cidr_str, node_ip) else { continue };

                let net: Ipv4Net = cidr_str.parse().context("invalid podCIDR")?;
                upsert_route(&handle, net, node_ip).await
                    .with_context(|| format!("upsert route {net} via {node_ip}"))?;
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

async fn fetch_pod_cidr(client: &Client, node_name: &str) -> Result<String> {
    let nodes: Api<Node> = Api::all(client.clone());
    loop {
        let node = nodes.get(node_name).await.context("failed to get node")?;
        if let Some(cidr) = node.spec.and_then(|s| s.pod_cidr) {
            return Ok(cidr);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn write_conflist(pod_cidr: &str) -> Result<()> {
    let conflist = serde_json::json!({
        "cniVersion": CNI_VERSION,
        "name": "arachne",
        "plugins": [{
            "type": "arachne",
            "subnet": pod_cidr
        }]
    });
    std::fs::write(CNI_CONF_PATH, serde_json::to_string_pretty(&conflist)?)
        .context("failed to write conflist")?;
    Ok(())
}
