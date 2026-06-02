mod conntrack;
mod endpoints;
mod routes;
mod services;
mod startup;

use anyhow::{Context, Result};
use std::time::Duration;

use kube::Client;

use routes::watch_node_routes;
use services::watch_services_and_slices;
use startup::{fetch_pod_cidr, write_conflist};

/// Run the long-lived agent: attach the datapath, write CNI config, then watch
/// the Kubernetes API to keep node routes and service load-balancing in sync
/// until SIGTERM.
pub async fn run() -> Result<()> {
    let node_name = std::env::var("NODE_NAME").context("NODE_NAME not set")?;
    let client = Client::try_default().await.context("failed to create Kubernetes client")?;

    let pod_cidr = fetch_pod_cidr(&client, &node_name).await?;
    crate::bpf::ensure_bpffs().context("failed to mount bpffs")?;
    crate::bpf::attach_node("eth0").context("failed to attach TC to eth0")?;
    write_conflist(&pod_cidr).context("failed to write conflist")?;

    // Attaching the node program pins the ENDPOINTS map, so it is open by now.
    // Sweep entries leaked by pods that died without a CNI DEL before serving.
    endpoints::reconcile();

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;

    let mut counter_tick = tokio::time::interval(Duration::from_secs(30));
    counter_tick.tick().await;

    let ct_timeouts = conntrack::timeouts();
    let mut gc_tick = tokio::time::interval(conntrack::gc_interval());
    gc_tick.tick().await;

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            res = watch_node_routes(&client, &node_name) => {
                res.context("node route watcher failed")?;
            }
            res = watch_services_and_slices(&client) => {
                res.context("service/slice watcher failed")?;
            }
            _ = counter_tick.tick() => {
                match crate::bpf::read_counters() {
                    Ok(c) => eprintln!(
                        "counters: map_hit={} fib_miss={} redirect={} service_punt={} svc_dnat={} svc_snat={} ct_evict={}",
                        c.map_hit, c.fib_miss, c.redirect, c.service_punt, c.service_dnat, c.service_snat, c.ct_evict
                    ),
                    Err(e) => eprintln!("counters: read failed: {e}"),
                }
            }
            _ = gc_tick.tick() => {
                conntrack::gc_tick(ct_timeouts);
            }
        }
    }
    Ok(())
}
