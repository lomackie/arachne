use anyhow::{Context, Result};

use k8s_openapi::api::core::v1::Node;
use kube::{Api, Client};

pub const CNI_CONF_PATH: &str = "/etc/cni/net.d/10-arachne.conflist";
pub const CNI_VERSION: &str = "1.1.0";

// ── Startup ───────────────────────────────────────────────────────────────────

pub async fn fetch_pod_cidr(client: &Client, node_name: &str) -> Result<String> {
    let nodes: Api<Node> = Api::all(client.clone());
    loop {
        let node = nodes.get(node_name).await.context("failed to get node")?;
        if let Some(cidr) = node.spec.and_then(|s| s.pod_cidr) {
            return Ok(cidr);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

pub fn write_conflist(pod_cidr: &str) -> Result<()> {
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
