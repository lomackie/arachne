use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Node;
use kube::{Api, Client};

const CNI_CONF_PATH: &str = "/etc/cni/net.d/10-arachne.conflist";
const CNI_VERSION: &str = "1.1.0";

#[tokio::main]
async fn main() -> Result<()> {
    let node_name = std::env::var("NODE_NAME").context("NODE_NAME not set")?;
    let client = Client::try_default().await.context("failed to create Kubernetes client")?;

    let pod_cidr = fetch_pod_cidr(&client, &node_name).await?;
    write_conflist(&pod_cidr).context("failed to write conflist")?;

    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?
        .recv()
        .await;
    Ok(())
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
