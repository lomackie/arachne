#[tokio::main]
async fn main() -> anyhow::Result<()> {
    arachne::agent::run().await
}
