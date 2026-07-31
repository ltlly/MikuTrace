#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracemiku_cli::run().await
}
