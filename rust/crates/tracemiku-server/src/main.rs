use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tracemiku-server", about = "traceMiku v2 analysis HTTP server")]
struct Cli {
    /// Per-call trace directory (e.g. traces/run1/calls/call_001_*)
    trace_dir: PathBuf,
    /// Listen port. 0 = OS-assigned.
    #[arg(long, default_value_t = 18900)]
    port: u16,
    /// Bind host.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let app = tracemiku_server::build_router(cli.trace_dir.clone()).context("build router")?;
    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    tracing::info!(target: "tracemiku-server",
        "listening on http://{actual}/  trace_dir={}",
        cli.trace_dir.display());

    axum::serve(listener, app).await?;
    Ok(())
}
