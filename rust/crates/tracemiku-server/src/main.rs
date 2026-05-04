use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use clap::Parser;
use tower_http::services::{ServeDir, ServeFile};
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
    /// Frontend dist directory. Defaults to repo-root/frontend/dist.
    #[arg(long)]
    static_dir: Option<PathBuf>,
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
    let static_dir = cli.static_dir.unwrap_or_else(default_static_dir);
    let index_path = Arc::new(static_dir.join("index.html"));
    let app = app
        .route(
            "/",
            get({
                let index_path = index_path.clone();
                move || serve_index(index_path.clone())
            }),
        )
        .route(
            "/index.html",
            get({
                let index_path = index_path.clone();
                move || serve_index(index_path.clone())
            }),
        )
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .fallback_service(
            ServeDir::new(&static_dir)
                .not_found_service(ServeFile::new(static_dir.join("index.html"))),
        );
    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    tracing::info!(target: "tracemiku-server",
        "listening on http://{actual}/  trace_dir={}",
        cli.trace_dir.display());

    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_index(index_path: Arc<PathBuf>) -> impl IntoResponse {
    match tokio::fs::read_to_string(&*index_path).await {
        Ok(html) => (
            [
                (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
                (PRAGMA, "no-cache"),
            ],
            Html(html),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read frontend index failed: {err}"),
        )
            .into_response(),
    }
}

fn default_static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("frontend")
        .join("dist")
}
