//! traceMiku v2 server library.
//!
//! The bin (`main.rs`) is a thin wrapper; everything else lives here so
//! integration tests can exercise the same code path.

pub mod bn_sidecar;
pub mod crypto_scan;
pub mod jni_scan;
pub mod phase_scan;
pub mod routes;
pub mod state;
pub mod taint_graph;

use std::path::PathBuf;

use anyhow::Context;
use axum::Router;

pub use state::AppState;

pub fn build_router(call_dir: PathBuf) -> anyhow::Result<Router> {
    let state = AppState::load(call_dir).context("load AppState")?;
    Ok(routes::router(state))
}

pub fn build_router_with_memshadow(call_dir: PathBuf) -> anyhow::Result<Router> {
    let state = AppState::load(call_dir).context("load AppState")?;
    let _ = state.inner.memshadow();
    Ok(routes::router(state))
}
