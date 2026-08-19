//! GET /api/crypto-scan.

use axum::extract::State;
use axum::Json;

use crate::crypto_scan::{scan_crypto_memory, CryptoScanResponse};
use crate::state::AppState;

pub async fn crypto_scan_handler(
    State(state): State<AppState>,
) -> Result<Json<CryptoScanResponse>, crate::routes::WorkerFailure> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || crypto_scan_response(&inner))
        .await
        .map_err(|err| crate::routes::worker_panic_response("crypto scan", &err))?;
    Ok(Json(response))
}

fn crypto_scan_response(inner: &crate::state::AppStateInner) -> CryptoScanResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let status = status.status_str();
            return CryptoScanResponse {
                status,
                scanned: 0,
                primitives: Vec::new(),
                any_hit: false,
            };
        }
    };
    if mem.bytes.is_empty() {
        return CryptoScanResponse {
            status: "ready",
            scanned: 0,
            primitives: Vec::new(),
            any_hit: false,
        };
    }
    scan_crypto_memory(mem)
}
