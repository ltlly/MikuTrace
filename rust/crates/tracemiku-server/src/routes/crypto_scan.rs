//! GET /api/crypto-scan.

use axum::extract::State;
use axum::Json;

use crate::crypto_scan::{scan_crypto_memory, CryptoScanResponse};
use crate::state::AppState;

pub async fn crypto_scan_handler(State(state): State<AppState>) -> Json<CryptoScanResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || crypto_scan_response(&inner))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "crypto scan worker failed: {err}");
                CryptoScanResponse {
                    status: "error",
                    scanned: 0,
                    primitives: Vec::new(),
                    any_hit: false,
                }
            }),
    )
}

fn crypto_scan_response(inner: &crate::state::AppStateInner) -> CryptoScanResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
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
    if let Some(cached) = inner.crypto_scan.get() {
        return cached.clone();
    }
    let response = scan_crypto_memory(mem);
    let _ = inner.crypto_scan.set(response.clone());
    response
}
