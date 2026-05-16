//! GET /api/crypto-analysis — combined crypto scan (mem + const + instr).
//!
//! Returns MemShadow byte-pattern matches, instruction-level cryptographic
//! constant hits (with verdict classification), and ARM Crypto Extensions
//! hardware instruction counts.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use tracemiku_core::crypto_scan::{
    ConstScanResult, CryptoInstrResult,
};
use crate::crypto_scan::{scan_crypto_memory, CryptoScanResponse};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAnalysisResponse {
    pub mem_scan: CryptoScanResponse,
    pub const_scan: ConstScanResult,
    pub crypto_instrs: CryptoInstrResult,
}

pub async fn crypto_analysis_handler(
    State(state): State<AppState>,
) -> Result<Json<CryptoAnalysisResponse>, StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || crypto_analysis(&inner))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
}

fn crypto_analysis(inner: &crate::state::AppStateInner) -> Result<CryptoAnalysisResponse, StatusCode> {
    let mem_scan = {
        let mem = inner.memshadow_ready_or_block_if_idle()
            .map_err(|status| {
                tracing::warn!(target: "tracemiku-server", "crypto-analysis: MemShadow {status}");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        if mem.bytes.is_empty() {
            CryptoScanResponse {
                status: "ready",
                scanned: 0,
                primitives: Vec::new(),
                any_hit: false,
            }
        } else {
            scan_crypto_memory(mem)
        }
    };

    let (const_scan, crypto_instrs) =
        tracemiku_core::crypto_scan::scan_combined(&inner.trace);

    Ok(CryptoAnalysisResponse {
        mem_scan,
        const_scan,
        crypto_instrs,
    })
}
