//! GET /api/crypto-analysis — combined crypto scan (mem + const + instr).
//!
//! Returns MemShadow byte-pattern matches, instruction-level cryptographic
//! constant hits (with verdict classification), and ARM Crypto Extensions
//! hardware instruction counts.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::crypto_scan::{scan_crypto_memory, CryptoScanResponse};
use crate::state::AppState;
use tracemiku_core::crypto_scan::{ConstScanResult, CryptoInstrResult};

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAnalysisResponse {
    pub mem_scan: CryptoScanResponse,
    pub const_scan: ConstScanResult,
    pub crypto_instrs: CryptoInstrResult,
    /// 三类扫描全部为空时的提示（无发现 + 建议下一步），供 AI 消费方直接引用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

const EMPTY_RESULT_NOTE: &str = "no crypto indicators found (mem bytes, constants, and crypto instructions all empty); next steps: widen the traced range, verify the target actually runs a crypto routine, or try hash-finalize-detect / hash-input-search for hashing implemented outside ARM Crypto Extension instructions";

pub async fn crypto_analysis_handler(
    State(state): State<AppState>,
) -> Result<Json<CryptoAnalysisResponse>, StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || crypto_analysis(&inner))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
}

fn crypto_analysis(
    inner: &crate::state::AppStateInner,
) -> Result<CryptoAnalysisResponse, StatusCode> {
    if let Some(cached) = inner.crypto_analysis.get() {
        return Ok(cached.clone());
    }
    let mem_scan = {
        let mem = inner.memshadow_ready_or_block_if_idle().map_err(|status| {
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

    let (const_scan, crypto_instrs) = tracemiku_core::crypto_scan::scan_combined(&inner.trace);

    let note = (!mem_scan.any_hit && const_scan.hits.is_empty() && crypto_instrs.hits.is_empty())
        .then_some(EMPTY_RESULT_NOTE);
    let response = CryptoAnalysisResponse {
        mem_scan,
        const_scan,
        crypto_instrs,
        note,
    };
    let _ = inner.crypto_analysis.set(response.clone());
    Ok(response)
}
