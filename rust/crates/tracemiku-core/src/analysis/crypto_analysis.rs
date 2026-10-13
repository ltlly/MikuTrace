//! 汇总内存、常量和指令中的密码算法特征。
//!
//! Returns MemShadow byte-pattern matches, instruction-level cryptographic
//! constant hits (with verdict classification), and ARM Crypto Extensions
//! hardware instruction counts.

use super::AnalysisError;
use serde::Serialize;

use crate::analysis::context::AnalysisContext;
use crate::analysis::crypto_scan_engine::{scan_crypto_memory, CryptoScanResponse};
use crate::crypto_scan::{ConstScanResult, CryptoInstrResult};

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAnalysisResponse {
    pub mem_scan: CryptoScanResponse,
    pub const_scan: ConstScanResult,
    pub crypto_instrs: CryptoInstrResult,
    /// 三类扫描全部为空时的提示（无发现 + 建议下一步），供 AI 消费方直接引用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

const EMPTY_RESULT_NOTE: &str = "no crypto indicators found (mem bytes, constants, and crypto instructions all empty); next steps: widen the traced range, verify the target actually runs a crypto routine, or try mem-write-bursts / hash-input-search for hashing implemented outside ARM Crypto Extension instructions";

pub fn crypto_analysis(state: &AnalysisContext) -> Result<CryptoAnalysisResponse, AnalysisError> {
    let inner = state.inner.clone();
    crypto_analysis_response(&inner)
}

fn crypto_analysis_response(
    inner: &crate::analysis::context::AnalysisData,
) -> Result<CryptoAnalysisResponse, AnalysisError> {
    if let Some(cached) = inner.crypto_analysis.get() {
        return Ok(cached.clone());
    }
    let mem_scan = {
        let mem = inner.memshadow();
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

    let (const_scan, crypto_instrs) = crate::crypto_scan::scan_combined(&inner.trace);

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
