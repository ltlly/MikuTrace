//! 扫描运行时内存中的密码算法常量。

use super::AnalysisError;
use crate::analysis::context::AnalysisContext;
use crate::analysis::crypto_scan_engine::{scan_crypto_memory, CryptoScanResponse};

pub fn crypto_scan(state: &AnalysisContext) -> Result<CryptoScanResponse, AnalysisError> {
    let inner = state.inner.clone();
    let response = crypto_scan_response(&inner);
    Ok(response)
}

fn crypto_scan_response(inner: &crate::analysis::context::AnalysisData) -> CryptoScanResponse {
    let mem = inner.memshadow();
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
