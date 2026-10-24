//! 查找寄存器的上次写入。
//!
//! Returns the largest record index < `before` that defines `reg`,
//! or null if no such index exists.

use crate::disasm::normalize_disasm_reg;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LastWriteQuery {
    pub reg: String,
    pub before: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LastWriteResponse {
    pub status: &'static str,
    pub idx: Option<usize>,
    pub value: Option<String>,
}

pub fn last_write_of_reg(state: &AnalysisContext, q: LastWriteQuery) -> LastWriteResponse {
    let before = q.before.unwrap_or_else(|| state.inner.trace.len());
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() {
        q.reg.clone()
    } else {
        canon
    };
    let idx = state.inner.index().last_def_before(&reg, before);
    let value = if before < state.inner.trace.len() {
        state
            .inner
            .trace
            .record(before)
            .reg_by_name(&reg)
            .map(|v| format!("{v:#x}"))
            .or_else(|| {
                state
                    .inner
                    .trace
                    .simd()
                    .and_then(|s| s.reg_bytes_by_name(before, &q.reg))
                    .map(|bytes| {
                        if bytes.len() <= 8 {
                            let mut buf = [0u8; 8];
                            buf[..bytes.len()].copy_from_slice(&bytes);
                            format!("{:#x}", u64::from_le_bytes(buf))
                        } else {
                            let mut buf = [0u8; 16];
                            let take = bytes.len().min(16);
                            buf[..take].copy_from_slice(&bytes[..take]);
                            format!("{:#x}", u128::from_le_bytes(buf))
                        }
                    })
            })
    } else {
        None
    };
    LastWriteResponse {
        status: "ready",
        idx,
        value,
    }
}
