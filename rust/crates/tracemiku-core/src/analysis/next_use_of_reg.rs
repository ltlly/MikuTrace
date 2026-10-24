//! 查找寄存器的下次读取。
//!
//! Returns the smallest record index > `after` that uses `reg`,
//! or null if no such index exists.
//! `value` is the pre-execution snapshot at the use index, i.e. the value read.

use crate::disasm::normalize_disasm_reg;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct NextUseQuery {
    pub reg: String,
    pub after: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct NextUseResponse {
    pub status: &'static str,
    pub idx: Option<usize>,
    pub value: Option<String>,
}

pub fn next_use_of_reg(state: &AnalysisContext, q: NextUseQuery) -> NextUseResponse {
    let after = q.after.unwrap_or(0);
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() {
        q.reg.clone()
    } else {
        canon
    };
    let idx = state.inner.index().next_use_after(&reg, after);
    let value = idx.and_then(|use_idx| {
        if use_idx >= state.inner.trace.len() {
            return None;
        }
        state
            .inner
            .trace
            .record(use_idx)
            .reg_by_name(&reg)
            .map(|v| format!("{v:#x}"))
            .or_else(|| {
                state
                    .inner
                    .trace
                    .simd()
                    .and_then(|s| s.reg_bytes_by_name(use_idx, &q.reg))
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
    });
    NextUseResponse {
        status: "ready",
        idx,
        value,
    }
}
