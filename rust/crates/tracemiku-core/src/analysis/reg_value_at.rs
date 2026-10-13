//! 读取指定记录的寄存器值与注释。

use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::disasm::normalize_disasm_reg;

#[derive(Debug, Deserialize, Default)]
pub struct RegValueAtQuery {
    pub idx: usize,
    pub reg: String,
}

#[derive(Debug, Serialize)]
pub struct RegValueAtResponse {
    pub status: String,
    pub idx: usize,
    pub reg: String,
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn reg_value_at(state: &AnalysisContext, q: RegValueAtQuery) -> RegValueAtResponse {
    let inner = &state.inner;
    if q.idx >= inner.trace.len() {
        return RegValueAtResponse {
            status: "error".to_string(),
            idx: q.idx,
            reg: q.reg,
            value: None,
            annotation: None,
            error: Some("idx out of range".to_string()),
        };
    }
    let record = inner.trace.record(q.idx);
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() { q.reg } else { canon };
    let raw_value = record.reg_by_name(&reg);
    if let Some(v) = raw_value {
        let annotation = if reg == "xzr" {
            None
        } else {
            let annotation = crate::analysis::record::classify_reg_value(
                inner,
                Some(inner.memshadow()),
                v,
                q.idx,
                record.reg_by_name("sp").unwrap_or(0),
            );
            (!annotation.is_empty()).then_some(annotation)
        };
        RegValueAtResponse {
            status: "ready".to_string(),
            idx: q.idx,
            reg,
            value: Some(format!("{v:#x}")),
            annotation,
            error: None,
        }
    } else {
        RegValueAtResponse {
            status: "error".to_string(),
            idx: q.idx,
            reg,
            value: None,
            annotation: None,
            error: Some("unknown register".to_string()),
        }
    }
}
