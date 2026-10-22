//! 有界记录读取：默认只解码选中记录，详情才加载符号、CFG 和内存注释。
use super::{AnalysisContext, AnalysisError};
use crate::disasm::addr_of;
use crate::memshadow::{value_of_read, value_of_write};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_RECORD_COUNT: usize = 1_000;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RecordsQuery {
    pub start: usize,
    pub count: usize,
    pub end: Option<usize>,
    pub regs: String,
    pub indices: Option<Vec<usize>>,
    pub detail: bool,
}
impl Default for RecordsQuery {
    fn default() -> Self {
        Self {
            start: 0,
            count: 100,
            end: None,
            regs: String::new(),
            indices: None,
            detail: false,
        }
    }
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegWriteEffect {
    pub reg: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MemAccessEffect {
    pub kind: &'static str,
    pub ea: String,
    pub size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub val: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RecordRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub module: Option<String>,
    pub func: Option<String>,
    pub off: Option<String>,
    pub asm: String,
    pub annotation: Option<String>,
    pub exec_count: Option<u64>,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes_reg: Vec<RegWriteEffect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_access: Option<MemAccessEffect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<super::record::RecordDetail>,
}
#[derive(Debug, Serialize)]
pub struct RecordsResponse {
    pub start: usize,
    pub end: usize,
    pub count: usize,
    pub returned: usize,
    pub requested_count: usize,
    pub max_count_used: usize,
    pub truncated: bool,
    pub detail: bool,
    pub records: Vec<RecordRow>,
}

pub fn records(state: &AnalysisContext, q: RecordsQuery) -> Result<RecordsResponse, AnalysisError> {
    let inner = &state.inner;
    let n = inner.trace.len();
    let names: Vec<&str> = q
        .regs
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    // Validate even for an empty trace/window; misspelled registers must not disappear silently.
    for name in &names {
        if !valid_register(name) {
            return Err(AnalysisError::invalid(format!("unknown register: {name}")));
        }
    }
    let window_count = q
        .end
        .map_or(q.count, |end_idx| end_idx.saturating_sub(q.start));
    let requested_count = q.indices.as_ref().map_or(window_count, Vec::len);
    let limit = requested_count.min(MAX_RECORD_COUNT);
    let selected_indices = q.indices.is_some();
    let indices = if let Some(indices) = q.indices {
        if indices.iter().any(|&idx| idx >= n) {
            return Err(AnalysisError::not_found("selected record is outside trace"));
        }
        indices.into_iter().take(limit).collect::<Vec<_>>()
    } else {
        (q.start.min(n)..q.start.saturating_add(limit).min(n)).collect()
    };
    let truncated =
        requested_count > limit && (selected_indices || q.start.saturating_add(limit) < n);
    let mut rows = Vec::with_capacity(indices.len());
    for i in indices {
        let r = inner.trace.record(i);
        let d = decode(r.pc, r.inst);
        let writes_reg = if i + 1 < n {
            let r_next = inner.trace.record(i + 1);
            let mut writes = Vec::new();
            for reg_idx in 0..31 {
                if r.regs[reg_idx] != r_next.regs[reg_idx] {
                    writes.push(RegWriteEffect {
                        reg: format!("x{reg_idx}"),
                        before: format!("{:#x}", r.regs[reg_idx]),
                        after: format!("{:#x}", r_next.regs[reg_idx]),
                    });
                }
            }
            if r.sp != r_next.sp {
                writes.push(RegWriteEffect {
                    reg: "sp".to_string(),
                    before: format!("{:#x}", r.sp),
                    after: format!("{:#x}", r_next.sp),
                });
            }
            writes
        } else {
            Vec::new()
        };
        let mem_access = d.mem_op.iter().find(|op| !op.base.is_empty()).map(|op| {
            let ea = addr_of(&r, op);
            let kind = if op.is_write { "w" } else { "r" };
            let val = if op.is_write {
                value_of_write(&inner.trace, i, op, &d)
            } else {
                value_of_read(&inner.trace, i, op, &d)
            }
            .map(|v| format!("{v:#x}"));
            MemAccessEffect {
                kind,
                ea: format!("{ea:#x}"),
                size: op.size,
                val,
            }
        });
        let detail = q
            .detail
            .then(|| super::record::record(state, i))
            .transpose()?;
        let (func, off, exec_count) = detail.as_ref().map_or((None, None, None), |d| {
            (d.func.clone(), d.off.clone(), d.exec_count)
        });
        let annotation = if q.detail && (d.is_call || d.is_branch) && i + 1 < n {
            let (name, off) = inner.symbols().lookup(inner.trace.pc(i + 1));
            (!name.is_empty() && Some(&name) != func.as_ref()).then(|| format!("→ {name}+{off:#x}"))
        } else {
            None
        };
        rows.push(RecordRow {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel: inner
                .modules
                .relative_offset(r.pc)
                .map(|v| format!("{v:#x}")),
            module: inner.modules.resolve_name(r.pc),
            func,
            off,
            asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
            annotation,
            exec_count,
            is_branch: d.is_branch,
            is_call: d.is_call,
            is_ret: d.is_ret,
            writes_reg,
            mem_access,
            regs: (!names.is_empty()).then(|| {
                names
                    .iter()
                    .filter_map(|name| r.reg(name).map(|v| (name.to_string(), format!("{v:#x}"))))
                    .collect()
            }),
            detail,
        });
    }
    Ok(RecordsResponse {
        start: rows.iter().map(|r| r.idx).min().unwrap_or(q.start),
        end: rows
            .iter()
            .map(|r| r.idx.saturating_add(1))
            .max()
            .unwrap_or(q.start),
        count: rows.len(),
        returned: rows.len(),
        requested_count,
        max_count_used: limit,
        truncated,
        detail: q.detail,
        records: rows,
    })
}
pub(crate) fn valid_register(name: &str) -> bool {
    matches!(name, "sp" | "fp" | "lr" | "pc" | "nzcv" | "xzr" | "wzr")
        || name
            .strip_prefix('x')
            .or_else(|| name.strip_prefix('w'))
            .and_then(|s| s.parse::<u8>().ok())
            .is_some_and(|n| n <= 30)
}
