//! 在 trace 中查询寄存器或内存条件命中。

use super::AnalysisError;
use serde::Deserialize;

use crate::prelude::{watchpoint_scan, WatchpointScan, WatchpointSpec};

use crate::analysis::context::AnalysisContext;
use crate::analysis::parse;

const MAX_WATCHPOINT_HITS: usize = 50_000;

#[derive(Debug, Deserialize)]
pub struct WatchpointsQuery {
    #[serde(default = "default_kind")]
    pub kind: String,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_kind() -> String {
    "reg-change".to_string()
}

fn default_limit() -> usize {
    200
}

pub fn watchpoints(
    state: &AnalysisContext,
    q: WatchpointsQuery,
) -> Result<WatchpointScan, AnalysisError> {
    let spec = parse_spec(&q)?;
    let limit = q.limit.clamp(1, MAX_WATCHPOINT_HITS);
    let inner = state.inner.clone();
    let scan = { watchpoint_scan(&inner.trace, &inner.index, &spec, q.cursor, limit) };
    Ok(scan)
}

fn parse_spec(q: &WatchpointsQuery) -> Result<WatchpointSpec, AnalysisError> {
    match q.kind.as_str() {
        "reg-change" | "reg_change" | "reg" => {
            let reg = q
                .reg
                .clone()
                .ok_or_else(|| bad_request("reg is required"))?;
            Ok(WatchpointSpec::RegChange { reg })
        }
        "reg-equals" | "reg_equals" | "equals" => {
            let reg = q
                .reg
                .clone()
                .ok_or_else(|| bad_request("reg is required"))?;
            let value = q
                .value
                .as_deref()
                .and_then(parse::parse_hex_u64)
                .ok_or_else(|| bad_request("value is required"))?;
            Ok(WatchpointSpec::RegEquals { reg, value })
        }
        "mem-touch" | "mem_touch" | "mem" => {
            let addr = q
                .addr
                .as_deref()
                .and_then(parse::parse_hex_u64)
                .ok_or_else(|| bad_request("addr is required"))?;
            Ok(WatchpointSpec::MemTouch {
                addr,
                size: q.size.max(1),
            })
        }
        _ => Err(bad_request("unknown watchpoint kind")),
    }
}

fn bad_request(msg: &str) -> AnalysisError {
    AnalysisError::invalid(msg.to_string())
}

impl Default for WatchpointsQuery {
    fn default() -> Self {
        Self {
            kind: default_kind(),
            reg: Default::default(),
            addr: Default::default(),
            value: Default::default(),
            size: Default::default(),
            cursor: Default::default(),
            limit: default_limit(),
        }
    }
}
