//! GET /api/jni-calls.

use std::collections::HashMap;
use std::path::PathBuf;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use tracemiku_core::prelude::decode;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct JniCallsQuery {
    pub in_fn: Option<String>,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_max() -> usize {
    200
}

#[derive(Debug, Serialize)]
pub struct JniCallHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub jni_fn: String,
    pub vtable_offset: String,
    pub args: HashMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub struct JniCallsResponse {
    pub in_fn: Option<String>,
    pub count: usize,
    pub hits: Vec<JniCallHit>,
    pub vtable_size: usize,
}

pub async fn jni_calls_handler(
    State(state): State<AppState>,
    Query(q): Query<JniCallsQuery>,
) -> Json<JniCallsResponse> {
    let jni_vtable = load_jni_vtable().unwrap_or_default();
    if jni_vtable.is_empty() {
        return Json(JniCallsResponse {
            in_fn: q.in_fn,
            count: 0,
            hits: Vec::new(),
            vtable_size: 0,
        });
    }

    let base = primary_base(&state);
    let mut hits = Vec::new();
    let mut prev = None;
    for i in 0..state.inner.trace.len() {
        let record = state.inner.trace.record(i);
        let decoded = decode(record.pc, record.inst);
        let (func_name, _) = state.inner.symbols.lookup(record.pc);
        if q.in_fn
            .as_deref()
            .is_some_and(|want| func_name.as_str() != want)
        {
            prev = Some(decoded);
            continue;
        }

        if decoded.mnemonic == "blr" {
            if let (Some(target_reg), Some(prev_decoded)) =
                (branch_reg(&decoded.op_str), prev.as_ref())
            {
                if prev_decoded.mnemonic == "ldr"
                    && prev_decoded.regs_def.iter().any(|r| r == &target_reg)
                    && prev_decoded.mem_op.first().is_some_and(|op| !op.is_write)
                {
                    let op = &prev_decoded.mem_op[0];
                    if let Ok(offset) = u64::try_from(op.disp) {
                        if let Some(jni_fn) = jni_vtable.get(&offset) {
                            hits.push(JniCallHit {
                                idx: i,
                                pc: format!("{:#x}", record.pc),
                                rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
                                func: (func_name != "?").then_some(func_name),
                                jni_fn: jni_fn.clone(),
                                vtable_offset: format!("{offset:#x}"),
                                args: ["x0", "x1", "x2", "x3", "x4"]
                                    .into_iter()
                                    .map(|reg| {
                                        (
                                            reg,
                                            format!("{:#x}", record.reg_by_name(reg).unwrap_or(0)),
                                        )
                                    })
                                    .collect(),
                            });
                            if q.max > 0 && hits.len() >= q.max {
                                break;
                            }
                        }
                    }
                }
            }
        }
        prev = Some(decoded);
    }

    Json(JniCallsResponse {
        in_fn: q.in_fn,
        count: hits.len(),
        hits,
        vtable_size: jni_vtable.len(),
    })
}

fn branch_reg(op_str: &str) -> Option<String> {
    let reg = op_str
        .split(',')
        .next()
        .unwrap_or(op_str)
        .trim()
        .to_lowercase();
    (!reg.is_empty()).then_some(reg)
}

fn primary_base(state: &AppState) -> Option<u64> {
    state
        .inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_int(&m.base))
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn load_jni_vtable() -> Option<HashMap<u64, String>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .parent()?
        .parent()?
        .parent()?
        .join("viewer")
        .join("jni_offsets.json");
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<Value>(&text).ok()?;
    let raw = value.get("offsets").unwrap_or(&value).as_object()?;
    let mut out = HashMap::new();
    for (k, v) in raw {
        let offset = parse_int(k)?;
        let name = v.as_str()?.to_string();
        out.insert(offset, name);
    }
    Some(out)
}
