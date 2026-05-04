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

#[derive(Debug, Clone, Serialize)]
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
    Json(
        tokio::task::spawn_blocking(move || {
            let (hits, vtable_size) = scan_jni_calls(&state, q.in_fn.as_deref(), q.max);
            JniCallsResponse {
                in_fn: q.in_fn,
                count: hits.len(),
                hits,
                vtable_size,
            }
        })
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "jni calls worker failed: {err}");
            JniCallsResponse {
                in_fn: None,
                count: 0,
                hits: Vec::new(),
                vtable_size: 0,
            }
        }),
    )
}

pub(crate) fn scan_jni_calls(
    state: &AppState,
    in_fn: Option<&str>,
    max: usize,
) -> (Vec<JniCallHit>, usize) {
    let jni_vtable = load_jni_vtable().unwrap_or_default();
    if jni_vtable.is_empty() {
        return (Vec::new(), 0);
    }

    let base = primary_base(state);
    let mut hits = Vec::new();
    for (&pc, idxs) in &state.inner.index.pc_to_idxs {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let decoded = decode(pc, state.inner.trace.inst(first_idx));
        if decoded.mnemonic != "blr" {
            continue;
        }
        let Some(target_reg) = branch_reg(&decoded.op_str) else {
            continue;
        };

        for &i in idxs {
            if i == 0 {
                continue;
            }
            let record = state.inner.trace.record(i);
            let (func_name, _) = state.inner.symbols.lookup(record.pc);
            if in_fn.is_some_and(|want| func_name.as_str() != want) {
                continue;
            }

            let prev_record = state.inner.trace.record(i - 1);
            let prev_decoded = decode(prev_record.pc, prev_record.inst);
            if prev_decoded.mnemonic != "ldr"
                || !prev_decoded.regs_def.iter().any(|r| r == &target_reg)
                || !prev_decoded.mem_op.first().is_some_and(|op| !op.is_write)
            {
                continue;
            }
            let op = &prev_decoded.mem_op[0];
            let Ok(offset) = u64::try_from(op.disp) else {
                continue;
            };
            let Some(jni_fn) = jni_vtable.get(&offset) else {
                continue;
            };
            hits.push(JniCallHit {
                idx: i,
                pc: format!("{:#x}", record.pc),
                rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
                func: (func_name != "?").then_some(func_name),
                jni_fn: jni_fn.clone(),
                vtable_offset: format!("{offset:#x}"),
                args: ["x0", "x1", "x2", "x3", "x4"]
                    .into_iter()
                    .map(|reg| (reg, format!("{:#x}", record.reg_by_name(reg).unwrap_or(0))))
                    .collect(),
            });
        }
    }
    hits.sort_by_key(|hit| hit.idx);
    if max > 0 && hits.len() > max {
        hits.truncate(max);
    }
    (hits, jni_vtable.len())
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

pub(crate) fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn load_jni_vtable() -> Option<HashMap<u64, String>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest.parent()?.parent()?.parent()?;
    for path in [
        repo_root.join("tools").join("jni_offsets.json"),
        repo_root.join("viewer").join("jni_offsets.json"),
    ] {
        if let Some(table) = load_jni_offsets_json(&path) {
            return Some(table);
        }
    }

    let header_path = repo_root.join("vendor").join("jni").join("jni_bn.h");
    load_jni_offsets_header(&header_path)
}

fn load_jni_offsets_json(path: &std::path::Path) -> Option<HashMap<u64, String>> {
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

fn load_jni_offsets_header(path: &std::path::Path) -> Option<HashMap<u64, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_struct = false;
    let mut slot = 0u64;
    let mut out = HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("struct JNINativeInterface_ {") {
            in_struct = true;
            continue;
        }
        if !in_struct {
            continue;
        }
        if trimmed.starts_with("};") {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("void *reserved") {
            slot += 1;
            continue;
        }

        if let Some(name) = parse_jni_fn_member(trimmed) {
            out.insert(slot * 8, name);
            slot += 1;
        }
    }

    (!out.is_empty()).then_some(out)
}

fn parse_jni_fn_member(line: &str) -> Option<String> {
    let marker = "(__stdcall *";
    let (_, after_star) = line.split_once(marker)?;
    let name = after_star.split(')').next()?.trim();
    if name.is_empty() || name.starts_with("reserved") {
        return None;
    }
    Some(name.to_string())
}
