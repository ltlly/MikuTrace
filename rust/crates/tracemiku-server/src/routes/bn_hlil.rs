//! Binary Ninja sidecar-backed HLIL and static CFG endpoints.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use tracemiku_core::function_index::parse_id;

use crate::state::{bn_response_cache_path, AppState};

const MAX_TRACE_FN_HINT_SPAN: u64 = 16 * 1024 * 1024;
const MAX_PERSISTED_BN_RESPONSES: usize = 256;

#[derive(Debug, Deserialize)]
pub struct PcQuery {
    pub pc: String,
}

#[derive(Debug, Deserialize)]
pub struct BnCfgForPcQuery {
    pub pc: String,
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BnCfgSvgForPcQuery {
    pub pc: String,
    pub mode: Option<String>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct FnQuery {
    pub fn_id: String,
}

pub async fn bn_sidecar_status_handler(State(state): State<AppState>) -> Json<Value> {
    let status = state
        .inner
        .bn_sidecar
        .lock()
        .map(|sidecar| sidecar.status())
        .unwrap_or_else(|e| json!({"ready": false, "configured": false, "error": e.to_string()}));
    Json(status)
}

pub async fn hlil_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    let response =
        request_sidecar_blocking(state.clone(), "hlil_for", params_for_pc(&state, pc)).await?;
    Ok(Json(enrich_hlil_for_pc_response(&state, pc, response)))
}

pub async fn hlil_for_fn_handler(
    State(state): State<AppState>,
    Query(q): Query<FnQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let fn_id = q.fn_id;
    let response = tokio::task::spawn_blocking(move || {
        let pc = resolve_fn_pc(&state, &fn_id)?;
        Ok::<_, (StatusCode, String)>(request_sidecar(&state, "hlil_for", json!({"pc": pc})))
    })
    .await
    .map_err(|err| {
        tracing::warn!(target: "tracemiku-server", "hlil-for-fn worker failed: {err}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "hlil-for-fn worker failed".to_string(),
        )
    })??;
    Ok(Json(response))
}

pub async fn bn_cfg_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<BnCfgForPcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    let mode = q.mode.unwrap_or_else(|| "asm".to_string());
    let mut params = params_for_pc(&state, pc);
    params["mode"] = json!(mode);
    Ok(Json(
        request_sidecar_blocking(state, "cfg_for", params).await?,
    ))
}

pub async fn bn_cfg_svg_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<BnCfgSvgForPcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    let mut params = params_for_pc(&state, pc);
    params["mode"] = json!(q.mode.unwrap_or_else(|| "asm".to_string()));
    if let Some(timeout) = q.timeout {
        params["timeout"] = json!(timeout);
    }
    let cfg = request_sidecar_blocking(state, "cfg_for", params).await?;
    let ok = cfg.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let ready = cfg.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut out = json!({
        "ok": cfg.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        "ready": cfg.get("ready").and_then(|v| v.as_bool()).unwrap_or(false),
        "svg": cfg.get("svg").and_then(|v| v.as_str()).unwrap_or(""),
        "error": cfg.get("error").cloned().unwrap_or(Value::Null),
        "status": cfg.get("status").and_then(|v| v.as_str()).unwrap_or(if ok && ready { "ok" } else { "not-ready" }),
    });
    for key in [
        "pc",
        "mode",
        "fn",
        "block_count",
        "edge_count",
        "dyn_only_count",
        "fn_total_exec",
        "current_bb",
        "created_function",
        "cache_hit",
    ] {
        if let Some(value) = cfg.get(key) {
            out[key] = value.clone();
        }
    }
    Ok(Json(out))
}

async fn request_sidecar_blocking(
    state: AppState,
    method: &'static str,
    params: Value,
) -> Result<Value, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || request_sidecar(&state, method, params))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "bn sidecar worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bn sidecar worker failed".to_string(),
            )
        })
}

fn request_sidecar(state: &AppState, method: &str, params: Value) -> Value {
    let cache_key = bn_cache_key(method, &params);
    if let Some(mut cached) = state
        .inner
        .bn_response_cache
        .lock()
        .expect("bn response cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        if let Some(obj) = cached.as_object_mut() {
            obj.insert("cache_hit".to_string(), json!(true));
        }
        return cached;
    }

    match state.inner.bn_sidecar.lock() {
        Ok(mut sidecar) => {
            let mut response = sidecar.request(method, params);
            if should_cache_bn_response(&response) {
                if let Some(obj) = response.as_object_mut() {
                    obj.insert("cache_hit".to_string(), json!(false));
                }
                let entries = {
                    let mut cache = state
                        .inner
                        .bn_response_cache
                        .lock()
                        .expect("bn response cache poisoned");
                    if cache.len() >= MAX_PERSISTED_BN_RESPONSES {
                        if let Some(oldest_key) = cache.keys().next().cloned() {
                            cache.remove(&oldest_key);
                        }
                    }
                    cache.insert(cache_key, response.clone());
                    cache.clone()
                };
                persist_bn_response_cache(state, &entries);
            }
            response
        }
        Err(e) => json!({"ok": false, "ready": false, "error": e.to_string()}),
    }
}

fn persist_bn_response_cache(state: &AppState, entries: &HashMap<String, Value>) {
    let path = bn_response_cache_path(&state.inner.trace);
    let tmp_path = path.with_file_name(format!(
        "{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("trace.bin.bn-sidecar-cache.v1.json"),
        std::process::id()
    ));
    let doc = json!({
        "version": 1,
        "trace_bytes": state.inner.trace.raw().len() as u64,
        "entries": entries,
    });
    let write_result = (|| -> std::io::Result<()> {
        let raw = serde_json::to_vec(&doc).map_err(std::io::Error::other)?;
        std::fs::write(&tmp_path, raw)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        tracing::warn!(
            target: "tracemiku-server",
            path = %path.display(),
            "failed to persist BN sidecar cache: {err}"
        );
    }
}

fn bn_cache_key(method: &str, params: &Value) -> String {
    format!("{method}:{params}")
}

fn should_cache_bn_response(response: &Value) -> bool {
    response
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && response
            .get("ready")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
}

fn params_for_pc(state: &AppState, pc: u64) -> Value {
    let mut params = json!({"pc": pc});
    if let Some(fn_start) = trace_fn_start(state, pc) {
        params["fn_start"] = json!(fn_start);
    }
    params
}

fn trace_fn_start(state: &AppState, pc: u64) -> Option<u64> {
    let (name, off) = state.inner.symbols.lookup(pc);
    if name == "?" || off > pc || off > MAX_TRACE_FN_HINT_SPAN {
        return None;
    }
    let start = pc - off;
    let has_index_entry = state.inner.function_index.entries.iter().any(|entry| {
        entry.source == "symbol"
            && entry.name == name
            && entry.entry_pc == Some(start)
            && entry.records > 0
    });
    has_index_entry.then_some(start)
}

fn resolve_fn_pc(state: &AppState, fn_id: &str) -> Result<u64, (StatusCode, String)> {
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => state
            .inner
            .top_ir()
            .fn_by_id(&payload)
            .map(|f| f.pc_start)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such trace fn {fn_id}"))),
        "sym" => state
            .inner
            .function_index
            .by_id(fn_id)
            .and_then(|f| f.entry_pc)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "bn" => parse_u64(&payload)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid bn fn id {fn_id}"))),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn enrich_hlil_for_pc_response(state: &AppState, pc: u64, mut response: Value) -> Value {
    let Some(obj) = response.as_object_mut() else {
        return response;
    };
    obj.entry("pc".to_string())
        .or_insert_with(|| json!(format!("{pc:#x}")));
    let ready = obj.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
    let ok = obj.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    obj.entry("status".to_string())
        .or_insert_with(|| json!(if ok && ready { "ok" } else { "not-ready" }));

    let (trace_name, trace_off) = state.inner.symbols.lookup(pc);
    if trace_name != "?" {
        obj.insert(
            "trace_fn".to_string(),
            json!({"name": trace_name, "off": format!("{trace_off:#x}")}),
        );
    }

    if let Some(lines) = obj.get("lines").and_then(|v| v.as_array()) {
        let mut best: Option<(usize, u64)> = None;
        for (i, line) in lines.iter().enumerate() {
            let Some(line_pc) = line.get("pc").and_then(|v| v.as_str()).and_then(parse_u64) else {
                continue;
            };
            if line_pc == pc {
                best = Some((i, line_pc));
                break;
            }
            if line_pc <= pc && best.map(|(_, old)| line_pc > old).unwrap_or(true) {
                best = Some((i, line_pc));
            }
        }
        obj.insert(
            "current_line_idx".to_string(),
            json!(best.map(|(i, _)| i as i64).unwrap_or(-1)),
        );
    }
    response
}
