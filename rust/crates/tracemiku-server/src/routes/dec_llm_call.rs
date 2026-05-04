//! POST /api/dec/llm-call — LLM-assisted decompile for one FuncIR.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{build_fn_decompile_prompt, build_symbol_func_ir_indexed, FuncIR};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct DecLlmCallPayload {
    #[serde(default)]
    pub fn_id: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub with_memshadow: bool,
    #[serde(default)]
    pub hooks: serde_json::Value,
    #[serde(default = "default_split_top_k")]
    pub split_top_k: usize,
    #[serde(default = "default_split_min_records")]
    pub split_min_records: usize,
}

fn default_model() -> String {
    "mimo".to_string()
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_lang() -> String {
    "en".to_string()
}

fn default_tier() -> String {
    "hot".to_string()
}

fn default_split_top_k() -> usize {
    10
}

fn default_split_min_records() -> usize {
    50
}

pub async fn dec_llm_call_handler(
    State(state): State<AppState>,
    Json(payload): Json<DecLlmCallPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.fn_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "fn_id is required".to_string()));
    }

    let inner = &state.inner;
    let fn_ = resolve_fn(&state, &payload.fn_id)?;
    let canonical_id = fn_.id.clone();
    let cache_key = cache_key(&payload, &canonical_id);

    if let Some(mut cached) = inner
        .llm_cache
        .lock()
        .expect("llm cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        if let Some(obj) = cached.as_object_mut() {
            obj.insert("cache_hit".to_string(), serde_json::Value::Bool(true));
        }
        return Ok(Json(cached));
    }

    let bundle =
        build_fn_decompile_prompt(inner.top_ir(), &fn_, &payload.tier, &payload.lang, 200_000);
    let result = crate::llm::call_model(
        &payload.model,
        &bundle.user,
        &bundle.system,
        payload.max_tokens,
    )
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let ok = result.error.is_none();
    let out = serde_json::json!({
        "ok": ok,
        "model": result.model,
        "error": result.error,
        "c_code": result.c_code,
        "in_tokens": result.prompt_tokens,
        "out_tokens": result.output_tokens,
        "latency_ms": result.latency_ms,
        "estimated_prompt_tokens": bundle.estimated_tokens,
        "cache_hit": false,
    });

    if ok {
        inner
            .llm_cache
            .lock()
            .expect("llm cache poisoned")
            .insert(cache_key, out.clone());
    }
    Ok(Json(out))
}

fn resolve_fn(state: &AppState, fn_id: &str) -> Result<FuncIR, (StatusCode, String)> {
    let inner = &state.inner;
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => inner
            .top_ir()
            .fn_by_id(&payload)
            .cloned()
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}"))),
        "sym" => build_symbol_func_ir_indexed(
            &inner.trace,
            &inner.symbols,
            &inner.cfg,
            &inner.index,
            &payload,
        )
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "bn" => Err((
            StatusCode::NOT_FOUND,
            "bn:* dec llm-call support is deferred until the Rust BN backend lands".to_string(),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}

fn cache_key(payload: &DecLlmCallPayload, canonical_id: &str) -> String {
    serde_json::json!({
        "kind": "dec_llm_out",
        "fn_id": payload.fn_id,
        "canonical_id": canonical_id,
        "model": payload.model,
        "lang": payload.lang,
        "tier": payload.tier,
        "with_memshadow": payload.with_memshadow,
        "hooks": payload.hooks,
        "max_tokens": payload.max_tokens,
        "split_top_k": payload.split_top_k,
        "split_min_records": payload.split_min_records,
    })
    .to_string()
}
