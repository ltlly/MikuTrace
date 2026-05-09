//! POST /api/dec/llm-call — LLM-assisted decompile for one FuncIR.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{
    build_fn_decompile_prompt, build_symbol_func_ir_at_indexed, build_symbol_func_ir_indexed,
    FuncIR, PromptBundle, TopIR,
};

use crate::routes::dec_options::{
    default_split_min_records, default_split_top_k, hook_paths_from_value,
};
use crate::state::AppState;
use crate::state::TraceIrBuildOptions;

#[derive(Debug, Clone, Deserialize)]
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

pub async fn dec_llm_call_handler(
    State(state): State<AppState>,
    Json(payload): Json<DecLlmCallPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.fn_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "fn_id is required".to_string()));
    }

    let prepare_state = state.clone();
    let prepare_payload = payload.clone();
    let prepared =
        tokio::task::spawn_blocking(move || prepare_dec_llm_call(&prepare_state, &prepare_payload))
            .await
            .map_err(|err| {
                tracing::warn!(target: "tracemiku-server", "dec llm prepare worker failed: {err}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "dec llm prepare worker failed".to_string(),
                )
            })??;
    let (cache_key, bundle) = match prepared {
        DecLlmPrepared::Cached(cached) => return Ok(Json(cached)),
        DecLlmPrepared::Ready { cache_key, bundle } => (cache_key, bundle),
    };
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
        state
            .inner
            .llm_cache
            .lock()
            .expect("llm cache poisoned")
            .insert(cache_key, out.clone());
    }
    Ok(Json(out))
}

enum DecLlmPrepared {
    Cached(serde_json::Value),
    Ready {
        cache_key: String,
        bundle: PromptBundle,
    },
}

fn prepare_dec_llm_call(
    state: &AppState,
    payload: &DecLlmCallPayload,
) -> Result<DecLlmPrepared, (StatusCode, String)> {
    let inner = &state.inner;
    let opts = TraceIrBuildOptions {
        hook_paths: hook_paths_from_value(&payload.hooks),
        with_memshadow: payload.with_memshadow,
        split_top_k: payload.split_top_k,
        split_min_records: payload.split_min_records,
    };
    let (fn_, top_owned) = resolve_fn(state, &payload.fn_id, &opts)?;
    let canonical_id = fn_.id.clone();
    let cache_key = cache_key(payload, &canonical_id);

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
        return Ok(DecLlmPrepared::Cached(cached));
    }

    let prompt_top_owned = if top_owned.is_none() && !opts.uses_cached_default() {
        Some(inner.build_top_ir_with_options(&opts))
    } else {
        top_owned
    };
    let top = prompt_top_owned
        .as_ref()
        .map(|top| top.as_ref())
        .unwrap_or_else(|| inner.top_ir());
    let bundle = build_fn_decompile_prompt(top, &fn_, &payload.tier, &payload.lang, 200_000);
    Ok(DecLlmPrepared::Ready { cache_key, bundle })
}

fn resolve_fn(
    state: &AppState,
    fn_id: &str,
    opts: &TraceIrBuildOptions,
) -> Result<(FuncIR, Option<Arc<TopIR>>), (StatusCode, String)> {
    let inner = &state.inner;
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => {
            if opts.uses_cached_default() {
                inner
                    .top_ir()
                    .fn_by_id(&payload)
                    .cloned()
                    .map(|fn_| (fn_, None))
                    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))
            } else {
                let top = inner.build_top_ir_with_options(opts);
                let fn_ = top
                    .fn_by_id(&payload)
                    .cloned()
                    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;
                Ok((fn_, Some(top)))
            }
        }
        "sym" => build_symbol_func_ir_indexed(
            &inner.trace,
            &inner.symbols,
            &inner.cfg,
            &inner.index,
            &payload,
        )
        .map(|fn_| (fn_, None))
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "symaddr" => {
            let pc = parse_u64(&payload)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid symaddr {fn_id}")))?;
            build_symbol_func_ir_at_indexed(
                &inner.trace,
                &inner.symbols,
                &inner.cfg,
                &inner.index,
                pc,
            )
            .map(|fn_| (fn_, None))
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("no such symaddr fn {payload}"),
                )
            })
        }
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

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
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
