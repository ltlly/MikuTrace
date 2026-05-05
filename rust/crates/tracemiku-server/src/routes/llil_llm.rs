//! POST /api/llil/llm — LLM-assisted decompile over rendered LLIL.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::llil_render::{render_llil_response, LlilRenderPayload};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LlilLlmPayload {
    #[serde(default = "default_fn_id")]
    pub fn_id: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
}

fn default_fn_id() -> String {
    "trace:F0".to_string()
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

fn default_max_records() -> usize {
    300
}

#[derive(Debug, Serialize)]
pub struct LlilLlmResponse {
    pub ok: bool,
    pub fn_id: String,
    pub model: String,
    pub error: Option<String>,
    pub c_code: String,
    pub in_tokens: u64,
    pub out_tokens: u64,
    pub latency_ms: u64,
    pub llil_records: usize,
    pub estimated_prompt_tokens: usize,
}

pub async fn llil_llm_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlilLlmPayload>,
) -> Result<Json<LlilLlmResponse>, (StatusCode, String)> {
    let render_payload = LlilRenderPayload {
        fn_id: payload.fn_id.clone(),
        max_records: payload.max_records,
        ssa: true,
        constfold: true,
        flag_elim: true,
        dce: false,
    };
    let render = tokio::task::spawn_blocking(move || render_llil_response(&state, render_payload))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "llil llm render worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "llil render worker failed".to_string(),
            )
        })??;
    let estimated_prompt_tokens = render.pseudocode.len() / 4;
    let system = if payload.lang == "zh" {
        "你是逆向工程助手。根据 LLIL 伪代码输出简洁的 C 风格伪代码。"
    } else {
        "You are a reverse engineering assistant. Convert LLIL pseudocode into concise C-like pseudocode."
    };
    let prompt = format!(
        "Function: {} ({})\nRecords: {}\n\nLLIL:\n```c\n{}\n```",
        render.name, render.fn_id, render.records, render.pseudocode
    );
    let result = crate::llm::call_model(&payload.model, &prompt, system, payload.max_tokens)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ok = result.error.is_none();
    Ok(Json(LlilLlmResponse {
        ok,
        fn_id: render.fn_id,
        model: result.model,
        error: result.error,
        c_code: result.c_code,
        in_tokens: result.prompt_tokens,
        out_tokens: result.output_tokens,
        latency_ms: result.latency_ms,
        llil_records: render.records,
        estimated_prompt_tokens,
    }))
}
