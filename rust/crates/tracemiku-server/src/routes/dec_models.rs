//! GET /api/dec/models — available LLM aliases and env key status.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DecModelsResponse {
    pub models: Vec<&'static str>,
    pub api_keys_configured: std::collections::BTreeMap<&'static str, bool>,
}

pub async fn dec_models_handler() -> Json<DecModelsResponse> {
    Json(DecModelsResponse {
        models: crate::llm::list_llm_models(),
        api_keys_configured: crate::llm::api_key_status(),
    })
}
