//! Async LLM adapters for `/api/dec/llm-call`.
//!
//! Env-only secrets. Request payloads never carry API keys.

use std::collections::BTreeMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResult {
    pub c_code: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub output_tokens: u64,
    pub latency_ms: u64,
    pub raw: serde_json::Value,
    pub error: Option<String>,
}

impl LlmResult {
    fn error(model: String, error: impl Into<String>) -> Self {
        Self {
            c_code: String::new(),
            model,
            prompt_tokens: 0,
            output_tokens: 0,
            latency_ms: 0,
            raw: serde_json::Value::Null,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone)]
enum Provider {
    Anthropic,
    OpenAiCompat,
}

#[derive(Debug, Clone)]
struct ModelConfig {
    provider: Provider,
    name: &'static str,
    model_id: String,
    api_key_env: &'static str,
    base_url: Option<String>,
}

pub fn list_llm_models() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = registry().keys().copied().collect();
    names.sort();
    names
}

pub fn api_key_status() -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        (
            "ANTHROPIC_API_KEY",
            std::env::var("ANTHROPIC_API_KEY").is_ok(),
        ),
        (
            "DEEPSEEK_API_KEY",
            std::env::var("DEEPSEEK_API_KEY").is_ok(),
        ),
        (
            "DASHSCOPE_API_KEY",
            std::env::var("DASHSCOPE_API_KEY").is_ok(),
        ),
        ("MIMO_API_KEY", std::env::var("MIMO_API_KEY").is_ok()),
    ])
}

pub async fn call_model(
    model_name: &str,
    prompt: &str,
    system: &str,
    max_tokens: u32,
) -> Result<LlmResult, String> {
    let config = resolve_model(model_name)?;
    match config.provider {
        Provider::Anthropic => Ok(call_anthropic(config, prompt, system, max_tokens).await),
        Provider::OpenAiCompat => Ok(call_openai_compat(config, prompt, system, max_tokens).await),
    }
}

fn registry() -> BTreeMap<&'static str, fn() -> ModelConfig> {
    BTreeMap::from([
        ("claude", claude as fn() -> ModelConfig),
        ("claude-sonnet-4-6", claude),
        ("claude-opus-4-7", claude_opus),
        ("deepseek", deepseek),
        ("deepseek-r1", deepseek),
        ("deepseek-reasoner", deepseek),
        ("deepseek-chat", deepseek_chat),
        ("qwen", qwen),
        ("qwen-coder", qwen),
        ("mimo", mimo),
        ("mimo-direct", mimo),
        ("mimo-v2.5-pro", mimo),
        ("mimo-v2-pro", mimo_v2_pro),
        ("mimo-v2.5", mimo_v25),
        ("mimo-v2-omni", mimo_v2_omni),
    ])
}

fn resolve_model(model_name: &str) -> Result<ModelConfig, String> {
    let key = model_name.trim().to_ascii_lowercase();
    registry()
        .get(key.as_str())
        .map(|factory| factory())
        .ok_or_else(|| format!("unknown model: {key:?}. Known: {:?}", list_llm_models()))
}

fn claude() -> ModelConfig {
    ModelConfig {
        provider: Provider::Anthropic,
        name: "claude",
        model_id: "claude-sonnet-4-6".to_string(),
        api_key_env: "ANTHROPIC_API_KEY",
        base_url: Some(env_or("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")),
    }
}

fn claude_opus() -> ModelConfig {
    ModelConfig {
        model_id: "claude-opus-4-7".to_string(),
        ..claude()
    }
}

fn deepseek() -> ModelConfig {
    ModelConfig {
        provider: Provider::OpenAiCompat,
        name: "deepseek",
        model_id: "deepseek-reasoner".to_string(),
        api_key_env: "DEEPSEEK_API_KEY",
        base_url: Some(env_or("DEEPSEEK_BASE_URL", "https://api.deepseek.com")),
    }
}

fn deepseek_chat() -> ModelConfig {
    ModelConfig {
        model_id: "deepseek-chat".to_string(),
        ..deepseek()
    }
}

fn qwen() -> ModelConfig {
    ModelConfig {
        provider: Provider::OpenAiCompat,
        name: "qwen",
        model_id: "qwen2.5-coder-32b-instruct".to_string(),
        api_key_env: "DASHSCOPE_API_KEY",
        base_url: Some(env_or(
            "QWEN_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        )),
    }
}

fn mimo() -> ModelConfig {
    ModelConfig {
        provider: Provider::OpenAiCompat,
        name: "mimo",
        model_id: "mimo-v2.5-pro".to_string(),
        api_key_env: "MIMO_API_KEY",
        base_url: Some(env_or(
            "MIMO_BASE_URL",
            "https://token-plan-cn.xiaomimimo.com/v1",
        )),
    }
}

fn mimo_v2_pro() -> ModelConfig {
    ModelConfig {
        model_id: "mimo-v2-pro".to_string(),
        ..mimo()
    }
}

fn mimo_v25() -> ModelConfig {
    ModelConfig {
        model_id: "mimo-v2.5".to_string(),
        ..mimo()
    }
}

fn mimo_v2_omni() -> ModelConfig {
    ModelConfig {
        model_id: "mimo-v2-omni".to_string(),
        ..mimo()
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn api_key(config: &ModelConfig) -> Option<String> {
    std::env::var(config.api_key_env)
        .ok()
        .filter(|s| !s.is_empty())
}

async fn call_anthropic(
    config: ModelConfig,
    prompt: &str,
    system: &str,
    max_tokens: u32,
) -> LlmResult {
    let Some(key) = api_key(&config) else {
        return LlmResult::error(config.model_id, format!("{} 未设", config.api_key_env));
    };
    let url = format!(
        "{}/messages",
        config
            .base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com/v1")
            .trim_end_matches('/')
    );
    let body = serde_json::json!({
        "model": config.model_id,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    });
    let t0 = Instant::now();
    let resp = reqwest::Client::new()
        .post(url)
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await;
    let latency_ms = t0.elapsed().as_millis() as u64;
    let Ok(resp) = resp else {
        return LlmResult::error(
            config.model_id,
            format!("anthropic API: {}", resp.unwrap_err()),
        );
    };
    parse_anthropic_response(config.model_id, resp, latency_ms).await
}

async fn parse_anthropic_response(
    model_id: String,
    resp: reqwest::Response,
    latency_ms: u64,
) -> LlmResult {
    let status = resp.status();
    let value: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return LlmResult::error(model_id, format!("anthropic API decode: {e}")),
    };
    if !status.is_success() {
        return LlmResult::error(model_id, format!("anthropic API status {status}: {value}"));
    }
    let text = value
        .get("content")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("text").and_then(|v| v.as_str()))
                .collect::<String>()
        })
        .unwrap_or_default();
    LlmResult {
        c_code: text,
        model: model_id,
        prompt_tokens: value
            .pointer("/usage/input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_tokens: value
            .pointer("/usage/output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        latency_ms,
        raw: serde_json::json!({
            "id": value.get("id").cloned().unwrap_or_default(),
            "stop_reason": value.get("stop_reason").cloned().unwrap_or_default(),
        }),
        error: None,
    }
}

async fn call_openai_compat(
    config: ModelConfig,
    prompt: &str,
    system: &str,
    max_tokens: u32,
) -> LlmResult {
    let local_base = config
        .base_url
        .as_deref()
        .is_some_and(|u| u.contains("localhost") || u.contains("127.0.0.1"));
    let key = api_key(&config).or_else(|| local_base.then(|| "EMPTY".to_string()));
    let Some(key) = key else {
        return LlmResult::error(config.model_id, format!("{} 未设", config.api_key_env));
    };
    let base = config
        .base_url
        .as_deref()
        .unwrap_or("")
        .trim_end_matches('/');
    let url = format!("{base}/chat/completions");
    let mut messages = Vec::new();
    if !system.is_empty() {
        messages.push(serde_json::json!({"role": "system", "content": system}));
    }
    messages.push(serde_json::json!({"role": "user", "content": prompt}));
    let body = serde_json::json!({
        "model": config.model_id,
        "max_tokens": max_tokens,
        "messages": messages,
    });
    let t0 = Instant::now();
    let resp = reqwest::Client::new()
        .post(url)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await;
    let latency_ms = t0.elapsed().as_millis() as u64;
    let Ok(resp) = resp else {
        return LlmResult::error(
            config.model_id,
            format!("{} API: {}", config.name, resp.unwrap_err()),
        );
    };
    parse_openai_compat_response(config.name, config.model_id, resp, latency_ms).await
}

async fn parse_openai_compat_response(
    name: &str,
    model_id: String,
    resp: reqwest::Response,
    latency_ms: u64,
) -> LlmResult {
    let status = resp.status();
    let value: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return LlmResult::error(model_id, format!("{name} API decode: {e}")),
    };
    if !status.is_success() {
        return LlmResult::error(model_id, format!("{name} API status {status}: {value}"));
    }
    let text = value
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    LlmResult {
        c_code: text,
        model: model_id,
        prompt_tokens: value
            .pointer("/usage/prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_tokens: value
            .pointer("/usage/completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        latency_ms,
        raw: serde_json::json!({
            "id": value.get("id").cloned().unwrap_or_default(),
            "finish_reason": value.pointer("/choices/0/finish_reason").cloned().unwrap_or_default(),
        }),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};

    #[test]
    fn list_llm_models_contains_expected_aliases() {
        let models = list_llm_models();
        assert!(models.contains(&"claude"));
        assert!(models.contains(&"deepseek"));
        assert!(models.contains(&"qwen"));
        assert!(models.contains(&"mimo"));
    }

    #[tokio::test]
    async fn unknown_model_returns_error() {
        let err = call_model("missing", "p", "", 16).await.unwrap_err();
        assert!(err.contains("unknown model"));
    }

    #[tokio::test]
    async fn openai_compat_parses_mock_response() {
        async fn handler(Json(_body): Json<serde_json::Value>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "id": "chatcmpl-test",
                "choices": [{"message": {"content": "```c\nreturn 0;\n```"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7}
            }))
        }

        let app = Router::new().route("/v1/chat/completions", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        std::env::set_var("MIMO_BASE_URL", format!("http://{addr}/v1"));
        std::env::set_var("MIMO_API_KEY", "test-key");
        let result = call_model("mimo", "prompt", "system", 64).await.unwrap();
        std::env::remove_var("MIMO_BASE_URL");
        std::env::remove_var("MIMO_API_KEY");

        assert!(
            result.error.is_none(),
            "unexpected error: {:?}",
            result.error
        );
        assert!(result.c_code.contains("return 0"));
        assert_eq!(result.prompt_tokens, 11);
        assert_eq!(result.output_tokens, 7);
    }
}
