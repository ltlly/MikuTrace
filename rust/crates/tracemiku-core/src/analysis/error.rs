use serde::Serialize;
use serde_json::Value;

/// 离线查询失败；未命中、歧义等正常分析结果仍由各查询的响应模型表达。
#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct AnalysisError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl AnalysisError {
    fn new(code: &'static str, value: impl Serialize) -> Self {
        let value = serde_json::to_value(value).unwrap_or(Value::Null);
        let message = value
            .as_str()
            .or_else(|| value.get("error").and_then(Value::as_str))
            .unwrap_or(code)
            .to_owned();
        let details = value.is_object().then_some(value);
        Self {
            code,
            message,
            details,
        }
    }

    pub fn invalid(message: impl Serialize) -> Self {
        Self::new("invalid_argument", message)
    }
    pub fn not_found(message: impl Serialize) -> Self {
        Self::new("not_found", message)
    }
    pub fn limit(message: impl Serialize) -> Self {
        Self::new("limit_exceeded", message)
    }
    pub fn internal(message: impl Serialize) -> Self {
        Self::new("internal_error", message)
    }
}
