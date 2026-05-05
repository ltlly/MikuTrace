//! GET /api/field-at.

use axum::extract::Query;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct FieldAtQuery {
    pub pc: String,
    pub reg: String,
    #[serde(default)]
    pub offset: String,
}

#[derive(Debug, Serialize)]
pub struct FieldAtResponse {
    pub pc: String,
    pub reg: String,
    pub offset: i64,
    pub hit: bool,
    pub r#struct: Option<String>,
    pub field: Option<String>,
    pub type_name: Option<String>,
}

pub async fn field_at_handler(Query(q): Query<FieldAtQuery>) -> Json<FieldAtResponse> {
    Json(FieldAtResponse {
        pc: q.pc,
        reg: q.reg,
        offset: parse_int(&q.offset).unwrap_or(0),
        hit: false,
        r#struct: None,
        field: None,
        type_name: None,
    })
}

fn parse_int(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0);
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<i64>().ok()
    }
}
