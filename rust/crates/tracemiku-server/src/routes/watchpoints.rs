//! GET /api/watchpoints — scan trace watchpoints.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use tracemiku_core::prelude::{watchpoint_scan, WatchpointScan, WatchpointSpec};

use crate::state::AppState;

const MAX_WATCHPOINT_HITS: usize = 50_000;

#[derive(Debug, Deserialize)]
pub struct WatchpointsQuery {
    #[serde(default = "default_kind")]
    pub kind: String,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_kind() -> String {
    "reg-change".to_string()
}

fn default_limit() -> usize {
    200
}

pub async fn watchpoints_handler(
    State(state): State<AppState>,
    Query(q): Query<WatchpointsQuery>,
) -> Result<Json<WatchpointScan>, (StatusCode, String)> {
    let spec = parse_spec(&q)?;
    let limit = q.limit.clamp(1, MAX_WATCHPOINT_HITS);
    let inner = state.inner.clone();
    let scan = tokio::task::spawn_blocking(move || {
        watchpoint_scan(&inner.trace, &inner.index, &spec, q.cursor, limit)
    })
    .await
    .map_err(|err| {
        tracing::warn!(target: "tracemiku-server", "watchpoints worker failed: {err}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "watchpoints worker failed".to_string(),
        )
    })?;
    Ok(Json(scan))
}

fn parse_spec(q: &WatchpointsQuery) -> Result<WatchpointSpec, (StatusCode, String)> {
    match q.kind.as_str() {
        "reg-change" | "reg_change" | "reg" => {
            let reg = q.reg.clone().ok_or_else(|| bad_request("reg is required"))?;
            Ok(WatchpointSpec::RegChange { reg })
        }
        "reg-equals" | "reg_equals" | "equals" => {
            let reg = q.reg.clone().ok_or_else(|| bad_request("reg is required"))?;
            let value = q
                .value
                .as_deref()
                .and_then(parse_int)
                .ok_or_else(|| bad_request("value is required"))?;
            Ok(WatchpointSpec::RegEquals { reg, value })
        }
        "mem-touch" | "mem_touch" | "mem" => {
            let addr = q
                .addr
                .as_deref()
                .and_then(parse_int)
                .ok_or_else(|| bad_request("addr is required"))?;
            Ok(WatchpointSpec::MemTouch {
                addr,
                size: q.size.max(1),
            })
        }
        _ => Err(bad_request("unknown watchpoint kind")),
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn bad_request(msg: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}
