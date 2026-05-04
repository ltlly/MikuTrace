//! API discovery and job-progress infrastructure endpoints.

use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

pub async fn jobs_ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        let snapshot = json!({
            "type": "snapshot",
            "jobs": [],
            "status": "idle",
        });
        let _ = socket.send(Message::Text(snapshot.to_string())).await;
    })
}

pub async fn openapi_handler() -> Json<Value> {
    Json(json!({
        "openapi": "3.0.3",
        "info": {
            "title": "traceMiku Rust API",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "paths": openapi_paths(),
    }))
}

fn openapi_paths() -> Value {
    let mut paths = serde_json::Map::new();
    for (path, method) in [
        ("/api/meta", "get"),
        ("/api/records", "get"),
        ("/api/record/{idx}", "get"),
        ("/api/functions", "get"),
        ("/api/cfg", "get"),
        ("/api/cfg-svg", "get"),
        ("/api/block", "get"),
        ("/api/block-for-pc", "get"),
        ("/api/loops", "get"),
        ("/api/backtrace", "get"),
        ("/api/call-chain", "get"),
        ("/api/idxs-for-pc", "get"),
        ("/api/idxs-for-block", "get"),
        ("/api/search", "get"),
        ("/api/search-pc", "get"),
        ("/api/so-stats", "get"),
        ("/api/reg-value-at", "get"),
        ("/api/reg-at-idx", "get"),
        ("/api/forward-taint", "get"),
        ("/api/backward-taint", "get"),
        ("/api/data-chase", "get"),
        ("/api/reg-timeline", "get"),
        ("/api/mem-diff", "get"),
        ("/api/mem-flow", "get"),
        ("/api/strings", "get"),
        ("/api/string-provenance", "get"),
        ("/api/mem-dump", "get"),
        ("/api/last-write-of-reg", "get"),
        ("/api/last-write-of-addr", "get"),
        ("/api/idxs-touching-addr", "get"),
        ("/api/idxs-touching-range", "get"),
        ("/api/find-mem-pattern", "get"),
        ("/api/jni-events", "get"),
        ("/api/jni-calls", "get"),
        ("/api/jobj-history", "get"),
        ("/api/jni-strings", "get"),
        ("/api/field-at", "get"),
        ("/api/asm-tokens-for-pcs", "get"),
        ("/api/fork-events", "get"),
        ("/api/crypto-scan", "get"),
        ("/api/ollvm-detect-vm", "get"),
        ("/api/hash-finalize-detect", "get"),
        ("/api/hash-input-search", "post"),
        ("/api/auto-phase-detect", "get"),
        ("/api/diff-traces", "post"),
        ("/api/fn-summary", "get"),
        ("/api/dec/summary", "get"),
        ("/api/dec/fn/{fn_id}", "get"),
        ("/api/dec/llm-call", "post"),
        ("/api/dec/models", "get"),
        ("/ws/jobs", "get"),
        ("/openapi.json", "get"),
    ] {
        paths.insert(
            path.to_string(),
            json!({
                method: {
                    "responses": {
                        "200": {
                            "description": "OK"
                        }
                    }
                }
            }),
        );
    }
    Value::Object(paths)
}
