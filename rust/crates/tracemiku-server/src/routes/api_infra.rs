//! API discovery and job-progress infrastructure endpoints.

use std::thread;

use axum::extract::{OriginalUri, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

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

/// 后台任务状态。cfg/index 在 `AppState::load` 中同步构建完成，直接报
/// ready 有事实依据；Python 时代的 pc_inst/pc_to_block/block_idxs 在 Rust
/// 侧没有对应产物（被同步构建的 Index/CFG 覆盖），不再上报。
pub async fn bg_status_handler(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "cfg": ready_task_status(),
        "index": ready_task_status(),
        "analysis_index": analysis_index_status_value(&state),
        "mem": mem_status_value(&state),
        "decomp": decomp_status_value(&state),
        "parallelism": parallelism_status_value(&state),
    }))
}

pub async fn decomp_status_handler(State(state): State<AppState>) -> Json<Value> {
    Json(decomp_status_value(&state))
}

pub async fn api_not_found_handler(OriginalUri(uri): OriginalUri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "status": "error",
            "error": "unknown api endpoint",
            "path": uri.path(),
        })),
    )
}

fn ready_task_status() -> Value {
    json!({
        "status": "ready",
        "started_at": null,
        "ready_at": null,
        "err": null,
    })
}

fn mem_status_value(state: &AppState) -> Value {
    json!({
        "status": state.inner.memshadow_status(),
        "started_at": null,
        "ready_at": null,
        "err": null,
    })
}

fn analysis_index_status_value(state: &AppState) -> Value {
    json!({
        "status": state.inner.analysis_index_status(),
        "started_at": null,
        "ready_at": null,
        "err": null,
    })
}

fn parallelism_status_value(state: &AppState) -> Value {
    let records = state.inner.trace.len();
    let available = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    json!({
        "available": available,
        "records": records,
        "workers": {
            "index": tracemiku_core::index::index_worker_count(records),
            "analysis_index": 1,
            "symbols": tracemiku_core::symbols::symbol_worker_count(records),
            "cfg": tracemiku_core::cfg::cfg_worker_count(records),
            "frame_depths": tracemiku_core::taint::frame_depth_worker_count(records),
            "memshadow": tracemiku_core::memshadow::memshadow_worker_count(records),
            "reg_timeline": crate::routes::timeline_diff::reg_timeline_worker_count(records),
            "jni_calls": crate::jni_scan::jni_worker_count(records),
        },
        "env": {
            "TRACEMIKU_ANALYSIS_THREADS": std::env::var("TRACEMIKU_ANALYSIS_THREADS").ok(),
            "TRACEMIKU_INDEX_THREADS": std::env::var("TRACEMIKU_INDEX_THREADS").ok(),
            "TRACEMIKU_SYMBOL_THREADS": std::env::var("TRACEMIKU_SYMBOL_THREADS").ok(),
            "TRACEMIKU_CFG_THREADS": std::env::var("TRACEMIKU_CFG_THREADS").ok(),
            "TRACEMIKU_FRAME_DEPTH_THREADS": std::env::var("TRACEMIKU_FRAME_DEPTH_THREADS").ok(),
            "TRACEMIKU_MEMSHADOW_THREADS": std::env::var("TRACEMIKU_MEMSHADOW_THREADS").ok(),
            "TRACEMIKU_INTERACTIVE_WARM_BACKGROUND": std::env::var("TRACEMIKU_INTERACTIVE_WARM_BACKGROUND").ok(),
            "TRACEMIKU_REG_TIMELINE_THREADS": std::env::var("TRACEMIKU_REG_TIMELINE_THREADS").ok(),
            "TRACEMIKU_JNI_THREADS": std::env::var("TRACEMIKU_JNI_THREADS").ok(),
        }
    })
}

fn decomp_status_value(state: &AppState) -> Value {
    // 读 BN sidecar 的无锁 status 快照：request 路径持 manager 锁横跨整个
    // 往返（最长为请求超时），此处绝不能在 async 上下文抢该锁。
    let status = state.inner.bn_sidecar_status.value();
    let ready = status
        .get("ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let configured = status
        .get("configured")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_error = status.get("error").is_some_and(|v| !v.is_null());
    let web_status = if ready {
        "ready"
    } else if has_error {
        "error"
    } else if configured {
        "loading"
    } else {
        "disabled"
    };
    json!({
        "status": web_status,
        "name": if configured { Value::String("bn".to_string()) } else { Value::Null },
        "err": status.get("error").cloned().unwrap_or(Value::Null),
        "started_at": null,
        "ready_at": null,
        "so_path": status.get("so_path").cloned().unwrap_or(Value::Null),
        "elapsed": null,
    })
}

fn openapi_paths() -> Value {
    let mut paths = serde_json::Map::new();
    for (path, method) in [
        ("/api/meta", "get"),
        ("/api/analysis-index", "get"),
        ("/api/records", "get"),
        ("/api/record/{idx}", "get"),
        ("/api/functions", "get"),
        ("/api/bn-sidecar/status", "get"),
        ("/api/hlil-for-pc", "get"),
        ("/api/hlil-for-fn", "get"),
        ("/api/bn-cfg-for-pc", "get"),
        ("/api/bn-cfg-svg-for-pc", "get"),
        ("/api/cfg", "get"),
        ("/api/cfg-svg", "get"),
        ("/api/block", "get"),
        ("/api/block-for-pc", "get"),
        ("/api/loops", "get"),
        ("/api/backtrace", "get"),
        ("/api/call-chain", "get"),
        ("/api/call-tree", "get"),
        ("/api/idxs-for-pc", "get"),
        ("/api/idxs-for-block", "get"),
        ("/api/search", "get"),
        ("/api/query", "get"),
        ("/api/search-pc", "get"),
        ("/api/so-stats", "get"),
        ("/api/coverage", "get"),
        ("/api/resolve", "get"),
        ("/api/indirect-targets", "get"),
        ("/api/reg-at", "get"),
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
        ("/api/mem-export", "get"),
        ("/api/last-write-of-reg", "get"),
        ("/api/next-use-of-reg", "get"),
        ("/api/last-write-of-addr", "get"),
        ("/api/mem-writes-in-range", "get"),
        ("/api/idxs-touching-addr", "get"),
        ("/api/idxs-touching-range", "get"),
        ("/api/find-mem-pattern", "get"),
        ("/api/bg-status", "get"),
        ("/api/decomp-status", "get"),
        ("/api/jni-events", "get"),
        ("/api/jni-calls", "get"),
        ("/api/jobj-history", "get"),
        ("/api/jni-strings", "get"),
        ("/api/asm-tokens-for-pcs", "get"),
        ("/api/fork-events", "get"),
        ("/api/crypto-analysis", "get"),
        ("/api/crypto-scan", "get"),
        ("/api/watchpoints", "get"),
        ("/api/ollvm-detect-vm", "get"),
        ("/api/hash-finalize-detect", "get"),
        ("/api/hash-input-search", "post"),
        ("/api/auto-phase-detect", "get"),
        ("/api/dep-graph", "get"),
        ("/api/forward-dep-tree", "get"),
        ("/api/bfs-slice", "get"),
        ("/api/diff-traces", "post"),
        ("/api/fn-summary", "get"),
        ("/api/functions", "get"),
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
