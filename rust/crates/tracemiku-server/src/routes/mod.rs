pub mod analysis_index;
pub mod api_infra;
pub mod asm_tokens;
pub mod auto_phase;
pub mod backward_taint;
pub mod bfs_slice;
pub mod bn_hlil;
pub mod call_tree;
pub mod cfg;
pub mod cfg_svg;
pub mod coverage;
pub mod crypto_analysis;
pub mod crypto_scan;
pub mod data_chase;
pub mod dep_graph;
pub mod diff_traces;
pub mod fn_summary;
pub mod fork_events;
pub mod forward_dep_tree;
pub mod forward_taint;
pub mod functions;
pub mod hash_finalize;
pub mod hash_input_search;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod indirect_targets;
pub mod jni_calls;
pub mod jni_events;
pub mod jni_strings;
pub mod jobj_history;
pub mod last_write_of_reg;
pub mod mem_dump;
pub mod mem_export;
pub mod mem_flow;
pub mod memory_query;
pub mod meta;
pub mod navigation;
pub mod next_use_of_reg;
pub mod ollvm_detect_vm;
pub mod parse;
pub mod query;
pub mod record;
pub mod records;
pub mod reg_at;
pub mod reg_value_at;
pub mod resolve;
pub mod search;
pub mod search_pc;
pub mod seed_resolver;
pub mod so_stats;
pub mod string_provenance;
pub mod strings;
pub mod timeline_diff;
pub mod watchpoints;

use axum::routing::{any, get, post};
use axum::Router;

use crate::state::AppState;

/// spawn_blocking worker panic/cancel 的统一错误类型（500 + 结构化 JSON）。
pub(crate) type WorkerFailure = (axum::http::StatusCode, axum::Json<serde_json::Value>);

/// worker panic 的统一响应：500 + 结构化错误 JSON。
///
/// panic 不允许被吞成 200 的"正常"响应（空数据/伪错误字段），fallback
/// 也不允许把重活拉回 async reactor；两种情况都直接失败并保留现场。
pub(crate) fn worker_panic_response(task: &str, err: &tokio::task::JoinError) -> WorkerFailure {
    tracing::warn!(target: "tracemiku-server", "{task} worker failed: {err}");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "status": "error",
            "error": format!("{task} worker failed"),
            "panic": err.is_panic(),
        })),
    )
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/openapi.json", get(api_infra::openapi_handler))
        .route("/api/meta", get(meta::meta_handler))
        .route(
            "/api/analysis-index",
            get(analysis_index::analysis_index_handler),
        )
        .route("/api/bg-status", get(api_infra::bg_status_handler))
        .route("/api/decomp-status", get(api_infra::decomp_status_handler))
        .route("/api/so-stats", get(so_stats::so_stats_handler))
        .route("/api/reg-at", get(reg_at::reg_at_handler))
        .route("/api/coverage", get(coverage::coverage_handler))
        .route("/api/resolve", get(resolve::resolve_handler))
        .route(
            "/api/indirect-targets",
            get(indirect_targets::indirect_targets_handler),
        )
        .route("/api/records", get(records::records_handler))
        .route("/api/record/:idx", get(record::record_handler))
        .route("/api/search", get(search::search_handler))
        .route("/api/query", get(query::query_handler))
        .route("/api/search-pc", get(search_pc::search_pc_handler))
        .route("/api/crypto-scan", get(crypto_scan::crypto_scan_handler))
        .route(
            "/api/crypto-analysis",
            get(crypto_analysis::crypto_analysis_handler),
        )
        .route("/api/watchpoints", get(watchpoints::watchpoints_handler))
        .route(
            "/api/hash-finalize-detect",
            get(hash_finalize::hash_finalize_detect_handler),
        )
        .route(
            "/api/hash-input-search",
            post(hash_input_search::hash_input_search_handler),
        )
        .route("/api/diff-traces", post(diff_traces::diff_traces_handler))
        .route(
            "/api/auto-phase-detect",
            get(auto_phase::auto_phase_detect_handler),
        )
        .route("/api/dep-graph", get(dep_graph::dep_graph_handler))
        .route(
            "/api/forward-dep-tree",
            get(forward_dep_tree::forward_dep_tree_handler),
        )
        .route("/api/bfs-slice", get(bfs_slice::bfs_slice_handler))
        .route("/api/jni-events", get(jni_events::jni_events_handler))
        .route("/api/jni-calls", get(jni_calls::jni_calls_handler))
        .route("/api/jobj-history", get(jobj_history::jobj_history_handler))
        .route("/api/jni-strings", get(jni_strings::jni_strings_handler))
        .route(
            "/api/asm-tokens-for-pcs",
            get(asm_tokens::asm_tokens_handler),
        )
        .route("/api/idxs-for-pc", get(idxs_for_pc::idxs_for_pc_handler))
        .route(
            "/api/idxs-for-block",
            get(idxs_for_block::idxs_for_block_handler),
        )
        .route("/api/cfg", get(cfg::cfg_handler))
        .route("/api/block-for-pc", get(navigation::block_for_pc_handler))
        .route("/api/block", get(navigation::block_handler))
        .route("/api/loops", get(navigation::loops_handler))
        .route("/api/backtrace", get(navigation::backtrace_handler))
        .route("/api/call-chain", get(navigation::call_chain_handler))
        .route("/api/cfg-svg", get(cfg_svg::cfg_svg_handler))
        .route("/api/call-tree", get(call_tree::call_tree_handler))
        .route("/api/fn-summary", get(fn_summary::fn_summary_handler))
        .route("/api/functions", get(functions::functions_handler))
        .route(
            "/api/bn-sidecar/status",
            get(bn_hlil::bn_sidecar_status_handler),
        )
        .route("/api/hlil-for-pc", get(bn_hlil::hlil_for_pc_handler))
        .route("/api/hlil-for-fn", get(bn_hlil::hlil_for_fn_handler))
        .route("/api/bn-cfg-for-pc", get(bn_hlil::bn_cfg_for_pc_handler))
        .route(
            "/api/bn-cfg-svg-for-pc",
            get(bn_hlil::bn_cfg_svg_for_pc_handler),
        )
        .route("/api/fork-events", get(fork_events::fork_events_handler))
        .route(
            "/api/ollvm-detect-vm",
            get(ollvm_detect_vm::ollvm_detect_vm_handler),
        )
        .route(
            "/api/last-write-of-reg",
            get(last_write_of_reg::last_write_of_reg_handler),
        )
        .route(
            "/api/next-use-of-reg",
            get(next_use_of_reg::next_use_of_reg_handler),
        )
        .route("/api/reg-value-at", get(reg_value_at::reg_value_at_handler))
        .route("/api/reg-at-idx", get(reg_value_at::reg_value_at_handler))
        .route(
            "/api/forward-taint",
            get(forward_taint::forward_taint_handler),
        )
        .route(
            "/api/backward-taint",
            get(backward_taint::backward_taint_handler),
        )
        .route("/api/data-chase", get(data_chase::data_chase_handler))
        .route(
            "/api/reg-timeline",
            get(timeline_diff::reg_timeline_handler),
        )
        .route("/api/mem-diff", get(timeline_diff::mem_diff_handler))
        .route("/api/mem-flow", get(mem_flow::mem_flow_handler))
        .route("/api/strings", get(strings::strings_handler))
        .route(
            "/api/string-provenance",
            get(string_provenance::string_provenance_handler),
        )
        .route("/api/mem-dump", get(mem_dump::mem_dump_handler))
        .route("/api/mem-export", get(mem_export::mem_export_handler))
        .route(
            "/api/last-write-of-addr",
            get(memory_query::last_write_of_addr_handler),
        )
        .route(
            "/api/mem-writes-in-range",
            get(memory_query::mem_writes_in_range_handler),
        )
        .route(
            "/api/idxs-touching-range",
            get(memory_query::idxs_touching_range_handler),
        )
        .route(
            "/api/idxs-touching-addr",
            get(memory_query::idxs_touching_addr_handler),
        )
        .route(
            "/api/find-mem-pattern",
            get(memory_query::find_mem_pattern_handler),
        )
        .route("/api/*path", any(api_infra::api_not_found_handler))
        .with_state(state)
}

/// Single source of truth for "does this request require a warm MemShadow".
///
/// Mirrors the routes that call `memshadow_ready_or_block_if_idle()`: warming
/// the sidecar before dispatching avoids the cold-load penalty (or the
/// Building error) on the first CLI call. Parameter-dependent routes inspect
/// query/body flags the same way their handlers do.
pub fn route_requires_memshadow(path: &str, body: Option<&serde_json::Value>) -> bool {
    let endpoint = path.split('?').next().unwrap_or(path);
    if matches!(endpoint, "/api/backward-taint" | "/api/forward-taint") {
        return path.contains("through_mem=true");
    }
    if endpoint == "/api/mem-writes-in-range" {
        return path.contains("src_byte=");
    }
    if endpoint == "/api/hash-input-search" {
        return body
            .and_then(|v| v.get("search_in_mem"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }
    if matches!(
        endpoint,
        "/api/auto-phase-detect"
            | "/api/crypto-analysis"
            | "/api/crypto-scan"
            | "/api/hash-finalize-detect"
            | "/api/jni-strings"
            | "/api/mem-diff"
            | "/api/mem-dump"
            | "/api/mem-export"
            | "/api/mem-flow"
            | "/api/find-mem-pattern"
            | "/api/string-provenance"
            | "/api/strings"
            | "/api/reg-timeline"
            | "/api/idxs-touching-addr"
            | "/api/idxs-touching-range"
    ) {
        return true;
    }
    endpoint == "/api/query"
        && [
            "kind=mem",
            "kind=memory",
            "kind=read",
            "kind=reads",
            "kind=reader",
            "kind=readers",
            "kind=write",
            "kind=writes",
            "kind=writer",
            "kind=writers",
            "kind=string",
            "kind=strings",
            "kind=provenance",
            "kind=prov",
        ]
        .iter()
        .any(|needle| path.contains(needle))
}
