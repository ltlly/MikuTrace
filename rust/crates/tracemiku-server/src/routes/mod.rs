pub mod api_infra;
pub mod asm_tokens;
pub mod auto_phase;
pub mod backward_taint;
pub mod call_tree;
pub mod cfg;
pub mod cfg_svg;
pub mod crypto_scan;
pub mod data_chase;
pub mod dec_fn;
pub mod dec_llm_call;
pub mod dec_models;
pub mod dec_summary;
pub mod diff_traces;
pub mod field_at;
pub mod fn_summary;
pub mod fork_events;
pub mod forward_taint;
pub mod functions;
pub mod hash_finalize;
pub mod hash_input_search;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod jni_calls;
pub mod jni_events;
pub mod jni_strings;
pub mod jobj_history;
pub mod last_write_of_reg;
pub mod llil_llm;
pub mod llil_render;
pub mod mem_dump;
pub mod mem_flow;
pub mod memory_query;
pub mod meta;
pub mod navigation;
pub mod ollvm_detect_vm;
pub mod record;
pub mod records;
pub mod reg_value_at;
pub mod search;
pub mod search_pc;
pub mod so_stats;
pub mod string_provenance;
pub mod strings;
pub mod timeline_diff;

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/openapi.json", get(api_infra::openapi_handler))
        .route("/ws/jobs", get(api_infra::jobs_ws_handler))
        .route("/api/meta", get(meta::meta_handler))
        .route("/api/so-stats", get(so_stats::so_stats_handler))
        .route("/api/records", get(records::records_handler))
        .route("/api/record/:idx", get(record::record_handler))
        .route("/api/search", get(search::search_handler))
        .route("/api/search-pc", get(search_pc::search_pc_handler))
        .route("/api/crypto-scan", get(crypto_scan::crypto_scan_handler))
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
        .route("/api/jni-events", get(jni_events::jni_events_handler))
        .route("/api/jni-calls", get(jni_calls::jni_calls_handler))
        .route("/api/jobj-history", get(jobj_history::jobj_history_handler))
        .route("/api/jni-strings", get(jni_strings::jni_strings_handler))
        .route("/api/field-at", get(field_at::field_at_handler))
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
        .route("/api/fork-events", get(fork_events::fork_events_handler))
        .route(
            "/api/ollvm-detect-vm",
            get(ollvm_detect_vm::ollvm_detect_vm_handler),
        )
        .route("/api/dec/summary", get(dec_summary::dec_summary_handler))
        .route("/api/dec/fn/:fn_id", get(dec_fn::dec_fn_handler))
        .route(
            "/api/dec/llm-call",
            post(dec_llm_call::dec_llm_call_handler),
        )
        .route("/api/dec/models", get(dec_models::dec_models_handler))
        .route("/api/llil/llm", post(llil_llm::llil_llm_handler))
        .route("/api/llil/render", post(llil_render::llil_render_handler))
        .route(
            "/api/last-write-of-reg",
            get(last_write_of_reg::last_write_of_reg_handler),
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
        .route(
            "/api/last-write-of-addr",
            get(memory_query::last_write_of_addr_handler),
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
        .with_state(state)
}
