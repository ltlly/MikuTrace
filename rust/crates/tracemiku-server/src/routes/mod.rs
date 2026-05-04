pub mod backward_taint;
pub mod call_tree;
pub mod cfg;
pub mod cfg_svg;
pub mod dec_fn;
pub mod dec_llm_call;
pub mod dec_models;
pub mod dec_summary;
pub mod forward_taint;
pub mod functions;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod last_write_of_reg;
pub mod mem_dump;
pub mod meta;
pub mod record;
pub mod records;
pub mod strings;

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/meta", get(meta::meta_handler))
        .route("/api/records", get(records::records_handler))
        .route("/api/record/:idx", get(record::record_handler))
        .route("/api/idxs-for-pc", get(idxs_for_pc::idxs_for_pc_handler))
        .route(
            "/api/idxs-for-block",
            get(idxs_for_block::idxs_for_block_handler),
        )
        .route("/api/cfg", get(cfg::cfg_handler))
        .route("/api/cfg-svg", get(cfg_svg::cfg_svg_handler))
        .route("/api/call-tree", get(call_tree::call_tree_handler))
        .route("/api/functions", get(functions::functions_handler))
        .route("/api/dec/summary", get(dec_summary::dec_summary_handler))
        .route("/api/dec/fn/:fn_id", get(dec_fn::dec_fn_handler))
        .route(
            "/api/dec/llm-call",
            post(dec_llm_call::dec_llm_call_handler),
        )
        .route("/api/dec/models", get(dec_models::dec_models_handler))
        .route(
            "/api/last-write-of-reg",
            get(last_write_of_reg::last_write_of_reg_handler),
        )
        .route(
            "/api/forward-taint",
            get(forward_taint::forward_taint_handler),
        )
        .route(
            "/api/backward-taint",
            get(backward_taint::backward_taint_handler),
        )
        .route("/api/strings", get(strings::strings_handler))
        .route("/api/mem-dump", get(mem_dump::mem_dump_handler))
        .with_state(state)
}
