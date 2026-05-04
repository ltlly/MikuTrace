pub mod backward_taint;
pub mod call_tree;
pub mod cfg;
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

use axum::routing::get;
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
        .route("/api/call-tree", get(call_tree::call_tree_handler))
        .route("/api/functions", get(functions::functions_handler))
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
