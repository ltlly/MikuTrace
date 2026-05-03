pub mod cfg;
pub mod functions;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod last_write_of_reg;
pub mod meta;
pub mod record;
pub mod records;

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
        .route("/api/functions", get(functions::functions_handler))
        .route(
            "/api/last-write-of-reg",
            get(last_write_of_reg::last_write_of_reg_handler),
        )
        .with_state(state)
}
