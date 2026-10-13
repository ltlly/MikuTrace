//! 离线核心查询的合成 trace 与边界契约。
mod analysis_support;

#[path = "analysis/bfs_slice_tests.rs"]
mod bfs_slice_tests;
#[path = "analysis/cfg_queries_tests.rs"]
mod cfg_queries_tests;
#[path = "analysis/contract_queries_1.rs"]
mod contract_queries_1;
#[path = "analysis/coverage_contract_tests.rs"]
mod coverage_contract_tests;
#[path = "analysis/crypto_scan_tests.rs"]
mod crypto_scan_tests;
#[path = "analysis/dep_graph_tests.rs"]
mod dep_graph_tests;
#[path = "analysis/fn_summary_tests.rs"]
mod fn_summary_tests;
#[path = "analysis/fork_events_tests.rs"]
mod fork_events_tests;
#[path = "analysis/forward_dep_tree_tests.rs"]
mod forward_dep_tree_tests;
#[path = "analysis/functions_tests.rs"]
mod functions_tests;
#[path = "analysis/idxs_for_pc_tests.rs"]
mod idxs_for_pc_tests;
#[path = "analysis/index_tests.rs"]
mod index_tests;
#[path = "analysis/indirect_targets_boundary_tests.rs"]
mod indirect_targets_boundary_tests;
#[path = "analysis/inspect_queries_tests.rs"]
mod inspect_queries_tests;
#[path = "analysis/jni_calls_tests.rs"]
mod jni_calls_tests;
#[path = "analysis/jni_events_tests.rs"]
mod jni_events_tests;
#[path = "analysis/jni_strings_tests.rs"]
mod jni_strings_tests;
#[path = "analysis/jobj_history_tests.rs"]
mod jobj_history_tests;
#[path = "analysis/mem_diff_boundary_tests.rs"]
mod mem_diff_boundary_tests;
#[path = "analysis/mem_dump_tests.rs"]
mod mem_dump_tests;
#[path = "analysis/mem_flow_tests.rs"]
mod mem_flow_tests;
#[path = "analysis/memory_query_tests.rs"]
mod memory_query_tests;
#[path = "analysis/meta_queries.rs"]
mod meta_queries;
#[path = "analysis/navigation_tests.rs"]
mod navigation_tests;
#[path = "analysis/query_boundary_contract_tests.rs"]
mod query_boundary_contract_tests;
#[path = "analysis/query_boundary_contract_tests2.rs"]
mod query_boundary_contract_tests2;
#[path = "analysis/records_queries.rs"]
mod records_queries;
#[path = "analysis/resolve_contract_tests.rs"]
mod resolve_contract_tests;
#[path = "analysis/search_tests.rs"]
mod search_tests;
#[path = "analysis/string_provenance_tests.rs"]
mod string_provenance_tests;
#[path = "analysis/strings_tests.rs"]
mod strings_tests;
#[path = "analysis/test_call_tree_query.rs"]
mod test_call_tree_query;
#[path = "analysis/test_taint_queries.rs"]
mod test_taint_queries;
#[path = "analysis/timeline_contract_tests.rs"]
mod timeline_contract_tests;
#[path = "analysis/timeline_diff_tests.rs"]
mod timeline_diff_tests;
#[path = "analysis/trace_replay_tests.rs"]
mod trace_replay_tests;
#[path = "analysis/watchpoints_tests.rs"]
mod watchpoints_tests;
