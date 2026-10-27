"""Contract-test branch-coverage guard.

Every CLI command family and every core query that should have a contract
test must be covered by a black-box test file that contains test functions.
Exit 0 = complete; exit 1 = gaps (listed as JSON on stdout).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "rust" / "crates" / "tracemiku-cli" / "tests"
CORE = REPO / "rust" / "crates" / "tracemiku-core" / "tests"

# Resource/lazy-loading regressions must name the executable tests that protect them;
# merely keeping a file with unrelated tests does not satisfy these invariants.
REQUIRED_TESTS = {
    CLI / "contract_consolidated.rs": [
        "records_selected_indices_honor_register_filter_and_share_pagination_shape",
        "records_detail_heavy_options_compose_and_restore_evidence",
        "zero_memory_budget_keeps_light_detail_and_limits_heavy_analysis",
        "concurrent_cold_cli_builds_queue_and_share_a_complete_sidecar",
    ],
    CORE / "analysis/records_queries.rs": [
        "records_detail_is_light_by_default_and_heavy_providers_are_independent",
    ],
    CORE / "analysis/mem_flow_tests.rs": [
        "memory_accesses_uses_trace_stream_and_memshadow_without_full_index",
    ],
    CORE / "memshadow_tests.rs": [
        "compact_byte_event_is_8_bytes_and_checks_record_index_boundaries",
        "mmap_sidecar_matches_cold_build_without_file_sized_heap_allocation",
        "large_worker_mmap_preserves_boundary_tail_conditional_and_anchor_semantics",
        "same_length_worker_rewrite_invalidates_sidecar",
    ],
    REPO / "rust/crates/tracemiku-core/src/cfg.rs": [
        "repeated_edges_aggregate_without_capacity_growth",
        "repeated_dynamic_branches_keep_counts_scc_and_memory_budget",
    ],
}

# CLI command families -> contract test file that must exist and contain tests.
# Keys are public commands from ./tracemiku; values are test files (no suffix).
CLI_COVERAGE: dict[str, list[str]] = {
    "events": ["contract_consolidated"],
    "experimental": ["contract_vm", "contract_consolidated"],
    "experimental vm-slice": ["contract_vm"],
    "experimental vm-ops": ["contract_vm"],
    "experimental vm-backstep": ["contract_vm"],
    "experimental vm-backchain": ["contract_vm"],
    "experimental vm-backtree": ["contract_vm"],
    "trace": ["contract_entrypoint", "contract_capture"],
    "recover": ["contract_capture", "contract_semantics"],
    "probe": ["contract_entrypoint"],
    "doctor": ["contract_entrypoint"],
    "capabilities": ["contract_basic", "contract_semantics", "contract_entrypoint"],
    "finalize": ["contract_basic"],
    "completions": ["contract_completions"],
    "list": ["contract_basic"],
    "info": ["contract_consolidated", "contract_basic", "contract_capture"],
    "records": ["contract_consolidated", "contract_query", "contract_offline"],
    "resolve": ["contract_consolidated", "contract_query"],
    "search": ["contract_query"],
    "reg-at": ["contract_query"],
    "last-write-of-reg": ["contract_query"],
    "next-use-of-reg": ["contract_query"],
    "indirect-targets": ["contract_query"],
    "so-stats": ["contract_query"],
    "strings": ["contract_query"],
    "mem-dump": ["contract_consolidated", "contract_query"],
    "mem-provenance": ["contract_consolidated", "contract_tenet", "contract_offline"],
    "find-mem-pattern": ["contract_query"],
    "taint-bwd": ["contract_query"],
    "taint-fwd": ["contract_query"],
    "bfs-slice": ["contract_consolidated", "contract_query"],
    "reg-timeline": ["contract_consolidated", "contract_query"],
    "crypto": ["contract_query"],
    "jni-calls": ["contract_consolidated", "contract_query"],
    "cfg": ["contract_consolidated", "contract_query"],
    "loops": ["contract_query"],
    "trace-replay": ["contract_replay"],
    "backtrace": ["contract_consolidated", "contract_query"],
    "call-tree": ["contract_query"],
    "output-backtrace": ["contract_output"],
    "byte-lineage": ["contract_output"],
    "functions": ["contract_consolidated", "contract_query"],
    "pc-hits": ["contract_query"],
    "mem-accesses": ["contract_consolidated", "contract_query"],
    "last-write-of-addr": ["contract_query"],
}

# 核心查询与其独立 fixture 断言；不依赖 HTTP 或浏览器。
QUERY_COVERAGE: dict[str, list[str]] = {
    "dependency_query": ["consolidated_queries", "analysis/dep_graph_tests", "analysis/forward_dep_tree_tests", "analysis/bfs_slice_tests"],
    "dependency_seeds": ["analysis/bfs_slice_tests"],
    "events": ["event_queries", "analysis/jni_events_tests", "analysis/fork_events_tests"],
    "mem_accesses": ["consolidated_queries", "analysis/mem_flow_tests"],
    "mem_provenance": ["consolidated_queries"],
    "analysis_index": ["analysis/contract_queries_1"],
    "backward_taint": ["analysis/test_taint_queries"],
    "call_tree": ["analysis/test_call_tree_query"],
    "cfg": ["analysis/cfg_queries_tests"],
    "coverage": ["analysis/coverage_contract_tests"],
    "crypto_analysis": ["analysis/crypto_scan_tests"],
    "fn_summary": ["analysis/fn_summary_tests"],
    "forward_taint": ["analysis/test_taint_queries"],
    "functions": ["analysis/functions_tests"],
    "idxs_for_block": ["analysis/cfg_queries_tests"],
    "idxs_for_pc": ["analysis/idxs_for_pc_tests"],
    "indirect_targets": ["analysis/contract_queries_1", "analysis/indirect_targets_boundary_tests"],
    "jni_calls": ["analysis/jni_calls_tests", "analysis/jobj_history_tests"],
    "jni_strings": ["analysis/jni_strings_tests"],
    "last_write_of_reg": ["analysis/functions_tests"],
    "trace_replay": ["analysis/trace_replay_tests"],
    "mem_dump": ["analysis/mem_dump_tests"],
    "memory_query": ["analysis/memory_query_tests"],
    "navigation": ["analysis/navigation_tests"],
    "next_use_of_reg": ["analysis/functions_tests"],
    "records": ["consolidated_queries", "analysis/records_queries"],
    "reg_at": ["analysis/contract_queries_1"],
    "resolve": ["consolidated_queries", "analysis/records_queries", "analysis/dep_graph_tests"],
    "search": ["analysis/search_tests"],
    "seed_resolver": ["analysis/dep_graph_tests", "analysis/bfs_slice_tests", "analysis/forward_dep_tree_tests"],
    "so_stats": ["analysis/inspect_queries_tests"],
    "string_provenance": ["analysis/string_provenance_tests"],
    "strings": ["analysis/strings_tests"],
    "timeline_diff": ["register_query_contracts", "analysis/timeline_diff_tests", "analysis/watchpoints_tests"],
}


def file_has_tests(root: Path, name: str) -> bool:
    path = root / f"{name}.rs"
    if not path.exists():
        return False
    text = path.read_text()
    return "#[test]" in text


def check_coverage(mapping: dict[str, list[str]], root: Path) -> list[str]:
    return [
        s
        for s, files in mapping.items()
        if not all(file_has_tests(root, f) for f in files)
    ]


def live_cli_commands() -> list[str]:
    """Read the public catalog; never substitute declarations for executable evidence."""
    import os

    bin_path = Path(os.environ.get(
        "TRACEMIKU_CLI_BIN", REPO / "rust" / "target" / "debug" / "tracemiku-cli"
    ))
    if not bin_path.is_file():
        raise RuntimeError("CLI binary missing; run make cli before the contract audit")
    env = dict(os.environ, TRACEMIKU_CLI_BIN=str(bin_path.resolve()))
    proc = subprocess.run(
        [sys.executable, str(REPO / "tracemiku"), "capabilities"],
        capture_output=True, text=True, timeout=30, check=True, env=env,
    )
    data = json.loads(proc.stdout)
    if data.get("schema_version") != 2 or not isinstance(data.get("commands"), list):
        raise ValueError("unsupported capabilities schema")
    def paths(commands, prefix=""):
        for command in commands:
            name = f'{prefix}{command["name"]}'
            yield name
            yield from paths(command.get("subcommands", []), name + " ")
    return list(paths(data["commands"]))


def check_required_tests() -> list[str]:
    missing = []
    for path, names in REQUIRED_TESTS.items():
        text = path.read_text() if path.exists() else ""
        missing.extend(f'{path.relative_to(REPO)}::{name}'
                       for name in names if f'fn {name}(' not in text)
    return missing


def main() -> int:
    cli_gaps = check_coverage(CLI_COVERAGE, CLI)
    query_gaps = check_coverage(QUERY_COVERAGE, CORE)
    required_test_gaps = check_required_tests()
    invariant_gaps = [name for name in ("contract_entrypoint", "contract_offline")
                      if not file_has_tests(CLI, name)]
    # Cross-check the declared command mapping against the real binary so a
    # renamed/removed command cannot silently leave a stale audit entry.
    try:
        live = set(live_cli_commands())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"cli_discovery_error": str(exc)}, ensure_ascii=False))
        return 1
    declared = set(CLI_COVERAGE)
    stale = sorted(declared - live)
    missing = sorted(live - declared)
    report = {
        "cli_commands_covered": len(CLI_COVERAGE) - len(cli_gaps),
        "cli_commands_total": len(CLI_COVERAGE),
        "core_queries_covered": len(QUERY_COVERAGE) - len(query_gaps),
        "core_queries_total": len(QUERY_COVERAGE),
        "cli_gaps": cli_gaps,
        "query_gaps": query_gaps,
        "invariant_gaps": invariant_gaps,
        "required_test_gaps": required_test_gaps,
        "cli_mapping_stale": stale,
        "cli_mapping_missing": missing,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    stale_ok = not stale and not missing
    return 0 if not cli_gaps and not query_gaps and not invariant_gaps and not required_test_gaps and stale_ok else 1


if __name__ == "__main__":
    sys.exit(main())
