"""Contract-test coverage guard.

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

# CLI command families -> contract test file that must exist and contain tests.
# Keys are public commands from ./tracemiku; values are test files (no suffix).
CLI_COVERAGE: dict[str, list[str]] = {
    "trace": ["contract_entrypoint"],
    "probe": ["contract_entrypoint"],
    "doctor": ["contract_entrypoint"],
    "capabilities": ["contract_basic", "contract_semantics", "contract_entrypoint"],
    "finalize": ["contract_basic"],
    "completions": ["contract_completions"],
    "stats": ["contract_basic"],
    "meta": ["contract_basic"],
    "list": ["contract_basic"],
    "info": ["contract_basic"],
    "records": ["contract_query"],
    "record": ["contract_query"],
    "resolve": ["contract_query"],
    "search": ["contract_query"],
    "reg-at": ["contract_query"],
    "reg-value-at": ["contract_query"],
    "last-write-of-reg": ["contract_query"],
    "next-use-of-reg": ["contract_query"],
    "indirect-targets": ["contract_query"],
    "so-stats": ["contract_query"],
    "strings": ["contract_query"],
    "string-provenance": ["contract_query"],
    "mem-dump": ["contract_query"],
    "mem-export": ["contract_query"],
    "mem-tenet": ["contract_tenet", "contract_offline"],
    "find-mem-pattern": ["contract_query"],
    "taint-bwd": ["contract_query"],
    "taint-fwd": ["contract_query"],
    "data-chase": ["contract_query"],
    "dep-graph": ["contract_query"],
    "bfs-slice": ["contract_query"],
    "forward-dep-tree": ["contract_query"],
    "reg-timeline": ["contract_query"],
    "mem-diff": ["contract_query"],
    "mem-flow": ["contract_query"],
    "mem-writes-in-range": ["contract_query"],
    "byte-writer-map": ["contract_query"],
    "ollvm-detect-vm": ["contract_query"],
    "fn-summary": ["contract_query"],
    "crypto-scan": ["contract_query"],
    "crypto": ["contract_query"],
    "hash-finalize-detect": ["contract_query"],
    "hash-input-search": ["contract_query"],
    "diff-traces": ["contract_query"],
    "auto-phase-detect": ["contract_query"],
    "jni-calls": ["contract_query"],
    "jni-events": ["contract_query"],
    "jni-output-strings": ["contract_query"],
    "scan-jni-output-strings": ["contract_query"],
    "jobj-history": ["contract_query"],
    "jni-strings": ["contract_query"],
    "cfg": ["contract_query"],
    "idxs-for-block": ["contract_query"],
    "block-for-pc": ["contract_query"],
    "block": ["contract_query"],
    "loops": ["contract_query"],
    "coverage": ["contract_query"],
    "trace-replay": ["contract_replay"],
    "backtrace": ["contract_query"],
    "call-tree": ["contract_query"],
    "call-chain": ["contract_query"],
    "watch": ["contract_query"],
    "output-backtrace": ["contract_output"],
    "output-map": ["contract_output", "contract_output_boundary"],
    "byte-lineage": ["contract_output"],
    "vm-slice": ["contract_vm"],
    "vm-ops": ["contract_vm"],
    "vm-backstep": ["contract_vm"],
    "vm-backchain": ["contract_vm"],
    "vm-backtree": ["contract_vm"],
    "fork-events": ["contract_query"],
    "functions": ["contract_query"],
    "idxs-for-pc": ["contract_query"],
    "idxs-touching-addr": ["contract_query"],
    "idxs-touching-range": ["contract_query"],
    "last-write-of-addr": ["contract_query"],
    "resolve-elf-symbol": ["contract_basic"],
    "resolve-map-addr": ["contract_basic"],
    "resolve-trace-addr": ["contract_basic"],
}

# 核心查询与其独立 fixture 断言；不依赖 HTTP 或浏览器。
QUERY_COVERAGE: dict[str, list[str]] = {
    "analysis_index": ["analysis/contract_queries_1"],
    "auto_phase": ["analysis/auto_phase_tests"],
    "backward_taint": ["analysis/test_taint_queries"],
    "bfs_slice": ["analysis/bfs_slice_tests"],
    "call_tree": ["analysis/test_call_tree_query"],
    "cfg": ["analysis/cfg_queries_tests"],
    "coverage": ["analysis/coverage_contract_tests"],
    "crypto_analysis": ["analysis/crypto_scan_tests"],
    "crypto_scan": ["analysis/crypto_scan_tests"],
    "data_chase": ["analysis/data_chase_tests"],
    "dep_graph": ["analysis/dep_graph_tests"],
    "diff_traces": ["analysis/diff_traces_tests"],
    "fn_summary": ["analysis/fn_summary_tests"],
    "fork_events": ["analysis/fork_events_tests"],
    "forward_dep_tree": ["analysis/forward_dep_tree_tests"],
    "forward_taint": ["analysis/test_taint_queries"],
    "functions": ["analysis/functions_tests"],
    "hash_finalize": ["analysis/hash_finalize_tests"],
    "hash_input_search": ["analysis/hash_input_search_tests"],
    "idxs_for_block": ["analysis/cfg_queries_tests"],
    "idxs_for_pc": ["analysis/idxs_for_pc_tests"],
    "indirect_targets": ["analysis/contract_queries_1", "analysis/indirect_targets_boundary_tests"],
    "jni_calls": ["analysis/jni_calls_tests"],
    "jni_events": ["analysis/jni_events_tests"],
    "jni_strings": ["analysis/jni_strings_tests"],
    "jobj_history": ["analysis/jobj_history_tests"],
    "last_write_of_reg": ["analysis/functions_tests"],
    "trace_replay": ["analysis/trace_replay_tests"],
    "mem_dump": ["analysis/mem_dump_tests"],
    "mem_export": ["analysis/contract_queries_1"],
    "mem_flow": ["analysis/mem_flow_tests"],
    "memory_query": ["analysis/memory_query_tests"],
    "meta": ["analysis/meta_queries"],
    "navigation": ["analysis/navigation_tests"],
    "next_use_of_reg": ["analysis/functions_tests"],
    "ollvm_detect_vm": ["analysis/ollvm_detect_vm_tests"],
    "record": ["analysis/records_queries"],
    "records": ["analysis/records_queries"],
    "reg_at": ["analysis/contract_queries_1"],
    "reg_value_at": ["analysis/inspect_queries_tests"],
    "resolve": ["analysis/records_queries", "analysis/dep_graph_tests"],
    "search": ["analysis/search_tests"],
    "seed_resolver": ["analysis/dep_graph_tests", "analysis/bfs_slice_tests", "analysis/forward_dep_tree_tests"],
    "so_stats": ["analysis/inspect_queries_tests"],
    "string_provenance": ["analysis/string_provenance_tests"],
    "strings": ["analysis/strings_tests"],
    "timeline_diff": ["analysis/timeline_diff_tests"],
    "watchpoints": ["analysis/watchpoints_tests"],
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
        if not any(file_has_tests(root, f) for f in files)
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
    return [command["name"] for command in data["commands"]]


def main() -> int:
    cli_gaps = check_coverage(CLI_COVERAGE, CLI)
    query_gaps = check_coverage(QUERY_COVERAGE, CORE)
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
        "cli_mapping_stale": stale,
        "cli_mapping_missing": missing,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    stale_ok = not stale and not missing
    return 0 if not cli_gaps and not query_gaps and not invariant_gaps and stale_ok else 1


if __name__ == "__main__":
    sys.exit(main())
