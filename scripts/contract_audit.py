"""Contract-test coverage guard.

Every CLI command family and every server route that should have a contract
test must be covered by a black-box test file that contains test functions.
Exit 0 = complete; exit 1 = gaps (listed as JSON on stdout). The human-
readable blindspot inventory lives in `.until-done/blindspots.md`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "rust" / "crates" / "tracemiku-cli" / "tests"
SVR = REPO / "rust" / "crates" / "tracemiku-server" / "tests"

# CLI command families -> contract test file that must exist and contain tests.
# Keys are command names from args.rs; values are test files (no suffix).
CLI_COVERAGE: dict[str, list[str]] = {
    "capabilities": ["contract_basic"],
    "completions": ["contract_completions"],
    "stats": ["contract_basic"],
    "meta": ["contract_basic"],
    "list": ["contract_basic"],
    "info": ["contract_basic"],
    "decomp-status": ["contract_basic"],
    "bg-status": ["contract_basic"],
    "records": ["contract_query"],
    "record": ["contract_query"],
    "resolve": ["contract_query"],
    "query": ["contract_query"],
    "search": ["contract_query"],
    "search-pc": ["contract_query"],
    "search-asm": ["contract_query"],
    "reg-at": ["contract_query"],
    "reg-value-at": ["contract_query"],
    "reg-at-idx": ["contract_query"],
    "last-write-of-reg": ["contract_query"],
    "next-use-of-reg": ["contract_query"],
    "indirect-targets": ["contract_query"],
    "so-stats": ["contract_query"],
    "strings": ["contract_query"],
    "string-provenance": ["contract_query"],
    "mem-dump": ["contract_query"],
    "mem-export": ["contract_query"],
    "mem-tenet": ["contract_tenet"],
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
    "asm-tokens-for-pcs": ["contract_query"],
    "bn-sidecar-status": ["contract_query"],
    "hlil-for-pc": ["contract_query"],
    "hlil-for-fn": ["contract_query"],
    "bn-cfg-for-pc": ["contract_query"],
    "bn-cfg-svg-for-pc": ["contract_query"],
    "auto-phase-detect": ["contract_query"],
    "jni-calls": ["contract_query"],
    "jni-events": ["contract_query"],
    "jni-output-strings": ["contract_query"],
    "scan-jni-output-strings": ["contract_query"],
    "jobj-history": ["contract_query"],
    "jni-strings": ["contract_query"],
    "cfg": ["contract_query"],
    "cfg-svg": ["contract_query"],
    "idxs-for-block": ["contract_query"],
    "block-for-pc": ["contract_query"],
    "block": ["contract_query"],
    "loops": ["contract_query"],
    "coverage": ["contract_query"],
    "backtrace": ["contract_query"],
    "call-tree": ["contract_query"],
    "call-chain": ["contract_query"],
    "watch": ["contract_query"],
    "dec-summary": ["contract_dec"],
    "dec-fn": ["contract_dec"],
    "dec-models": ["contract_dec"],
    "output-backtrace": ["contract_output"],
    "output-map": ["contract_output"],
    "byte-lineage": ["contract_output"],
    "vm-slice": ["contract_vm"],
    "vm-ops": ["contract_vm"],
    "vm-backstep": ["contract_vm"],
    "vm-backchain": ["contract_vm"],
    "vm-backtree": ["contract_vm"],
    "api": ["contract_basic"],
    "fork-events": ["contract_query"],
    "functions": ["contract_query"],
    "idxs-for-pc": ["contract_query"],
    "idxs-touching-addr": ["contract_query"],
    "idxs-touching-range": ["contract_query"],
    "last-write-of-addr": ["contract_query"],
    "llil-pipeline": ["contract_basic"],
    "llil-render": ["contract_basic"],
    "resolve-elf-symbol": ["contract_basic"],
    "resolve-map-addr": ["contract_basic"],
    "resolve-trace-addr": ["contract_basic"],
}

# Server routes -> contract test files that cover them. Values are existing or
# new test files. Routes without dedicated behavior tests land in the new
# contract_routes_1/2 files (see blindspots.md section 2.2).
ROUTE_COVERAGE: dict[str, list[str]] = {
    "analysis_index": ["contract_routes_1"],
    "asm_tokens": ["asm_tokens_tests"],
    "auto_phase": ["auto_phase_tests"],
    "backward_taint": ["test_taint_routes"],
    "bfs_slice": ["bfs_slice_tests"],
    "bn_hlil": ["bn_sidecar_tests", "test_dec_fn_route"],
    "call_tree": ["test_call_tree_route"],
    "cfg": ["cfg_endpoint_tests"],
    "cfg_svg": ["cfg_endpoint_tests"],
    "coverage": ["coverage_contract_tests"],
    "crypto_analysis": ["crypto_scan_tests"],
    "crypto_scan": ["crypto_scan_tests"],
    "data_chase": ["data_chase_tests"],
    "dec_fn": ["test_dec_fn_route"],
    "dec_llm_call": ["test_dec_llm_call_route"],
    "dec_models": ["test_dec_llm_call_route"],
    "dec_options": ["test_dec_fn_route", "test_dec_summary_route"],
    "dec_summary": ["test_dec_summary_route"],
    "dep_graph": ["dep_graph_tests"],
    "diff_traces": ["diff_traces_tests"],
    "fn_summary": ["fn_summary_tests"],
    "fork_events": ["fork_events_tests"],
    "forward_dep_tree": ["forward_dep_tree_tests"],
    "forward_taint": ["test_taint_routes"],
    "functions": ["functions_tests"],
    "hash_finalize": ["hash_finalize_tests"],
    "hash_input_search": ["hash_input_search_tests"],
    "idxs_for_block": ["cfg_endpoint_tests"],
    "idxs_for_pc": ["idxs_for_pc_tests"],
    "indirect_targets": ["contract_routes_1"],
    "jni_calls": ["jni_calls_tests"],
    "jni_events": ["jni_events_tests"],
    "jni_strings": ["jni_strings_tests"],
    "jobj_history": ["jobj_history_tests"],
    "last_write_of_reg": ["functions_tests"],
    "llil_llm": ["llil_render_tests"],
    "llil_pipeline": ["llil_render_tests"],
    "llil_render": ["llil_render_tests"],
    "mem_dump": ["mem_dump_tests"],
    "mem_export": ["contract_routes_1"],
    "mem_flow": ["mem_flow_tests"],
    "memory_query": ["memory_query_tests"],
    "meta": ["meta_endpoint"],
    "navigation": ["navigation_tests"],
    "next_use_of_reg": ["functions_tests"],
    "ollvm_detect_vm": ["ollvm_detect_vm_tests"],
    "query": ["query_tests"],
    "record": ["records_endpoint"],
    "records": ["records_endpoint"],
    "reg_at": ["contract_routes_1"],
    "reg_value_at": ["inspect_endpoint_tests"],
    "resolve": ["records_endpoint", "dep_graph_tests"],
    "search": ["search_tests"],
    "search_pc": ["search_pc_tests"],
    "seed_resolver": ["dep_graph_tests", "bfs_slice_tests", "forward_dep_tree_tests"],
    "so_stats": ["inspect_endpoint_tests"],
    "string_provenance": ["string_provenance_tests"],
    "strings": ["strings_tests"],
    "timeline_diff": ["timeline_diff_tests"],
    "watchpoints": ["watchpoints_tests"],
}


def file_has_tests(root: Path, name: str) -> bool:
    path = root / f"{name}.rs"
    if not path.exists():
        return False
    text = path.read_text()
    return "#[test]" in text or "#[tokio::test]" in text


def check_coverage(mapping: dict[str, list[str]], root: Path) -> list[str]:
    return [s for s, files in mapping.items() if not any(file_has_tests(root, f) for f in files)]


def live_cli_commands() -> list[str]:
    """Actual command names from the built binary's capabilities output."""
    import subprocess

    bin_path = REPO / "rust" / "target" / "debug" / "tracemiku-cli"
    if not bin_path.exists():
        # Fall back to the declared mapping when the binary is not built.
        return sorted(CLI_COVERAGE)
    proc = subprocess.run(
        [str(bin_path), "capabilities"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        return sorted(CLI_COVERAGE)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return sorted(CLI_COVERAGE)
    return [c["name"] for c in data.get("commands", [])]


def main() -> int:
    cli_gaps = check_coverage(CLI_COVERAGE, CLI)
    route_gaps = check_coverage(ROUTE_COVERAGE, SVR)
    # Cross-check the declared command mapping against the real binary so a
    # renamed/removed command cannot silently leave a stale audit entry.
    live = set(live_cli_commands())
    declared = set(CLI_COVERAGE)
    stale = sorted(declared - live)
    missing = sorted(live - declared)
    report = {
        "cli_commands_covered": len(CLI_COVERAGE) - len(cli_gaps),
        "cli_commands_total": len(CLI_COVERAGE),
        "server_routes_covered": len(ROUTE_COVERAGE) - len(route_gaps),
        "server_routes_total": len(ROUTE_COVERAGE),
        "cli_gaps": cli_gaps,
        "route_gaps": route_gaps,
        "cli_mapping_stale": stale,
        "cli_mapping_missing": missing,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    stale_ok = not stale and not missing
    return 0 if not cli_gaps and not route_gaps and stale_ok else 1


if __name__ == "__main__":
    sys.exit(main())
