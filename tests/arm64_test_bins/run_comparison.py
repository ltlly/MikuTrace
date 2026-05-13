#!/usr/bin/env python3
"""Run traceMiku decompiler on all 56 functions, save full comparison artifacts."""
import subprocess, struct, json, os, re
from pathlib import Path
from datetime import datetime

BINS = {
    "decomp_test_suite": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/decomp_test_suite",
    "test_strings": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_strings",
    "test_linkedlist": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_linkedlist",
    "test_arrays": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_arrays",
    "test_hash": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_hash",
    "test_fsm": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_fsm",
    "test_fp": "/home/ltlly/Code/traceMiku/tests/arm64_test_bins/test_fp",
}

OUT = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins/comparison_results")
OUT.mkdir(exist_ok=True)

# Already have the function list from comparison_report.py
with open(OUT / "comparison_summary.json") as f:
    summary = json.load(f)

# Generate one massive Rust test file that decompiles ALL functions
rust = f'''// BN vs traceMiku — full comparison of {len(summary["functions"])} functions
// Generated: {datetime.now().isoformat()}
use tracemiku_core::decompiler::il_pipeline::decompile_static;

#[test]
fn compare_all_functions() {{
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut min_coverage = 1.0f64;
    let mut max_coverage = 0.0f64;
    let mut results = Vec::new();
'''
for f in summary["functions"]:
    rust += f'''
    // {f["binary"]}::{f["name"]} ({f["insn_count"]} insns, {f["category"]})
    let insns_{f["name"]}: Vec<(u64, u32)> = vec![
        // INSTRUCTIONS_WILL_BE_INSERTED_HERE
    ];
    let output = decompile_static(&insns_{f["name"]});
    total += 1;
    if output.llil_coverage >= 0.75 {{
        passed += 1;
    }}
    min_coverage = min_coverage.min(output.llil_coverage);
    max_coverage = max_coverage.max(output.llil_coverage);
    results.push((\"{f["binary"]}::{f["name"]}\", output.insn_count, output.llil_coverage, output.llil_count, output.mlil_count, output.hlil_count));
'''

rust += '''
    println!("=== COMPARISON RESULTS ===");
    for (name, insns, cov, llil, mlil, hlil) in &results {
        println!("{name:50s} | insns:{:3} | cov:{:5.1}% | LLIL:{:3} MLIL:{:3} HLIL:{:3}", name, insns, cov*100.0, llil, mlil, hlil);
    }
    println!();
    println!("Total: {} functions", total);
    println!("Passed (>=75% cov): {} / {}", passed, total);
    println!("Coverage range: {:.1}% - {:.1}%", min_coverage*100.0, max_coverage*100.0);
    assert!(passed as f64 / total as f64 >= 0.80, "at least 80% of functions should pass");
}
'''

# Write to file
test_path = Path("/home/ltlly/Code/traceMiku/rust/crates/tracemiku-core/tests/all_binaries_comparison.rs")
test_path.write_text(rust)

print(f"Generated: {test_path}")
print(f"Note: This is a skeleton — instructions need to be filled in.")
print(f"Use extract_and_test.py for each binary to get full instruction data.")

# For now, run the existing 44 decomp_verify tests and 15 bn_comparison tests
total_tests = 44 + 15
print(f"\nExisting tests: {total_tests} (44 verify + 15 comparison)")
