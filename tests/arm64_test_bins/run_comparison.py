#!/usr/bin/env python3
"""Run traceMiku decompiler on all 56 functions, save full comparison artifacts.

历史脚本：本地反编译管线已从 core 移除（反编译统一由 BN sidecar 提供），
本脚本仅作历史参考保留。生成的 Rust 对比测试骨架打印到 stdout，不再写入
rust/crates（该路径下没有对应测试文件，写入只会制造孤儿文件）。

用法：
    python3 tests/arm64_test_bins/run_comparison.py > /tmp/all_binaries_comparison.rs
    # 骨架中的 INSTRUCTIONS_WILL_BE_INSERTED_HERE 占位需要先用
    # extract_and_test.py 提取指令数据后才可用。
"""
import json
import sys
from pathlib import Path
from datetime import datetime

WORK = Path(__file__).resolve().parent

BINS = {
    "decomp_test_suite": str(WORK / "decomp_test_suite"),
    "test_strings": str(WORK / "test_strings"),
    "test_linkedlist": str(WORK / "test_linkedlist"),
    "test_arrays": str(WORK / "test_arrays"),
    "test_hash": str(WORK / "test_hash"),
    "test_fsm": str(WORK / "test_fsm"),
    "test_fp": str(WORK / "test_fp"),
}

OUT = WORK / "comparison_results"
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

# 骨架输出到 stdout（见模块 docstring 的用法说明）
print(rust)

print(f"Note: This is a skeleton — instructions need to be filled in.", file=sys.stderr)
print(f"Use extract_and_test.py for each binary to get full instruction data.", file=sys.stderr)

# For now, run the existing 44 decomp_verify tests and 15 bn_comparison tests
total_tests = 44 + 15
print(f"\nExisting tests: {total_tests} (44 verify + 15 comparison)")
