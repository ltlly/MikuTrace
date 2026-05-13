#!/usr/bin/env python3
"""Systematic BN vs traceMiku comparison across all IL levels and categories."""
import subprocess, struct, json, os, sys
from pathlib import Path
from datetime import datetime

ELF = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins/decomp_test_suite")
OUT = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins/comparison_results")
OUT.mkdir(exist_ok=True)

# 10 representative functions covering all categories
FUNCTIONS = [
    ("test_add", 0x400740, 0x400760, "Arithmetic"),
    ("test_mul", 0x400780, 0x4007a0, "Arithmetic"),
    ("test_if_else", 0x40093c, 0x400978, "ControlFlow"),
    ("test_while_loop", 0x4009dc, 0x400a28, "Loop"),
    ("test_call_two_args", 0x400aa8, 0x400ae8, "FunctionCall"),
    ("test_struct_field_read", 0x400b88, 0x400bac, "Struct"),
    ("test_ptr_arith", 0x400d5c, 0x400d84, "Pointer"),
    ("test_switch", 0x400e1c, 0x400e7c, "Switch"),
    ("test_factorial", 0x400ddc, 0x400e1c, "Recursion"),
    ("test_csel", 0x400f3c, 0x400f60, "Csel"),
    ("test_stack_spill", 0x400bf8, 0x400cf8, "StackSpill"),
    ("test_ldrsw", 0x400eac, 0x400ec4, "LoadStore"),
    ("test_bitfield_extract", 0x400cf8, 0x400d14, "Bitfield"),
    ("test_for_loop", 0x400a28, 0x400a74, "Loop"),
    ("test_do_while", 0x400a74, 0x400aa8, "Loop"),
]

# Extract instructions from ELF
objdump_out = subprocess.check_output(["aarch64-linux-gnu-objdump", "-d", str(ELF)], text=True)
all_insns = {}
for line in objdump_out.splitlines():
    parts = line.strip().replace('\t', ' ').split()
    if len(parts) >= 2:
        try:
            all_insns[int(parts[0].rstrip(':'), 16)] = int(parts[1], 16)
        except ValueError:
            continue

# Generate comparison test file
comparisons = []
rust_code = '''// Auto-generated BN vs traceMiku comparison tests
// Generated: ''' + datetime.now().isoformat() + '''
use tracemiku_core::decompiler::il_pipeline::decompile_static;

'''

for name, start, end, category in FUNCTIONS:
    insns = [(pc, all_insns[pc]) for pc in sorted(all_insns) if start <= pc < end and pc in all_insns]
    if len(insns) < 2:
        continue
    
    comparisons.append({
        "name": name, "category": category,
        "start": f"{start:#x}", "end": f"{end:#x}",
        "insn_count": len(insns),
        "insns": [(f"{pc:#x}", f"{inst:#010x}") for pc, inst in insns]
    })
    
    rust_code += f'''
#[test]
fn compare_{name}() {{
    let insns: Vec<(u64, u32)> = vec![
'''
    for pc, inst in insns:
        rust_code += f'        ({pc:#018x}u64, {inst:#010x}u32),\n'
    rust_code += f'''    ];
    let output = decompile_static(&insns);
    
    println!("=== {name} ({category}) ===");
    println!("insns: {{}}", output.insn_count);
    println!("coverage: {{:.1}}%", output.llil_coverage * 100.0);
    println!("LLIL: {{}} exprs", output.llil_count);
    println!("MLIL: {{}} exprs", output.mlil_count);
    println!("HLIL: {{}} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{{}}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{{}}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{{}}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for {name}");
}}
'''
    print(f"[{category:15s}] {name:30s}: {len(insns):3d} insns @ {start:#x}-{end:#x}")

# Write Rust test
test_path = Path("/home/ltlly/Code/traceMiku/rust/crates/tracemiku-core/tests/bn_comparison_tests.rs")
test_path.write_text(rust_code)

# Write JSON summary
with open(OUT / "comparison_index.json", 'w') as f:
    json.dump({"functions": comparisons, "total": len(comparisons), "timestamp": datetime.now().isoformat()}, f, indent=2)

print(f"\n{len(comparisons)} comparisons written to {test_path}")
print(f"Index: {OUT / 'comparison_index.json'}")
print(f"\nRun: cargo test --manifest-path /home/ltlly/Code/traceMiku/rust/Cargo.toml -p tracemiku-core --test bn_comparison_tests -- --nocapture")
