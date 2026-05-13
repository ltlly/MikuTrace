#!/usr/bin/env python3
"""Extract ARM64 test functions, build trace.bin, feed to decompiler, verify."""
import subprocess, struct, os, sys, json, tempfile
from pathlib import Path

ELF = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins/decomp_test_suite")
WORK = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins")

# 1. Get function addresses using nm
nm_out = subprocess.check_output(["aarch64-linux-gnu-nm", str(ELF)], text=True)
funcs = {}
for line in nm_out.splitlines():
    parts = line.split()
    if len(parts) >= 3 and parts[1] in ('T', 't'):
        addr = int(parts[0], 16)
        name = parts[2]
        if name.startswith('test_'):
            funcs[name] = addr

print(f"Found {len(funcs)} test functions:")
for name, addr in sorted(funcs.items(), key=lambda x: x[1]):
    print(f"  {name}: {addr:#010x}")

# 2. Disassemble entire .text section to get (addr, raw_bytes) mapping
objdump = subprocess.check_output(
    ["aarch64-linux-gnu-objdump", "-d", str(ELF)], text=True
)

insns = {}  # addr -> (inst_word, mnemonic)
for line in objdump.splitlines():
    line = line.strip()
    if not line or ':' not in line:
        continue
    # Parse: "  400290:   90000510    adrp    x16, 4a0000"
    parts = line.replace('\t', ' ').split()
    if len(parts) >= 2:
        try:
            addr = int(parts[0].rstrip(':'), 16)
            raw = int(parts[1], 16)
            # Simple mnemonic check: if part[2] looks like an instruction name (starts with letter)
            mnem = parts[2] if len(parts) > 2 and parts[2][0].isalpha() else "?"
            insns[addr] = (raw, mnem)
        except (ValueError, IndexError):
            continue

# 3. For each test function, extract its instructions (from func addr to next func or ret + some padding)
sorted_funcs = sorted(funcs.items(), key=lambda x: x[1])
func_insns = {}

for i, (name, addr) in enumerate(sorted_funcs):
    end_addr = sorted_funcs[i+1][1] - 4 if i+1 < len(sorted_funcs) else addr + 0x200
    func_insns[name] = [(pc, insns[pc][0]) for pc in sorted(insns.keys()) 
                        if addr <= pc < end_addr and pc in insns]

# 4. Print stats
print(f"\n{'Function':<35} {'Insns':>6}")
print("-" * 43)
for name in sorted(func_insns.keys()):
    count = len(func_insns[name])
    print(f"{name:<35} {count:>6}")

# 5. Output Rust test file
rust_test = '''// Auto-generated ARM64 decompiler verification test
// Generated from decomp_test_suite ARM64 binary
use tracemiku_core::decompiler::il_pipeline::decompile_static;

'''

for name, insns in sorted(func_insns.items()):
    if len(insns) < 2:
        continue
    rust_test += f'#[test]\nfn verify_{name}() {{\n'
    rust_test += f'    let insns: Vec<(u64, u32)> = vec![\n'
    for pc, inst in insns:
        rust_test += f'        ({pc:#018x}u64, {inst:#010x}u32),\n'
    rust_test += '    ];\n'
    rust_test += f'    let output = decompile_static(&insns);\n'
    rust_test += f'    assert!(output.insn_count > 0, "no insns for {name}");\n'
    rust_test += f'    assert!(!output.hlil_text.is_empty(), "empty HLIL for {name}");\n'
    # Check coverage
    rust_test += f'    assert!(output.llil_coverage >= 0.90, "low coverage {{:.1}}% for {name}", output.llil_coverage*100.0);\n'
    rust_test += '}\n\n'

test_path = WORK / "decomp_verify_tests.rs"
test_path.write_text(rust_test)
print(f"\nWrote {len(func_insns)} tests to {test_path}")
print(f"Run: cargo test --manifest-path /home/ltlly/Code/traceMiku/rust/Cargo.toml -p tracemiku-core --test decomp_verify_tests -- --nocapture")

# 6. Also write summary JSON
summary = {}
for name, insns in sorted(func_insns.items()):
    summary[name] = {"insn_count": len(insns), "pcs": [f"{pc:#x}" for pc, _ in insns]}

summary_path = WORK / "function_map.json"
with open(summary_path, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"Summary: {summary_path}")
