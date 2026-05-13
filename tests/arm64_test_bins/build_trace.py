#!/usr/bin/env python3
"""Build trace.bin + meta.json from ARM64 ELF, then run decompiler eval tool."""
import struct, subprocess, json, os, tempfile
from pathlib import Path

ELF = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins/decomp_test_suite")
WORK = Path("/home/ltlly/Code/traceMiku/tests/arm64_test_bins")

# 1. Disassemble
objdump = subprocess.check_output(["aarch64-linux-gnu-objdump", "-d", str(ELF)], text=True)
insns = {}
for line in objdump.splitlines():
    line = line.strip()
    parts = line.replace('\t', ' ').split()
    if len(parts) >= 2:
        try:
            addr = int(parts[0].rstrip(':'), 16)
            raw = int(parts[1], 16)
            insns[addr] = raw
        except (ValueError, IndexError):
            continue

REC_SIZE = 272
trace_dir = WORK / "trace_output" / "calls" / "call_001_tid1_1000r_10ms"
trace_dir.mkdir(parents=True, exist_ok=True)

# Build trace.bin — one record per unique PC
unique_insns = sorted(insns.items())  # (pc, inst)
records = []
for pc, inst in unique_insns:
    buf = bytearray(REC_SIZE)
    struct.pack_into('<Q', buf, 0, pc)        # pc at offset 0
    struct.pack_into('<I', buf, 268, inst)     # inst at offset 268
    records.append(bytes(buf))

with open(trace_dir / "trace.bin", 'wb') as f:
    for r in records:
        f.write(r)

# meta.json for trace dir
meta_call = {
    "callIdx": 1, "pid": 1, "tid": 1,
    "records": len(records),
    "bytes": len(records) * REC_SIZE,
    "truncated": False,
    "last_insn_is_ret": True,
    "first_pc": f"{unique_insns[0][0]:#018x}",
    "last_pc": f"{unique_insns[-1][0]:#018x}",
}
with open(trace_dir / "meta.json", 'w') as f:
    json.dump(meta_call, f, indent=2)

# Run-level meta.json
run_dir = WORK / "trace_output"
run_meta = {
    "module": {"name": "decomp_test_suite", "base": f"{min(insns.keys()):#x}", "size": max(insns.keys()) - min(insns.keys())},
    "pkg": "test", "so": "decomp_test_suite",
}
with open(run_dir / "meta.json", 'w') as f:
    json.dump(run_meta, f, indent=2)

print(f"trace.bin: {len(records)} records ({len(records)*REC_SIZE} bytes)")
print(f"unique PCs: {len(insns)}")
print(f"trace dir: {trace_dir}")

# 2. Run decompiler eval tool
print("\n=== Running decompiler eval ===")
result = subprocess.run(
    ["cargo", "run", "--manifest-path", "/home/ltlly/Code/traceMiku/rust/Cargo.toml",
     "--example", "decompile_trace", "--release", "--",
     str(trace_dir), "--max-fns", "20", "--min-records", "5"],
    capture_output=True, text=True, timeout=120
)
print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
if result.stderr and "error" in result.stderr.lower():
    print("STDERR:", result.stderr[:500])

print(f"\nExit: {result.returncode}")
