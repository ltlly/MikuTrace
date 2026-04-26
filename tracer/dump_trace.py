#!/usr/bin/env python3
"""Quick sanity-dump for trace.bin / meta.json. Prints first/last N records
with all GPR + raw insn (disasm if capstone is installed).
"""
import sys, struct, json, pathlib

REC_SIZE = 272
REGS = ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12",
        "x13","x14","x15","x16","x17","x18","x19","x20","x21","x22","x23",
        "x24","x25","x26","x27","x28","fp","lr"]

def parse_record(b):
    pc = struct.unpack_from("<Q", b, 0)[0]
    xs = struct.unpack_from("<31Q", b, 8)
    sp = struct.unpack_from("<Q", b, 256)[0]
    nzcv = struct.unpack_from("<I", b, 264)[0]
    inst = struct.unpack_from("<I", b, 268)[0]
    return pc, xs, sp, nzcv, inst

def disasm(pc, inst):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = False
        ins = next(md.disasm(inst.to_bytes(4, "little"), pc), None)
        if ins is None: return f"{inst:08x} ; <bad>"
        return f"{inst:08x}  {ins.mnemonic} {ins.op_str}"
    except ImportError:
        return f"{inst:08x}"

def main():
    if len(sys.argv) < 2:
        print("usage: dump_trace.py <trace_dir|trace_file> [max_records]")
        sys.exit(1)
    p = pathlib.Path(sys.argv[1])
    n_max = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    if p.is_file():
        raw = p.read_bytes()
        meta = {}
        # try sibling meta_<pid>.json
        if "_" in p.stem:
            pid = p.stem.split("_")[-1]
            mp = p.parent / f"meta_{pid}.json"
            if mp.exists(): meta = json.load(open(mp))
    else:
        d = p
        meta = json.load(open(d/"meta.json"))
        if (d/"trace.bin").exists():
            raw = (d/"trace.bin").read_bytes()
        else:
            # pick largest per-PID trace
            cands = sorted(d.glob("trace_*.bin"), key=lambda x: x.stat().st_size, reverse=True)
            if not cands:
                print("no trace files"); sys.exit(1)
            print(f"[*] using {cands[0].name}")
            raw = cands[0].read_bytes()
            pid = cands[0].stem.split("_")[-1]
            mp = d / f"meta_{pid}.json"
            if mp.exists(): meta.update(json.load(open(mp)))
    print("=== meta ==="); print(json.dumps(meta, indent=2)); print()
    n = len(raw) // REC_SIZE
    print(f"=== trace.bin: {n} records ({len(raw)} bytes) ===")
    if n == 0: return
    print(f"first {min(n_max, n)} records:")
    for i in range(min(n_max, n)):
        pc, xs, sp, nz, inst = parse_record(raw[i*REC_SIZE:(i+1)*REC_SIZE])
        print(f"  #{i:5d} pc={pc:#018x}  {disasm(pc, inst)}")
        # show 4 most-changing regs vs prev
        if i == 0:
            for j, r in enumerate(REGS[:8]):
                print(f"        {r:>3}={xs[j]:#018x}", end="" if (j+1)%4 else "\n")
            print(f"        sp ={sp:#018x}")
    print()
    if n > n_max*2:
        print(f"last {n_max} records:")
        for i in range(n - n_max, n):
            pc, xs, sp, nz, inst = parse_record(raw[i*REC_SIZE:(i+1)*REC_SIZE])
            print(f"  #{i:5d} pc={pc:#018x}  {disasm(pc, inst)}")

if __name__ == "__main__":
    main()
