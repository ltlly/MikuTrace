#!/usr/bin/env python3
"""Analyze the tail of a trace to find what triggered process death.

Looks for:
  - svc #0 (syscall) instructions
  - bl/blr to non-libsgmainso ranges (libc / linker calls — likely the anti-debug API)
  - tbz/tbnz/cbz that took the "death" branch
  - last N records with disassembly + register state

Usage:
  analyze_tail.py <trace_dir> [tail_count] [meta_pid]
  analyze_tail.py <trace.bin path> --raw [base_addr_hex] [tail_count]
"""
import sys, struct, json, pathlib

REC_SIZE = 272

def parse_record(b):
    pc = struct.unpack_from("<Q", b, 0)[0]
    xs = struct.unpack_from("<31Q", b, 8)
    sp = struct.unpack_from("<Q", b, 256)[0]
    inst = struct.unpack_from("<I", b, 268)[0]
    return pc, xs, sp, inst

def cs_disasm():
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return md

def is_syscall(inst):  return (inst & 0xFFE0001F) == 0xD4000001  # svc #imm
def is_bl(inst):       return (inst & 0xFC000000) == 0x94000000  # bl
def is_blr(inst):      return (inst & 0xFFFFFC1F) == 0xD63F0000  # blr Xn
def is_br(inst):       return (inst & 0xFFFFFC1F) == 0xD61F0000  # br  Xn
def is_brk(inst):      return (inst & 0xFFE0001F) == 0xD4200000  # brk #imm
def is_ret(inst):      return (inst & 0xFFFFFC1F) == 0xD65F0000

def main():
    arg1 = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == "--raw":
        # raw mode: arg1 is path to trace.bin; need base addr from arg3
        raw = pathlib.Path(arg1).read_bytes()
        base = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
        end  = base + 0x2fe000 if base else None
        tail_n = int(sys.argv[4]) if len(sys.argv) > 4 else 60
    else:
        d = pathlib.Path(arg1)
        tail_n = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        # find session: prefer trace_<pid>.bin else trace.bin
        if (d/"trace.bin").exists() and not list(d.glob("trace_*.bin")):
            raw = (d/"trace.bin").read_bytes()
            meta = json.load(open(d/"meta.json"))
            base = int(meta["module"]["base"], 16) if "module" in meta else None
            end = base + meta["module"]["size"] if base else None
        else:
            # pick first session
            target_pid = int(sys.argv[3]) if len(sys.argv) > 3 else None
            sess = sorted(d.glob("trace_*.bin"), key=lambda p: p.stat().st_size, reverse=True)
            if not sess: print("no trace files"); return
            chosen = next((p for p in sess if not target_pid or f"_{target_pid}." in p.name), sess[0])
            print(f"[*] session: {chosen.name}")
            raw = chosen.read_bytes()
            pid = int(chosen.stem.split("_")[1])
            try:
                m = json.load(open(d/f"meta_{pid}.json"))
                base = int(m["module"]["base"], 16) if "module" in m else None
                end = base + m["module"]["size"] if base else None
            except Exception:
                base = end = None

    n = len(raw) // REC_SIZE
    print(f"[*] {n} records, base={hex(base) if base else '?'}, end={hex(end) if end else '?'}")
    if n == 0: return
    md = cs_disasm()

    # Pass 1: count syscalls + outbound calls
    syscalls = []
    outbound_calls = []  # (idx, pc, target_via_bl_imm)
    for i in range(n):
        rec = raw[i*REC_SIZE:(i+1)*REC_SIZE]
        pc, xs, sp, inst = parse_record(rec)
        if is_syscall(inst):
            syscalls.append((i, pc, xs[8]))  # x8 = syscall number on ARM64 linux
        if is_bl(inst):
            # bl #imm — compute target
            imm = inst & 0x03FFFFFF
            if imm & 0x02000000: imm |= ~0x03FFFFFF
            tgt = (pc + (imm << 2)) & 0xffffffffffffffff
            in_so = base is not None and base <= tgt < end
            if not in_so:
                outbound_calls.append((i, pc, tgt))

    print(f"\n=== syscalls ({len(syscalls)} total) ===")
    SYSCALL_NAMES = {
        29: "ioctl", 56: "openat", 57: "close", 63: "read",
        64: "write", 78: "readlinkat", 80: "fstat", 117: "ptrace",
        122: "setpgid", 156: "getpgid", 162: "sysinfo",
        178: "gettid", 220: "clone", 221: "execve",
        261: "prlimit64", 173: "getppid",
    }
    for i, pc, num in syscalls[-20:]:
        nm = SYSCALL_NAMES.get(num, f"#{num}")
        print(f"  rec#{i:5d} pc={pc:#x} svc x8={num} ({nm})")

    print(f"\n=== outbound calls ({len(outbound_calls)} total) ===")
    for i, pc, tgt in outbound_calls[-20:]:
        print(f"  rec#{i:5d} pc={pc:#x} bl -> {tgt:#x}")

    print(f"\n=== last {tail_n} instructions ===")
    for i in range(max(0, n - tail_n), n):
        rec = raw[i*REC_SIZE:(i+1)*REC_SIZE]
        pc, xs, sp, inst = parse_record(rec)
        ib = inst.to_bytes(4, "little")
        ins = next(md.disasm(ib, pc), None)
        s = f"{ins.mnemonic} {ins.op_str}" if ins else f"<bad {inst:08x}>"
        marker = ""
        if is_syscall(inst): marker = " [SVC]"
        elif is_brk(inst):   marker = " [BRK]"
        elif is_blr(inst):
            # show register value
            regname = (inst >> 5) & 0x1f
            if regname <= 30:
                tgt = xs[regname] if regname < 31 else 0
                marker = f" [BLR x{regname} -> {tgt:#x}]"
        elif is_br(inst):
            regname = (inst >> 5) & 0x1f
            tgt = xs[regname] if regname < 31 else 0
            marker = f" [BR x{regname} -> {tgt:#x}]"
        elif is_bl(inst):
            imm = inst & 0x03FFFFFF
            if imm & 0x02000000: imm |= ~0x03FFFFFF
            tgt = (pc + (imm << 2)) & 0xffffffffffffffff
            in_so = base is not None and base <= tgt < end
            marker = f" [BL -> {tgt:#x}{'*' if not in_so else ''}]"
        rel = f"+{pc-base:#x}" if base is not None else f"{pc:#x}"
        print(f"  #{i:5d} {rel:>10s}  {s}{marker}")

if __name__ == "__main__":
    main()
