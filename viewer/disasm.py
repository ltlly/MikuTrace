"""Capstone wrapper with caching for ARM64 disassembly + def/use parsing.

Each instruction is decoded once and cached by (pc, inst). We also extract
which registers are written (def) and read (use) — used for cross-reference
view and taint tracking.
"""
from __future__ import annotations
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Tuple
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import (
    ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM,
    ARM64_REG_INVALID,
)

_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_md.detail = True


def _norm_reg(name: str) -> str:
    if not name: return ""
    n = name.lower()
    # w0..w30 → x0..x30; wzr/xzr → xzr; wsp/sp → sp; nzcv/cpsr → nzcv
    if n.startswith("w") and n[1:].isdigit():
        return "x" + n[1:]
    if n in ("wzr", "xzr"): return "xzr"
    if n in ("wsp",): return "sp"
    if n == "x29": return "fp"
    if n == "x30": return "lr"
    return n


@dataclass
class Decoded:
    pc: int
    inst: int
    mnemonic: str
    op_str: str
    regs_def: tuple = ()
    regs_use: tuple = ()
    mem_op: tuple = ()   # ((base_reg, index_reg, disp, size, is_write, src_reg), ...)
                          # src_reg is the destination on load OR source on store
                          # — important for stp/ldp pair where one insn has 2
                          # mem_op tuples with different src/dst regs.
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    branch_target: int = 0      # for direct b/bl
    indirect_branch_reg: str = ""  # x for blr/br xN


def _is_load(mnem: str) -> bool:
    return mnem.startswith(("ldr", "ldp", "ldur", "ldax", "ldax", "ldnp",
                             "ldarh", "ldarb", "ldar", "ldur", "ldrb", "ldrh",
                             "ldrsb", "ldrsh", "ldrsw", "ldp", "ldnp"))

def _is_store(mnem: str) -> bool:
    return mnem.startswith(("str", "stp", "stur", "stax", "stnp",
                             "strh", "strb", "stlr", "stlx", "sturb", "sturh"))


@lru_cache(maxsize=200000)
def decode(pc: int, inst: int) -> Decoded:
    ib = inst.to_bytes(4, "little")
    ins = next(_md.disasm(ib, pc), None)
    if ins is None:
        return Decoded(pc, inst, "<bad>", f"{inst:08x}")
    d = Decoded(pc, inst, ins.mnemonic, ins.op_str)
    mnem = ins.mnemonic.split(".")[0]  # b.eq -> b
    is_load = _is_load(mnem)
    is_store = _is_store(mnem)
    is_branch = mnem in ("b","bl","br","blr","ret","cbz","cbnz","tbz","tbnz") \
                 or mnem.startswith("b.")
    is_call = mnem in ("bl","blr")
    is_ret = mnem == "ret"
    d.is_branch = is_branch
    d.is_call = is_call
    d.is_ret = is_ret

    # Use capstone's regs_access for def/use
    try:
        regs_read, regs_write = ins.regs_access()
        d.regs_use = tuple(_norm_reg(ins.reg_name(r)) for r in regs_read if ins.reg_name(r))
        d.regs_def = tuple(_norm_reg(ins.reg_name(r)) for r in regs_write if ins.reg_name(r))
    except Exception:
        pass

    # Fix capstone bug: compare-style instructions (cmp/tst/cmn/ccmn/ccmp/fcmp/fccmp)
    # only WRITE nzcv, they don't write their operand. capstone often lists the
    # operand as both read+written. Reclassify it as use-only.
    if mnem in ("cmp", "tst", "cmn", "ccmn", "ccmp", "fcmp", "fccmp", "fccmpe"):
        nzcv_def = "nzcv" in d.regs_def
        # All non-nzcv "defs" are actually uses
        falsely_def = tuple(r for r in d.regs_def if r != "nzcv")
        d.regs_def = ("nzcv",) if nzcv_def else ()
        d.regs_use = tuple(set(d.regs_use + falsely_def))
        # If capstone gave us nothing, derive from operands
        if not d.regs_use:
            ops = []
            for op in ins.operands:
                if op.type == ARM64_OP_REG:
                    nm = _norm_reg(ins.reg_name(op.reg))
                    if nm and nm not in ("xzr", "wzr"):
                        ops.append(nm)
            d.regs_use = tuple(ops)

    # Memory operands. mem_op tuple = (base, idx, disp, size, is_write, src_reg)
    # src_reg = the dest reg (load) or src reg (store) for this byte range.
    # Empty for non-stp/ldp insns (consumers fallback to picking from regs_use).
    mem_ops = []
    for op in ins.operands:
        if op.type == ARM64_OP_MEM:
            base = ins.reg_name(op.mem.base) if op.mem.base != ARM64_REG_INVALID else ""
            idx = ins.reg_name(op.mem.index) if op.mem.index != ARM64_REG_INVALID else ""
            disp = op.mem.disp
            sz = 8
            if mnem.endswith("b"): sz = 1
            elif mnem.endswith("h"): sz = 2
            elif "w" in mnem[:4] or any(o.type == ARM64_OP_REG and ins.reg_name(o.reg).startswith("w") for o in ins.operands):
                sz = 4
            mem_ops.append((_norm_reg(base), _norm_reg(idx), disp, sz, is_store, ""))
        elif op.type == ARM64_OP_IMM and is_branch and not is_ret and not d.indirect_branch_reg:
            d.branch_target = op.imm
        elif op.type == ARM64_OP_REG and mnem in ("br", "blr"):
            d.indirect_branch_reg = _norm_reg(ins.reg_name(op.reg))

    # stp/ldp 配对: capstone 给 1 个 mem_op, 但实际是 2 段 (8+8 或 4+4 字节).
    # split 让 MemShadow 不丢第二个寄存器的 8 字节 + taint 能看到完整 16 字节范围.
    if mnem in ("stp", "ldp", "stnp", "ldnp") and len(mem_ops) == 1:
        reg_operands = [o for o in ins.operands if o.type == ARM64_OP_REG]
        if len(reg_operands) >= 2:
            r0 = _norm_reg(ins.reg_name(reg_operands[0].reg))
            r1 = _norm_reg(ins.reg_name(reg_operands[1].reg))
            # 32-bit pair (stp w0, w1) 4+4; 64-bit pair (stp x0, x1) 8+8
            pair_sz = 4 if ins.reg_name(reg_operands[0].reg).startswith("w") else 8
            base, idx_reg, disp, _, is_w, _ = mem_ops[0]
            mem_ops = [
                (base, idx_reg, disp,           pair_sz, is_w, r0),
                (base, idx_reg, disp + pair_sz, pair_sz, is_w, r1),
            ]
    d.mem_op = tuple(mem_ops)
    return d


def fmt(pc: int, inst: int, base: int = 0) -> str:
    d = decode(pc, inst)
    if base:
        return f"+{pc-base:#x}  {d.mnemonic} {d.op_str}"
    return f"{pc:#x}  {d.mnemonic} {d.op_str}"
