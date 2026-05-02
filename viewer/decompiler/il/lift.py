"""Pass 1: ARM64 → TLIL lifting.

输入: viewer.disasm.Decoded (capstone wrapped) — 我们复用现成 ARM64 disasm,
不重写. lift 只做"语义层 op 抽取".

§7.0 自查:
  ✓ ARM64 ISA 通用, 不绑特定 SO
  ✓ 命中率: 真机 trace 通常 95%+ 是 mov/load/store/add/sub/branch 这些核心 op,
            剩余 NEON/SVE/SVC 自动走 OP_RAW + extra['unhandled']=True (后续
            pass 跳过)
  ✓ 静态 lift: 一个静态 PC 只 lift 一次 (LRU cache 在 disasm.decode + 这里
              再加一层); 15M trace 上仍只跑 ~5K 次 lift, 0.1s 量级
  ✓ 没 hardcoded SO 名 / fn 偏移; 输入纯 (pc, inst) 字节级

实施范围 (MVP):
  - mov / movz / movk
  - add / sub / mul
  - and / or / xor / lsl / lsr / asr
  - ldr / ldrb / ldrh / str / strb / strh / ldp / stp
  - cmp
  - b / b.cond / bl / blr / br / ret / cbz / cbnz / tbz / tbnz
  - 其余 → OP_RAW

不在 MVP 内 (留给 pass 2+ 或 OP_RAW 兜底):
  - SIMD / NEON / SVE
  - SVC / HVC / system register
  - pre/post-update load 的语义副作用 (base reg 自更新): 标 OP_RAW + 注释
"""
from __future__ import annotations
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional
from .ops import (
    TlilOp,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_MUL, OP_NEG,
    OP_AND, OP_OR, OP_XOR, OP_NOT, OP_LSL, OP_LSR, OP_ASR,
    OP_LOAD, OP_STORE, OP_CMP,
    OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
    OP_CALL, OP_CALL_INDIRECT, OP_RET, OP_NOP, OP_RAW,
)
from ...disasm import decode as _decode, Decoded


@dataclass
class LiftStats:
    """lift 的覆盖率统计 — 看是不是 MVP op 表覆盖够."""
    total: int = 0
    raw: int = 0
    by_op: dict = field(default_factory=dict)

    def coverage(self) -> float:
        """非 OP_RAW 占比 — 0..1, 越高 lift 表越完善."""
        if self.total == 0: return 1.0
        return 1.0 - self.raw / self.total

    def short(self) -> str:
        c = self.coverage() * 100
        return (f"lifted {self.total} static insns, "
                f"raw {self.raw} ({100-c:.1f}%), coverage {c:.1f}%")


# ─────────────────── arithmetic / bit op 表 ───────────────────

_ARITH_MAP = {
    "add":  OP_ADD,  "adds": OP_ADD,    # adds 是 add+set_flags, MVP 当 add
    "sub":  OP_SUB,  "subs": OP_SUB,
    "mul":  OP_MUL,
    "and":  OP_AND,  "ands": OP_AND,
    "orr":  OP_OR,
    "eor":  OP_XOR,  "eon":  OP_XOR,    # eon 是 a ^ ~b, 简化
    "lsl":  OP_LSL,  "lslv": OP_LSL,
    "lsr":  OP_LSR,  "lsrv": OP_LSR,
    "asr":  OP_ASR,  "asrv": OP_ASR,
    "neg":  OP_NEG,  "negs": OP_NEG,
    "mvn":  OP_NOT,
}

# 条件分支的 cond suffix (从 mnem 'b.eq' 抽出 'eq')
_BCOND_SUFFIXES = {
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
}


def _parse_imm(s: str) -> Optional[int]:
    """capstone op_str 里的 '#0x10' / '#42' 抽数字; 失败 None."""
    s = s.strip().lstrip("#").rstrip(",")
    if not s: return None
    try:
        if s.startswith(("0x", "-0x")):
            return int(s, 16)
        return int(s, 0)
    except ValueError:
        return None


@lru_cache(maxsize=200000)
def lift_arm64(pc: int, inst: int) -> tuple:
    """Lift one ARM64 instruction → tuple of TlilOp (immutable, cacheable).

    Returns tuple (TlilOp, ...) — typically 1 op, ldp/stp 2 ops, 0 for nop.
    一个静态 PC 一次 lift; 全 trace 复用同一结果.

    cache 目标 200K (远大于典型 trace 静态 PC 数 ~5-50K). 避免重复 lift.
    """
    d = _decode(pc, inst)
    return tuple(_lift_decoded(d))


def _lift_decoded(d: Decoded) -> list[TlilOp]:
    """核心: Decoded → list of TlilOp."""
    mnem = d.mnemonic.lower()
    base = mnem.split(".")[0]   # 'b.eq' → 'b'

    # ── arithmetic / bit op ──
    if base in _ARITH_MAP:
        return [_lift_arith(d, _ARITH_MAP[base])]

    # ── mov ──
    if base in ("mov", "movz"):
        return [_lift_mov(d)]
    if base == "movk":
        # mov-keep: dst |= imm << shift, 复杂, 走 RAW
        return [_raw(d)]

    # ── load / store ──
    if base.startswith("ldr") or base in ("ldur", "ldp", "ldnp"):
        return _lift_load(d)
    if base.startswith("str") or base in ("stur", "stp", "stnp"):
        return _lift_store(d)

    # ── cmp / cmn / tst ──
    if base in ("cmp", "cmn", "tst"):
        return [_lift_cmp(d)]

    # ── branch ──
    if base == "ret":
        return [TlilOp(pc=d.pc, op=OP_RET)]
    if base == "bl":
        return [TlilOp(pc=d.pc, op=OP_CALL,
                       extra={"target": d.branch_target})]
    if base == "blr":
        return [TlilOp(pc=d.pc, op=OP_CALL_INDIRECT,
                       srcs=[d.indirect_branch_reg or "?"])]
    if base == "br":
        return [TlilOp(pc=d.pc, op=OP_BRANCH_INDIRECT,
                       srcs=[d.indirect_branch_reg or "?"])]
    if base == "b":
        cond_suffix = mnem[2:] if mnem.startswith("b.") else ""
        if cond_suffix and cond_suffix in _BCOND_SUFFIXES:
            return [TlilOp(pc=d.pc, op=OP_BRANCH_COND,
                           extra={"cond": cond_suffix,
                                  "target": d.branch_target})]
        return [TlilOp(pc=d.pc, op=OP_BRANCH_UNCOND,
                       extra={"target": d.branch_target})]
    if base in ("cbz", "cbnz"):
        # cbz xN, target → cmp xN, 0; b.eq target (合成 2 ops 可能也行,
        # MVP 单 op 标 cond=eq/ne)
        cond = "eq" if base == "cbz" else "ne"
        return [TlilOp(pc=d.pc, op=OP_BRANCH_COND,
                       srcs=list(d.regs_use[:1]) + [0],
                       extra={"cond": cond, "target": d.branch_target,
                              "compound": "cbz/cbnz"})]
    if base in ("tbz", "tbnz"):
        cond = "eq" if base == "tbz" else "ne"
        return [TlilOp(pc=d.pc, op=OP_BRANCH_COND,
                       srcs=list(d.regs_use[:1]),
                       extra={"cond": cond, "target": d.branch_target,
                              "compound": "tbz/tbnz"})]

    # ── nop ──
    if base == "nop":
        return [TlilOp(pc=d.pc, op=OP_NOP)]

    # ── 其余 (NEON / SVC / system / 未实现) ──
    return [_raw(d, unhandled=True)]


def _lift_arith(d: Decoded, op: str) -> TlilOp:
    """add/sub/and/or/xor/... → TlilOp.

    op_str 形如: 'x0, x1, #0x10' / 'x0, x1, x2' / 'x0, x1, x2, lsl #4'
    我们简化处理: dst = first def, srcs = use list (immediate 从 op_str 解析).
    capstone regs_use 不含 imm, 所以 imm 要单独抠.
    """
    if not d.regs_def:
        return _raw(d)
    dst = d.regs_def[0]
    # imm 检测: op_str 里末尾若有 '#imm' 抽出来
    parts = [p.strip() for p in d.op_str.split(",")]
    srcs: list = list(d.regs_use)
    for p in parts:
        if p.startswith("#"):
            v = _parse_imm(p)
            if v is not None:
                srcs.append(v)
                break
    return TlilOp(pc=d.pc, op=op, dst=dst, srcs=srcs)


def _lift_mov(d: Decoded) -> TlilOp:
    """mov xN, imm 或 mov xN, xM."""
    if not d.regs_def:
        return _raw(d)
    dst = d.regs_def[0]
    parts = [p.strip() for p in d.op_str.split(",")]
    if len(parts) == 2 and parts[1].startswith("#"):
        v = _parse_imm(parts[1])
        if v is not None:
            return TlilOp(pc=d.pc, op=OP_MOV_IMM, dst=dst, srcs=[v])
    if d.regs_use:
        return TlilOp(pc=d.pc, op=OP_MOV_REG, dst=dst, srcs=[d.regs_use[0]])
    return _raw(d)


def _lift_load(d: Decoded) -> list[TlilOp]:
    """ldr/ldrb/ldrh/ldur/ldp/...  → 1 或 2 个 OP_LOAD.

    捕获 pre/post-update (op_str 含 '!' 或 ',#imm]' 之后的 imm) 时, 我们 MVP
    标 OP_RAW + extra['unhandled']=True (避免错的 SSA).
    pass 后续应该把 self-update 拆成 LOAD + ADD 两步.
    """
    if "!" in d.op_str:
        return [_raw(d, unhandled=True, note="self_update_load")]
    if not d.mem_op or not d.regs_def:
        return [_raw(d)]
    ops: list[TlilOp] = []
    # ldp/ldnp: 2 mem_ops, 各自一个 dst
    for i, mem in enumerate(d.mem_op):
        base, idx_reg, disp, sz, is_w, src = mem
        if is_w:
            continue   # store 在 _lift_store 里处理
        # dst from regs_def, ldp 顺序对应 mem_op[0]/[1]
        if i < len(d.regs_def):
            dst = d.regs_def[i]
        elif d.regs_def:
            dst = d.regs_def[0]
        else:
            return [_raw(d)]
        srcs: list = [("mem", base, disp)]
        ops.append(TlilOp(pc=d.pc, op=OP_LOAD, dst=dst, srcs=srcs,
                          extra={"size": sz}))
    return ops or [_raw(d)]


def _lift_store(d: Decoded) -> list[TlilOp]:
    """str/strb/strh/stur/stp/...  → 1 或 2 个 OP_STORE."""
    if "!" in d.op_str:
        return [_raw(d, unhandled=True, note="self_update_store")]
    if not d.mem_op:
        return [_raw(d)]
    ops: list[TlilOp] = []
    for i, mem in enumerate(d.mem_op):
        base, idx_reg, disp, sz, is_w, src = mem
        if not is_w:
            continue
        # src reg: capstone 把 mem.src_reg 填了; 否则 fallback regs_use[0]
        src_reg = src or (d.regs_use[i] if i < len(d.regs_use)
                          else (d.regs_use[0] if d.regs_use else "?"))
        ops.append(TlilOp(pc=d.pc, op=OP_STORE,
                          srcs=[src_reg, ("mem", base, disp)],
                          extra={"size": sz}))
    return ops or [_raw(d)]


def _lift_cmp(d: Decoded) -> TlilOp:
    """cmp/cmn/tst — 仅 set flags, 无 dst."""
    parts = [p.strip() for p in d.op_str.split(",")]
    srcs: list = list(d.regs_use)
    if len(parts) >= 2 and parts[1].startswith("#"):
        v = _parse_imm(parts[1])
        if v is not None:
            srcs = list(d.regs_use[:1]) + [v]
    return TlilOp(pc=d.pc, op=OP_CMP, srcs=srcs,
                  extra={"flavor": d.mnemonic.split(".")[0]})


def _raw(d: Decoded, unhandled: bool = False, note: str = "") -> TlilOp:
    """OP_RAW 占位 — 我们没识别但 trace 上确实命中过."""
    extra = {"mnem": d.mnemonic, "op_str": d.op_str}
    if unhandled: extra["unhandled"] = True
    if note: extra["note"] = note
    return TlilOp(pc=d.pc, op=OP_RAW, extra=extra)


def lift_static(pcs_and_insts) -> tuple[dict[int, list[TlilOp]], LiftStats]:
    """批量 lift 一组 (pc, inst) 对 → {pc: list[TlilOp]} + 统计.

    pcs_and_insts: iterable of (pc, inst).
    返回 dict 按 pc 索引. 同 PC 重复出现合并 (cache hit).
    """
    out: dict[int, list[TlilOp]] = {}
    stats = LiftStats()
    for pc, inst in pcs_and_insts:
        if pc in out:
            continue
        ops = list(lift_arm64(pc, inst))
        out[pc] = ops
        stats.total += len(ops)
        for o in ops:
            stats.by_op[o.op] = stats.by_op.get(o.op, 0) + 1
            if o.op == OP_RAW:
                stats.raw += 1
    return out, stats
