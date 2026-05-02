"""Pass 1: ARM64 → LLIL expression tree (BN style).

每条 ARM64 指令 lift 成一个 root LlilExpr (statement-level). sub-expr 嵌套.

§7.0 自查:
  ✓ ARM64 ISA 通用, 不绑特定 SO
  ✓ 不命中的 op → LLIL_INTRINSIC + extra['mnem']
  ✓ 静态 lift 一次 (LRU cache 200K)
  ✓ self-update load → LLIL_INTRINSIC (后 pass 可拆 LOAD+SET_REG)

实施范围 (MVP, 同 v1):
  - mov / movz
  - add / sub / mul (含 ADD/ADDS/SUB/SUBS)
  - and / orr / eor (BN 命名: AND/OR/XOR)
  - lsl / lsr / asr / ror
  - ldr / ldrb / ldrh / ldur / ldp
  - str / strb / strh / stur / stp
  - cmp / cmn (lift 成 LLIL_SUB → LLIL_SET_FLAG; b.cond 后用)
  - b / b.cond / bl / blr / br / ret
  - cbz / cbnz / tbz / tbnz (拆成 cmp + branch)
  - nop

不实施 (走 INTRINSIC):
  - SIMD/NEON/SVE
  - SVC / system register
  - movk (mov-keep, 复杂)
  - 自更新 load/store (extra: 'self_update')
"""
from __future__ import annotations
from dataclasses import dataclass, field
from functools import lru_cache
from .expr import (
    LlilExpr,
    LLIL_NOP, LLIL_REG, LLIL_CONST, LLIL_INTRINSIC,
    LLIL_LOAD, LLIL_STORE, LLIL_SET_REG, LLIL_SET_FLAG,
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR,
    LLIL_GOTO, LLIL_IF, LLIL_CALL, LLIL_TAILCALL, LLIL_RET, LLIL_JUMP,
    LLIL_FLAG_COND, LLIL_CMP_E, LLIL_CMP_NE,
    reg, const, const_ptr, flag_cond, flag,
    load, store, set_reg,
    add, sub, mul, neg, and_, or_, xor, not_,
    lsl, lsr, asr, rol, ror,
    goto, jump, if_, call, ret, nop, intrinsic,
    cmp_e, cmp_ne,
)
from ...disasm import decode as _decode, Decoded


@dataclass
class LiftStats:
    total: int = 0
    intrinsic: int = 0
    by_op: dict = field(default_factory=dict)

    def coverage(self) -> float:
        if self.total == 0: return 1.0
        return 1.0 - self.intrinsic / self.total

    def short(self) -> str:
        c = self.coverage() * 100
        return (f"lifted {self.total} static insns, "
                f"intrinsic {self.intrinsic} ({100-c:.1f}%), "
                f"coverage {c:.1f}%")


# arithmetic / bitwise ARM mnem → LLIL builder
_BIN_BUILDERS = {
    "add":  add,  "adds": add,
    "sub":  sub,  "subs": sub,
    "mul":  mul,
    "and":  and_, "ands": and_,
    "orr":  or_,
    "eor":  xor,
    "lsl":  lsl,  "lslv": lsl,
    "lsr":  lsr,  "lsrv": lsr,
    "asr":  asr,  "asrv": asr,
    "ror":  ror,  "rorv": ror,        # crypto round ops 必备
}

_UNARY_BUILDERS = {
    "neg": neg, "negs": neg, "mvn": not_,
}

_BCOND_SUFFIXES = frozenset((
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
))


def _first_reg_token(op_str: str) -> str:
    """从 op_str 抓第一个 reg-like token (x0/w0/sp), 归一为 x-form. 失败 ''.

    w0..w30 → x0..x30 (同物理 reg, ARM64 写 wN 隐式 zero-extend xN); wzr → xzr.
    保证整个 lift 内 reg 名一致, 不破坏 SSA 跨 w/x 形态的 def-use chain.
    """
    from ...regs import normalize_disasm_reg
    for p in op_str.split(","):
        p = p.strip()
        if p and p[0] in ("x", "w") and len(p) > 1 and p[1:].rstrip().isdigit():
            return normalize_disasm_reg(p)
        if p in ("sp", "lr", "fp", "xzr", "wzr"):
            return normalize_disasm_reg(p)
    return ""


def _parse_imm(s: str):
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
    """Lift one ARM64 inst → tuple of root LlilExpr (immutable, cached).

    Typically 1 expr. ldp/stp 2 (each 8B). cbz/tbz 1 (combined cmp+if).
    nop 可以 1 (LLIL_NOP).
    """
    d = _decode(pc, inst)
    return tuple(_lift(d))


def _lift(d: Decoded) -> list:
    mnem = d.mnemonic.lower()
    base = mnem.split(".")[0]
    pc = d.pc

    # ── nop ──
    if base == "nop":
        return [nop(pc=pc)]

    # ── arithmetic / bitwise binary ──
    if base in _BIN_BUILDERS and d.regs_def:
        return [_lift_arith_bin(d, _BIN_BUILDERS[base])]
    if base in _UNARY_BUILDERS and d.regs_def:
        return [_lift_arith_unary(d, _UNARY_BUILDERS[base])]

    # ── adr / adrp — capstone 已算 absolute, 直接 SET_REG CONST_PTR ──
    if base in ("adr", "adrp"):
        if d.regs_def:
            dst = d.regs_def[0]
            for p in d.op_str.split(","):
                p = p.strip().lstrip("#")
                if not p:
                    continue
                if p.startswith("0x") or p.lstrip("-").isdigit():
                    try:
                        v = int(p, 0)
                        return [set_reg(dst, const_ptr(v), pc=d.pc)]
                    except ValueError:
                        break
        return [_intrinsic(d)]

    # ── mov / movz ──
    if base in ("mov", "movz"):
        return [_lift_mov(d)]
    if base == "movk":
        return [_intrinsic(d)]      # 复杂, 走 intrinsic

    # ── multiply-add/sub: madd/msub/smull/umull/smaddl/umaddl/smulh/umulh ──
    if base in ("madd", "msub", "smaddl", "umaddl", "smsubl", "umsubl"):
        return [_lift_madd_msub(d, sub_op=base in ("msub", "smsubl", "umsubl"))]
    if base in ("smull", "umull", "smulh", "umulh"):
        return [_lift_smull(d)]

    # ── extension: sxtw / uxtw / sxtb/h / uxtb/h ──
    if base in ("sxtw", "uxtw", "sxtb", "uxtb", "sxth", "uxth"):
        return [_lift_extension(d, base)]

    # ── bitfield extract ──
    # ubfx xN, xM, #lsb, #width — 提取 xM 的 [lsb, lsb+width-1] bits.
    # 特殊 case: lsb=0 + width=8/16/32 等价 ZX. 其他走 AND+LSR 表达.
    if base == "ubfx":
        return [_lift_ubfx(d)]
    # sbfx 是 signed 版, 类似 SX
    if base == "sbfx":
        return [_lift_sbfx(d)]

    # ── system register read ──
    # mrs xN, sysreg — read system register. BN 译 _ReadMSR(name).
    if base == "mrs":
        if d.regs_def:
            dst = d.regs_def[0]
            # op_str 形如 'x0, tpidr_el0'
            parts = [p.strip() for p in d.op_str.split(",")]
            sysreg = parts[1] if len(parts) >= 2 else "?"
            return [set_reg(dst,
                LlilExpr(LLIL_INTRINSIC, size=8,
                    operands=["_ReadMSR", sysreg],
                    extra={"mnem": "mrs", "kind": "read_sysreg",
                           "sysreg": sysreg}),
                pc=d.pc)]
        return [_intrinsic(d)]

    # ── divide ──
    if base in ("sdiv", "udiv"):
        from .expr import LLIL_DIVS, LLIL_DIVU
        op_const = LLIL_DIVS if base == "sdiv" else LLIL_DIVU
        if d.regs_def and len(d.regs_use) >= 2:
            dst = d.regs_def[0]
            return [set_reg(dst, LlilExpr(op_const, size=8,
                operands=[reg(d.regs_use[0]), reg(d.regs_use[1])]),
                pc=d.pc)]

    # ── load / store ──
    if base.startswith("ldr") or base in ("ldur", "ldp", "ldnp"):
        return _lift_load(d)
    if base.startswith("str") or base in ("stur", "stp", "stnp"):
        return _lift_store(d)

    # ── cmp / cmn / tst ──
    # cmp xN, xM == subs xzr, xN, xM (set flags). lift 成 LLIL_SET_FLAG 链
    # 简化: 用 LLIL_SUB 包成 LLIL_SET_FLAG (我们用一个伪 flag 'cmp_result' 存)
    # b.cond 用 LLIL_FLAG_COND 引用具体 cond.
    if base in ("cmp", "cmn", "tst"):
        return [_lift_cmp(d)]

    # ── branches ──
    if base == "ret":
        return [ret(pc=pc)]
    if base == "bl":
        return [call(const_ptr(d.branch_target), pc=pc)]
    if base == "blr":
        r = d.indirect_branch_reg or "?"
        return [call(reg(r), pc=pc)]
    if base == "br":
        r = d.indirect_branch_reg or "?"
        return [jump(reg(r), pc=pc)]
    if base == "b":
        cond_suffix = mnem[2:] if mnem.startswith("b.") else ""
        if cond_suffix and cond_suffix in _BCOND_SUFFIXES:
            cond_expr = flag_cond(cond_suffix)
            # if (flag_cond) goto target else fallthrough (next pc)
            return [if_(cond_expr,
                        d.branch_target,
                        pc + 4,
                        pc=pc)]
        return [goto(d.branch_target, pc=pc)]
    if base in ("cbz", "cbnz"):
        # cbz xN, target = if (xN == 0) goto target else fallthrough
        # capstone 把 cbz 的 use 标 nzcv (错), 自己从 op_str 解析 reg.
        r = _first_reg_token(d.op_str)
        if r:
            cmp_op = cmp_e if base == "cbz" else cmp_ne
            cond_expr = cmp_op(reg(r), const(0))
            return [if_(cond_expr, d.branch_target, pc + 4, pc=pc)]
        return [_intrinsic(d)]
    if base in ("tbz", "tbnz"):
        # tbz xN, #bit, target = if (xN & (1<<bit) == 0) goto target
        r = _first_reg_token(d.op_str)
        if r:
            parts = [p.strip() for p in d.op_str.split(",")]
            bit_pos = 0
            for p in parts:
                if p.startswith("#"):
                    v = _parse_imm(p)
                    if v is not None:
                        bit_pos = v; break
            mask = and_(reg(r), const(1 << bit_pos))
            cmp_op = cmp_e if base == "tbz" else cmp_ne
            cond_expr = cmp_op(mask, const(0))
            return [if_(cond_expr, d.branch_target, pc + 4, pc=pc)]
        return [_intrinsic(d)]

    # ── 其他 ──
    return [_intrinsic(d)]


def _lift_arith_bin(d: Decoded, builder) -> LlilExpr:
    """add/sub/and/or/xor/lsl/... → LLIL_SET_REG(dst, op(src1, src2|imm))."""
    dst = d.regs_def[0]
    parts = [p.strip() for p in d.op_str.split(",")]
    # 两个 src: 第一个肯定是 reg (capstone use[0]), 第二个 reg 或 imm
    if not d.regs_use:
        return _intrinsic(d)
    src1 = reg(d.regs_use[0])
    src2: LlilExpr | None = None
    # 找第二个: 优先 imm
    for p in parts[2:] if len(parts) >= 3 else parts:
        if p.startswith("#"):
            v = _parse_imm(p)
            if v is not None:
                src2 = const(v)
                break
    if src2 is None and len(d.regs_use) >= 2:
        src2 = reg(d.regs_use[1])
    if src2 is None:
        return _intrinsic(d)
    return set_reg(dst, builder(src1, src2), pc=d.pc)


def _lift_arith_unary(d: Decoded, builder) -> LlilExpr:
    """neg / mvn → LLIL_SET_REG(dst, op(src))."""
    dst = d.regs_def[0]
    if not d.regs_use:
        return _intrinsic(d)
    return set_reg(dst, builder(reg(d.regs_use[0])), pc=d.pc)


def _lift_madd_msub(d: Decoded, sub_op: bool = False) -> LlilExpr:
    """madd dst, rn, rm, ra → SET_REG(dst, ADD(MUL(rn,rm), ra)).
    msub → SET_REG(dst, SUB(ra, MUL(rn,rm))).
    smaddl/umaddl/smsubl/umsubl 同结构, 简化忽略宽度差 (32→64 ext).
    """
    if len(d.regs_use) < 3 or not d.regs_def:
        return _intrinsic(d)
    dst = d.regs_def[0]
    rn, rm, ra = d.regs_use[0], d.regs_use[1], d.regs_use[2]
    prod = mul(reg(rn), reg(rm))
    if sub_op:
        body = sub(reg(ra), prod)
    else:
        body = add(prod, reg(ra))
    return set_reg(dst, body, pc=d.pc)


def _lift_smull(d: Decoded) -> LlilExpr:
    """smull/umull/smulh/umulh dst, rn, rm → SET_REG(dst, MUL(rn,rm))."""
    if len(d.regs_use) < 2 or not d.regs_def:
        return _intrinsic(d)
    dst = d.regs_def[0]
    return set_reg(dst, mul(reg(d.regs_use[0]), reg(d.regs_use[1])),
                   pc=d.pc)


def _lift_ubfx(d: Decoded) -> LlilExpr:
    """ubfx xN, xM, #lsb, #width.
    特殊 case: lsb=0 + width 是 8/16/32/64 → ZX (zero extend src_size=width/8).
    其他: SET_REG(dst, AND(LSR(src, lsb), mask)) — 通用 bitfield.
    """
    from .expr import LLIL_ZX
    if not d.regs_def or not d.regs_use:
        return _intrinsic(d)
    dst = d.regs_def[0]
    src = reg(d.regs_use[0])
    parts = [p.strip().lstrip("#") for p in d.op_str.split(",")]
    # 期望 ['x0', 'x1', '0', '0x20'] — 4 个 token
    if len(parts) < 4:
        return _intrinsic(d)
    try:
        lsb = int(parts[2], 0)
        width = int(parts[3], 0)
    except ValueError:
        return _intrinsic(d)
    if lsb == 0 and width in (8, 16, 32):
        # zero extend
        return set_reg(dst,
            LlilExpr(LLIL_ZX, size=8, operands=[src],
                     extra={"src_size": width // 8}),
            pc=d.pc)
    # 通用: (src >> lsb) & ((1 << width) - 1)
    mask = (1 << width) - 1
    body = and_(lsr(src, const(lsb)), const(mask))
    return set_reg(dst, body, pc=d.pc)


def _lift_sbfx(d: Decoded) -> LlilExpr:
    """sbfx xN, xM, #lsb, #width — signed 版 (lsb=0 + width=8/16/32 → SX)."""
    from .expr import LLIL_SX
    if not d.regs_def or not d.regs_use:
        return _intrinsic(d)
    dst = d.regs_def[0]
    src = reg(d.regs_use[0])
    parts = [p.strip().lstrip("#") for p in d.op_str.split(",")]
    if len(parts) < 4:
        return _intrinsic(d)
    try:
        lsb = int(parts[2], 0)
        width = int(parts[3], 0)
    except ValueError:
        return _intrinsic(d)
    if lsb == 0 and width in (8, 16, 32):
        return set_reg(dst,
            LlilExpr(LLIL_SX, size=8, operands=[src],
                     extra={"src_size": width // 8}),
            pc=d.pc)
    return _intrinsic(d)


def _lift_extension(d: Decoded, base: str) -> LlilExpr:
    """sxtw/uxtw/sxtb/uxtb/sxth/uxth dst, src → SET_REG(dst, SX/ZX(src)).
    base: 's' = sign extend, 'u' = zero extend; suffix 'b'/'h'/'w' 是源宽度.
    """
    from .expr import LLIL_SX, LLIL_ZX
    if not d.regs_def or not d.regs_use:
        return _intrinsic(d)
    dst = d.regs_def[0]
    src = reg(d.regs_use[0])
    op = LLIL_SX if base.startswith("s") else LLIL_ZX
    src_size = {"b": 1, "h": 2, "w": 4}.get(base[-1], 4)
    return set_reg(dst,
                   LlilExpr(op, size=8, operands=[src],
                            extra={"src_size": src_size}),
                   pc=d.pc)


def _lift_mov(d: Decoded) -> LlilExpr:
    if not d.regs_def:
        return _intrinsic(d)
    dst = d.regs_def[0]
    parts = [p.strip() for p in d.op_str.split(",")]
    if len(parts) == 2 and parts[1].startswith("#"):
        v = _parse_imm(parts[1])
        if v is not None:
            return set_reg(dst, const(v), pc=d.pc)
    if d.regs_use:
        return set_reg(dst, reg(d.regs_use[0]), pc=d.pc)
    return _intrinsic(d)


def _lift_load(d: Decoded) -> list:
    """ldr/ldp/...  → 1 或 2 个 LLIL_SET_REG(dst, LLIL_LOAD(addr_expr))."""
    if "!" in d.op_str:
        return [_intrinsic(d, note="self_update_load")]
    if not d.mem_op or not d.regs_def:
        return [_intrinsic(d)]
    out: list = []
    for i, mem in enumerate(d.mem_op):
        base, idx_reg, disp, sz, is_w, _src = mem
        if is_w:
            continue
        if i < len(d.regs_def):
            dst = d.regs_def[i]
        elif d.regs_def:
            dst = d.regs_def[0]
        else:
            return [_intrinsic(d)]
        # addr = base + disp  (idx_reg 复杂, MVP 不展开 — 走 intrinsic 兜底)
        if idx_reg:
            return [_intrinsic(d, note="indexed_addressing")]
        addr_expr = (reg(base) if disp == 0
                     else add(reg(base), const(disp), size=8))
        out.append(set_reg(dst, load(addr_expr, size=sz, pc=d.pc),
                           size=sz, pc=d.pc))
    return out or [_intrinsic(d)]


def _lift_store(d: Decoded) -> list:
    """str/stp/...  → 1 或 2 个 LLIL_STORE."""
    if "!" in d.op_str:
        return [_intrinsic(d, note="self_update_store")]
    if not d.mem_op:
        return [_intrinsic(d)]
    out: list = []
    for i, mem in enumerate(d.mem_op):
        base, idx_reg, disp, sz, is_w, src = mem
        if not is_w:
            continue
        if idx_reg:
            return [_intrinsic(d, note="indexed_addressing")]
        # src reg 优先 capstone mem.src; 否则 regs_use 取
        src_reg_name = src or (d.regs_use[i] if i < len(d.regs_use)
                               else (d.regs_use[0] if d.regs_use else "?"))
        addr_expr = (reg(base) if disp == 0
                     else add(reg(base), const(disp), size=8))
        out.append(store(addr_expr, reg(src_reg_name),
                         size=sz, pc=d.pc))
    return out or [_intrinsic(d)]


def _lift_cmp(d: Decoded) -> LlilExpr:
    """cmp xN, xM / cmp xN, #imm → LLIL_SET_FLAG('cmp_result', LLIL_SUB(...)).

    'cmp_result' 是合成 flag, BN 实际用 N/Z/C/V 4 个 flag. MVP 简化:
    后续 b.cond 用 LLIL_FLAG_COND(suffix) 解读.
    """
    parts = [p.strip() for p in d.op_str.split(",")]
    if not d.regs_use:
        return _intrinsic(d)
    src1 = reg(d.regs_use[0])
    src2 = None
    for p in parts[1:]:
        if p.startswith("#"):
            v = _parse_imm(p)
            if v is not None:
                src2 = const(v); break
    if src2 is None and len(d.regs_use) >= 2:
        src2 = reg(d.regs_use[1])
    if src2 is None:
        return _intrinsic(d)
    base_mnem = d.mnemonic.split(".")[0]
    builder = sub if base_mnem in ("cmp",) else (
              add if base_mnem == "cmn" else and_)   # tst = and+set_flags
    expr = builder(src1, src2)
    # Wrap as LLIL_SET_FLAG('cmp_result', expr)
    return LlilExpr(LLIL_SET_FLAG, size=expr.size,
                    operands=["cmp_result", expr], pc=d.pc,
                    extra={"flavor": base_mnem})


def _intrinsic(d: Decoded, note: str = "") -> LlilExpr:
    extra = {"mnem": d.mnemonic, "op_str": d.op_str}
    if note: extra["note"] = note
    return LlilExpr(LLIL_INTRINSIC, size=0,
                    operands=[d.mnemonic],
                    extra=extra, pc=d.pc)


def lift_static(pcs_and_insts) -> tuple[dict[int, list], LiftStats]:
    """批量 lift (pc, inst) 对 → {pc: list[LlilExpr]} + 统计."""
    out: dict[int, list] = {}
    stats = LiftStats()
    for pc, inst in pcs_and_insts:
        if pc in out:
            continue
        exprs = list(lift_arm64(pc, inst))
        out[pc] = exprs
        stats.total += len(exprs)
        for e in exprs:
            stats.by_op[e.op] = stats.by_op.get(e.op, 0) + 1
            if e.op == LLIL_INTRINSIC:
                stats.intrinsic += 1
    return out, stats
