"""LLIL expression tree — BN-style.

每个 ARM64 指令 lift 成一个 root expression (statement-level: SET_REG / STORE
/ GOTO / IF / CALL / RET / NOP / INTRINSIC). 内部嵌 sub-expression (REG / CONST
/ ADD / LOAD / CMP_E / FLAG_COND / etc).

§7.0 自查:
  ✓ 命名跟 BN LLIL 一对一 (LLIL_REG / LLIL_CONST / LLIL_SET_REG / LLIL_ADD ...)
  ✓ ARM64 ISA 通用, 不绑特定 SO/SDK
  ✓ 不识别 op → LLIL_INTRINSIC + extra['mnem'] 占位 (BN 也用 INTRINSIC 兜底)
  ✓ size first-class 字段, 跟 BN 一致
  ✓ flag-based: cmp 拆成 LLIL_SUB 设 flags, b.cond 用 LLIL_FLAG_COND
    (BN 也是这样)

参考 BN docs:
  https://docs.binary.ninja/dev/bnil-llil.html
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional


# ─────────────────────── Op constants (BN 一致) ───────────────────────

# Atom / Leaf (sub-expression only)
LLIL_NOP        = "LLIL_NOP"
LLIL_UNDEF      = "LLIL_UNDEF"
LLIL_UNIMPL     = "LLIL_UNIMPL"            # BN 兜底
LLIL_REG        = "LLIL_REG"               # operands: [reg_name]
LLIL_CONST      = "LLIL_CONST"             # operands: [int_value]
LLIL_CONST_PTR  = "LLIL_CONST_PTR"         # operands: [int_value], 标 ptr
LLIL_FLAG       = "LLIL_FLAG"              # operands: [flag_name 'C'/'N'/'V'/'Z']
LLIL_FLAG_BIT   = "LLIL_FLAG_BIT"

# Memory ops
LLIL_LOAD       = "LLIL_LOAD"              # operands: [addr_expr]; size = bytes
LLIL_STORE      = "LLIL_STORE"             # operands: [addr_expr, value_expr]; size = bytes
LLIL_PUSH       = "LLIL_PUSH"
LLIL_POP        = "LLIL_POP"

# Statement-level (= root expression that has effect)
LLIL_SET_REG       = "LLIL_SET_REG"        # operands: [reg_name, value_expr]
LLIL_SET_REG_SPLIT = "LLIL_SET_REG_SPLIT"
LLIL_SET_FLAG      = "LLIL_SET_FLAG"

# Arithmetic
LLIL_ADD        = "LLIL_ADD"
LLIL_SUB        = "LLIL_SUB"
LLIL_MUL        = "LLIL_MUL"
LLIL_NEG        = "LLIL_NEG"
LLIL_DIVS       = "LLIL_DIVS"
LLIL_DIVU       = "LLIL_DIVU"
LLIL_MODS       = "LLIL_MODS"
LLIL_MODU       = "LLIL_MODU"
LLIL_ADC        = "LLIL_ADC"               # add with carry
LLIL_SBB        = "LLIL_SBB"               # sub with borrow

# Bit
LLIL_AND        = "LLIL_AND"
LLIL_OR         = "LLIL_OR"
LLIL_XOR        = "LLIL_XOR"
LLIL_NOT        = "LLIL_NOT"
LLIL_LSL        = "LLIL_LSL"
LLIL_LSR        = "LLIL_LSR"
LLIL_ASR        = "LLIL_ASR"
LLIL_ROL        = "LLIL_ROL"
LLIL_ROR        = "LLIL_ROR"

# Extension
LLIL_SX         = "LLIL_SX"                # sign extend
LLIL_ZX         = "LLIL_ZX"                # zero extend
LLIL_LOW_PART   = "LLIL_LOW_PART"          # truncate

# Comparison (输出 1-bit boolean)
LLIL_CMP_E      = "LLIL_CMP_E"
LLIL_CMP_NE     = "LLIL_CMP_NE"
LLIL_CMP_SLT    = "LLIL_CMP_SLT"
LLIL_CMP_SLE    = "LLIL_CMP_SLE"
LLIL_CMP_SGE    = "LLIL_CMP_SGE"
LLIL_CMP_SGT    = "LLIL_CMP_SGT"
LLIL_CMP_ULT    = "LLIL_CMP_ULT"
LLIL_CMP_ULE    = "LLIL_CMP_ULE"
LLIL_CMP_UGE    = "LLIL_CMP_UGE"
LLIL_CMP_UGT    = "LLIL_CMP_UGT"

# Flag-condition (BN: from N/Z/C/V derive cond)
LLIL_FLAG_COND  = "LLIL_FLAG_COND"         # operands: [cond_str like 'eq']
LLIL_FLAG_GROUP = "LLIL_FLAG_GROUP"

# Control flow (statement-level)
LLIL_GOTO       = "LLIL_GOTO"              # operands: [target_pc]; uncond
LLIL_JUMP       = "LLIL_JUMP"              # operands: [target_expr]; indirect uncond
LLIL_IF         = "LLIL_IF"                # operands: [cond_expr, true_pc, false_pc]
LLIL_CALL       = "LLIL_CALL"              # operands: [target_expr]; direct or indirect
LLIL_TAILCALL   = "LLIL_TAILCALL"
LLIL_RET        = "LLIL_RET"               # operands: [target_expr] (typically pop LR)
LLIL_NORET      = "LLIL_NORET"
LLIL_TRAP       = "LLIL_TRAP"

# Misc
LLIL_INTRINSIC  = "LLIL_INTRINSIC"         # operands: [name, *args]; SVC/NEON/未实现 兜底
LLIL_BP         = "LLIL_BP"


# Sets for quick classification
ATOMS = frozenset((
    LLIL_REG, LLIL_CONST, LLIL_CONST_PTR, LLIL_FLAG, LLIL_FLAG_BIT,
    LLIL_NOP, LLIL_UNDEF, LLIL_UNIMPL,
))

STATEMENTS = frozenset((
    LLIL_SET_REG, LLIL_SET_REG_SPLIT, LLIL_SET_FLAG,
    LLIL_STORE, LLIL_PUSH, LLIL_POP,
    LLIL_GOTO, LLIL_JUMP, LLIL_IF,
    LLIL_CALL, LLIL_TAILCALL, LLIL_RET, LLIL_NORET, LLIL_TRAP,
    LLIL_NOP, LLIL_INTRINSIC, LLIL_BP, LLIL_UNIMPL,
))

ARITH_OPS = frozenset((
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_DIVS, LLIL_DIVU, LLIL_MODS, LLIL_MODU,
    LLIL_ADC, LLIL_SBB,
))

BITWISE_OPS = frozenset((
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR, LLIL_ROL, LLIL_ROR,
))

CMP_OPS = frozenset((
    LLIL_CMP_E, LLIL_CMP_NE,
    LLIL_CMP_SLT, LLIL_CMP_SLE, LLIL_CMP_SGE, LLIL_CMP_SGT,
    LLIL_CMP_ULT, LLIL_CMP_ULE, LLIL_CMP_UGE, LLIL_CMP_UGT,
))

# 副作用 op (DCE 不可删)
SIDE_EFFECT_OPS = frozenset((
    LLIL_STORE, LLIL_PUSH, LLIL_POP,
    LLIL_CALL, LLIL_TAILCALL, LLIL_RET, LLIL_NORET, LLIL_TRAP,
    LLIL_GOTO, LLIL_JUMP, LLIL_IF,
    LLIL_INTRINSIC,        # 未知 op 保守留
    LLIL_BP, LLIL_UNIMPL,
    LLIL_SET_FLAG,         # flag 是隐式 use
    # LOAD 也保留 (mem read 可能 page-fault, BN 同样标 SideEffect)
    LLIL_LOAD,
))


# ─────────────────────── Expression dataclass ───────────────────────


@dataclass
class LlilExpr:
    """Expression node — 递归 BN-style.

    operands 元素可以是:
      - LlilExpr — sub-expression
      - str — reg name (e.g. 'x0', 'sp')  (only valid as direct operand of
        LLIL_REG / LLIL_SET_REG / LLIL_FLAG / LLIL_SET_FLAG)
      - int — const value (for LLIL_CONST / LLIL_GOTO target / LLIL_IF target)
      - None — empty slot

    size: 字节数 (1/2/4/8/16). 对 statement-level expr, size 通常 = inner 子
          expr 的 size (e.g. LLIL_SET_REG.size 跟 value_expr.size 一致).
    pc: 源 ARM64 PC. 顶层 root 必填; sub-expr 可缺省 (= 0).
    extra: 杂项字段, 例如 LLIL_INTRINSIC.extra['mnem'].
    """
    op: str
    size: int = 0
    operands: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    pc: int = 0

    # ─────────── helper: 类型判断 ───────────
    def is_atom(self) -> bool:
        return self.op in ATOMS

    def is_statement(self) -> bool:
        return self.op in STATEMENTS

    def has_side_effect(self) -> bool:
        return self.op in SIDE_EFFECT_OPS

    # ─────────── 递归遍历 ───────────
    def walk(self) -> Iterator["LlilExpr"]:
        """Yield self + 所有 sub-expression (DFS pre-order)."""
        yield self
        for o in self.operands:
            if isinstance(o, LlilExpr):
                yield from o.walk()

    # ─────────── repr (调试用) ───────────
    def short(self) -> str:
        if self.op == LLIL_REG:
            return f"reg({self.operands[0]})"
        if self.op == LLIL_CONST:
            v = self.operands[0]
            return f"{v:#x}" if abs(v) >= 16 else str(v)
        if self.op == LLIL_CONST_PTR:
            return f"ptr({self.operands[0]:#x})"
        if self.op == LLIL_FLAG:
            return f"flag({self.operands[0]})"
        if self.op == LLIL_FLAG_COND:
            return f"flag_cond({self.operands[0]})"
        if self.op == LLIL_SET_REG:
            return f"{self.operands[0]} = {_short(self.operands[1])}"
        if self.op == LLIL_LOAD:
            sz = f".{self.size}" if self.size else ""
            return f"load{sz}({_short(self.operands[0])})"
        if self.op == LLIL_STORE:
            sz = f".{self.size}" if self.size else ""
            return f"store{sz}({_short(self.operands[0])}, {_short(self.operands[1])})"
        if self.op == LLIL_GOTO:
            return f"goto {self.operands[0]:#x}"
        if self.op == LLIL_IF:
            return (f"if {_short(self.operands[0])} "
                    f"then {self.operands[1]:#x} else {self.operands[2]:#x}")
        if self.op == LLIL_CALL:
            return f"call({_short(self.operands[0])})"
        if self.op == LLIL_RET:
            return "ret"
        if self.op == LLIL_INTRINSIC:
            return f"intrinsic({self.extra.get('mnem','?')})"
        if self.op in ARITH_OPS or self.op in BITWISE_OPS:
            sym = _SYM.get(self.op, self.op)
            if len(self.operands) == 2:
                return f"({_short(self.operands[0])} {sym} {_short(self.operands[1])})"
            return f"{sym}({', '.join(_short(o) for o in self.operands)})"
        if self.op in CMP_OPS:
            sym = _SYM.get(self.op, self.op)
            return f"({_short(self.operands[0])} {sym} {_short(self.operands[1])})"
        return self.op


def _short(o: Any) -> str:
    if isinstance(o, LlilExpr):
        return o.short()
    if isinstance(o, int):
        return f"{o:#x}" if abs(o) >= 16 else str(o)
    return str(o)


_SYM = {
    LLIL_ADD: "+", LLIL_SUB: "-", LLIL_MUL: "*",
    LLIL_AND: "&", LLIL_OR: "|", LLIL_XOR: "^",
    LLIL_LSL: "<<", LLIL_LSR: ">>u", LLIL_ASR: ">>s",
    LLIL_NEG: "-", LLIL_NOT: "~",
    LLIL_CMP_E: "==", LLIL_CMP_NE: "!=",
    LLIL_CMP_SLT: "<s", LLIL_CMP_SLE: "<=s",
    LLIL_CMP_SGE: ">=s", LLIL_CMP_SGT: ">s",
    LLIL_CMP_ULT: "<u", LLIL_CMP_ULE: "<=u",
    LLIL_CMP_UGE: ">=u", LLIL_CMP_UGT: ">u",
}


# ─────────────────────── Builder helpers (BN-like API) ───────────────────────

def reg(name: str, size: int = 8) -> LlilExpr:
    return LlilExpr(LLIL_REG, size=size, operands=[name])

def const(value: int, size: int = 8) -> LlilExpr:
    return LlilExpr(LLIL_CONST, size=size, operands=[value])

def const_ptr(value: int, size: int = 8) -> LlilExpr:
    return LlilExpr(LLIL_CONST_PTR, size=size, operands=[value])

def flag(name: str) -> LlilExpr:
    return LlilExpr(LLIL_FLAG, size=1, operands=[name])

def flag_cond(cond: str) -> LlilExpr:
    return LlilExpr(LLIL_FLAG_COND, size=1, operands=[cond])

def load(addr: LlilExpr, size: int = 8, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_LOAD, size=size, operands=[addr], pc=pc)

def store(addr: LlilExpr, value: LlilExpr, size: int = 8, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_STORE, size=size, operands=[addr, value], pc=pc)

def set_reg(reg_name: str, value: LlilExpr, size: int = 8, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_SET_REG, size=size, operands=[reg_name, value], pc=pc)

def add(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_ADD, size=size, operands=[a, b])

def sub(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_SUB, size=size, operands=[a, b])

def mul(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_MUL, size=size, operands=[a, b])

def and_(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_AND, size=size, operands=[a, b])

def or_(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_OR, size=size, operands=[a, b])

def xor(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or b.size or 8
    return LlilExpr(LLIL_XOR, size=size, operands=[a, b])

def lsl(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_LSL, size=size, operands=[a, b])

def lsr(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_LSR, size=size, operands=[a, b])

def asr(a: LlilExpr, b: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_ASR, size=size, operands=[a, b])

def neg(a: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_NEG, size=size, operands=[a])

def not_(a: LlilExpr, size: Optional[int] = None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_NOT, size=size, operands=[a])

def goto(target: int, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_GOTO, size=0, operands=[target], pc=pc)

def jump(target: LlilExpr, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_JUMP, size=0, operands=[target], pc=pc)

def if_(cond: LlilExpr, true_pc: int, false_pc: int, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_IF, size=0,
                    operands=[cond, true_pc, false_pc], pc=pc)

def call(target: LlilExpr, pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_CALL, size=0, operands=[target], pc=pc)

def ret(pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_RET, size=0, operands=[], pc=pc)

def nop(pc: int = 0) -> LlilExpr:
    return LlilExpr(LLIL_NOP, size=0, operands=[], pc=pc)

def intrinsic(name: str, args: list = None, pc: int = 0,
              op_str: str = "") -> LlilExpr:
    return LlilExpr(LLIL_INTRINSIC, size=0,
                    operands=[name] + (args or []),
                    extra={"mnem": name, "op_str": op_str},
                    pc=pc)

def cmp_e(a, b, size=None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_CMP_E, size=1, operands=[a, b])

def cmp_ne(a, b, size=None) -> LlilExpr:
    if size is None: size = a.size or 8
    return LlilExpr(LLIL_CMP_NE, size=1, operands=[a, b])
