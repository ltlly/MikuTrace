"""TLIL op 表 + TlilOp dataclass.

§7.0 自查:
  ✓ ARM64 ISA 是公开标准, 不绑特定 SO/变种
  ✓ 不命中的 op 走 OP_RAW (occupant + raw asm 字符串), 后续 pass 跳过即可,
    不靠"hardcoded VM 编码"或"假设特定 dispatcher pattern"
  ✓ 命名跟 BN LLIL 风格类似 (业界惯例, 不绑专有库)
  ✓ 反例 case (NEON / SVE / SVC) 标 OP_RAW + extra['unhandled']=True

Op 命名规范:
  OP_X 是 module-level 字符串常量, TlilOp.op == OP_X 即 X 类型.
  没用 enum, 因为字符串在 dataclass / json 序列化时更友好.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ─────────── 数据移动 ───────────
OP_MOV_IMM   = "mov_imm"     # dst = imm
OP_MOV_REG   = "mov_reg"     # dst = src_reg

# ─────────── 算术 ───────────
OP_ADD       = "add"
OP_SUB       = "sub"
OP_MUL       = "mul"
OP_NEG       = "neg"

# ─────────── 位运算 ───────────
OP_AND       = "and"
OP_OR        = "or"
OP_XOR       = "xor"
OP_NOT       = "not"
OP_LSL       = "lsl"
OP_LSR       = "lsr"
OP_ASR       = "asr"

# ─────────── 内存 ───────────
OP_LOAD      = "load"        # dst = *(base + idx*scale + disp)
OP_STORE     = "store"       # *(base + idx*scale + disp) = src

# ─────────── 比较 / 标志 ───────────
OP_CMP       = "cmp"         # 仅 set NZCV, 无 dst

# ─────────── 控制流 ───────────
OP_BRANCH_UNCOND   = "branch_uncond"
OP_BRANCH_COND     = "branch_cond"      # extra['cond'] = 'eq'/'ne'/...
OP_BRANCH_INDIRECT = "branch_indirect"  # br xN
OP_CALL            = "call"             # bl direct (extra['target'])
OP_CALL_INDIRECT   = "call_indirect"    # blr xN
OP_RET             = "ret"

# ─────────── 杂项 ───────────
OP_NOP       = "nop"
OP_RAW       = "raw"         # 未识别 / NEON / SVC etc; extra['mnem'], extra['op_str']


OPS_ALL = (
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_MUL, OP_NEG,
    OP_AND, OP_OR, OP_XOR, OP_NOT, OP_LSL, OP_LSR, OP_ASR,
    OP_LOAD, OP_STORE, OP_CMP,
    OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
    OP_CALL, OP_CALL_INDIRECT, OP_RET,
    OP_NOP, OP_RAW,
)

OPS_ARITH = frozenset((OP_ADD, OP_SUB, OP_MUL, OP_NEG,
                       OP_AND, OP_OR, OP_XOR, OP_NOT,
                       OP_LSL, OP_LSR, OP_ASR))

OPS_BRANCH = frozenset((OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
                        OP_CALL, OP_CALL_INDIRECT, OP_RET))


@dataclass
class TlilOp:
    """One TLIL operation.

    Fields:
      pc:    原 ARM64 指令 PC (一对一映射, 复合 ARM64 op 也只 lift 一份).
      op:    OP_* 字符串常量
      dst:   输出寄存器名 (e.g. 'x0', 'sp'). "" 表示无 dst (cmp/store/branch).
      srcs:  输入操作数 list. 元素可以是:
              - str — reg name ('x0', 'sp', 'lr')
              - int — 立即数
              - tuple ('mem', base_reg, disp) — 内存地址 (load/store)
              - tuple ('shifted', reg, shift_kind, shift_amt) — 带移位的 reg
      extra: dict, op-specific 额外字段:
              cond    str    branch_cond 时的条件 (eq/ne/lt/...)
              target  int    direct branch / call 的目标 PC
              size    int    load/store 的字节数 (1/2/4/8)
              scale   int    indexed mem 的 lsl 量 (default 0)
              mnem    str    OP_RAW 时存原 mnemonic
              op_str  str    OP_RAW 时存原 op_str
              unhandled bool OP_RAW 标 True 表示我们认识但未实现 (NEON 等)
    """
    pc: int
    op: str
    dst: str = ""
    srcs: list[Any] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def is_branch(self) -> bool:
        return self.op in OPS_BRANCH

    def short(self) -> str:
        """One-line debug repr — 调试用, 不是 final render."""
        s = f"{self.dst+' = ' if self.dst else ''}{self.op}"
        if self.srcs:
            s += " " + ", ".join(_fmt_src(x) for x in self.srcs)
        if self.extra:
            keys = [k for k in ("cond", "target", "size") if k in self.extra]
            if keys:
                s += " {" + ",".join(f"{k}={self.extra[k]}" for k in keys) + "}"
        return s


def _fmt_src(x: Any) -> str:
    if isinstance(x, tuple):
        if x and x[0] == "mem":
            _, base, disp = x[0], x[1], x[2]
            sign = "+" if x[2] >= 0 else "-"
            return f"[{x[1]}{sign}{abs(x[2]):#x}]"
        return repr(x)
    if isinstance(x, int):
        return f"{x:#x}" if abs(x) >= 16 else str(x)
    return str(x)
