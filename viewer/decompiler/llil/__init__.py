"""Low-Level IL (LLIL) — BN expression-tree style.

设计: docs/trace-decompiler-il-design.md (路线 B v2 — C 选项 expression tree).
参考: BN LLIL https://docs.binary.ninja/dev/bnil-llil.html

每个 ARM64 指令 lift 成一个 root LlilExpr (statement-level), 内部嵌
sub-expression. visitor pattern 走树.

8-pass pipeline (跟 BN 数据流类似):
  1. lift      — ARM64 → LLIL root expr per insn
  2. ssa       — block-local SSA (每 def 出新 version)
  3. constfold — visitor 走子 expr, 替 LLIL_CONST
  4. dce       — backward, 删 dead SET_REG
  5. typelat   — 类型 lattice (INT/PTR/HANDLE/BOOL)
  6. struct    — PTR + offset 聚类 → struct shape
  7. restructure — loop / if 重建 (高级 IL)
  8. render    — 输出 markdown / Tenet / LLM bundle
"""
from .lift import lift_arm64, lift_static, LiftStats
from .ssa import SsaTag, SsaBlock, ssa_block, ssa_blocks
from .pass_constfold import fold_expr, constfold_block, constfold_blocks
from .pass_dce import dce_block, dce_blocks
from .pass_typelat import (
    TypeEnv, typelat_block, join,
    T_TOP, T_INT, T_PTR, T_HANDLE, T_BOOL, T_BOT,
)
from .pass_struct import (
    FieldAccess, StructShape,
    struct_recover_block, merge_shapes,
)
from .pass_restructure import (
    HlilSeq, HlilLoop, HlilIfElse, HlilBlock, HlilGoto, HlilRet,
    CfgInfo, restructure, from_viewer_cfg,
)

from .expr import (
    LlilExpr,
    # Op constants — BN naming (LLIL_*)
    LLIL_NOP, LLIL_UNDEF, LLIL_UNIMPL,
    LLIL_REG, LLIL_CONST, LLIL_CONST_PTR, LLIL_FLAG, LLIL_FLAG_BIT,
    LLIL_LOAD, LLIL_STORE, LLIL_PUSH, LLIL_POP,
    LLIL_SET_REG, LLIL_SET_REG_SPLIT, LLIL_SET_FLAG,
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_DIVS, LLIL_DIVU, LLIL_MODS, LLIL_MODU, LLIL_ADC, LLIL_SBB,
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR, LLIL_ROL, LLIL_ROR,
    LLIL_SX, LLIL_ZX, LLIL_LOW_PART,
    LLIL_CMP_E, LLIL_CMP_NE,
    LLIL_CMP_SLT, LLIL_CMP_SLE, LLIL_CMP_SGE, LLIL_CMP_SGT,
    LLIL_CMP_ULT, LLIL_CMP_ULE, LLIL_CMP_UGE, LLIL_CMP_UGT,
    LLIL_FLAG_COND, LLIL_FLAG_GROUP,
    LLIL_GOTO, LLIL_JUMP, LLIL_IF,
    LLIL_CALL, LLIL_TAILCALL, LLIL_RET, LLIL_NORET, LLIL_TRAP,
    LLIL_INTRINSIC, LLIL_BP,
    # 分类集合
    ATOMS, STATEMENTS, ARITH_OPS, BITWISE_OPS, CMP_OPS, SIDE_EFFECT_OPS,
    # Builders (BN-like API)
    reg, const, const_ptr, flag, flag_cond,
    load, store, set_reg,
    add, sub, mul, neg, and_, or_, xor, not_,
    lsl, lsr, asr,
    goto, jump, if_, call, ret, nop, intrinsic,
    cmp_e, cmp_ne,
)


__all__ = [
    "LlilExpr",
    "LLIL_NOP", "LLIL_UNDEF", "LLIL_UNIMPL",
    "LLIL_REG", "LLIL_CONST", "LLIL_CONST_PTR", "LLIL_FLAG", "LLIL_FLAG_BIT",
    "LLIL_LOAD", "LLIL_STORE", "LLIL_PUSH", "LLIL_POP",
    "LLIL_SET_REG", "LLIL_SET_REG_SPLIT", "LLIL_SET_FLAG",
    "LLIL_ADD", "LLIL_SUB", "LLIL_MUL", "LLIL_NEG",
    "LLIL_DIVS", "LLIL_DIVU", "LLIL_MODS", "LLIL_MODU", "LLIL_ADC", "LLIL_SBB",
    "LLIL_AND", "LLIL_OR", "LLIL_XOR", "LLIL_NOT",
    "LLIL_LSL", "LLIL_LSR", "LLIL_ASR", "LLIL_ROL", "LLIL_ROR",
    "LLIL_SX", "LLIL_ZX", "LLIL_LOW_PART",
    "LLIL_CMP_E", "LLIL_CMP_NE",
    "LLIL_CMP_SLT", "LLIL_CMP_SLE", "LLIL_CMP_SGE", "LLIL_CMP_SGT",
    "LLIL_CMP_ULT", "LLIL_CMP_ULE", "LLIL_CMP_UGE", "LLIL_CMP_UGT",
    "LLIL_FLAG_COND", "LLIL_FLAG_GROUP",
    "LLIL_GOTO", "LLIL_JUMP", "LLIL_IF",
    "LLIL_CALL", "LLIL_TAILCALL", "LLIL_RET", "LLIL_NORET", "LLIL_TRAP",
    "LLIL_INTRINSIC", "LLIL_BP",
    "ATOMS", "STATEMENTS", "ARITH_OPS", "BITWISE_OPS", "CMP_OPS", "SIDE_EFFECT_OPS",
    "reg", "const", "const_ptr", "flag", "flag_cond",
    "load", "store", "set_reg",
    "add", "sub", "mul", "neg", "and_", "or_", "xor", "not_",
    "lsl", "lsr", "asr",
    "goto", "jump", "if_", "call", "ret", "nop", "intrinsic",
    "cmp_e", "cmp_ne",
    "lift_arm64", "lift_static", "LiftStats",
    "SsaTag", "SsaBlock", "ssa_block", "ssa_blocks",
    "fold_expr", "constfold_block", "constfold_blocks",
    "dce_block", "dce_blocks",
    "TypeEnv", "typelat_block", "join",
    "T_TOP", "T_INT", "T_PTR", "T_HANDLE", "T_BOOL", "T_BOT",
    "FieldAccess", "StructShape", "struct_recover_block", "merge_shapes",
    "HlilSeq", "HlilLoop", "HlilIfElse", "HlilBlock", "HlilGoto", "HlilRet",
    "CfgInfo", "restructure", "from_viewer_cfg",
]
