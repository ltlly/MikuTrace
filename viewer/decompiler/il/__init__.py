"""Trace IL pipeline (路线 B v2).

设计: docs/trace-decompiler-il-design.md.
入口: lift_static() → SSA → pass_constfold → pass_dce → ... → render.

Pass 1 (lift) ship in 同 commit. 后续 pass 单独 commit.
"""
from .ops import (
    TlilOp, OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_AND, OP_OR, OP_XOR,
    OP_LSL, OP_LSR, OP_ASR, OP_NEG, OP_NOT, OP_MUL, OP_LOAD, OP_STORE,
    OP_CMP, OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
    OP_CALL, OP_CALL_INDIRECT, OP_RET, OP_NOP, OP_RAW,
    OPS_ALL, OPS_ARITH, OPS_BRANCH,
)
from .lift import lift_arm64, lift_static, LiftStats
from .ssa import SsaInsn, SsaBlock, ssa_block, ssa_blocks
from .pass_constfold import constfold_block, constfold_blocks
from .pass_dce import dce_block, dce_blocks
from .pass_typelat import (
    TypeEnv, typelat_block,
    T_TOP, T_INT, T_PTR, T_HANDLE, T_BOOL, T_BOT,
)

__all__ = [
    "TlilOp",
    "OP_MOV_IMM", "OP_MOV_REG", "OP_ADD", "OP_SUB", "OP_AND", "OP_OR",
    "OP_XOR", "OP_LSL", "OP_LSR", "OP_ASR", "OP_NEG", "OP_NOT", "OP_MUL",
    "OP_LOAD", "OP_STORE", "OP_CMP",
    "OP_BRANCH_UNCOND", "OP_BRANCH_COND", "OP_BRANCH_INDIRECT",
    "OP_CALL", "OP_CALL_INDIRECT", "OP_RET", "OP_NOP", "OP_RAW",
    "OPS_ALL", "OPS_ARITH", "OPS_BRANCH",
    "lift_arm64", "lift_static", "LiftStats",
    "SsaInsn", "SsaBlock", "ssa_block", "ssa_blocks",
    "constfold_block", "constfold_blocks",
    "dce_block", "dce_blocks",
    "TypeEnv", "typelat_block",
    "T_TOP", "T_INT", "T_PTR", "T_HANDLE", "T_BOOL", "T_BOT",
]
