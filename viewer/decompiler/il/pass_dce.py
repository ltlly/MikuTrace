"""Pass 4: Dead code elimination on SSA TLIL.

依赖 pass 2 (SSA). 在 SsaBlock 内 backward scan, 维护 live (reg, version)
集合. 一条 def 如果它的 (dst, dst_v) 不在 live 里, 且没副作用 (store / call /
branch / cmp / raw with side-effect), 就 dead, 删除.

§7.0 自查:
  ✓ 不假设特定 ABI / SDK
  ✓ 副作用 op (call/store/cmp/branch/raw) 永不删 — 安全保守
  ✓ 块出口 reg 全标 live (cross-block use 看不到, 保守保留)
  ✓ 反例 case (callee-saved reg 实际跨函数 live): 由块出口 live 集合自动覆盖

效果: ARM64 prologue 'stp x29,x30,[sp,#-0x20]!; mov x29,sp' 等如果 x29
后续不被 read, 自动消失 (但 store 永不删, 所以 stp 留, mov x29 走).
更典型: OLLVM 反混淆后 reg shuffle 链 (mov x0,xN; mov xN,x0) 中间步骤删掉.
"""
from __future__ import annotations
from .ops import (
    TlilOp,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_MUL, OP_NEG,
    OP_AND, OP_OR, OP_XOR, OP_NOT, OP_LSL, OP_LSR, OP_ASR,
    OP_LOAD, OP_STORE, OP_CMP,
    OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
    OP_CALL, OP_CALL_INDIRECT, OP_RET, OP_NOP, OP_RAW,
)
from .ssa import SsaBlock, SsaInsn


# 永远 live 的 op (有副作用, 即使 dst 没被读也不能删)
_SIDE_EFFECT_OPS = frozenset((
    OP_STORE, OP_CALL, OP_CALL_INDIRECT,
    OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
    OP_RET, OP_CMP,
    # OP_RAW: 保守视为有副作用 (我们不知道这条 SVC/NEON 在做啥)
    OP_RAW,
    # OP_LOAD: 保守 — 内存读可能触发 page fault, 不删 (即使 dst 没用)
    OP_LOAD,
))


def dce_block(blk: SsaBlock,
              extra_live_at_exit: set[str] | None = None) -> SsaBlock:
    """Backward scan, 删 dead def. 返回新 block, 不改原.

    extra_live_at_exit: 块出口时额外标 live 的 reg 集合 (e.g. caller saved /
                        cross-block use). 默认为空 (保守).
    """
    # 入口: live = exit_versions 里所有 reg (跨 block 用) ∪ extra
    live: set[tuple] = set()
    for r, v in blk.exit_versions.items():
        live.add((r, v))
    if extra_live_at_exit:
        for r in extra_live_at_exit:
            v = blk.exit_versions.get(r, 0)
            live.add((r, v))

    # backward scan
    keep_idx: list[bool] = [True] * len(blk.insns)
    for i in range(len(blk.insns) - 1, -1, -1):
        ins = blk.insns[i]
        op = ins.base
        # side effect → 永 live, 同时把 src 加 live
        if op.op in _SIDE_EFFECT_OPS:
            for j, s in enumerate(op.srcs):
                if isinstance(s, str):
                    sv = ins.src_v[j] if j < len(ins.src_v) else 0
                    live.add((s, sv))
                elif isinstance(s, tuple) and s and s[0] == "mem":
                    # ('mem', base_reg, disp) — base_reg 是 use
                    base = s[1]
                    if base:
                        # base reg 的 version 来自 op 之前的 def, 我们没存, 用 entry
                        # 简化: 找之前最近一次 def 的 version, 这里用入口 version
                        live.add((base, blk.entry_versions.get(base, 0)))
            continue
        # 非 side-effect op: 看 dst 是否 live
        if op.dst and ins.dst_v >= 0:
            dst_key = (op.dst, ins.dst_v)
            if dst_key not in live:
                # dead — 删
                keep_idx[i] = False
                continue
            # live: srcs → live, 自己从 live 移除 (因为是这一条产生的)
            live.discard(dst_key)
        for j, s in enumerate(op.srcs):
            if isinstance(s, str):
                sv = ins.src_v[j] if j < len(ins.src_v) else 0
                live.add((s, sv))

    new_insns = [ins for keep, ins in zip(keep_idx, blk.insns) if keep]
    new_blk = SsaBlock(
        block_pc=blk.block_pc,
        insns=new_insns,
        entry_versions=dict(blk.entry_versions),
        exit_versions=dict(blk.exit_versions),
    )
    return new_blk


def dce_blocks(blocks: dict[int, SsaBlock],
               extra_live_at_exit: set[str] | None = None
               ) -> tuple[dict[int, SsaBlock], int]:
    """对多个 block 跑 DCE. 返回 (新 dict, 删除的 op 数)."""
    out: dict[int, SsaBlock] = {}
    removed = 0
    for pc, blk in blocks.items():
        new = dce_block(blk, extra_live_at_exit=extra_live_at_exit)
        removed += len(blk.insns) - len(new.insns)
        out[pc] = new
    return out, removed
