"""Pass 2: SSA on TLIL (block-local).

Trace 是线性的, 块间没真 join point — 跨 block 时 reg 的 last def
直接传给下一 block 的 first use, 不需要 phi node. 我们 SSA 简化为:

  Block-local SSA — 一个 block 内, 每写一次 dst reg 出新 version.
  跨 block: 维护 entry_versions / exit_versions 字典, 让 pass 3+ 能
  跨 block 链 def-use.

§7.0 自查:
  ✓ 算法不假设特定 ABI / SDK / 寄存器约定
  ✓ 输出确定性: 同 trace + 同 cfg 输入 → 同 SSA 输出
  ✓ 反例 case: 自更新 load (lift 已标 OP_RAW) 在 SSA 时按通用规则处理
    (基本不读不写, 不污染版本流)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .ops import TlilOp, OPS_BRANCH


@dataclass
class SsaInsn:
    """SSA-annotated TLIL instruction. base 不可变, 新增 version 字段."""
    base: TlilOp
    # dst 的 version (在所属 block 内). -1 表示无 dst.
    dst_v: int = -1
    # parallel to base.srcs: 对应位置 reg 的 version (-1 表示 src 不是 reg
    # — imm / mem tuple).
    src_v: list[int] = field(default_factory=list)


@dataclass
class SsaBlock:
    """SSA basic block — 静态 cfg block 上的 SSA 视图."""
    block_pc: int                        # cfg block start_pc
    insns: list[SsaInsn] = field(default_factory=list)
    # 块入口 / 出口时每个 reg 的最近 def version.
    # entry_versions: 块入口时, 每 reg 上一次被定义的 version (来自上游 block).
    entry_versions: dict[str, int] = field(default_factory=dict)
    exit_versions: dict[str, int] = field(default_factory=dict)


def ssa_block(block_pc: int, ops: list[TlilOp],
              entry_versions: Optional[dict[str, int]] = None) -> SsaBlock:
    """对一个 block 的 ops list 跑 local SSA.

    entry_versions: 上一 block 出口时的 reg→version (用于跨块 def-use).
                    None / 空 → 每 reg 入口 version = 0.
    """
    cur: dict[str, int] = dict(entry_versions or {})
    blk = SsaBlock(block_pc=block_pc,
                   entry_versions=dict(cur))
    for op in ops:
        # src versions
        sv: list[int] = []
        for s in op.srcs:
            if isinstance(s, str):
                # reg name
                sv.append(cur.get(s, 0))
            else:
                sv.append(-1)
        # dst version: bump
        if op.dst:
            cur[op.dst] = cur.get(op.dst, 0) + 1
            dv = cur[op.dst]
        else:
            dv = -1
        blk.insns.append(SsaInsn(base=op, dst_v=dv, src_v=sv))
    blk.exit_versions = dict(cur)
    return blk


def ssa_blocks(blocks: dict[int, list[TlilOp]]) -> dict[int, SsaBlock]:
    """对每个 cfg block 跑 SSA, 不串联跨块 (各自从 0 起).

    跨块 def-use 链 由 caller 决定怎么用 (通常 pass 3+ 在 cfg 上走 dominator
    tree / cfg-flow 时用). 这里保持 per-block 独立, 简单且并行可行.
    """
    out: dict[int, SsaBlock] = {}
    for pc, ops in blocks.items():
        out[pc] = ssa_block(pc, ops)
    return out
