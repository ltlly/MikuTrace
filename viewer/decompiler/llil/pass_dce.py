"""Pass 4: Dead code elimination on LLIL expression tree.

Backward scan SsaBlock. 维护 live (reg, version) 集合. 每条 root:
  - SET_REG: dst 在 live → 保留, 把 use sub-expr 加 live; dst 不 live → 删
  - SET_FLAG: 同
  - 其他 (STORE / CALL / RET / GOTO / IF / INTRINSIC ...) — 永留 (副作用),
    把 use sub-expr 加 live
块出口: live = exit_versions ∪ extra_live_at_exit (跨 block 保守).

§7.0:
  ✓ visitor 跟 BN 一致
  ✓ 副作用 op (SIDE_EFFECT_OPS in expr.py) 永留, 不丢正确性
  ✓ extra_live_at_exit 让用户/cfg 显式标 cross-block live
"""
from __future__ import annotations
from .expr import (
    LlilExpr,
    LLIL_REG, LLIL_FLAG,
    LLIL_SET_REG, LLIL_SET_FLAG,
    SIDE_EFFECT_OPS,
)
from .ssa import SsaBlock, SsaTag


def _collect_uses(node: LlilExpr, tag: SsaTag,
                  live: set[tuple],
                  entry_versions: dict[str, int]) -> None:
    """递归找 sub-expr 中所有 LLIL_REG / LLIL_FLAG, 加入 live."""
    if not isinstance(node, LlilExpr):
        return
    if node.op == LLIL_REG:
        rname = node.operands[0]
        v = tag.get(node) if tag.get(node) > 0 else entry_versions.get(rname, 0)
        live.add((rname, v))
        return
    if node.op == LLIL_FLAG:
        fname = node.operands[0]
        v = tag.get(node)
        live.add(("flag:" + fname, v))
        return
    for o in node.operands:
        if isinstance(o, LlilExpr):
            _collect_uses(o, tag, live, entry_versions)


def dce_block(blk: SsaBlock,
              extra_live_at_exit: set[str] | None = None) -> SsaBlock:
    """Backward scan. 删 dead SET_REG / SET_FLAG. 副作用 op 永留."""
    live: set[tuple] = set()
    for r, v in blk.exit_versions.items():
        live.add((r, v))
    if extra_live_at_exit:
        for r in extra_live_at_exit:
            live.add((r, blk.exit_versions.get(r, 0)))

    keep = [True] * len(blk.roots)
    for i in range(len(blk.roots) - 1, -1, -1):
        root = blk.roots[i]
        if not isinstance(root, LlilExpr):
            continue
        if root.op in SIDE_EFFECT_OPS:
            # use sub-expr → live
            for o in root.operands:
                if isinstance(o, LlilExpr):
                    _collect_uses(o, blk.tag, live, blk.entry_versions)
            continue
        if root.op == LLIL_SET_REG:
            rname = root.operands[0]
            dv = blk.tag.get(root)
            key = (rname, dv)
            if key not in live:
                keep[i] = False
                continue
            live.discard(key)
            value = root.operands[1]
            if isinstance(value, LlilExpr):
                _collect_uses(value, blk.tag, live, blk.entry_versions)
            continue
        if root.op == LLIL_SET_FLAG:
            fname = root.operands[0]
            dv = blk.tag.get(root)
            key = ("flag:" + fname, dv)
            if key not in live:
                keep[i] = False
                continue
            live.discard(key)
            value = root.operands[1]
            if isinstance(value, LlilExpr):
                _collect_uses(value, blk.tag, live, blk.entry_versions)
            continue
        # 其他 root 类型: use sub-expr → live (保守留)
        for o in root.operands:
            if isinstance(o, LlilExpr):
                _collect_uses(o, blk.tag, live, blk.entry_versions)

    new_roots = [r for k, r in zip(keep, blk.roots) if k]
    return SsaBlock(
        block_pc=blk.block_pc,
        roots=new_roots,
        tag=blk.tag,
        entry_versions=dict(blk.entry_versions),
        exit_versions=dict(blk.exit_versions),
    )


def dce_blocks(blocks: dict[int, SsaBlock],
               extra_live_at_exit: set[str] | None = None
               ) -> tuple[dict[int, SsaBlock], int]:
    out: dict[int, SsaBlock] = {}
    removed = 0
    for pc, blk in blocks.items():
        new = dce_block(blk, extra_live_at_exit=extra_live_at_exit)
        removed += len(blk.roots) - len(new.roots)
        out[pc] = new
    return out, removed
