"""Pass 2: SSA on LLIL expression tree.

BN-style: 每个 LLIL_REG / LLIL_SET_REG 注 SSA version.
我们用 SsaTag 包装 (而非改 LlilExpr 字段, 保持 lift cache 不变).

Trace linear 没 join → block-local SSA. 每写一次 reg 出新 version.
跨 block 用 entry/exit_versions 字典传 (caller 决定怎么链).

§7.0 自查:
  ✓ visitor pattern 跟 BN MLIL_SSA 一致
  ✓ 跨 reg 边界 (e.g. x0/w0/h0/b0 同物理 reg 部分) MVP 不展开 — 假设 ARM64
    norm reg 名 (x0/x1/...) 已规范, 跟 disasm.py 一致
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .expr import (
    LlilExpr, LLIL_SET_REG, LLIL_REG, LLIL_FLAG, LLIL_SET_FLAG, LLIL_CALL,
)


# ARM64 AAPCS64: caller-saved (volatile) regs — call 后 callee 可任意覆写,
# 所以 SSA 必须 bump 其 version 确保之后的 use 不会错链到 call 前的 def.
# x0/x1 是返回值; x2..x7 是参数; x9..x15 临时; x16/x17 IP; x18 platform.
# nzcv (flags) 也被 call 杀死.
_CALLER_SAVED = (
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8",                                         # indirect return
    "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18",
    "lr",                                         # bl 写 lr
)
_CALLER_SAVED_FLAGS = ("nzcv", "n", "z", "c", "v")


@dataclass
class SsaTag:
    """SSA 版本号 — 挂在 LlilExpr 之外的并行结构, 避免 lift cache 失效.

    versions[id(expr_node)] → version int.
      LLIL_SET_REG 顶层: dst version (这条 set_reg 后该 reg 的 version)
      LLIL_REG 子 expr: 读取时该 reg 的 version
      LLIL_SET_FLAG: 类似 SET_REG, dst 是 flag name
      LLIL_FLAG: 同 LLIL_REG
    """
    versions: dict[int, int] = field(default_factory=dict)

    def get(self, node: LlilExpr) -> int:
        return self.versions.get(id(node), 0)

    def set(self, node: LlilExpr, v: int) -> None:
        self.versions[id(node)] = v


@dataclass
class SsaBlock:
    """SSA 视图 — 一个 cfg block 上的 LLIL roots + SSA 版本表."""
    block_pc: int
    roots: list[LlilExpr] = field(default_factory=list)
    tag: SsaTag = field(default_factory=SsaTag)
    entry_versions: dict[str, int] = field(default_factory=dict)
    exit_versions: dict[str, int] = field(default_factory=dict)


def _walk_with_parent(node: LlilExpr, parent: Optional[LlilExpr] = None):
    """递归遍历 expr tree. yield (node, parent_op)."""
    yield node, parent.op if parent else None
    for o in node.operands:
        if isinstance(o, LlilExpr):
            yield from _walk_with_parent(o, node)


def ssa_block(block_pc: int, roots: list[LlilExpr],
              entry_versions: Optional[dict[str, int]] = None) -> SsaBlock:
    """Block-local SSA pass.

    遍历每条 root expr (statement). 在 root 内部:
      - 看到 LLIL_REG → src reg use, 标 current version
      - 看到 LLIL_FLAG → 同
    顶层 root 若是 LLIL_SET_REG → dst reg version 递增, 标在 root.
    若 LLIL_SET_FLAG → flag version 递增.
    """
    cur_reg: dict[str, int] = dict(entry_versions or {})
    cur_flag: dict[str, int] = {}
    blk = SsaBlock(block_pc=block_pc,
                   roots=list(roots),
                   entry_versions=dict(cur_reg))

    for root in roots:
        # 先标 use (sub-expr LLIL_REG / LLIL_FLAG) — 注: BN 中 set_reg 是
        # 'compute value, then write', 所以 use 用 cur, dst 后 bump.
        for node, parent_op in _walk_with_parent(root):
            if node is root:
                continue   # 顶层下面再处理
            if node.op == LLIL_REG:
                rname = node.operands[0]
                blk.tag.set(node, cur_reg.get(rname, 0))
            elif node.op == LLIL_FLAG:
                fname = node.operands[0]
                blk.tag.set(node, cur_flag.get(fname, 0))

        # 再处理 root: 若 SET_REG / SET_FLAG / CALL 则 bump
        if root.op == LLIL_SET_REG:
            rname = root.operands[0]
            cur_reg[rname] = cur_reg.get(rname, 0) + 1
            blk.tag.set(root, cur_reg[rname])
        elif root.op == LLIL_SET_FLAG:
            fname = root.operands[0]
            cur_flag[fname] = cur_flag.get(fname, 0) + 1
            blk.tag.set(root, cur_flag[fname])
        elif root.op == LLIL_CALL:
            # AAPCS64: caller-saved 全 kill — 之后的读应链到新 version,
            # 不能错指 call 前的 def. 这是 BN MLIL_SSA call 的标准行为.
            for r in _CALLER_SAVED:
                cur_reg[r] = cur_reg.get(r, 0) + 1
            for fl in _CALLER_SAVED_FLAGS:
                cur_flag[fl] = cur_flag.get(fl, 0) + 1

    blk.exit_versions = dict(cur_reg)
    return blk


def ssa_blocks(blocks: dict[int, list[LlilExpr]]) -> dict[int, SsaBlock]:
    """对每个 cfg block 跑 SSA, 各自从 0 起 (跨块由 caller 串)."""
    return {pc: ssa_block(pc, exprs) for pc, exprs in blocks.items()}
