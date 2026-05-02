"""Pass 4.5: Flag elimination — 把 LLIL_SET_FLAG('cmp_result', SUB(a,b)) +
LLIL_IF(LLIL_FLAG_COND('eq'), ...) 合并成 LLIL_IF(LLIL_CMP_E(a,b), ...).

跟 BN MLIL 'flag analysis' 一致. ARM64 cmp 写 NZCV flags, b.cond 读 cond
逻辑表达式 — lift 时拆开是必要的, 但 HLIL 应该合并显示.

§7.0:
  ✓ 通用 ARM64 cond suffix 表 (eq/ne/lt/gt/...)
  ✓ 不识别 cond 留 LLIL_FLAG_COND 不动
  ✓ 不假设 SDK / VM
"""
from __future__ import annotations
from .expr import (
    LlilExpr,
    LLIL_SET_FLAG, LLIL_FLAG_COND, LLIL_IF, LLIL_SUB,
    LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT, LLIL_CMP_SLE,
    LLIL_CMP_SGE, LLIL_CMP_SGT, LLIL_CMP_ULT, LLIL_CMP_ULE,
    LLIL_CMP_UGE, LLIL_CMP_UGT,
)
from .ssa import SsaBlock


# ARM64 cond suffix → LLIL_CMP_* op
_COND_TO_CMP = {
    "eq": LLIL_CMP_E,    "ne": LLIL_CMP_NE,
    "lt": LLIL_CMP_SLT,  "le": LLIL_CMP_SLE,
    "ge": LLIL_CMP_SGE,  "gt": LLIL_CMP_SGT,
    "cc": LLIL_CMP_ULT,  "lo": LLIL_CMP_ULT,
    "ls": LLIL_CMP_ULE,
    "cs": LLIL_CMP_UGE,  "hs": LLIL_CMP_UGE,
    "hi": LLIL_CMP_UGT,
}


def flag_elim_block(blk: SsaBlock) -> SsaBlock:
    """合并 SET_FLAG('cmp_result', SUB(a,b)) + IF(FLAG_COND(c), ...)
    → IF(CMP_X(a,b), ...). 删除 SET_FLAG.
    """
    new_roots: list[LlilExpr] = []
    last_set_flag: LlilExpr | None = None
    last_set_flag_idx_in_new: int | None = None

    for root in blk.roots:
        if not isinstance(root, LlilExpr):
            new_roots.append(root)
            last_set_flag = None
            continue

        # 看是不是 SET_FLAG('cmp_result', SUB(a, b))
        if (root.op == LLIL_SET_FLAG
                and len(root.operands) == 2
                and root.operands[0] == "cmp_result"
                and isinstance(root.operands[1], LlilExpr)
                and root.operands[1].op == LLIL_SUB):
            new_roots.append(root)
            last_set_flag = root
            last_set_flag_idx_in_new = len(new_roots) - 1
            continue

        # 看是不是 IF(FLAG_COND(c), ...)
        if (root.op == LLIL_IF
                and len(root.operands) >= 1
                and isinstance(root.operands[0], LlilExpr)
                and root.operands[0].op == LLIL_FLAG_COND
                and last_set_flag is not None):
            cond_name = root.operands[0].operands[0]
            if cond_name in _COND_TO_CMP:
                cmp_op = _COND_TO_CMP[cond_name]
                a, b = last_set_flag.operands[1].operands  # SUB(a, b) operands
                # 构造新 cond expression
                new_cond = LlilExpr(cmp_op, size=1, operands=[a, b])
                new_if = LlilExpr(LLIL_IF, size=root.size,
                                  operands=[new_cond] + list(root.operands[1:]),
                                  extra=dict(root.extra), pc=root.pc)
                # 删 SET_FLAG (它已被合并到 IF 里)
                if last_set_flag_idx_in_new is not None:
                    new_roots.pop(last_set_flag_idx_in_new)
                new_roots.append(new_if)
                last_set_flag = None
                last_set_flag_idx_in_new = None
                continue

        new_roots.append(root)
        # 任何其他 root 都打断 flag chain (保守)
        if root.op != LLIL_SET_FLAG:
            last_set_flag = None
            last_set_flag_idx_in_new = None

    return SsaBlock(
        block_pc=blk.block_pc,
        roots=new_roots,
        tag=blk.tag,
        entry_versions=dict(blk.entry_versions),
        exit_versions=dict(blk.exit_versions),
    )


def flag_elim_blocks(blocks: dict[int, SsaBlock]
                     ) -> tuple[dict[int, SsaBlock], int]:
    out: dict[int, SsaBlock] = {}
    merged = 0
    for pc, blk in blocks.items():
        new = flag_elim_block(blk)
        merged += len(blk.roots) - len(new.roots)
        out[pc] = new
    return out, merged
