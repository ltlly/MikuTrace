"""Pass 6.5: Variable unification — BN HLIL var 模型.

BN HLIL 把同 reg 不同 SSA version 当作不同 var (e.g. x8_1, x8_27),
通过 def-use chain 决定哪些 version 合并成同 var. 我们简化为:
  - 每个 (reg, version) → 一个 var name
  - 命名规则: 'arg_<n>' for fn 入口前 8 个 GPR (x0..x7) v0
              'callee_save_<reg>' for x19..x28 + fp/lr v0
              'var_<reg>_<version>' for 其他

§7.0:
  ✓ 不假设特定 ABI 之外的 reg 用法 (ARM64 ABI 标准)
  ✓ 命名规则可扩展 (后续接入 user spec / type anchor 后可换 'env' / 'ctx' 等)
  ✓ render layer 用, 不影响其他 pass

输出: dict[(reg, version) → var_name]. render 用 var_name 替代 reg.
"""
from __future__ import annotations
from .expr import LlilExpr, LLIL_REG, LLIL_SET_REG
from .ssa import SsaBlock


# ARM64 ABI:
_ARG_REGS = ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
_CALLEE_SAVED = (
    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
    "x27", "x28", "x29", "x30", "fp", "lr",
)


def unify_vars(blocks: dict[int, SsaBlock]
               ) -> dict[tuple, str]:
    """Build a (reg, version) → var_name mapping.

    规则:
      - (xN, 0) where N ∈ 0..7 → arg_N
      - (reg, 0) where reg ∈ callee-saved → cs_<reg>
      - 其他 → var_<reg>_v<version>

    跨 block: SSA 是 block-local, 但 entry_versions 跨 block 已有. 我们
    收集所有 block 的 (reg, version) 对, 各自命名. 由于 SSA 是稀疏的,
    实际产出 var 数 = sum of unique (reg, version) across blocks.
    """
    seen: set[tuple] = set()
    for blk in blocks.values():
        # block 入口 versions
        for r, v in blk.entry_versions.items():
            seen.add((r, v))
        # block 出口 versions (上一 block 在不在 dict 不重要, 单 block 视野)
        for r, v in blk.exit_versions.items():
            seen.add((r, v))
        # block 内每条 root 的 dst version
        for root in blk.roots:
            if isinstance(root, LlilExpr) and root.op == LLIL_SET_REG:
                rname = root.operands[0]
                v = blk.tag.get(root)
                if v >= 0:
                    seen.add((rname, v))
            # use sub-expr LLIL_REG
            for n in (root.walk() if isinstance(root, LlilExpr) else []):
                if n.op == LLIL_REG:
                    rname = n.operands[0]
                    v = blk.tag.get(n)
                    seen.add((rname, v))

    names: dict[tuple, str] = {}
    for (r, v) in seen:
        if v == 0 and r in ("sp", "fp"):
            names[(r, v)] = r              # sp/fp 本名保留 (优先于 cs)
        elif v == 0 and r in _ARG_REGS:
            idx = _ARG_REGS.index(r)
            names[(r, v)] = f"arg_{idx}"
        elif v == 0 and r in _CALLEE_SAVED:
            names[(r, v)] = f"cs_{r}"
        else:
            names[(r, v)] = f"{r}_v{v}"
    return names
