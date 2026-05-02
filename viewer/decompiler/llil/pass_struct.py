"""Pass 6: Struct field recovery on LLIL expression tree.

依赖 pass 5 typelat. 对 PTR 类型的 reg, 收集所有 LLIL_LOAD/LLIL_STORE
访问的 (offset, size, r/w), 聚类成 struct shape.

§7.0:
  ✓ 不假设特定 struct (Mutex / pthread_t / JNIEnv / ...) — 仅"形状"抽取
  ✓ 命名留给 user spec 或 LLM (后续 pass)
  ✓ shape conflict (同 offset 不同 size) 标 conflict, 不强行 union

跟 BN MLIL 的 struct recovery 思路一致: 我们做形状, BN 还有 type
inference + struct vote. MVP 仅形状.

输出: dict[(base_reg, version) → StructShape].
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .expr import (
    LlilExpr,
    LLIL_LOAD, LLIL_STORE, LLIL_REG, LLIL_ADD, LLIL_CONST,
)
from .ssa import SsaBlock, SsaTag
from .pass_typelat import TypeEnv, T_PTR


@dataclass
class FieldAccess:
    offset: int
    size: int
    reads: int = 0
    writes: int = 0


@dataclass
class StructShape:
    base_reg: str
    base_version: int
    fields: dict[int, FieldAccess] = field(default_factory=dict)
    conflict: bool = False

    def sorted_fields(self) -> list[FieldAccess]:
        return sorted(self.fields.values(), key=lambda f: f.offset)

    def short(self) -> str:
        rs = sum(f.reads for f in self.fields.values())
        ws = sum(f.writes for f in self.fields.values())
        c = " CONFLICT" if self.conflict else ""
        return (f"{self.base_reg}_v{self.base_version}: "
                f"{len(self.fields)} fields, {rs}r/{ws}w{c}")


def _extract_base_disp(addr: LlilExpr,
                       tag: SsaTag,
                       entry_versions: dict[str, int]
                       ) -> tuple[str, int, int] | None:
    """从 addr expr 抽 (base_reg, base_version, disp). 失败返 None.

    支持 pattern:
      LLIL_REG('xN')                                  → ('xN', v, 0)
      LLIL_ADD(LLIL_REG('xN'), LLIL_CONST(disp))       → ('xN', v, disp)
      LLIL_ADD(LLIL_CONST(disp), LLIL_REG('xN'))       → swap, 同上
    """
    if not isinstance(addr, LlilExpr): return None
    if addr.op == LLIL_REG:
        rname = addr.operands[0]
        v = tag.get(addr) or entry_versions.get(rname, 0)
        return (rname, v, 0)
    if addr.op == LLIL_ADD and len(addr.operands) == 2:
        a, b = addr.operands
        # try a is REG, b is CONST
        if (isinstance(a, LlilExpr) and a.op == LLIL_REG
                and isinstance(b, LlilExpr) and b.op == LLIL_CONST):
            rname = a.operands[0]
            v = tag.get(a) or entry_versions.get(rname, 0)
            return (rname, v, int(b.operands[0]))
        # swapped
        if (isinstance(a, LlilExpr) and a.op == LLIL_CONST
                and isinstance(b, LlilExpr) and b.op == LLIL_REG):
            rname = b.operands[0]
            v = tag.get(b) or entry_versions.get(rname, 0)
            return (rname, v, int(a.operands[0]))
    return None


def _walk_load_store(node: LlilExpr) -> list[LlilExpr]:
    """递归收集 LLIL_LOAD / LLIL_STORE 节点."""
    out: list[LlilExpr] = []
    if not isinstance(node, LlilExpr):
        return out
    if node.op in (LLIL_LOAD, LLIL_STORE):
        out.append(node)
    for o in node.operands:
        if isinstance(o, LlilExpr):
            out.extend(_walk_load_store(o))
    return out


def struct_recover_block(blk: SsaBlock,
                         types: TypeEnv) -> dict[tuple, StructShape]:
    """收集 PTR-typed reg 的 (offset, size, r/w) → StructShape."""
    shapes: dict[tuple, StructShape] = {}
    for root in blk.roots:
        for ls in _walk_load_store(root):
            addr_expr = ls.operands[0]
            br = _extract_base_disp(addr_expr, blk.tag, blk.entry_versions)
            if br is None:
                continue
            base, version, disp = br
            ty = types.get(base, version)
            if ty != T_PTR:
                continue
            key = (base, version)
            shape = shapes.get(key)
            if shape is None:
                shape = StructShape(base_reg=base, base_version=version)
                shapes[key] = shape
            size = ls.size or 8
            fa = shape.fields.get(disp)
            if fa is None:
                fa = FieldAccess(offset=disp, size=size)
                shape.fields[disp] = fa
            else:
                if fa.size != size:
                    shape.conflict = True
            if ls.op == LLIL_LOAD:
                fa.reads += 1
            else:
                fa.writes += 1
    return shapes


def merge_shapes(shapes_list: list[dict[tuple, StructShape]]
                 ) -> dict[tuple, StructShape]:
    """合并多个 block 的 shape (same key = base_reg + version)."""
    out: dict[tuple, StructShape] = {}
    for shapes in shapes_list:
        for key, sh in shapes.items():
            if key not in out:
                out[key] = StructShape(
                    base_reg=sh.base_reg, base_version=sh.base_version,
                    fields=dict(sh.fields), conflict=sh.conflict,
                )
            else:
                target = out[key]
                target.conflict = target.conflict or sh.conflict
                for off, fa in sh.fields.items():
                    tfa = target.fields.get(off)
                    if tfa is None:
                        target.fields[off] = FieldAccess(
                            offset=off, size=fa.size,
                            reads=fa.reads, writes=fa.writes,
                        )
                    else:
                        if tfa.size != fa.size:
                            target.conflict = True
                        tfa.reads += fa.reads
                        tfa.writes += fa.writes
    return out
