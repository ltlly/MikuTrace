"""Pass 5: Type lattice 推导 on LLIL expression tree.

Visitor 走 expr tree, 给每个 (reg, version) 推类型. 跟 BN MLIL/HLIL 的
TypeReference 类似.

Lattice (BN 类似但简化):
  T_TOP    = 'any'      未知
  T_INT    = 'int'      标量整数
  T_PTR    = 'ptr'      内存指针
  T_HANDLE = 'handle'   不透明 (JNI handle / fd / jclass / ...)
  T_BOOL   = 'bool'     1-bit (CMP 输出)
  T_BOT    = 'conflict' 类型冲突 (e.g. PTR/HANDLE 混)

Join 规则:
  - same → same
  - TOP + X → X
  - PTR + INT → PTR (offset 算术)
  - 其他不同 → BOT

推断规则 (visitor 自下而上):
  LLIL_LOAD: addr 子 expr 必 PTR; dst (从 SET_REG outer) 默认 INT
  LLIL_STORE: addr 子 expr 必 PTR
  LLIL_CONST: INT (LLIL_CONST_PTR 是 PTR)
  LLIL_REG: 查 env, 默认 TOP
  LLIL_ADD/SUB: PTR+INT→PTR, INT+INT→INT, PTR-PTR→INT
  LLIL_AND/OR/XOR/MUL/LSL/LSR/ASR/NEG/NOT: INT
  LLIL_CMP_*: BOOL
  LLIL_FLAG_COND: BOOL
  LLIL_CALL: ret 类型 (default TOP, anchor 注 specific)

§7.0:
  ✓ visitor pattern, 不假设 SDK
  ✓ anchor 来源外置 (TypeAnchor JSON)
  ✓ 反例 case (PTR/INT 冲突) → BOT, 不强行决定
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .expr import (
    LlilExpr,
    LLIL_REG, LLIL_CONST, LLIL_CONST_PTR,
    LLIL_LOAD, LLIL_STORE, LLIL_SET_REG,
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR,
    CMP_OPS, LLIL_FLAG_COND, LLIL_FLAG,
    LLIL_CALL, LLIL_INTRINSIC,
)
from .ssa import SsaBlock, SsaTag


T_TOP    = "any"
T_INT    = "int"
T_PTR    = "ptr"
T_HANDLE = "handle"
T_BOOL   = "bool"
T_BOT    = "conflict"


def join(a: str, b: str) -> str:
    if a == b: return a
    if a == T_TOP: return b
    if b == T_TOP: return a
    if {a, b} == {T_PTR, T_INT}: return T_PTR
    return T_BOT


@dataclass
class TypeEnv:
    """(reg, version) → type."""
    types: dict[tuple, str] = field(default_factory=dict)

    def get(self, reg: str, version: int) -> str:
        return self.types.get((reg, version), T_TOP)

    def set(self, reg: str, version: int, ty: str) -> None:
        self.types[(reg, version)] = ty

    def update(self, reg: str, version: int, ty: str) -> None:
        cur = self.get(reg, version)
        self.types[(reg, version)] = join(cur, ty)


def _infer(expr: LlilExpr, tag: SsaTag, env: TypeEnv,
           entry_versions: dict[str, int]) -> str:
    """递归推 sub-expr 类型. 副作用: 把推断的 PTR base reg 写回 env."""
    if not isinstance(expr, LlilExpr):
        if isinstance(expr, int):
            return T_INT
        return T_TOP
    if expr.op == LLIL_CONST:
        return T_INT
    if expr.op == LLIL_CONST_PTR:
        return T_PTR
    if expr.op == LLIL_REG:
        rname = expr.operands[0]
        v = tag.get(expr) or entry_versions.get(rname, 0)
        return env.get(rname, v)
    if expr.op == LLIL_FLAG or expr.op == LLIL_FLAG_COND:
        return T_BOOL
    if expr.op == LLIL_LOAD:
        # addr 必 PTR
        addr = expr.operands[0]
        _force_ptr(addr, tag, env, entry_versions)
        return T_INT       # default; overridden if outer SET_REG has anchor
    if expr.op == LLIL_STORE:
        addr = expr.operands[0]
        _force_ptr(addr, tag, env, entry_versions)
        # store 不输出值 (不是 sub-expr value)
        return T_TOP
    if expr.op == LLIL_ADD:
        ts = [_infer(o, tag, env, entry_versions) for o in expr.operands]
        joined = T_TOP
        for t in ts: joined = join(joined, t)
        return joined if joined != T_TOP else T_INT
    if expr.op == LLIL_SUB:
        if len(expr.operands) == 2:
            t0 = _infer(expr.operands[0], tag, env, entry_versions)
            t1 = _infer(expr.operands[1], tag, env, entry_versions)
            if t0 == T_PTR and t1 == T_PTR: return T_INT
            if t0 == T_PTR: return T_PTR
        return T_INT
    if expr.op in (LLIL_MUL, LLIL_NEG, LLIL_NOT,
                    LLIL_AND, LLIL_OR, LLIL_XOR,
                    LLIL_LSL, LLIL_LSR, LLIL_ASR):
        # 还要递归 (虽然最后是 INT) — 让 sub-expr 的 PTR 推断 propagate
        for o in expr.operands:
            _infer(o, tag, env, entry_versions)
        return T_INT
    if expr.op in CMP_OPS:
        for o in expr.operands:
            _infer(o, tag, env, entry_versions)
        return T_BOOL
    if expr.op in (LLIL_CALL, LLIL_INTRINSIC):
        return T_TOP
    # 其他: 递归子 expr 让 PTR 标记 propagate
    for o in expr.operands:
        if isinstance(o, LlilExpr):
            _infer(o, tag, env, entry_versions)
    return T_TOP


def _force_ptr(node: LlilExpr, tag: SsaTag, env: TypeEnv,
               entry_versions: dict[str, int]) -> None:
    """把 LLIL_REG 在 addr 位置标 PTR. 递归处理 ADD(PTR, INT) 类组合."""
    if not isinstance(node, LlilExpr):
        return
    if node.op == LLIL_REG:
        rname = node.operands[0]
        v = tag.get(node) or entry_versions.get(rname, 0)
        env.update(rname, v, T_PTR)
        return
    if node.op == LLIL_ADD:
        # 一般是 base + offset. base 是 reg, 标 PTR; offset 是 int 不动.
        for o in node.operands:
            if isinstance(o, LlilExpr) and o.op == LLIL_REG:
                _force_ptr(o, tag, env, entry_versions)
            else:
                _infer(o, tag, env, entry_versions)
        return
    # const_ptr 不需 force
    _infer(node, tag, env, entry_versions)


def typelat_block(blk: SsaBlock,
                  anchors: Optional[list[tuple[int, dict[str, str]]]] = None,
                  initial: Optional[TypeEnv] = None) -> TypeEnv:
    """对一个 SsaBlock 推类型. anchors: list of (root_idx, {reg → ty})."""
    env = initial or TypeEnv()
    anchor_map: dict[int, dict[str, str]] = {}
    if anchors:
        for idx, mp in anchors:
            anchor_map[idx] = mp

    for i, root in enumerate(blk.roots):
        if not isinstance(root, LlilExpr):
            continue
        # 先 anchor (优先级最高)
        if i in anchor_map:
            for r, ty in anchor_map[i].items():
                # SET_REG 写 r, version = tag.get(root) (若 root 是 SET_REG 写 r)
                if root.op == LLIL_SET_REG and root.operands[0] == r:
                    env.set(r, blk.tag.get(root), ty)
        # SET_REG: value 推断 → dst type
        if root.op == LLIL_SET_REG:
            rname = root.operands[0]
            value = root.operands[1]
            value_ty = _infer(value, blk.tag, env, blk.entry_versions)
            dv = blk.tag.get(root)
            # 若 anchor 已 set 同 reg, 不覆盖
            if env.get(rname, dv) == T_TOP:
                if value_ty != T_TOP:
                    env.update(rname, dv, value_ty)
                else:
                    env.update(rname, dv, T_INT)   # 默认 INT
            continue
        # 其他 root (STORE / CALL / IF / RET / ...): 递归推 sub-expr
        _infer(root, blk.tag, env, blk.entry_versions)
    return env
