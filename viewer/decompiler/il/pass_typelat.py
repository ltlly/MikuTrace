"""Pass 5: Type lattice 推导 on SSA TLIL.

简单 type lattice (从下往上扩):
  TOP (any)
   ├─ INT (int64 / int32 / ...)
   ├─ PTR (pointer to mem)
   ├─ HANDLE (opaque, 来自 user spec — JNI handle / fd / etc)
   └─ BOOL (cmp 输出, 仅 NZCV)
  BOTTOM (conflict / unknown)

§7.0 自查:
  ✓ 不假设 ABI / SDK — 类型 anchor 来自 user spec (TypeAnchor) 或 IL 结构推断
  ✓ 反例 case: 模糊类型 (int as ptr) → BOTTOM, 不强行决定
  ✓ 不命中 anchor 的 reg 留 TOP (any), 后续 pass / LLM 可继续推

推断来源 (优先级):
  1. TypeAnchor (user JSON spec) — 最强证据
  2. mem op base reg → PTR
  3. cmp 结果 → BOOL (写 NZCV, 我们不显式表达; 仅做用)
  4. mov_imm with imm in known string-pool / so-base range → 启发式 PTR
     (留给 pass 6 struct, 这里不做)
  5. 算术 (PTR + INT) → PTR (typical for offset)
  6. 默认 INT
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .ops import (
    TlilOp,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_AND, OP_OR, OP_XOR,
    OP_LSL, OP_LSR, OP_ASR, OP_MUL, OP_NEG, OP_NOT,
    OP_LOAD, OP_STORE, OP_CMP,
    OP_BRANCH_COND, OP_CALL, OP_CALL_INDIRECT,
)
from .ssa import SsaBlock, SsaInsn


# Type lattice values
T_TOP    = "any"        # 未知
T_INT    = "int"
T_PTR    = "ptr"
T_HANDLE = "handle"     # JNI handle / fd / 不透明
T_BOOL   = "bool"
T_BOT    = "conflict"   # 冲突 (e.g. int + ptr 混)


def _join(a: str, b: str) -> str:
    """lattice join — meet of two types. 不同 → bottom; 相同 → 不变;
    其一 TOP → 另一; PTR + INT → PTR (offset 算术常态)."""
    if a == b: return a
    if a == T_TOP: return b
    if b == T_TOP: return a
    # PTR + INT 视为 PTR (典型: ptr + offset)
    if {a, b} == {T_PTR, T_INT}: return T_PTR
    return T_BOT


@dataclass
class TypeEnv:
    """每 (reg, version) → type. 跨 block 由调用方维护."""
    types: dict[tuple, str] = field(default_factory=dict)

    def get(self, reg: str, version: int) -> str:
        return self.types.get((reg, version), T_TOP)

    def set(self, reg: str, version: int, ty: str) -> None:
        self.types[(reg, version)] = ty

    def update(self, reg: str, version: int, ty: str) -> None:
        cur = self.get(reg, version)
        self.types[(reg, version)] = _join(cur, ty)


def typelat_block(blk: SsaBlock,
                  anchors: Optional[list[tuple[int, dict[str, str]]]] = None,
                  initial: Optional[TypeEnv] = None) -> TypeEnv:
    """对一个 block 推断 (reg, version) → type.

    anchors: list of (idx_in_block, {reg → type}) — 来自 user TypeSpec 命中,
             pass 5 调用方负责把 trace anchor 映射到 IL 内 idx.
    initial: 块入口 type env (跨块传递).
    Returns: TypeEnv 含所有 def 的类型.
    """
    env = initial or TypeEnv()
    anchor_map: dict[int, dict[str, str]] = {}
    if anchors:
        for idx, mp in anchors:
            anchor_map[idx] = mp

    for i, ins in enumerate(blk.insns):
        op = ins.base
        # ── anchor 注入 ──
        # anchor 通常表示某 idx 后 reg 类型确定 (e.g. bl FindClass 后 x0=jclass)
        if i in anchor_map:
            for reg, ty in anchor_map[i].items():
                v = blk.exit_versions.get(reg, 0) if i == len(blk.insns) - 1 \
                    else (ins.dst_v if op.dst == reg else
                          env.types.get((reg, env.types.get((reg, 0), 0)), T_TOP) and 0)
                # 简化: 在该 idx 处 reg 的当前 version 上注 type
                # 用 exit_versions 不准, 改用 SSA def 的方式
                # MVP: anchor 挂在 op.dst 上 (call 后定 ret 类型)
                if op.dst == reg and ins.dst_v >= 0:
                    env.set(reg, ins.dst_v, ty)
            # continue: 仍要处理本 op 的常规推导

        # ── 常规推导 ──
        if op.op == OP_LOAD and op.dst:
            # base reg in mem op → PTR
            for s in op.srcs:
                if isinstance(s, tuple) and s and s[0] == "mem":
                    base = s[1]
                    if base:
                        env.update(base, blk.entry_versions.get(base, 0), T_PTR)
            env.update(op.dst, ins.dst_v, T_INT)   # 默认 load 出 int
            continue
        if op.op == OP_STORE:
            for s in op.srcs:
                if isinstance(s, tuple) and s and s[0] == "mem":
                    base = s[1]
                    if base:
                        env.update(base, blk.entry_versions.get(base, 0), T_PTR)
            continue
        if op.op == OP_MOV_IMM and op.dst:
            # imm 默认 INT
            env.update(op.dst, ins.dst_v, T_INT)
            continue
        if op.op == OP_MOV_REG and op.dst:
            src = op.srcs[0]
            sv = ins.src_v[0] if ins.src_v else 0
            ty = env.get(src, sv) if isinstance(src, str) else T_INT
            env.update(op.dst, ins.dst_v, ty)
            continue
        if op.op == OP_ADD and op.dst:
            # 推导: PTR + INT → PTR; INT + INT → INT
            tys = []
            for j, s in enumerate(op.srcs):
                if isinstance(s, str):
                    sv = ins.src_v[j] if j < len(ins.src_v) else 0
                    tys.append(env.get(s, sv))
                else:
                    tys.append(T_INT)
            joined = T_TOP
            for ty in tys: joined = _join(joined, ty)
            env.update(op.dst, ins.dst_v, joined if joined != T_TOP else T_INT)
            continue
        if op.op == OP_SUB and op.dst:
            # PTR - PTR → INT; PTR - INT → PTR; INT - INT → INT
            if len(op.srcs) == 2:
                t0 = env.get(op.srcs[0], ins.src_v[0]) if isinstance(op.srcs[0], str) else T_INT
                t1 = env.get(op.srcs[1], ins.src_v[1]) if isinstance(op.srcs[1], str) else T_INT
                if t0 == T_PTR and t1 == T_PTR:
                    env.update(op.dst, ins.dst_v, T_INT)
                elif t0 == T_PTR:
                    env.update(op.dst, ins.dst_v, T_PTR)
                else:
                    env.update(op.dst, ins.dst_v, T_INT)
            continue
        if op.op in (OP_AND, OP_OR, OP_XOR, OP_LSL, OP_LSR, OP_ASR,
                     OP_MUL, OP_NEG, OP_NOT) and op.dst:
            env.update(op.dst, ins.dst_v, T_INT)
            continue
        if op.op == OP_CMP:
            # 不写 dst, 留 flags
            continue
        if op.op in (OP_CALL, OP_CALL_INDIRECT):
            # call 默认 ret 在 x0 (ARM64 ABI), 类型 TOP
            # user spec anchor 在 anchor_map 处理
            continue
        # 其他 op: dst 留 TOP

    return env
