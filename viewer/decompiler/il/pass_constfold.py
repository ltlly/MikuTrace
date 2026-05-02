"""Pass 3: Constant folding on SSA TLIL.

依赖 pass 2 (SSA). 在 SsaBlock 内 forward scan, 维护 dict[(reg, version) → const_value].
- 看到 mov_imm dst, imm → 记 const[(dst, dst_v)] = imm
- 看到 add/sub/and/or/xor/lsl/... 的 src reg 全 const + imm 也 const → 折叠
  替换为 mov_imm dst, fold_value
- 不 const 的不动

§7.0 自查:
  ✓ 算法跟 ARM64 ISA 解耦 — TLIL op 抽象层
  ✓ 不假设特定 OLLVM 变种 (任何 mov-imm + add-imm chain 都折)
  ✓ 不能确定 const 的 ABI / 寄存器 (sp/fp/x29) 不特殊处理 — 通用算法
  ✓ 反例 case: 涉及 reg 但版本未知 → 跳过, 不假装常量

Output: SsaBlock with rewritten insns. 原 block 不动 (immutable principle).
"""
from __future__ import annotations
from copy import copy
from .ops import (
    TlilOp,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_AND, OP_OR, OP_XOR,
    OP_LSL, OP_LSR, OP_ASR, OP_MUL, OP_NEG, OP_NOT,
)
from .ssa import SsaBlock, SsaInsn


# ARM64 GPR width (大多数 op 都按 64-bit 计算; 32-bit op 用 wN, 我们简化)
_MASK = (1 << 64) - 1


def _fold(op: str, srcs_vals: list[int]) -> int | None:
    """计算 op 在已知 const srcs 下的结果. 不能算 → None."""
    try:
        if op == OP_ADD:
            return (sum(srcs_vals)) & _MASK
        if op == OP_SUB and len(srcs_vals) == 2:
            return (srcs_vals[0] - srcs_vals[1]) & _MASK
        if op == OP_MUL and len(srcs_vals) == 2:
            return (srcs_vals[0] * srcs_vals[1]) & _MASK
        if op == OP_AND:
            r = _MASK
            for v in srcs_vals: r &= v
            return r
        if op == OP_OR:
            r = 0
            for v in srcs_vals: r |= v
            return r & _MASK
        if op == OP_XOR:
            r = 0
            for v in srcs_vals: r ^= v
            return r & _MASK
        if op == OP_NEG and len(srcs_vals) == 1:
            return (-srcs_vals[0]) & _MASK
        if op == OP_NOT and len(srcs_vals) == 1:
            return (~srcs_vals[0]) & _MASK
        if op == OP_LSL and len(srcs_vals) == 2:
            shift = srcs_vals[1] & 63
            return (srcs_vals[0] << shift) & _MASK
        if op == OP_LSR and len(srcs_vals) == 2:
            shift = srcs_vals[1] & 63
            return (srcs_vals[0] & _MASK) >> shift
        if op == OP_ASR and len(srcs_vals) == 2:
            shift = srcs_vals[1] & 63
            v = srcs_vals[0]
            # arithmetic shift: 64-bit signed
            if v & (1 << 63):
                v -= 1 << 64
            return (v >> shift) & _MASK
    except Exception:
        return None
    return None


def constfold_block(blk: SsaBlock) -> SsaBlock:
    """对一个 SsaBlock 跑 constant folding. 返回新 block, 不改原 block.

    forward scan 维护 const env: {(reg, version) → int}.
    """
    env: dict[tuple, int] = {}
    new_insns: list[SsaInsn] = []
    folded = 0

    for ins in blk.insns:
        op = ins.base
        # 检查 src 是否全 const
        if op.dst and op.op in (OP_MOV_IMM,):
            # mov_imm 直接记
            env[(op.dst, ins.dst_v)] = int(op.srcs[0])
            new_insns.append(ins)
            continue

        # mov_reg: 透传 const if src is const
        if op.op == OP_MOV_REG and op.dst:
            src_reg = op.srcs[0]
            src_v = ins.src_v[0]
            key = (src_reg, src_v)
            if key in env:
                # 替换为 mov_imm
                new_op = TlilOp(pc=op.pc, op=OP_MOV_IMM, dst=op.dst,
                                srcs=[env[key]],
                                extra={**op.extra, "_folded_from": "mov_reg"})
                new_ins = SsaInsn(base=new_op, dst_v=ins.dst_v,
                                  src_v=[-1])
                env[(op.dst, ins.dst_v)] = env[key]
                new_insns.append(new_ins)
                folded += 1
                continue
            new_insns.append(ins)
            continue

        # 算术 op: 检查 src 全是 const reg or imm
        if op.dst and op.op in (OP_ADD, OP_SUB, OP_MUL,
                                OP_AND, OP_OR, OP_XOR,
                                OP_LSL, OP_LSR, OP_ASR,
                                OP_NEG, OP_NOT):
            srcs_vals: list[int] = []
            ok = True
            for i, s in enumerate(op.srcs):
                if isinstance(s, int):
                    srcs_vals.append(s)
                elif isinstance(s, str):
                    sv = ins.src_v[i] if i < len(ins.src_v) else 0
                    key = (s, sv)
                    if key in env:
                        srcs_vals.append(env[key])
                    else:
                        ok = False
                        break
                else:
                    ok = False
                    break
            if ok:
                folded_val = _fold(op.op, srcs_vals)
                if folded_val is not None:
                    new_op = TlilOp(pc=op.pc, op=OP_MOV_IMM, dst=op.dst,
                                    srcs=[folded_val],
                                    extra={**op.extra, "_folded_from": op.op})
                    new_ins = SsaInsn(base=new_op, dst_v=ins.dst_v,
                                      src_v=[-1])
                    env[(op.dst, ins.dst_v)] = folded_val
                    new_insns.append(new_ins)
                    folded += 1
                    continue

        # 不能 fold: 如果 dst 被 def, 该 (dst, version) 不再是 const
        if op.dst and ins.dst_v >= 0:
            env.pop((op.dst, ins.dst_v), None)
        new_insns.append(ins)

    new_blk = SsaBlock(
        block_pc=blk.block_pc,
        insns=new_insns,
        entry_versions=dict(blk.entry_versions),
        exit_versions=dict(blk.exit_versions),
    )
    return new_blk


def constfold_blocks(blocks: dict[int, SsaBlock]) -> tuple[dict[int, SsaBlock], int]:
    """对多个 block 跑 const fold. 返回 (新 dict, 总 folded 计数).

    每 block 独立 (env 不跨 block) — 跨 block const propagation 留 pass 6/7.
    """
    out: dict[int, SsaBlock] = {}
    total_folded = 0
    for pc, blk in blocks.items():
        # 算 fold 数: count 新 insns 中 mov_imm with _folded_from
        new = constfold_block(blk)
        f = sum(1 for i in new.insns
                if i.base.op == OP_MOV_IMM and i.base.extra.get("_folded_from"))
        total_folded += f
        out[pc] = new
    return out, total_folded
