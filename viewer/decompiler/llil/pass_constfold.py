"""Pass 3: Constant folding on LLIL expression tree.

依赖 pass 2 SSA. visitor 走 expr tree:
  - LLIL_CONST → 已是常量
  - LLIL_REG → 查 (reg, version) 是否已知 const
  - 算术/位 op (ADD/SUB/MUL/AND/OR/XOR/LSL/LSR/ASR/NEG/NOT) 子 expr 全 const
    → fold 为 LLIL_CONST
  - LLIL_SET_REG dst 若 fold 后 value 是 LLIL_CONST → 记录 const env
    供后续 LLIL_REG use 查询

跟 v1 的 flat 版差别:
  - 走 expression tree 递归 fold (BN visitor pattern)
  - sub-expr 的 LLIL_ADD(LLIL_CONST(1), LLIL_CONST(2)) → LLIL_CONST(3)
    可发生在任意嵌套层 (e.g. LLIL_LOAD(LLIL_ADD(LLIL_CONST(1), LLIL_CONST(2)))
    → LLIL_LOAD(LLIL_CONST(3)))

§7.0:
  ✓ visitor pattern, 不假设特定 op 顺序
  ✓ 不识别的 op (INTRINSIC) 不 fold, 保留
  ✓ size 保留 (LLIL_CONST 默认 8B, fold 后跟 inner expr 一致)
"""
from __future__ import annotations
from .expr import (
    LlilExpr,
    LLIL_CONST, LLIL_REG, LLIL_SET_REG, LLIL_LOAD, LLIL_STORE,
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR,
    LLIL_SX, LLIL_ZX, LLIL_LOW_PART,
    LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT, LLIL_CMP_SGT,
    const,
)
from .ssa import SsaBlock, SsaTag


_MASK = (1 << 64) - 1


def _eval_op(op: str, vals: list[int]) -> int | None:
    try:
        if op == LLIL_ADD: return sum(vals) & _MASK
        if op == LLIL_SUB and len(vals) == 2: return (vals[0] - vals[1]) & _MASK
        if op == LLIL_MUL and len(vals) == 2: return (vals[0] * vals[1]) & _MASK
        if op == LLIL_AND:
            r = _MASK
            for v in vals: r &= v
            return r
        if op == LLIL_OR:
            r = 0
            for v in vals: r |= v
            return r & _MASK
        if op == LLIL_XOR:
            r = 0
            for v in vals: r ^= v
            return r & _MASK
        if op == LLIL_NEG and len(vals) == 1: return (-vals[0]) & _MASK
        if op == LLIL_NOT and len(vals) == 1: return (~vals[0]) & _MASK
        if op == LLIL_LSL and len(vals) == 2:
            return (vals[0] << (vals[1] & 63)) & _MASK
        if op == LLIL_LSR and len(vals) == 2:
            return (vals[0] & _MASK) >> (vals[1] & 63)
        if op == LLIL_ASR and len(vals) == 2:
            v = vals[0]
            if v & (1 << 63): v -= 1 << 64
            return (v >> (vals[1] & 63)) & _MASK
        if op == LLIL_CMP_E and len(vals) == 2:
            return 1 if vals[0] == vals[1] else 0
        if op == LLIL_CMP_NE and len(vals) == 2:
            return 0 if vals[0] == vals[1] else 1
    except Exception:
        return None
    return None


def _read_mem_bytes(mem, addr: int, size: int, t_idx: int) -> int | None:
    """从 memshadow 读 size 字节 (LE) → int. 任何字节缺失返 None."""
    if mem is None or not mem.built:
        return None
    val = 0
    for i in range(size):
        b, _kind, _src = mem.byte_at(addr + i, t_idx)
        if b is None:
            return None
        val |= (b & 0xFF) << (i * 8)
    return val


def _fold_extend(op: str, val: int, src_size: int) -> int:
    bits = max(1, int(src_size) * 8)
    mask = (1 << bits) - 1
    val &= mask
    if op == LLIL_SX and (val & (1 << (bits - 1))):
        val -= 1 << bits
    return val & _MASK


def fold_expr(node: LlilExpr,
              tag: SsaTag,
              env: dict[tuple, int],
              mem=None,
              mem_t_idx: int = -1) -> LlilExpr:
    """递归 fold 一个 sub-expression. 返回新 expr (immutable principle).
    若没 fold 机会, 返回 node 自身 (object identity 保持, 上层判等高效).

    env: dict[(reg_name, version) → int_value] — 已知 const 的 SSA def.
    mem: optional MemShadow — 当 LLIL_LOAD addr 全 const 时, 用 memshadow
         查实际字节, fold LOAD → CONST (trace 反编译器独家能力, BN 静态做不到).
    mem_t_idx: 用 memshadow 在哪个 trace idx 查 (默认 -1 = 末尾, 最稳态值).
    """
    if node.op == LLIL_CONST:
        return node
    if node.op == LLIL_REG:
        rname = node.operands[0]
        v = tag.get(node)
        key = (rname, v)
        if key in env:
            return LlilExpr(LLIL_CONST, size=node.size or 8,
                            operands=[env[key]],
                            extra={"_folded_from": "REG"})
        return node
    if node.op == LLIL_LOAD:
        # fold sub addr 后, 若 addr 是 LLIL_CONST + memshadow 可用 → fold 成
        # LLIL_CONST(实际字节). 这是 trace 反编译器独家能力 (BN 静态没此优势).
        new_addr = (fold_expr(node.operands[0], tag, env, mem, mem_t_idx)
                    if isinstance(node.operands[0], LlilExpr)
                    else node.operands[0])
        if (mem is not None and isinstance(new_addr, LlilExpr)
                and new_addr.op == LLIL_CONST and node.size > 0):
            addr_val = int(new_addr.operands[0])
            mem_val = _read_mem_bytes(mem, addr_val, node.size, mem_t_idx)
            if mem_val is not None:
                return LlilExpr(LLIL_CONST, size=node.size,
                                operands=[mem_val],
                                extra={"_folded_from": "LOAD",
                                       "_load_addr": addr_val})
        if isinstance(node.operands[0], LlilExpr) and new_addr is node.operands[0]:
            return node
        return LlilExpr(node.op, size=node.size,
                        operands=[new_addr], extra=dict(node.extra),
                        pc=node.pc)
    if node.op in (LLIL_SX, LLIL_ZX, LLIL_LOW_PART):
        child = node.operands[0] if node.operands else None
        new_child = fold_expr(child, tag, env, mem, mem_t_idx) \
            if isinstance(child, LlilExpr) else child
        if isinstance(new_child, LlilExpr) and new_child.op == LLIL_CONST:
            src_size = int(node.extra.get("src_size") or new_child.size or node.size or 8)
            return LlilExpr(LLIL_CONST, size=node.size or 8,
                            operands=[_fold_extend(node.op, new_child.operands[0], src_size)],
                            extra={"_folded_from": node.op})
        if new_child is child:
            return node
        return LlilExpr(node.op, size=node.size,
                        operands=[new_child], extra=dict(node.extra),
                        pc=node.pc)
    if node.op == LLIL_STORE:
        # fold sub addr / value 但 op 本身不 fold (有副作用)
        new_ops = [
            fold_expr(o, tag, env, mem, mem_t_idx) if isinstance(o, LlilExpr) else o
            for o in node.operands
        ]
        if all(a is b for a, b in zip(new_ops, node.operands)):
            return node
        return LlilExpr(node.op, size=node.size,
                        operands=new_ops, extra=dict(node.extra),
                        pc=node.pc)
    # arithmetic/bitwise/cmp: 递归 fold 子 expr, 全 const 则 evaluate
    new_ops = [
        fold_expr(o, tag, env, mem, mem_t_idx) if isinstance(o, LlilExpr) else o
        for o in node.operands
    ]
    consts: list[int] = []
    all_const = True
    for o in new_ops:
        if isinstance(o, LlilExpr) and o.op == LLIL_CONST:
            consts.append(o.operands[0])
        elif isinstance(o, int):
            consts.append(o)
        else:
            all_const = False
            break
    if all_const and consts:
        v = _eval_op(node.op, consts)
        if v is not None:
            return LlilExpr(LLIL_CONST,
                            size=node.size or 8,
                            operands=[v],
                            extra={"_folded_from": node.op})
    if all(a is b for a, b in zip(new_ops, node.operands)):
        return node
    return LlilExpr(node.op, size=node.size,
                    operands=new_ops, extra=dict(node.extra),
                    pc=node.pc)


def constfold_block(blk: SsaBlock,
                    uidf: dict | None = None,
                    mem=None, mem_t_idx: int = -1) -> SsaBlock:
    """对一个 SsaBlock 跑 const fold. 返回新 block.

    维护 env: dict[(reg, version) → int]. 每条 SET_REG fold value 后, 若
    LLIL_CONST 则记 env. 后续 LLIL_REG use 查 env 替代.

    uidf: optional dict[(block_pc, root_idx) → ObservedValues] from pass_uidf.
          ObservedValues.is_const() 的 SET_REG 注入 env (BN UIDF 思想 —
          trace 真值告诉 const fold 哪些寄存器实际上是常量, 即使 lift 看
          的是 LLIL_LOAD / LLIL_INTRINSIC 这种不可推).
    """
    env: dict[tuple, int] = {}
    uidf_locked: set[tuple] = set()    # UIDF 注入的 keys, 不被普通 fold pop
    if uidf is not None:
        from .pass_uidf import apply_uidf_to_constfold_env
        apply_uidf_to_constfold_env(uidf, blk, env)
        uidf_locked = set(env)
    new_roots: list[LlilExpr] = []
    new_tag = SsaTag()
    new_tag.versions = dict(blk.tag.versions)   # 复用 (新 expr 都重建 id)

    for root in blk.roots:
        if root.op == LLIL_SET_REG:
            rname = root.operands[0]
            value_expr = root.operands[1]
            new_value = fold_expr(value_expr, blk.tag, env, mem, mem_t_idx) \
                if isinstance(value_expr, LlilExpr) else value_expr
            if new_value is value_expr:
                new_roots.append(root)
            else:
                new_root = LlilExpr(LLIL_SET_REG, size=root.size,
                                    operands=[rname, new_value],
                                    extra=dict(root.extra), pc=root.pc)
                new_tag.set(new_root, blk.tag.get(root))
                # walk new value: 给新 LLIL_REG 节点搬 version
                _copy_versions(value_expr, new_value, blk.tag, new_tag)
                new_roots.append(new_root)
            # update env: fold 后是 LLIL_CONST → 记 (但不覆盖 UIDF lock)
            cur_root = new_roots[-1]
            v_node = cur_root.operands[1]
            dst_v = blk.tag.get(root)
            key = (rname, dst_v)
            if key in uidf_locked:
                # UIDF 已注入真值, 不动 (即使 fold 看起来不出 const)
                continue
            if isinstance(v_node, LlilExpr) and v_node.op == LLIL_CONST:
                env[key] = int(v_node.operands[0])
            else:
                env.pop(key, None)
            continue

        # 其他 root: 递归 fold sub expr
        new_root = root
        if isinstance(root, LlilExpr) and root.operands:
            new_ops = [
                fold_expr(o, blk.tag, env, mem, mem_t_idx) if isinstance(o, LlilExpr) else o
                for o in root.operands
            ]
            if not all(a is b for a, b in zip(new_ops, root.operands)):
                new_root = LlilExpr(root.op, size=root.size,
                                    operands=new_ops,
                                    extra=dict(root.extra), pc=root.pc)
                new_tag.set(new_root, blk.tag.get(root))
                for old_o, new_o in zip(root.operands, new_ops):
                    if isinstance(old_o, LlilExpr) and isinstance(new_o, LlilExpr):
                        _copy_versions(old_o, new_o, blk.tag, new_tag)
        new_roots.append(new_root)

    return SsaBlock(
        block_pc=blk.block_pc,
        roots=new_roots,
        tag=new_tag,
        entry_versions=dict(blk.entry_versions),
        exit_versions=dict(blk.exit_versions),
    )


def _copy_versions(old: LlilExpr, new: LlilExpr,
                   old_tag: SsaTag, new_tag: SsaTag) -> None:
    """递归把 old expr 节点的 version 复制到对应位置的 new expr 节点.
    用于 fold 完保留 SSA tag 信息. 仅在结构对应时有效 (没 fold 的 sub-expr)."""
    if old is new:
        new_tag.set(new, old_tag.get(old))
        return
    new_tag.set(new, old_tag.get(old))
    if old.op != new.op or len(old.operands) != len(new.operands):
        return
    for o_old, o_new in zip(old.operands, new.operands):
        if isinstance(o_old, LlilExpr) and isinstance(o_new, LlilExpr):
            _copy_versions(o_old, o_new, old_tag, new_tag)


def constfold_blocks(blocks: dict[int, SsaBlock],
                     uidf: dict | None = None,
                     mem=None, mem_t_idx: int = -1
                     ) -> tuple[dict[int, SsaBlock], int]:
    """批量. 返回 (新 dict, fold 次数 — 子 expr 替换次数)."""
    out: dict[int, SsaBlock] = {}
    total = 0
    for pc, blk in blocks.items():
        new = constfold_block(blk, uidf=uidf, mem=mem, mem_t_idx=mem_t_idx)
        # count: 顶层 SET_REG value 是 LLIL_CONST + _folded_from
        for r in new.roots:
            if r.op == LLIL_SET_REG and isinstance(r.operands[1], LlilExpr):
                if r.operands[1].extra.get("_folded_from"):
                    total += 1
            else:
                # 子 expr 中找 _folded_from 标记
                for n in r.walk() if isinstance(r, LlilExpr) else []:
                    if n.op == LLIL_CONST and n.extra.get("_folded_from"):
                        total += 1
                        break
        out[pc] = new
    return out, total
