"""Pass 7: Control flow restructuring on LLIL CFG.

类似 BN HLIL 的 control flow recovery: 把 LLIL_GOTO/LLIL_IF 跨 block 边
重建为高级 statement (HlilLoop / HlilIfElse / HlilSequence).

输入: cfg (block_pc → SsaBlock) + cfg edges (来自 viewer/cfg.py).
输出: HlilStatement tree (root = sequence / loop / ifelse / goto-as-fallback).

§7.0:
  ✓ Cooper-Ferrante 完整算法太重, MVP 简化:
    - dominator tree → loop 检测 (single-entry SCC)
    - cfg 上 backedge → loop header
    - 不能识别的复杂结构降级 LLIL_GOTO (不强行套结构)
  ✓ 不假设特定 ABI / VM
  ✓ 反例 (irreducible CFG) → goto fallback

实现策略 — 简化的 hammock decomposition:
  1. 找 backedge (cfg.edges 中 dst 在 src 之前的 dominator chain 上 →
     视为 loop)
  2. 同 SCC 块视为 loop body
  3. 在 loop body 内 / 外, 顺序排块, branch_cond 转 IfElse
  4. fall-through 块拼成 Sequence

为 MVP 不重写 cfg, 直接接受 viewer/cfg.py 输出.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Union
from .ssa import SsaBlock
from .expr import LlilExpr, LLIL_GOTO, LLIL_IF, LLIL_RET, LLIL_JUMP


# ─────────── HLIL Statement classes ───────────

@dataclass
class HlilSeq:
    """sequence: stmts 按顺序执行."""
    stmts: list["HlilStmt"] = field(default_factory=list)


@dataclass
class HlilLoop:
    """do { body } while (cond) / while (cond) { body } / for(;;).
    MVP 简化: 只标 loop, body 是 HlilSeq. cond 留 None 表示 'unknown'."""
    body: "HlilStmt"
    iters: int = 0           # 实测 (从 cfg block.executions 拿)
    header_pc: int = 0
    cond: Optional[LlilExpr] = None     # cond expression (来自 backedge IF)


@dataclass
class HlilIfElse:
    """if (cond) then_branch else else_branch."""
    cond: LlilExpr
    then_b: "HlilStmt"
    else_b: Optional["HlilStmt"] = None
    pc: int = 0


@dataclass
class HlilBlock:
    """SsaBlock 的 leaf 包装 (一个 cfg block 的 LLIL roots)."""
    block_pc: int
    block: SsaBlock


@dataclass
class HlilGoto:
    """无法重建为高级结构 → fallback goto."""
    target_pc: int
    pc: int = 0


@dataclass
class HlilRet:
    pc: int = 0


HlilStmt = Union[HlilSeq, HlilLoop, HlilIfElse, HlilBlock, HlilGoto, HlilRet]


# ─────────── Restructure ───────────

@dataclass
class CfgInfo:
    """简化 CFG view, 给 restructure 用. 不依赖 viewer/cfg.py 的 dataclass.

    Caller 把 viewer.cfg.CFG 转成这个 (block_pc → succ_pcs list).
    """
    succs: dict[int, list[int]] = field(default_factory=dict)
    preds: dict[int, list[int]] = field(default_factory=dict)
    entry: int = 0
    exec_count: dict[int, int] = field(default_factory=dict)


def _find_backedges(cfg: CfgInfo) -> set[tuple[int, int]]:
    """找 backedge (src, dst) where dst dominates src in DFS visit order.

    简化版: DFS post-order, 记录访问中状态. backedge = src→dst 且 dst 在
    DFS 当前栈上.
    """
    if cfg.entry == 0 or cfg.entry not in cfg.succs:
        return set()
    visited: set[int] = set()
    on_stack: set[int] = set()
    backedges: set[tuple[int, int]] = set()
    # iterative DFS
    work: list[tuple[int, int]] = [(cfg.entry, 0)]   # (node, succ_idx)
    while work:
        node, si = work[-1]
        if si == 0:
            visited.add(node); on_stack.add(node)
        succs = cfg.succs.get(node, [])
        if si < len(succs):
            work[-1] = (node, si + 1)
            nxt = succs[si]
            if nxt in on_stack:
                backedges.add((node, nxt))
            elif nxt not in visited:
                work.append((nxt, 0))
        else:
            on_stack.discard(node)
            work.pop()
    return backedges


def _scc_of_block(cfg: CfgInfo, header: int,
                  backedges: set[tuple[int, int]]) -> set[int]:
    """给 backedge header, 找其 loop body — header 可达 + 能回到 header 的块."""
    # 反向可达 from header (沿 preds), 但限定 forward 可达自 header
    forward = {header}
    work = [header]
    while work:
        n = work.pop()
        for s in cfg.succs.get(n, []):
            if s not in forward:
                forward.add(s); work.append(s)
    # 反向可达
    backward = {header}
    work = [header]
    while work:
        n = work.pop()
        for p in cfg.preds.get(n, []):
            if p not in backward:
                backward.add(p); work.append(p)
    return forward & backward


def restructure(cfg: CfgInfo,
                blocks: dict[int, SsaBlock]) -> HlilStmt:
    """主入口 — cfg + ssa blocks → HLIL statement tree.

    简化版 MVP:
      - 检测 backedge → 标 loop header + body
      - 顺序遍历: 在 loop body 内的块包成 HlilLoop, 外的包成 HlilSeq
      - branch_cond IF → HlilIfElse (then = target block, else = fallthrough)
      - 不能识别的 → HlilGoto fallback

    注: 这是 minimal 版, 不做 dominance tree 完整算法. 真复杂 OLLVM-flatten
    交给 LLM 处理 (走 fallback goto + 扁平 sequence).
    """
    if cfg.entry == 0:
        # 无 cfg 入口 → 全 sequence
        return HlilSeq(stmts=[HlilBlock(b.block_pc, b)
                              for b in blocks.values()])

    backedges = _find_backedges(cfg)
    loop_headers = {dst for _src, dst in backedges}
    loop_bodies: dict[int, set[int]] = {
        h: _scc_of_block(cfg, h, backedges) for h in loop_headers
    }

    visited: set[int] = set()

    def _build(start_pc: int) -> HlilStmt:
        if start_pc in visited or start_pc not in blocks:
            return HlilGoto(target_pc=start_pc, pc=start_pc)
        visited.add(start_pc)
        blk = blocks[start_pc]

        # 在 loop header → 包 HlilLoop
        if start_pc in loop_headers:
            body_blocks = loop_bodies[start_pc]
            inner_stmts: list[HlilStmt] = []
            for inner_pc in sorted(body_blocks):
                if inner_pc not in visited:
                    visited.add(inner_pc)
                    if inner_pc in blocks:
                        inner_stmts.append(HlilBlock(inner_pc, blocks[inner_pc]))
            return HlilLoop(
                body=HlilSeq(stmts=inner_stmts),
                iters=cfg.exec_count.get(start_pc, 0),
                header_pc=start_pc,
            )

        # 块自身
        leaf = HlilBlock(start_pc, blk)

        # 看末尾 root: LLIL_IF / LLIL_GOTO / LLIL_RET / LLIL_JUMP / 顺序
        last_root = blk.roots[-1] if blk.roots else None
        if isinstance(last_root, LlilExpr):
            if last_root.op == LLIL_IF:
                cond, true_pc, false_pc = last_root.operands
                then_stmt = _build(true_pc) if true_pc in blocks else HlilGoto(true_pc)
                else_stmt = _build(false_pc) if false_pc in blocks else HlilGoto(false_pc)
                return HlilSeq(stmts=[
                    leaf,
                    HlilIfElse(cond=cond, then_b=then_stmt,
                               else_b=else_stmt, pc=last_root.pc),
                ])
            if last_root.op == LLIL_RET:
                return HlilSeq(stmts=[leaf, HlilRet(pc=last_root.pc)])
            if last_root.op == LLIL_GOTO:
                target = last_root.operands[0]
                return HlilSeq(stmts=[leaf, _build(target)])
            if last_root.op == LLIL_JUMP:
                # indirect — trace 实际跳到 cfg.succs[start_pc] 中的 succ.
                # 用最常见 succ (cfg.succs[0]) 续 build. 这是 trace 反编译器
                # 独家 (BN 静态看不到 indirect 真目标). 注: 多 succ 时其他
                # 走 visited 跳过 — 完整覆盖需 multi-path traversal (TODO).
                succs_list = cfg.succs.get(start_pc, [])
                if succs_list:
                    return HlilSeq(stmts=[leaf, _build(succs_list[0])])
                return HlilSeq(stmts=[leaf,
                                       HlilGoto(target_pc=0, pc=last_root.pc)])
        # fallthrough 到下一 succ
        succs = cfg.succs.get(start_pc, [])
        if len(succs) == 1:
            return HlilSeq(stmts=[leaf, _build(succs[0])])
        return leaf

    head = _build(cfg.entry)
    # 把 cfg 内还未 visit 的 block 拼到末尾 (indirect jump / multi-path 切断
    # 后的 cleanup). 否则用户看不到 unreached blocks 的 LLIL.
    leftover: list = []
    for pc in sorted(blocks):
        if pc not in visited:
            visited.add(pc)
            leftover.append(HlilBlock(pc, blocks[pc]))
    if leftover:
        if isinstance(head, HlilSeq):
            head.stmts.extend(leftover)
            return head
        return HlilSeq(stmts=[head] + leftover)
    return head


def from_viewer_cfg(viewer_cfg, exec_count_only_module: bool = True) -> CfgInfo:
    """Helper: viewer.cfg.CFG → CfgInfo.

    把 v1 的 cfg 数据转成本 pass 的精简 view, 不修改 viewer/cfg.py.
    """
    info = CfgInfo()
    info.entry = viewer_cfg.entry_pc
    for (src, dst), _ in viewer_cfg.edges.items():
        info.succs.setdefault(src, []).append(dst)
        info.preds.setdefault(dst, []).append(src)
    for pc, blk in viewer_cfg.blocks.items():
        info.exec_count[pc] = blk.executions
    return info
