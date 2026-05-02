"""Build TraceIR from a Trace + already-existing analyses.

复用 viewer/ 全部已有: cfg.py / calltree.py / symbols.py / disasm.py.
本文件只做组装, 不重写分析.

阶段进展:
  P2-DEC1: 整 trace 当 1 个 FuncIR (顶层 F0)
  P2-DEC3-A: hot/warm/cold tier
  P2-DEC3-B0: calltree 切子 FuncIR — top-K callee 升级独立 fn,
              按静态 PC 合并 (sub_54fe8 在 trace 里被调 4 次 → 1 个 FuncIR)
"""
from __future__ import annotations
import datetime
from collections import defaultdict
import numpy as np
from typing import Optional
from ..trace import Trace
from ..cfg import build_cfg, loop_sccs
from ..calltree import build_call_tree
from ..disasm import decode, fmt as fmt_insn
from ..symbols import build_from_trace, SymbolMap
from .ir import (
    TopIR, FuncIR, BlockIR, LoopIR, CallIR, EdgeIR, TypeAnchorIR, VmCandidateIR,
    InductionVarIR,
)
from .type_anchor import load_type_specs, find_anchors, TypeSpec, TypeAnchor
from .vm_candidate import detect_vm_candidates
from .loop_fold import detect_induction_vars, InductionVar


_TRACEMIKU_VERSION = "0.3.0-dec3b0"   # bump per ship stage


def _flatten_calltree(root: dict) -> list[dict]:
    """Flatten 嵌套 calltree → 平铺帧列表 (深度优先, root 不含).

    每帧 dict: fn_pc, fn (name), enter_idx, exit_idx, depth.
    """
    out: list[dict] = []
    def walk(node):
        for c in node.get("children", []):
            out.append({
                "fn_pc": c.get("fn_pc", 0),
                "fn": c.get("fn") or "",
                "enter_idx": c["enter_idx"],
                "exit_idx": c["exit_idx"],
                "depth": c["depth"],
            })
            walk(c)
    walk(root)
    return out


def split_top_k_callees(top: TopIR, t: Trace, sym: SymbolMap,
                        cfg, top_k: int = 10,
                        min_records: int = 50) -> None:
    """In-place: 把 top-K 子 callee 提升为独立 FuncIR.

    输入: top.fns 当前是 [F0=root_fn]. 加 F1..Fk = top callees.

    算法:
      1. flatten calltree, 按 fn_pc 分组 (静态 PC 合并多次调用)
      2. 每组 score = 总命中 records (累计 trace 长度)
      3. top_k 中超 min_records 的升级独立 FuncIR
      4. 每个新 FuncIR: blocks = 该 fn 所有调用区段内, 命中过的 cfg blocks
         exec_count = 调用次数; samples = 首次调用入参快照
      5. F0 (root) 不去掉这些块 — 它仍包含整 trace 视图. LLM 可选看哪个 fn.
    """
    if not top.fns:
        return
    n = len(t)
    if n == 0:
        return
    pc_arr = t.pc_array()

    # 1. flatten calltree
    tree = build_call_tree(t, sym=sym)
    frames = _flatten_calltree(tree)
    if not frames:
        return

    # 2. 过滤 calltree noise. OLLVM 大量 br 替代 ret → bl/ret 不平衡, 导致
    # 部分 instance 的 exit_idx 错误飘到 trace 末尾. 经验门限:
    #   - instance 长度 > 30% trace 视为 calltree 配对失败, 丢
    #   - 也丢 < 3 records 的 (空 frame)
    max_inst_len = max(int(n * 0.30), 1)
    frames = [
        f for f in frames
        if 3 <= (f["exit_idx"] - f["enter_idx"] + 1) <= max_inst_len
    ]

    # 3. group by fn_pc
    by_pc: dict[int, list[dict]] = defaultdict(list)
    for f in frames:
        if f["fn_pc"] == 0:        # blr 没找到 next pc, 跳过
            continue
        by_pc[f["fn_pc"]].append(f)

    # 4. score
    def _score(fs: list[dict]) -> int:
        return sum(f["exit_idx"] - f["enter_idx"] + 1 for f in fs)
    ranked = sorted(by_pc.items(), key=lambda kv: -_score(kv[1]))

    # 4. 升级 top-K 中达标的为 FuncIR
    block_pcs: set[int] = set(cfg.blocks)
    block_pcs_sorted = sorted(block_pcs)
    pc_to_bid_global = {pc: f"B{i}" for i, pc in enumerate(block_pcs_sorted)}

    new_fns: list[FuncIR] = []
    for fn_pc, instances in ranked[:top_k]:
        records = _score(instances)
        if records < min_records:
            continue
        # union mask across all instances
        mask = np.zeros(n, dtype=bool)
        for inst in instances:
            lo, hi = inst["enter_idx"], inst["exit_idx"]
            if lo < 0: lo = 0
            if hi >= n: hi = n - 1
            mask[lo:hi + 1] = True
        # PCs hit within mask
        own_pcs = pc_arr[mask]
        unique_pcs, counts = np.unique(own_pcs, return_counts=True)
        # 预先算 mask 内每 PC 的 first_idx (O(n) 一次):
        masked_pcs = pc_arr.copy()
        # 用 sentinel 把 mask 外标 0 (PCs 都 != 0 实际, 但保险用 inverted index)
        mask_first_idx: dict[int, int] = {}
        # 走 mask 顺序 — first occurrence
        idxs_in_mask = np.nonzero(mask)[0]
        for i in idxs_in_mask:
            p = int(pc_arr[i])
            if p not in mask_first_idx:
                mask_first_idx[p] = int(i)
            # 限制扫描数 — 5M 已经够 sample / asm
            if len(mask_first_idx) > 50000:
                break
        # 全 trace 静态 first_idx (preprocessed)
        global_first = {int(p): int(i) for p, i in zip(*np.unique(pc_arr, return_index=True))}
        # 只留命中 cfg block 起点的 (不是块内中间指令)
        own_blocks: list[BlockIR] = []
        for pc, cnt in zip(unique_pcs, counts):
            ipc = int(pc)
            if ipc not in block_pcs:
                continue
            blk = cfg.blocks[ipc]
            # samples 用 mask 内首次出现, 没有就用全局
            first_idx = mask_first_idx.get(ipc, global_first.get(ipc))
            if first_idx is not None:
                r = t.record(first_idx)
                samples = {reg: r.reg(reg) for reg in ("x0", "x1", "x2", "x3")}
                samples["sp"] = r.sp
            else:
                samples = {}
            # asm: 块内 disasm — 用 global_first dict (O(1) 替 mask scan)
            asm_lines = []
            for ins_pc in blk.insns:
                fi = global_first.get(ins_pc)
                if fi is not None:
                    iw = t.inst(int(fi))
                    d = decode(ins_pc, iw)
                    asm_lines.append(f"  {ins_pc:#x}: {d.mnemonic} {d.op_str}".rstrip())
            # exits: cfg.edges 上有的边
            exits: list[EdgeIR] = []
            for (src_pc, dst_pc), info in cfg.edges.items():
                if src_pc != ipc:
                    continue
                dst_bid = pc_to_bid_global.get(dst_pc, f"ext:{dst_pc:#x}")
                exits.append(EdgeIR(
                    dst=dst_bid, kind=str(info.get("kind", "uncond")),
                    taken_count=int(info.get("count", 0)),
                ))
            own_blocks.append(BlockIR(
                id=pc_to_bid_global.get(ipc, f"B?{ipc:#x}"),
                pc=ipc, end_pc=blk.end_pc or ipc,
                insns=len(blk.insns),
                exec_count=int(cnt),       # 该 fn 内执行次数 (mask 内出现次数)
                exits=exits, samples=samples, asm="\n".join(asm_lines),
            ))
        if not own_blocks:
            continue
        # name: 优先用 sym lookup, 否则 sub_<pc>
        nm, _ = sym.lookup(fn_pc) if sym else ("", 0)
        if not nm or nm == "?":
            nm = f"sub_{fn_pc:x}"
        # samples: 用最早一次调用 instance 的 x0..x3 快照
        first_inst = min(instances, key=lambda f: f["enter_idx"])
        first_idx = first_inst["enter_idx"]

        last_idx = max(inst["exit_idx"] for inst in instances)
        new_fns.append(FuncIR(
            id=f"F{len(top.fns) + len(new_fns)}",
            name=nm,
            pc_start=fn_pc,
            pc_end=max(b.end_pc for b in own_blocks),
            entry_idx=first_idx,
            exit_idx=last_idx,
            blocks=own_blocks,
            loops=[],          # 子 fn 的循环可由后续 stage 单独检测
            calls=[],          # 子 fn 内的 sub-call MVP 不展开
            exec_count=len(instances),
        ))

    top.fns.extend(new_fns)


def classify_blocks_by_tier(top: TopIR,
                            hot_top_k: int = 150,
                            min_hot_frac: float = 0.6) -> None:
    """In-place: 给每个 fn 的 blocks 标 tier='hot'/'warm'.

    规则 (DEC3-A):
      - block.exec_count == 0 → 'cold' (MVP 不出现, 留给 BN prior)
      - blocks ≤ hot_top_k → 全部 'hot'
      - 否则按 exec_count 降序, 累计覆盖 ≥ min_hot_frac 总执行计数前都 'hot',
        其余 'warm'. 强制至少前 hot_top_k 是 hot, 即使 exec_count tie 很多.

    动机: 真机 OLLVM trace (libsgmainso 1056 块) 只有 ~50-150 块真热,
    其余是 dispatcher 衍生. 截掉冷块, 单 fn IR 从 506KB → 30-60KB.
    """
    for fn in top.fns:
        if not fn.blocks:
            continue
        total_exec = sum(b.exec_count for b in fn.blocks)
        if total_exec == 0:
            continue
        if len(fn.blocks) <= hot_top_k:
            for b in fn.blocks:
                b.tier = "cold" if b.exec_count == 0 else "hot"
            continue
        # 按 exec_count 降序排, 标 hot 直到累计 frac
        sorted_blocks = sorted(fn.blocks, key=lambda b: -b.exec_count)
        accum = 0
        target = total_exec * min_hot_frac
        for i, b in enumerate(sorted_blocks):
            if b.exec_count == 0:
                b.tier = "cold"
            elif i < hot_top_k or accum < target:
                b.tier = "hot"
                accum += b.exec_count
            else:
                b.tier = "warm"


def build_trace_ir(t: Trace,
                   sym: Optional[SymbolMap] = None,
                   only_module: bool = True,
                   split_top_k: int = 10,
                   split_min_records: int = 50,
                   type_spec_paths: Optional[list] = None,
                   detect_vm: bool = True,
                   memshadow=None) -> TopIR:
    """Build TopIR from a loaded Trace.

    Args:
        t: loaded trace (mmap'd)
        sym: optional symbol map (built from trace if not given)
        only_module: keep only main-module blocks (跟 cfg 一致默认)
        split_top_k: 升级 top-K callee 为独立 FuncIR (DEC3-B0). 0 = 不切.
        split_min_records: 子 fn 至少这么多 records 才独立, 否则留 F0.
        type_spec_paths: list of JSON paths with type specs (DEC3-B).
                         None / [] = 不注入类型锚点 (普适, 没 spec 就没 anchor).

    Returns:
        TopIR with one root FuncIR (F0) + up to split_top_k child fns.
    """
    if sym is None:
        sym = build_from_trace(t)
    cfg = build_cfg(t, only_module=only_module)
    n = len(t)

    # Top-level metadata
    top = TopIR(
        records=n,
        truncated=bool(t.meta.raw.get("truncated", False)),
        last_insn_is_ret=bool(t.meta.raw.get("last_insn_is_ret", False)),
        cmd=t.meta.cmd,
        method=t.meta.method or "",
        tracemiku_version=_TRACEMIKU_VERSION,
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    )
    if t.meta.module:
        top.module_name = t.meta.module.name
        top.module_base = t.meta.module.base
        top.module_size = t.meta.module.size

    if n == 0:
        return top

    # Build per-block first-idx map. 用 numpy.unique(return_index=True) 一次
    # O(n log n), 替代之前 N_blocks × O(n) 的 mask 扫描 (15M trace × 3228 块
    # 慢到 1+ 分钟).
    pc_arr = t.pc_array()
    unique_pcs, first_indices = np.unique(pc_arr, return_index=True)
    pc_to_first = dict(zip(unique_pcs.tolist(), first_indices.tolist()))
    first_idx_for_pc: dict[int, int] = {
        pc: int(pc_to_first[pc]) for pc in cfg.blocks if pc in pc_to_first
    }

    # ── Block IDs ────────────────────────────────────────────────────────
    # 排序: 按 entry_pc 起点 first, 确保稳定 (LLM 引用 B0 永远是同一块).
    block_pcs_sorted = sorted(cfg.blocks)
    pc_to_bid = {pc: f"B{i}" for i, pc in enumerate(block_pcs_sorted)}

    # ── BlockIR ──────────────────────────────────────────────────────────
    blocks: list[BlockIR] = []
    for pc in block_pcs_sorted:
        blk = cfg.blocks[pc]
        bid = pc_to_bid[pc]
        # samples: 首次执行 x0..x3 + sp
        samples: dict[str, int] = {}
        if pc in first_idx_for_pc:
            r = t.record(first_idx_for_pc[pc])
            for reg in ("x0", "x1", "x2", "x3"):
                samples[reg] = r.reg(reg)
            samples["sp"] = r.sp
        # asm: 块内逐条 mnemonic + ops
        asm_lines = []
        for ins_pc in blk.insns:
            # 用预算好的 pc_to_first dict (O(1)) 替代 N×M numpy mask 扫描.
            first = pc_to_first.get(ins_pc)
            if first is not None:
                inst_word = t.inst(int(first))
                d = decode(ins_pc, inst_word)
                asm_lines.append(f"  {ins_pc:#x}: {d.mnemonic} {d.op_str}".rstrip())
        # exits: 从 cfg.edges 取出 (src=blk.start_pc) 的所有边
        exits: list[EdgeIR] = []
        for (src_pc, dst_pc), info in cfg.edges.items():
            if src_pc != pc:
                continue
            dst_bid = pc_to_bid.get(dst_pc, f"ext:{dst_pc:#x}")
            exits.append(EdgeIR(
                dst=dst_bid,
                kind=str(info.get("kind", "uncond")),
                taken_count=int(info.get("count", 0)),
            ))
        blocks.append(BlockIR(
            id=bid,
            pc=pc,
            end_pc=blk.end_pc or pc,
            insns=len(blk.insns),
            exec_count=blk.executions,
            exits=exits,
            samples=samples,
            asm="\n".join(asm_lines),
        ))

    # ── LoopIR ───────────────────────────────────────────────────────────
    loops: list[LoopIR] = []
    for i, scc in enumerate(loop_sccs(cfg)):
        # scc 是 block start_pc 列表
        # header = SCC 中 block.start_pc 最小的 (近似入口; CFG 没显式记 header)
        # 真正 header 应是从外部能进入的 block, MVP 简化用 min-pc.
        body = [pc_to_bid[p] for p in scc if p in pc_to_bid]
        if not body:
            continue
        header_pc = min(scc)
        if header_pc not in pc_to_bid:
            continue
        header_bid = pc_to_bid[header_pc]
        # iters = header block executions (近似, 多入口循环会高估)
        iters = cfg.blocks[header_pc].executions if header_pc in cfg.blocks else 0
        # DEC3-C: induction var 检测 — 通用 numpy regression
        ivs_raw = detect_induction_vars(t, header_pc) if iters >= 3 else []
        ivs = [InductionVarIR(
            reg=iv.reg, init=iv.init, final=iv.final, step=iv.step,
            n_iters=iv.n_iters, classification=iv.classification,
            linearity_score=iv.linearity_score, samples=list(iv.samples),
        ) for iv in ivs_raw]
        loops.append(LoopIR(
            id=f"L{i}",
            header=header_bid,
            body=body,
            iters=iters,
            induction_vars=ivs,
        ))

    # ── CallIR ───────────────────────────────────────────────────────────
    # 扫 trace 找 bl/blr, 每个对应一个 CallIR. ret 配对 (栈式).
    calls: list[CallIR] = []
    call_stack: list[int] = []   # 存当前 open call 的 idx (在 calls list 中位置)
    for i in range(n):
        r = t.record(i)
        d = decode(r.pc, r.inst)
        m = d.mnemonic
        if m in ("bl", "blr"):
            target_pc = int(pc_arr[i + 1]) if i + 1 < n else 0
            callee_name = ""
            if sym and target_pc:
                cf, _ = sym.lookup(target_pc)
                callee_name = cf or ""
            # 找发起 call 的 block id (当前 PC 落在哪个 block)
            src_bid = ""
            for pc in block_pcs_sorted:
                blk = cfg.blocks[pc]
                if pc <= r.pc <= blk.end_pc:
                    src_bid = pc_to_bid[pc]
                    break
            ci = CallIR(
                idx=i,
                src_block=src_bid,
                callee_pc=target_pc,
                callee_name=callee_name,
            )
            calls.append(ci)
            call_stack.append(len(calls) - 1)
        elif m == "ret":
            if call_stack:
                pos = call_stack.pop()
                calls[pos].ret_idx = i
                calls[pos].ret_val_x0 = r.reg("x0")

    # ── Top-level FuncIR ─────────────────────────────────────────────────
    fn_pc_start = cfg.entry_pc or (block_pcs_sorted[0] if block_pcs_sorted else 0)
    fn_pc_end = max((b.end_pc or b.pc for b in blocks), default=fn_pc_start)
    fn_name, _ = sym.lookup(fn_pc_start) if sym and fn_pc_start else ("?", 0)
    if not fn_name or fn_name == "?":
        fn_name = f"sub_{fn_pc_start:x}"

    last_d = decode(t.pc(n - 1), t.inst(n - 1)) if n > 0 else None
    last_is_ret = bool(last_d and last_d.mnemonic == "ret")

    root_fn = FuncIR(
        id="F0",
        name=fn_name,
        pc_start=fn_pc_start,
        pc_end=fn_pc_end,
        entry_idx=0,
        exit_idx=n - 1,
        truncated=top.truncated,
        last_insn_is_ret=last_is_ret,
        blocks=blocks,
        loops=loops,
        calls=calls,
        exec_count=1,
    )
    top.fns.append(root_fn)
    # last_insn_is_ret 在 top 上保险也填 (meta 没填的情况)
    top.last_insn_is_ret = last_is_ret

    # P2-DEC3-B0: 升级 top-K callee 为独立 FuncIR
    if split_top_k > 0 and n > 0:
        split_top_k_callees(top, t, sym, cfg,
                            top_k=split_top_k,
                            min_records=split_min_records)

    # P2-DEC3-B: 类型锚点 (JSON-spec driven). 没 spec → 跳过, 不影响其他.
    if type_spec_paths and n > 0:
        attach_type_anchors(top, t, type_spec_paths)

    # P2-DEC3-D: VM 候选区检测. 复用 ollvmdet, 不假设变种, 不 disasm.
    # 没 ollvm 痕迹 → 空列表. memshadow 提供时附 hex dump.
    if detect_vm and n > 0:
        try:
            top.vm_candidates = detect_vm_candidates(t, cfg, mem=memshadow)
        except Exception:
            top.vm_candidates = []

    # P2-DEC3-A: 默认按 exec_count 分级 hot/warm. 调用方可通过 render
    # 的 tier_filter 选择只渲染热块.
    classify_blocks_by_tier(top)

    return top


def attach_type_anchors(top: TopIR, t: Trace, spec_paths: list) -> None:
    """In-place: 给每个 fn 填入落在其 idx 范围内的 type_anchors.

    流程:
      1. load_type_specs(spec_paths) — 读多个 JSON spec 文件
      2. find_anchors(trace, specs) — 扫 trace 找命中 bl idx
      3. 按 fn.[entry_idx, exit_idx] 分配 anchor 到 fn

    一个 anchor 可能落在多个 fn 内 (子 fn 是父 fn 区间的子集). 我们 dedup
    给最深的 fn — 即 idx 范围最窄的那个 (典型: child 比 parent 优先).
    """
    specs = load_type_specs(spec_paths)
    if not specs:
        return
    anchors = find_anchors(t, specs)
    if not anchors:
        return
    for a in anchors:
        # 找 idx 范围最窄且包含该 anchor 的 fn
        candidates = [
            f for f in top.fns
            if f.entry_idx <= a.idx <= f.exit_idx
        ]
        if not candidates:
            continue
        narrow = min(candidates, key=lambda f: f.exit_idx - f.entry_idx)
        narrow.type_anchors.append(TypeAnchorIR(
            idx=a.idx, callee_pc=a.callee_pc,
            callee_name=a.spec.name,
            params=list(a.spec.params),
            ret_reg=a.spec.ret_reg,
            ret_type=a.spec.ret_type,
            provenance=a.spec.provenance,
        ))
