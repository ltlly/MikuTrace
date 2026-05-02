"""Build TraceIR from a Trace + already-existing analyses.

复用 viewer/ 全部已有: cfg.py / calltree.py / symbols.py / disasm.py.
本文件只做组装, 不重写分析.

MVP 范围 (P2-DEC1):
  - 整 trace 当作一个 FuncIR (顶层调用); 子调用作为 calls 列出
  - 块去重: 同 PC 块只一次 BlockIR (静态骨架)
  - 计数: cfg 已有 block.executions / edge.count
  - samples: 首次执行的 x0..x3 + sp 快照
  - asm: 块内每条指令 mnemonic + ops 文本

Stage 2 加: BN 静态 prior, 子 fn 切分, JNI 锚点, 循环 induction var.
"""
from __future__ import annotations
import datetime
import numpy as np
from typing import Optional
from ..trace import Trace
from ..cfg import build_cfg, loop_sccs
from ..disasm import decode, fmt as fmt_insn
from ..symbols import build_from_trace, SymbolMap
from .ir import TopIR, FuncIR, BlockIR, LoopIR, CallIR, EdgeIR


_TRACEMIKU_VERSION = "0.1.0-dec1"   # bump per ship stage


def build_trace_ir(t: Trace,
                   sym: Optional[SymbolMap] = None,
                   only_module: bool = True) -> TopIR:
    """Build TopIR from a loaded Trace.

    Args:
        t: loaded trace (mmap'd)
        sym: optional symbol map (built from trace if not given)
        only_module: keep only main-module blocks (跟 cfg 一致默认)

    Returns:
        TopIR with one root FuncIR covering the whole trace.
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

    # Build per-block first-idx map (已在 build_cfg 时记录每个 block 的指令 PCs,
    # 但没记 first_idx). 再扫一遍 numpy pc_array 找每 block 首次 idx.
    pc_arr = t.pc_array()
    first_idx_for_pc: dict[int, int] = {}
    for blk_pc in cfg.blocks:
        # np.argmax 第一个 True 索引; 若都 False 跳过 (不应发生, block 必有执行).
        mask = (pc_arr == np.uint64(blk_pc))
        if mask.any():
            first_idx_for_pc[blk_pc] = int(np.argmax(mask))

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
            # 找该 PC 首次 inst (静态指令字节, 取首次实测 inst).
            mask = (pc_arr == np.uint64(ins_pc))
            if mask.any():
                first = int(np.argmax(mask))
                inst_word = t.inst(first)
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
        loops.append(LoopIR(
            id=f"L{i}",
            header=header_bid,
            body=body,
            iters=iters,
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

    return top
