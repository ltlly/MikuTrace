"""traceMiku Web SPA backend.

单进程, FastAPI 包一层在已有 viewer/ 模块之上, 前端在浏览器拉数据.
mmap 在后端, 客户端按 viewport 拉切片, 200 万条 trace 滚动丝滑.
"""
from __future__ import annotations
import os, pathlib, time, threading, multiprocessing as mp, logging
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from viewer.trace import load, ALL_REGS
from viewer.disasm import decode
from viewer.symbols import build_from_trace
from viewer.cfg import build_cfg, loop_sccs
from viewer.index import Index
from viewer.display import (collect_modules_from_trace, deref_u64,
                            is_in_known_module, maybe_string_at, _heuristic_region)
from webui.cfg_render import (
    html_esc as _html_esc, MNEM_COLORS as _MNEM_COLORS,
    classify_mnem as _classify_mnem, build_block_label as _build_block_label,
    TOK_COLOR as _TOK_COLOR, render_tokens_html as _render_tokens_html,
    format_insn_row as _format_insn_row, BN_EDGE_KIND_COLOR as _BN_EDGE_KIND_COLOR,
    bn_bb_border_color as _bn_bb_border_color,
    split_mnem_ops_from_tokens as _split_mnem_ops_from_tokens,
    render_dot_to_svg as _render_dot_to_svg,
)
from webui.schemas import (
    MetaResponse, ModuleInfo, RecordsResponse, RecordRow, RecordDetail,
    CfgResponse, CfgBuildingResponse, CfgReadyResponse,
    BlockResponse, BlockDetail, LoopsResponse,
    SearchResponse, StringsResponse,
    ForwardTaintResponse, BackwardTaintResponse, TaintResponse,
    MemDumpResponse, IdxsForPcResponse, IdxsForBlockResponse,
    BacktraceResponse, BgStatusResponse, LastWriteResponse, RegValueResponse,
    TouchingRangeResponse, TouchingAddrResponse, TouchingResponse,
    StringProvenanceResponse, DecompStatusResponse,
    AsmTokensResponse, HlilResponse, BnCfgSvgResponse, BnCfgForPcResponse,
    BlockForPcResponse, FieldAtResponse, CfgSvgResponse,
    RegTimelineResponse, MemDiffResponse, FnSummaryResponse,
    DataChaseResponse, LastWriteOfAddrResponse,
    FindMemPatternResponse, JniCallsResponse,
    JobjHistoryResponse, JniStringsResponse,
    SoStatsResponse,
    RegAtIdxResponse, CallChainResponse,
    MemWritesInRangeAny, MemFlowAny,
    CryptoScanAny, AutoPhaseDetectAny,
    HashInputSearchAny, HashInputSearchRequest,
    DiffTracesResponse, DiffTracesRequest,
    JniEventsResponse, CallTreeResponse,
    HashFinalizeDetectAny, OllvmDetectResponse,
    ForkEventsResponse,
)


log = logging.getLogger(__name__)


# Reg name canonicalization — single source in viewer.regs.
from viewer.regs import canonical_reg as _norm_reg


def _subprocess_build_cfg_and_pcinst(trace_path: str, conn):
    """Run in CHILD process — own GIL, doesn't block parent's API threads.
    Single pass over trace builds 4 dicts:
      - cfg: full CFG dataclass
      - pc_inst: dict pc → first-seen inst encoding
      - pc_to_block: dict pc → block_start (O(1) block lookup)
      - block_idxs: dict block_start → list of trace idxs in that block

    NOTE: 不再建 pc_to_idxs — 那要 5.6GB python ints (200M 条目).
    /api/idxs-for-pc 改用从 cursor 双向扫 (O(距离), 通常很快).
    """
    try:
        from viewer.trace import load as _load
        from viewer.cfg import build_cfg as _bc, build_aux_indices as _aux
        t = _load(trace_path)
        cfg = _bc(t, only_module=True)
        # 向量化辅助 dict 构建 (替代 10M 行 Python loop): 5GB trace 上 ~3s → <0.5s.
        pc_inst, pc_to_block, block_idxs = _aux(t, cfg)
        conn.send(("ok", cfg, pc_inst, pc_to_block, block_idxs))
    except Exception:
        import traceback
        conn.send(("error", traceback.format_exc()))
    finally:
        try: conn.close()
        except Exception: pass


HERE = pathlib.Path(__file__).resolve().parent


def make_app(trace_path: pathlib.Path,
             decomp_so: Optional[pathlib.Path] = None,
             decomp_backend: Optional[str] = None) -> FastAPI:
    """Build a FastAPI app bound to one trace.

    Heavy structures (CFG, symbols, index) are lazily computed on first hit
    and cached. mmap'd trace stays open for the lifetime of the server.

    decomp_so / decomp_backend: if given, kick off background BN/Ghidra/IDA
    load at startup; /api/hlil-for-pc serves results once ready. base for the
    backend = trace.meta.module.base (so caller passes absolute runtime PCs).
    """
    t = load(trace_path)
    sym = build_from_trace(t)
    cache: dict = {}

    # ---- decompiler backend (optional, slow init in BG) ----
    DECOMP = {
        "backend": None,           # the live backend instance (or None)
        "name": None,              # 'binja' | 'ghidra' | 'ida' | 'r2' | 'none'
        "status": "disabled",      # disabled | loading | ready | error
        "err": None,
        "started_at": 0.0,
        "ready_at": 0.0,
        "so_path": str(decomp_so) if decomp_so else None,
    }
    if decomp_so is not None:
        DECOMP["status"] = "loading"
        DECOMP["started_at"] = time.time()
        def _load_decomp():
            try:
                from viewer.decompiler import make_backend
                bk = make_backend(decomp_backend)
                # base: 我们传 trace 看到的 module.base (绝对运行时 base).
                # 这样后端 function_at(absolute_pc) 直接命中.
                base = t.meta.module.base if t.meta.module else 0
                bk.open(str(decomp_so), base=base)
                DECOMP["backend"] = bk
                DECOMP["name"] = bk.name
                DECOMP["status"] = "ready"
                DECOMP["ready_at"] = time.time()
                log.info("decomp backend %s ready in %.1fs",
                         bk.name, DECOMP["ready_at"] - DECOMP["started_at"])
            except Exception as e:
                DECOMP["err"] = repr(e)
                DECOMP["status"] = "error"
                log.exception("decomp backend failed")
        threading.Thread(target=_load_decomp, daemon=True, name="decomp-load").start()

    # 重型结构 (CFG / pc_inst / index / mem-shadow) 都跑后台线程, 不阻塞 UI 响应.
    # 状态: "idle" → "building" → "ready" / "error"
    BG = {
        "cfg":         {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
        "pc_inst":     {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
        "pc_to_block": {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
        "block_idxs":  {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
        "index":       {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
        "mem":         {"status": "idle", "data": None, "err": None,
                        "started_at": 0.0, "ready_at": 0.0},
    }
    BG_LOCK = threading.Lock()

    def _bg_run(key: str, fn):
        """启一次后台构建. 重复 trigger 已 building/ready 时直接返回."""
        with BG_LOCK:
            st = BG[key]
            if st["status"] in ("building", "ready"): return st
            st["status"] = "building"; st["started_at"] = time.time()
        def _t():
            try:
                d = fn()
                with BG_LOCK:
                    st["data"] = d; st["status"] = "ready"
                    st["ready_at"] = time.time()
            except Exception as e:
                with BG_LOCK:
                    st["err"] = repr(e); st["status"] = "error"
        threading.Thread(target=_t, daemon=True, name=f"bg-{key}").start()
        return BG[key]

    def _bg_get(key: str, fn):
        """便捷: 拿到 ready 数据, 不到则 None (调用方决定如何处理)."""
        st = BG[key]
        if st["status"] == "idle": _bg_run(key, fn)
        return st["data"] if st["status"] == "ready" else None

    BG_KEYS_FROM_SUBPROCESS = ("cfg", "pc_inst", "pc_to_block", "block_idxs")

    def _build_cfg_pack_in_subprocess():
        """启子进程一次跑 CFG + pc_inst + pc_to_block + block_idxs.
        子进程独立 GIL, 不阻塞主进程 API. 4 个 dict 一次回传."""
        parent_conn, child_conn = mp.Pipe()
        proc = mp.Process(target=_subprocess_build_cfg_and_pcinst,
                          args=(str(trace_path), child_conn), daemon=True)
        proc.start()
        try:
            tag, *rest = parent_conn.recv()
        finally:
            try: parent_conn.close()
            except Exception: pass
            proc.join(timeout=5)
            if proc.is_alive():
                try: proc.terminate()
                except Exception: pass
        if tag == "ok":
            return rest  # [cfg, pc_inst, pc_to_block, block_idxs]
        raise RuntimeError(rest[0] if rest else "subprocess failed")

    def _bg_run_combined():
        """一次子进程拿 4 个结果, 同时标 ready."""
        with BG_LOCK:
            if BG["cfg"]["status"] in ("building", "ready"): return
            for k in BG_KEYS_FROM_SUBPROCESS:
                BG[k]["status"] = "building"
                BG[k]["started_at"] = time.time()
        def _t():
            try:
                results = _build_cfg_pack_in_subprocess()
                with BG_LOCK:
                    for k, d in zip(BG_KEYS_FROM_SUBPROCESS, results):
                        BG[k]["data"] = d
                        BG[k]["status"] = "ready"
                        BG[k]["ready_at"] = time.time()
            except Exception as e:
                with BG_LOCK:
                    msg = repr(e)
                    for k in BG_KEYS_FROM_SUBPROCESS:
                        BG[k]["err"] = msg; BG[k]["status"] = "error"
        threading.Thread(target=_t, daemon=True, name="bg-cfg-supervisor").start()

    def _build_index():
        idx = Index(t); idx.build(); return idx
    def _build_mem():
        from viewer.memshadow import MemShadow
        m = MemShadow(t); m.build(); return m

    def block_for_pc(pc: int) -> Optional[int]:
        # O(1) via precomputed dict (subprocess builds it once).
        d = BG["pc_to_block"]["data"]
        if d is None: return None
        return d.get(pc)

    app = FastAPI(title="traceMiku web")

    @app.get("/api/meta", response_model=MetaResponse)
    def meta():
        m = t.meta.module
        return {
            "path": str(trace_path),
            "records": len(t),
            "module": {"name": m.name, "base": hex(m.base), "size": m.size,
                       "end": hex(m.end)} if m else None,
            "modules": [{"name": x.name, "base": hex(x.base), "size": x.size,
                         "end": hex(x.end)} for x in t.meta.modules],
            "method": t.meta.method, "cmd": t.meta.cmd,
            "fn_addr": hex(t.meta.fn_addr) if t.meta.fn_addr else None,
            "regs": ALL_REGS,
        }

    # ModuleResolver: cached at app build time, used by /api/records to attach
    # module name to each row. Multi-SO traces (--include-so 抓的) 用这个让前端
    # 按 SO 折叠/过滤. 单 SO trace 仍 OK — 所有 row module 都是同一个.
    from viewer.symbols import ModuleResolver as _MR
    _module_resolver = _MR(t.meta.modules)

    @app.get("/api/records", response_model=RecordsResponse)
    def records(start: int = 0, count: int = 100, regs: str = ""):
        if start < 0 or start >= len(t):
            return {"start": start, "end": start, "count": 0, "records": []}
        end = min(start + count, len(t))
        regs_filter = [r for r in regs.split(",") if r in ALL_REGS] if regs else None
        m = t.meta.module
        base = m.base if m else 0
        cfg_data = BG["cfg"]["data"] if BG["cfg"]["status"] == "ready" else None
        pc_to_block_d = BG["pc_to_block"]["data"] if BG["pc_to_block"]["status"] == "ready" else None
        def exec_count(pc):
            if not cfg_data or not pc_to_block_d: return None
            bs = pc_to_block_d.get(pc)
            if bs is None: return None
            b = cfg_data.blocks.get(bs)
            return b.executions if b else None

        rows = []
        for i in range(start, end):
            r = t.record(i)
            d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            mod = _module_resolver.resolve(r.pc)
            ann = None
            if d.is_call or d.is_branch:
                if i + 1 < len(t):
                    next_pc = t.pc(i + 1)
                    tfn, tfoff = sym.lookup(next_pc)
                    if tfn and tfn != "?" and tfn != fname:
                        ann = f"→ {tfn}+{tfoff:#x}"
            row = {
                "idx": i, "pc": hex(r.pc), "rel": hex(r.pc - base) if base else None,
                "module": mod.name if mod else None,
                "func": fname if fname != "?" else None,
                "off": hex(foff) if fname != "?" else None,
                "asm": f"{d.mnemonic} {d.op_str}",
                "annotation": ann,
                "exec_count": exec_count(r.pc),
                "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
            }
            if regs_filter:
                row["regs"] = {nm: hex(r.reg(nm)) for nm in regs_filter}
            rows.append(row)
        return {"start": start, "end": end, "count": end-start, "records": rows}

    @app.get("/api/so-stats", response_model=SoStatsResponse)
    def api_so_stats(top: int = 20, all: bool = False):
        """Per-SO record counts. numpy vectorized on pc_array. Drives the
        UI's 'SO filter' panel — list of modules + record count + percent."""
        import numpy as np
        arr = t.pc_array()
        if not _module_resolver.modules:
            return {"records": int(len(arr)), "modules_total": 0,
                    "unknown_records": int(len(arr)), "unknown_percent": 100.0,
                    "modules": []}
        idx_arr = _module_resolver.vectorize(arr)
        n = int(len(arr))
        counts = np.bincount(idx_arr + 1, minlength=len(_module_resolver.modules) + 1)
        out = []
        unknown = int(counts[0])
        for i, m in enumerate(_module_resolver.modules):
            c = int(counts[i + 1])
            if c == 0 and not all: continue
            out.append({
                "name": m.name, "base": hex(m.base), "end": hex(m.end),
                "size": m.size, "records": c,
                "percent": round(c * 100 / n, 2) if n else 0,
            })
        out.sort(key=lambda x: -x["records"])
        if top > 0: out = out[:top]
        return {
            "records": n,
            "modules_total": len(_module_resolver.modules),
            "unknown_records": unknown,
            "unknown_percent": round(unknown * 100 / n, 2) if n else 0,
            "modules": out,
        }

    # collect_modules_from_trace 只用 t.meta.module + 启发式, 在 trace lifetime
    # 是 const. cache 一次, 省 /api/record 33-reg classify 时 33 次重建.
    _MODULES_CACHE = {"data": None}

    def _classify_reg_value(value: int, t_cursor: int, sp: int = 0,
                             max_depth: int = 3) -> str:
        """pwndbg 风格 — 返回纯文本注释 (前端能直接 append 到 hex 后)."""
        if BG["mem"]["status"] != "ready":
            return ""
        mem = BG["mem"]["data"]
        modules = _MODULES_CACHE["data"]
        if modules is None:
            modules = collect_modules_from_trace(t, mem)
            _MODULES_CACHE["data"] = modules
        if value == 0: return "  NULL"
        seen = set(); parts = []; cur = value; depth = 0
        while True:
            if cur in seen: parts.append(" ↺"); break
            seen.add(cur)
            if cur == 0:
                if depth == 0: parts.append(" NULL")
                break
            if sp and abs(cur - sp) < 0x20000:
                sign = "+" if cur >= sp else "-"
                parts.append(f"  [SP{sign}{abs(cur-sp):#x}]"); break
            modhit = is_in_known_module(modules, cur)
            if modhit:
                mname, moff = modhit
                if t.meta.module and mname == t.meta.module.name:
                    fname, foff = sym.lookup(cur)
                    if fname != "?":
                        parts.append(f"  [{fname}+{foff:#x}]")
                    else:
                        parts.append(f"  [{mname}+{moff:#x}]")
                else:
                    parts.append(f"  [{mname}+{moff:#x}]")
                break
            hint = _heuristic_region(cur)
            try:
                s = maybe_string_at(mem, cur, t_cursor)
            except Exception:
                s = None
            if s:
                parts.append(f'  → "{s}"'); break
            if depth < max_depth:
                nxt = deref_u64(mem, cur, t_cursor)
                if nxt is not None and nxt != 0 and nxt != cur:
                    if hint and depth == 0: parts.append(f"  ({hint})")
                    parts.append(f"  → {nxt:#x}")
                    cur = nxt; depth += 1; continue
            if hint:
                parts.append(f"  ({hint})")
            elif 0 < cur < 0x1000000:
                sign_ext = cur if cur < 0x80000000 else cur - 0x100000000
                if abs(sign_ext) < 0x10000:
                    parts.append(f"  ({sign_ext})")
                else:
                    parts.append(f"  ({cur})")
            break
        return "".join(parts)

    @app.get("/api/record/{idx}", response_model=RecordDetail)
    def one_record(idx: int):
        if idx < 0 or idx >= len(t): raise HTTPException(404)
        r = t.record(idx); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        m = t.meta.module
        base = m.base if m else 0
        bpc = None
        if BG["cfg"]["status"] == "ready":
            bp = block_for_pc(r.pc)
            if bp is not None: bpc = hex(bp)
        regs = {nm: hex(r.reg(nm)) for nm in ALL_REGS if nm not in ("nzcv",)}
        prev_regs = None
        if idx > 0:
            pr = t.record(idx - 1)
            prev_regs = {nm: hex(pr.reg(nm)) for nm in ALL_REGS if nm not in ("nzcv",)}
        # PDF p.3 / pwndbg 风: 每个 reg 加 classify 注释 (代码指针/字符串/栈/...).
        # mem ready 才有值; 否则 None.
        sp_val = r.reg("sp") if hasattr(r, "reg") else 0
        regs_annotated = {}
        if BG["mem"]["status"] == "ready":
            for nm in ALL_REGS:
                if nm == "nzcv": continue
                v = r.reg(nm)
                regs_annotated[nm] = _classify_reg_value(v, idx, sp=sp_val)
        # field_at: 若当前指令是 ldr/str [reg, #offset], 给 base reg 注释加上结构体字段语义
        # 例: ldr x9, [x8, 0x80] → x8 注释 += "  [pthread_mutex_t.__lock]"
        if DECOMP["status"] == "ready" and d.mem_op:
            bk = DECOMP["backend"]
            for base_reg, idx_reg, disp, sz, is_w, _src in d.mem_op:
                if not base_reg or base_reg not in regs_annotated:
                    continue
                try:
                    hint = bk.field_at(r.pc, base_reg, disp)
                except Exception:
                    hint = None
                if hint and (hint.struct or hint.field):
                    label = hint.field or hint.struct or "?"
                    if hint.struct and hint.field:
                        label = f"{hint.struct}.{hint.field}"
                    regs_annotated[base_reg] = (regs_annotated[base_reg] or "") + f"  [{label}]"
        # exec_count: 与 /api/records 一致, 该 PC 所在 block 的 executions
        exec_count = None
        if BG["cfg"]["status"] == "ready" and BG["pc_to_block"]["status"] == "ready":
            bs = BG["pc_to_block"]["data"].get(r.pc)
            if bs is not None:
                blk = BG["cfg"]["data"].blocks.get(bs)
                if blk: exec_count = blk.executions
        return {
            "idx": idx, "pc": hex(r.pc), "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "off": hex(foff) if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}",
            "regs": regs, "prev_regs": prev_regs,
            "regs_annotated": regs_annotated,
            "regs_def": list(d.regs_def), "regs_use": list(d.regs_use),
            "exec_count": exec_count,
            "block_pc": bpc, "cfg_status": BG["cfg"]["status"],
            "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
        }

    @app.get("/api/cfg", response_model=CfgResponse)
    def cfg(fn: Optional[str] = None):
        # 触发后台子进程构建 (CFG + pc_inst 一次出). 子进程独立 GIL,
        # 主进程的 /api/records /api/record 不会被它阻塞.
        _bg_run_combined()
        cfg_st = BG["cfg"]
        pcinst_st = BG["pc_inst"]
        if cfg_st["status"] != "ready" or pcinst_st["status"] != "ready":
            return {
                "status": "building",
                "cfg": cfg_st["status"],
                "pc_inst": pcinst_st["status"],
                "elapsed": {
                    "cfg":     time.time() - cfg_st["started_at"]     if cfg_st["status"]    == "building" else 0,
                    "pc_inst": time.time() - pcinst_st["started_at"] if pcinst_st["status"] == "building" else 0,
                },
                "errors": {k: BG[k]["err"] for k in ("cfg", "pc_inst") if BG[k]["err"]},
            }
        c = cfg_st["data"]; pc_inst = pcinst_st["data"]
        m = t.meta.module
        base = m.base if m else 0
        # 可选 fn 过滤: 只返回名字匹配的 blocks (大 trace 默认单函数, 1913 → ~50)
        # fn 为 None → 全图
        blocks = []
        included_starts = set()
        for pc, b in c.blocks.items():
            fname, foff = sym.lookup(pc)
            if fn and (fname or "") != fn:
                continue
            included_starts.add(pc)
            label_lines = []
            for ins_pc in b.insns[:3]:
                inst = pc_inst.get(ins_pc, 0)
                d = decode(ins_pc, inst)
                rel = (ins_pc - base) if base else ins_pc
                label_lines.append(f"+{rel:x}: {d.mnemonic} {d.op_str}")
            if len(b.insns) > 3:
                label_lines.append(f"...+{len(b.insns)-3}")
            blocks.append({
                "id": hex(pc),
                "start": hex(pc), "end": hex(b.end_pc),
                "rel": hex(pc - base) if base else None,
                "func": fname if fname != "?" else None,
                "insns": len(b.insns),
                "executions": b.executions,
                "label": "\n".join(label_lines),
            })
        edges = []
        for (s, d), v in c.edges.items():
            if fn and (s not in included_starts or d not in included_starts):
                continue
            edges.append({"id": f"{hex(s)}->{hex(d)}", "src": hex(s), "dst": hex(d),
                          "kind": v["kind"], "count": v["count"]})
        # 列出全部 func 名 (前端用来切函数)
        funcs_seen = {}
        for pc in c.blocks:
            fn, _ = sym.lookup(pc)
            if not fn or fn == "?": continue
            funcs_seen[fn] = funcs_seen.get(fn, 0) + 1
        funcs = sorted(([{"name": k, "blocks": v} for k, v in funcs_seen.items()]),
                       key=lambda x: -x["blocks"])
        return {"status": "ready",
                "blocks": blocks, "edges": edges,
                "entry": hex(c.entry_pc),
                "block_count": len(blocks), "edge_count": len(edges),
                "total_block_count": len(c.blocks),
                "fn": fn, "funcs": funcs}

    @app.get("/api/block-for-pc", response_model=BlockForPcResponse)
    def block_for_pc_api(pc: str):
        # 不强制 trigger CFG build (record endpoint 调它高频)
        if BG["cfg"]["status"] != "ready":
            return {"pc": pc, "block": None, "cfg_status": BG["cfg"]["status"]}
        bp = block_for_pc(int(pc, 16))
        return {"pc": pc, "block": hex(bp) if bp else None}

    @app.get("/api/block", response_model=BlockResponse)
    def block_detail(pc: str):
        if BG["cfg"]["status"] != "ready":
            return {"status": BG["cfg"]["status"]}
        c = BG["cfg"]["data"]
        start = int(pc, 16)
        if start not in c.blocks: raise HTTPException(404)
        b = c.blocks[start]
        m = t.meta.module
        base = m.base if m else 0
        fname, foff = sym.lookup(start)
        ins = []
        pc_inst = BG["pc_inst"]["data"] or {}
        for ins_pc in b.insns:
            inst = pc_inst.get(ins_pc, 0)
            d = decode(ins_pc, inst)
            ins.append({
                "pc": hex(ins_pc), "rel": hex(ins_pc - base) if base else None,
                "asm": f"{d.mnemonic} {d.op_str}",
                "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
            })
        return {
            "start": hex(start), "end": hex(b.end_pc),
            "func": fname if fname != "?" else None,
            "off": hex(foff) if fname != "?" else None,
            "executions": b.executions, "insns": ins,
            "exits": [{"to": hex(t), "kind": k} for t, k in b.exits],
        }

    @app.get("/api/loops", response_model=LoopsResponse)
    def api_loops():
        """所有 loop SCC: [{members:[pc,...], size:N}, ...] (size>=2 或自环)."""
        if BG["cfg"]["status"] != "ready":
            return {"status": BG["cfg"]["status"], "loops": []}
        c = BG["cfg"]["data"]
        loops = []
        for scc in loop_sccs(c):
            loops.append({"members": [hex(p) for p in scc], "size": len(scc)})
        return {"status": "ready", "loops": loops, "count": len(loops)}

    # cfg-svg 是大函数 graphviz 调用 (~5-30s), 同 fn 重复请求直接返回 cache.
    # cache key = fn (timeout 不影响输出, dot 输出确定); cfg/pc_inst 是 readonly 一次构建.
    _CFG_SVG_CACHE: dict = {}

    @app.get("/api/cfg-svg", response_model=CfgSvgResponse)
    def cfg_svg(fn: Optional[str] = None, timeout: int = 60):
        """IDA-style CFG: HTML-label per insn (HREF→<a xlink:href>, JS click + CSS 高亮),
        graphviz dot Sugiyama layout. 单函数 (fn 默认 current cursor 函数).
        条件分支 → 绿色 taken / 红色 fall-through.

        Cached: 同 fn 第二次调用直接返回 (cfg/pc_inst 不变, 输出确定).
        """
        if BG["cfg"]["status"] != "ready" or BG["pc_inst"]["status"] != "ready":
            _bg_run_combined()
            return {"status": "building",
                    "cfg": BG["cfg"]["status"], "pc_inst": BG["pc_inst"]["status"]}
        cache_key = fn or "<all>"
        cached = _CFG_SVG_CACHE.get(cache_key)
        if cached is not None:
            return {"status": "ready", "svg": cached["svg"], "fn": fn,
                    "block_count": cached["block_count"],
                    "total_block_count": cached["total_block_count"],
                    "cached": True}
        c = BG["cfg"]["data"]; pc_inst = BG["pc_inst"]["data"]
        m = t.meta.module
        base = m.base if m else 0

        included = []
        for pc, b in c.blocks.items():
            fname, foff = sym.lookup(pc)
            if fn and (fname or "") != fn: continue
            included.append((pc, b, fname))
        if not included:
            return {"status": "empty", "fn": fn, "svg": None}
        included_starts = {pc for pc, _, _ in included}

        # 循环检测: 每个 loop SCC 给一个不同的 border 颜色 (PDF p.10 风)
        # 用 HSL 色相轮; 单个 loop = 1 色相, 嵌套也按 SCC 各自分.
        loops = loop_sccs(c)
        loop_color: dict = {}
        for li, scc in enumerate(loops):
            # HSL hue rotation; 高饱和度低明度
            import colorsys
            h = (li * 0.137) % 1.0   # 黄金比 ratio for max distance
            rgb = colorsys.hls_to_rgb(h, 0.55, 0.65)
            hex_col = "#{:02x}{:02x}{:02x}".format(
                int(rgb[0]*255), int(rgb[1]*255), int(rgb[2]*255))
            for pc in scc:
                loop_color[pc] = hex_col

        # html_esc / build_label / format_insn_row 用模块顶层 _html_esc / _build_block_label / _format_insn_row

        # 探测每条 insn 是否是分支 (用来识别 block 末尾的 cond/uncond 性质)
        block_term_kind: dict = {}
        for pc, b, _ in included:
            if b.insns:
                last_pc = b.insns[-1]
                d = decode(last_pc, pc_inst.get(last_pc, 0))
                if d.is_branch:
                    block_term_kind[pc] = d.mnemonic
                else:
                    block_term_kind[pc] = None

        import io
        buf = io.StringIO()
        buf.write("digraph CFG {\n")
        buf.write('  graph [bgcolor="#0e1117", rankdir=TB, '
                  'fontname="JetBrainsMono,monospace", fontcolor="#d0d7de", '
                  'splines=ortho, nodesep=0.45, ranksep=0.55, pad=0.3];\n')
        buf.write('  node [shape=plaintext, fontname="JetBrainsMono,monospace", '
                  'fontsize=10];\n')
        buf.write('  edge [arrowsize=0.8, penwidth=1.4, '
                  'fontname="JetBrainsMono,monospace", fontsize=8, fontcolor="#6e7681"];\n')

        # 节点: HTML label, 每行 <TD HREF="#insn_<pc>">. CSS/JS 用 a[xlink|href$="<pc>"]
        # 选中改 class.
        for pc, b, fname in included:
            head_rel_str = f"+{(pc - base):x}" if base else f"{pc:x}"
            head_lbl = _html_esc(f"{head_rel_str}  ×{b.executions}")
            rows = []
            # Header 用浅灰色 — 不要用 #58a6ff (蓝, 同 cursor highlight 撞色, 用户分不清)
            rows.append(f'<TR><TD ALIGN="LEFT" BGCOLOR="#0e1117" '
                        f'HREF="#hdr_b{pc:x}" TITLE="block {pc:#x}">'
                        f'<FONT COLOR="#8b949e" POINT-SIZE="9">{head_lbl}</FONT></TD></TR>')
            for ins_pc in b.insns:
                inst = pc_inst.get(ins_pc, 0)
                d = decode(ins_pc, inst)
                rel_str = f"+{(ins_pc - base):x}" if base else f"{ins_pc:x}"
                ops = d.op_str
                if len(ops) > 50: ops = ops[:48] + ".."
                title = f"{ins_pc:#x}: {d.mnemonic} {d.op_str}"
                rows.append(_format_insn_row(rel_str, d.mnemonic, ops, ins_pc, title))
            ints = min(b.executions, 50) / 50
            # 优先 loop 色 — PDF p.10 "不同循环不同颜色"
            if pc in loop_color:
                br = loop_color[pc]
            else:
                br = "#30363d"
                if ints > 0.1:
                    r = int(0x30 + ints * 0x80); g = int(0x36 + ints * 0x60); bl = int(0x3d + ints * 0x10)
                    br = f"#{r:02x}{g:02x}{bl:02x}"
            label = _build_block_label(rows, br)
            buf.write(f'  "b{pc:x}" [label={label}, id="b{pc:x}"];\n')

        # edges: green=cond taken, red=cond not-taken (fall-through after b.cond/cbz/tbz),
        #        blue=uncond branch, magenta=ret, gray=natural fall, purple=call
        # 4 种 edge 处境:
        #  src∈fn ∧ dst∈fn         普通块间边 (b/br/fall/...)
        #  src∈fn ∧ dst∉fn         caller bl 调外部 → ext_out stub
        #  src∉fn ∧ dst∈fn         外部 call 返回到本 fn → ext_in stub (NEW)
        #  否则                    跳过
        for (s, d), v in c.edges.items():
            src_in = s in included_starts
            dst_in = d in included_starts
            if not src_in and not dst_in: continue
            if not src_in and dst_in:
                # external return into this fn — 用 ext_in 桩.
                # (典型: 当函数内某 BB 没在 trace 入口里出现, 但有外部 ret 进来时.)
                kind = v["kind"]; cnt = v["count"]
                ext_lbl = f"from +{(s-base):x}" if base else f"from {s:x}"
                buf.write(f'  "ext_in_{s:x}" [shape=ellipse, fontsize=9, '
                          f'style=filled, fillcolor="#1f2630", color="#bc8cff", '
                          f'fontcolor="#bc8cff", label="{ext_lbl}", '
                          f'id="ext_in_{s:x}"];\n')
                lbl = f'{kind} ×{cnt}' if cnt > 1 else kind
                buf.write(f'  "ext_in_{s:x}" -> "b{d:x}" [color="#bc8cff", '
                          f'label="{lbl}", style=dashed];\n')
                continue
            kind = v["kind"]; cnt = v["count"]
            term = block_term_kind.get(s)
            is_cond = bool(term) and (term.startswith("b.") or term in ("cbz", "cbnz", "tbz", "tbnz"))
            color = "#666666"; lblcol = None
            extra = ""
            if kind == "call-return":
                # PDF p.8 风: 调用返回边 (caller bl block → post-call block)
                # 紫色虚线, 与普通 bl 区分; 让 CFG 不被 callee 切断
                color = "#bc8cff"
                extra = ", style=dashed"
                lblcol = "#bc8cff"
            elif kind == "fall":
                # natural fallthrough into next block (no branch)
                color = "#444c56"
            elif is_cond:
                # block ends with conditional. Taken edge != src+4 → green.
                # Fall-through (dst == last+4) → red.
                last_pc = d  # dst
                src_block = c.blocks[s]
                last_in_src = src_block.insns[-1] if src_block.insns else 0
                if last_in_src and d == last_in_src + 4:
                    color = "#f85149"   # red = fall-through (cond false)
                    lblcol = "#f85149"
                else:
                    color = "#3fb950"   # green = taken (cond true)
                    lblcol = "#3fb950"
            elif kind == "ret":
                color = "#bc8cff"
            elif kind in ("bl", "blr"):
                color = "#bc8cff"
            else:
                color = "#58a6ff"   # uncond
            label_txt = f'{kind} ×{cnt}' if cnt > 1 else kind
            label_attr = f'label="{label_txt}"'
            if lblcol: label_attr += f', fontcolor="{lblcol}"'
            if d in included_starts:
                buf.write(f'  "b{s:x}" -> "b{d:x}" [color="{color}", {label_attr}{extra}];\n')
            else:
                ext_lbl = f"ext +{(d-base):x}" if base else f"ext {d:x}"
                buf.write(f'  "ext_{s:x}_{d:x}" [shape=ellipse, fontsize=9, '
                          f'style=filled, fillcolor="#1f2630", color="#6e7681", '
                          f'fontcolor="#6e7681", label="{ext_lbl}", '
                          f'id="ext_{s:x}_{d:x}"];\n')
                buf.write(f'  "b{s:x}" -> "ext_{s:x}_{d:x}" [color="{color}", {label_attr}{extra}];\n')
        buf.write("}\n")
        dot_text = buf.getvalue()

        svg, err = _render_dot_to_svg(dot_text, timeout=timeout)
        if err is not None:
            return {"status": "error", "err": err}

        result = {"svg": svg,
                  "block_count": len(included),
                  "total_block_count": len(c.blocks)}
        _CFG_SVG_CACHE[cache_key] = result
        return {"status": "ready", "fn": fn, **result}

    # backtrace lazy build: 一次扫 trace 找所有 bl/blr/ret 位置, 存 (idx, kind),
    # 之后 backtrace(idx) 只需在事件列表里 bisect + 重放
    BG.setdefault("frame_events", {"status": "idle", "data": None,
                                    "started_at": 0.0, "ready_at": 0.0, "err": None})
    def _build_frame_events():
        # numpy 一次拿整张 inst 表; 返回 dict{events, idxs_arr} 让 backtrace 端
        # 直接 np.searchsorted 而不重建 list (频繁 cursor 移动时 O(N) → O(log N)).
        import numpy as np
        from viewer.trace import REC_SIZE
        u32 = np.frombuffer(t._mm, dtype=np.uint32, count=t.n * (REC_SIZE // 4))
        inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]
        is_bl  = (inst_arr & np.uint32(0xFC000000)) == np.uint32(0x94000000)
        is_blr = (inst_arr & np.uint32(0xFFFFFC1F)) == np.uint32(0xD63F0000)
        is_ret = (inst_arr & np.uint32(0xFFFFFC1F)) == np.uint32(0xD65F0000)
        is_call = is_bl | is_blr
        call_idxs = np.nonzero(is_call)[0].astype(np.int64)
        ret_idxs = np.nonzero(is_ret)[0].astype(np.int64)
        # 合并 + 按 idx 排序 (用 numpy)
        all_idxs = np.concatenate([call_idxs, ret_idxs])
        all_kinds = np.concatenate([np.zeros(len(call_idxs), dtype=np.int8),
                                     np.ones(len(ret_idxs), dtype=np.int8)])
        order = np.argsort(all_idxs, kind="stable")
        sorted_idxs = all_idxs[order]
        sorted_kinds = all_kinds[order]
        return {"idxs": sorted_idxs, "kinds": sorted_kinds}

    @app.get("/api/backtrace", response_model=BacktraceResponse)
    def backtrace(idx: int):
        """call stack at trace idx. 用预计算的 bl/blr/ret 事件列表 bisect+重放,
        典型 < 100ms (之前每次 0→idx full scan 是 5+s).
        """
        n = len(t)
        if idx < 0 or idx >= n: raise HTTPException(404)
        st = BG["frame_events"]
        if st["status"] != "ready":
            _bg_run("frame_events", _build_frame_events)
            return {"status": st["status"], "stack": [], "depth": 0}
        import numpy as np
        data = st["data"]
        sorted_idxs = data["idxs"]; sorted_kinds = data["kinds"]
        cut = int(np.searchsorted(sorted_idxs, idx, side="right"))
        # 重放 events[:cut]
        stack = []
        pc_arr = t.pc_array()
        m = t.meta.module
        base = m.base if m else 0
        def _fmt(pc):
            if pc is None: return None
            if base and base <= pc < base + (m.size if m else 0):
                fn, foff = sym.lookup(pc)
                if fn and fn != "?":
                    return f"{fn}+{foff:#x}"
                return f"+{(pc - base):#x}"
            return hex(pc)
        for k in range(cut):
            ev_idx = int(sorted_idxs[k]); kind = int(sorted_kinds[k])
            if kind == 0:  # push (call)
                callee = int(pc_arr[ev_idx + 1]) if ev_idx + 1 < n else None
                fn = sym.lookup(callee)[0] if callee else None
                call_pc = int(pc_arr[ev_idx])
                stack.append({
                    "call_site_idx": ev_idx,
                    "call_pc": hex(call_pc),
                    "call_pc_fmt": _fmt(call_pc),
                    "callee_pc": hex(callee) if callee else None,
                    "callee_pc_fmt": _fmt(callee) if callee else None,
                    "fn": fn if fn != "?" else None,
                })
            else:  # pop (ret)
                if stack: stack.pop()
        return {"status": "ready", "idx": idx, "stack": stack, "depth": len(stack)}

    @app.get("/api/idxs-for-pc", response_model=IdxsForPcResponse)
    def idxs_for_pc(pc: str, cursor: int = 0, limit: int = 30):
        """numpy vector scan: pc_array() 是 mmap 上的 zero-copy uint64 视图.
        np.nonzero(pc_arr == target) ~5ms 跑完 2.5M (Python loop 是 320ms).
        不预存 dict (5GB+ 内存太大)."""
        import numpy as np, bisect
        target = int(pc, 16)
        n = len(t)
        cur = max(0, min(cursor, n))
        # 全量 indices where pc==target
        arr = t.pc_array()
        all_idxs = np.nonzero(arr == np.uint64(target))[0]
        cut = int(np.searchsorted(all_idxs, cur, side="left"))
        total_before = cut
        total_after = len(all_idxs) - cut
        # before: 离 cursor 最近的 limit 个 (即 idx 最大的 limit 个 < cursor)
        before = all_idxs[max(0, cut - limit):cut][::-1].tolist()
        after = all_idxs[cut:cut + limit].tolist()
        return {"status": "ready", "pc": pc, "cursor": cursor,
                "before": before, "after": after,
                "total_before": total_before,
                "total_after": total_after,
                "before_capped": total_before > limit,
                "after_capped": total_after > limit}

    @app.get("/api/idxs-for-block", response_model=IdxsForBlockResponse)
    def idxs_for_block(pc: str, max_count: int = 200, near: int = -1):
        """所有 trace 中 PC 落在该 block 内的 idx. 用预建 dict, O(1).
        near>=0 时, 优先返回离该 idx 最近的 max_count 个."""
        if BG["block_idxs"]["status"] != "ready":
            return {"status": BG["block_idxs"]["status"], "idxs": []}
        bi = BG["block_idxs"]["data"]
        start = int(pc, 16)
        if start not in bi: raise HTTPException(404)
        all_idxs = bi[start]
        truncated = False
        if near >= 0 and len(all_idxs) > max_count:
            sub = sorted(all_idxs, key=lambda i: abs(i - near))[:max_count]
            idxs = sorted(sub); truncated = True
        elif len(all_idxs) > max_count:
            idxs = all_idxs[:max_count]; truncated = True
        else:
            idxs = list(all_idxs)
        return {"block": hex(start), "idxs": idxs, "truncated": truncated, "total": len(all_idxs)}

    @app.get("/api/search", response_model=SearchResponse)
    def search(pattern: str, max_results: int = 200):
        """Regex 搜索指令 mnemonic+op_str. 简单线扫 + early-break, decode 有
        lru_cache 所以重复 PC 几乎零开销. 6.8M trace 上 ~10-200ms 取决于命中
        密度 (max_results 提前 break).
        """
        import re
        rx = re.compile(pattern, re.I)
        m = t.meta.module
        base = m.base if m else 0
        rows = []
        for i in range(len(t)):
            r = t.record(i); d = decode(r.pc, r.inst)
            if rx.search(f"{d.mnemonic} {d.op_str}"):
                fname, foff = sym.lookup(r.pc)
                rows.append({"idx": i, "pc": hex(r.pc),
                             "rel": hex(r.pc - base) if base else None,
                             "func": fname if fname != "?" else None,
                             "off": hex(foff) if fname != "?" else None,
                             "asm": f"{d.mnemonic} {d.op_str}"})
                if len(rows) >= max_results: break
        return {"count": len(rows), "pattern": pattern, "hits": rows}

    # 上限保护: 单 endpoint 一次最多构建 50k 行 — 超过 ~10MB JSON,
    # 防止 max_count=1M 触发 200MB+ 内存峰值.
    TAINT_MAX_COUNT_CEILING = 50000

    @app.get("/api/forward-taint", response_model=ForwardTaintResponse)
    def forward_taint_api(start: int, reg: str, max_count: int = 5000,
                          through_mem: bool = False, data_only: bool = False,
                          cross_fn_call: bool = False):
        from viewer.taint import forward_taint
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"status": BG["index"]["status"], "hits": []}
        eff = min(max(max_count, 0), TAINT_MAX_COUNT_CEILING)
        mem_obj = BG["mem"]["data"] if (through_mem and BG["mem"]["status"] == "ready") else None
        if through_mem and mem_obj is None:
            _bg_run("mem", _build_mem)
        # 用 index 做 bisect 加速 — O(|hits|·log N) vs 旧 O(N²)
        results, stopped = forward_taint(t, start, reg, max_count=eff,
                                index=BG["index"]["data"], return_status=True,
                                data_only=data_only,
                                through_mem=through_mem and mem_obj is not None,
                                mem=mem_obj, cross_fn_call=cross_fn_call)
        m = t.meta.module
        base = m.base if m else 0
        rows = []
        for entry in results:
            if cross_fn_call:
                i, why, fdepth = entry
            else:
                i, why = entry; fdepth = None
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            row = {"idx": i, "pc": hex(r.pc),
                   "rel": hex(r.pc - base) if base else None,
                   "func": fname if fname != "?" else None,
                   "asm": f"{d.mnemonic} {d.op_str}", "why": why}
            if fdepth is not None: row["frame_depth"] = fdepth
            rows.append(row)
        return {"count": len(rows), "from": start, "reg": reg, "hits": rows,
                "stopped_at_max": stopped, "max_count_used": eff}

    @app.get("/api/backward-taint", response_model=BackwardTaintResponse)
    def backward_taint_api(start: int, reg: str, max_count: int = 5000,
                           through_mem: bool = False, data_only: bool = False,
                           cross_fn_call: bool = False):
        from viewer.taint import backward_taint
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"status": BG["index"]["status"], "chain": []}
        eff = min(max(max_count, 0), TAINT_MAX_COUNT_CEILING)
        mem_obj = BG["mem"]["data"] if (through_mem and BG["mem"]["status"] == "ready") else None
        if through_mem and mem_obj is None:
            _bg_run("mem", _build_mem)
        results, stopped = backward_taint(t, start, reg, max_count=eff,
                                 index=BG["index"]["data"], return_status=True,
                                 data_only=data_only,
                                 through_mem=through_mem and mem_obj is not None,
                                 mem=mem_obj, cross_fn_call=cross_fn_call)
        m = t.meta.module
        base = m.base if m else 0
        rows = []
        for entry in results:
            if cross_fn_call:
                i, via, fdepth = entry
            else:
                i, via = entry; fdepth = None
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            row = {"idx": i, "pc": hex(r.pc),
                   "rel": hex(r.pc - base) if base else None,
                   "func": fname if fname != "?" else None,
                   "asm": f"{d.mnemonic} {d.op_str}", "via": via}
            if fdepth is not None: row["frame_depth"] = fdepth
            rows.append(row)
        return {"count": len(rows), "from": start, "reg": reg, "chain": rows,
                "stopped_at_max": stopped, "max_count_used": eff}

    @app.get("/api/strings", response_model=StringsResponse)
    def strings_api(min_len: int = 4, q: str = "", cursor: int = -1, limit: int = 0):
        """字符串列表. cursor>=0 时按 cursor 时刻的内存状态过滤
        (只显示在 cursor 时刻 已 written 的字节构成的字符串).
        limit=0 → 不限."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            st = BG["mem"]["status"]
            if st != "ready":
                return {"status": st, "strings": []}
        mem = BG["mem"]["data"]
        if cursor < 0:
            results = mem.find_strings(min_len=min_len)
        else:
            # 按 cursor 时刻过滤: 字符串的所有字节必须在 cursor 之前已被写入
            all_results = mem.find_strings(min_len=min_len)
            results = []
            for addr, s in all_results:
                ok = True
                for o in range(len(s)):
                    b, kind, src = mem.byte_at(addr + o, cursor)
                    if b is None or src is None or src > cursor:
                        ok = False; break
                if ok: results.append((addr, s))
        if q:
            ql = q.lower()
            results = [(a, s) for a, s in results if ql in s.lower()]
        if limit > 0:
            results = results[:limit]
        return {"status": "ready", "count": len(results), "cursor": cursor,
                "strings": [{"addr": hex(a), "len": len(s), "str": s} for a, s in results]}

    @app.get("/api/string-provenance", response_model=StringProvenanceResponse)
    def string_provenance(addr: str, length: int = 32):
        """对 [addr, addr+length) 区域, 列每个字节的 write idxs (谁构造) +
        read idxs (谁消费). 全 numpy: 不再 Python scatter 循环, 即使 hot buffer
        被写 100K 次也 ~ms 级."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            st = BG["mem"]["status"]
            if st != "ready":
                return {"status": st, "bytes": []}
        import numpy as np
        mem = BG["mem"]["data"]
        start = int(addr, 16); end = start + length
        # 一次性过滤: 只留与 [start, end) 真重叠的 ops (绝大多数被剔)
        w_mask = (mem.w_addr < np.uint64(end)) & ((mem.w_addr.astype(np.int64) + mem.w_size) > start)
        r_mask = (mem.r_addr < np.uint64(end)) & ((mem.r_addr.astype(np.int64) + mem.r_size) > start)
        w_a64 = mem.w_addr[w_mask].astype(np.int64); w_s = mem.w_size[w_mask]; w_i = mem.w_idx[w_mask]
        r_a64 = mem.r_addr[r_mask].astype(np.int64); r_s = mem.r_size[r_mask]; r_i = mem.r_idx[r_mask]
        w_end = w_a64 + w_s.astype(np.int64)
        r_end = r_a64 + r_s.astype(np.int64)
        WRITERS_CAP = 20

        out_bytes = []
        for offset in range(length):
            a = start + offset
            # ops covering byte a: addr <= a < addr+size — pure numpy mask, 无 Python 循环
            wh = (w_a64 <= a) & (a < w_end)
            rh = (r_a64 <= a) & (a < r_end)
            w_full = w_i[wh]; r_full = r_i[rh]
            byte_val = None; kind = "??"
            if mem.bytes:
                b, k, _ = mem.byte_at(a, 1 << 63)
                byte_val = b; kind = k
            out_bytes.append({
                "addr": hex(a), "byte": byte_val, "kind": kind,
                "writers": w_full[:WRITERS_CAP].tolist(),
                "readers": r_full[:WRITERS_CAP].tolist(),
                "writers_total": int(w_full.size),
                "readers_total": int(r_full.size),
            })
        return {"status": "ready", "addr": addr, "length": length, "bytes": out_bytes}

    @app.get("/api/mem-dump", response_model=MemDumpResponse)
    def mem_dump(addr: str, count: int = 256):
        """Hex dump from MemShadow at given address. ?? for unaccessed bytes."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "bytes": []}
        mem = BG["mem"]["data"]
        start = int(addr, 16)
        out = []
        for i in range(count):
            a = start + i
            b, kind, src_idx = mem.byte_at(a, 1<<63)   # latest
            out.append({"addr": hex(a), "byte": b, "kind": kind,
                        "src_idx": src_idx})
        return {"status": "ready", "addr": addr, "count": count, "bytes": out}

    @app.get("/api/last-write-of-reg", response_model=LastWriteResponse)
    def last_write_of_reg(cursor: int, reg: str):
        """返回 cursor 之前最近一次该 reg 被 def 的指令 idx.
        index.reg_defs bisect: O(log N) vs 旧 O(cursor) 线性扫.
        """
        canon = _norm_reg(reg)
        if canon is None:
            return {"status": "error", "err": f"unknown reg {reg}"}
        if canon == "ZERO":
            # xzr/wzr 不会被 def, 永远读 0
            return {"status": "ready", "idx": None, "value": "0x0"}
        reg = canon
        n = len(t)
        if cursor <= 0 or cursor > n: return {"status": "ready", "idx": None}
        cur_val = t.record(cursor).reg(reg) if cursor < n else None
        # 用 reg_defs index 找 cursor 之前最近的 def idx
        if BG["index"]["status"] == "ready":
            idx_obj = BG["index"]["data"]
            defs = idx_obj.reg_defs.get(reg, [])
            import bisect
            pos = bisect.bisect_left(defs, cursor) - 1
            if pos >= 0:
                def_idx = defs[pos]
                return {"status": "ready", "idx": def_idx,
                        "value": hex(cur_val) if cur_val is not None else None}
            return {"status": "ready", "idx": 0,
                    "value": hex(cur_val) if cur_val is not None else None}
        # fallback: index 没建好, 用旧线性扫
        _bg_run("index", _build_index)
        i = cursor - 1
        while i >= 0:
            v = t.record(i).reg(reg)
            if v != cur_val:
                return {"status": "ready", "idx": i + 1,
                        "value": hex(cur_val) if cur_val is not None else None}
            i -= 1
        return {"status": "ready", "idx": 0,
                "value": hex(cur_val) if cur_val is not None else None}

    @app.get("/api/reg-value-at", response_model=RegValueResponse)
    def reg_value_at(idx: int, reg: str):
        """读 idx 处 reg 的当前值 + classify 注释."""
        if idx < 0 or idx >= len(t): raise HTTPException(404)
        canon = _norm_reg(reg)
        if canon is None:
            return {"status": "error", "err": f"unknown reg {reg}"}
        if canon == "ZERO":
            return {"status": "ready", "idx": idx, "reg": reg,
                    "value": "0x0", "annotation": ""}
        r = t.record(idx)
        v = r.reg(canon)
        ann = ""
        if BG["mem"]["status"] == "ready":
            ann = _classify_reg_value(v, idx, sp=r.reg("sp"))
        return {"status": "ready", "idx": idx, "reg": canon,
                "value": hex(v), "annotation": ann}

    @app.get("/api/idxs-touching-range", response_model=TouchingRangeResponse)
    def idxs_touching_range(addr: str, size: int = 1, cursor: int = 0, limit: int = 50):
        """所有 trace idx 中读/写 [addr, addr+size) 的位置. 向量化版: 用 numpy
        mask 替代 set comprehension, 6.8M trace 上 596ms → ~5ms."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            st = BG["mem"]["status"]
            if st != "ready":
                return {"status": st, "writers_before": [], "writers_after": [],
                        "writers_total": 0, "readers_before": [], "readers_after": [],
                        "readers_total": 0}
        import numpy as np
        mem = BG["mem"]["data"]
        start = int(addr, 16); endaddr = start + size
        # vectorized: writes 已按 trace order, idx 列升序. mask 后保持升序.
        w_mask = (mem.w_addr < np.uint64(endaddr)) & ((mem.w_addr.astype(np.int64) + mem.w_size) > start)
        r_mask = (mem.r_addr < np.uint64(endaddr)) & ((mem.r_addr.astype(np.int64) + mem.r_size) > start)
        writers = mem.w_idx[w_mask]
        readers = mem.r_idx[r_mask]
        # cursor 邻域 split (writers/readers 已升序)
        wcut = int(np.searchsorted(writers, cursor))
        rcut = int(np.searchsorted(readers, cursor))
        wb = writers[max(0, wcut - limit):wcut][::-1].tolist()
        wa = writers[wcut:wcut + limit].tolist()
        rb = readers[max(0, rcut - limit):rcut][::-1].tolist()
        ra = readers[rcut:rcut + limit].tolist()
        return {"status": "ready", "addr": addr, "size": size, "cursor": cursor,
                "writers_before": wb, "writers_after": wa, "writers_total": int(len(writers)),
                "readers_before": rb, "readers_after": ra, "readers_total": int(len(readers))}

    @app.get("/api/idxs-touching-addr", response_model=TouchingAddrResponse)
    def idxs_touching_addr(addr: str, cursor: int = 0, limit: int = 30):
        """所有 trace idx 中触碰 (load/store) 该 addr 的位置. 向量化, 6.8M trace
        上 ~5ms vs 旧线扫数百 ms."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "before": [], "after": []}
        import numpy as np
        mem = BG["mem"]["data"]
        target = int(addr, 16)
        # vectorized: target ∈ [addr, addr+size)
        w_mask = (mem.w_addr <= np.uint64(target)) & ((mem.w_addr.astype(np.int64) + mem.w_size) > target)
        r_mask = (mem.r_addr <= np.uint64(target)) & ((mem.r_addr.astype(np.int64) + mem.r_size) > target)
        w_idxs = mem.w_idx[w_mask]
        r_idxs = mem.r_idx[r_mask]
        # 合并 + 标 kind, 按 idx sort. 用 numpy concat + argsort.
        if len(w_idxs) == 0 and len(r_idxs) == 0:
            return {"status": "ready", "addr": addr, "before": [], "after": [],
                    "total_before": 0, "total_after": 0}
        all_idxs = np.concatenate([w_idxs, r_idxs])
        all_kinds = np.concatenate([np.zeros(len(w_idxs), dtype=np.int8),
                                     np.ones(len(r_idxs), dtype=np.int8)])
        order = np.argsort(all_idxs, kind="stable")
        sorted_idxs = all_idxs[order]; sorted_kinds = all_kinds[order]
        cut = int(np.searchsorted(sorted_idxs, cursor))
        bef_i = sorted_idxs[max(0, cut-limit):cut][::-1].tolist()
        bef_k = sorted_kinds[max(0, cut-limit):cut][::-1].tolist()
        aft_i = sorted_idxs[cut:cut+limit].tolist()
        aft_k = sorted_kinds[cut:cut+limit].tolist()
        kind_str = lambda k: "w" if k == 0 else "r"
        before = [{"idx": int(i), "kind": kind_str(k)} for i, k in zip(bef_i, bef_k)]
        after  = [{"idx": int(i), "kind": kind_str(k)} for i, k in zip(aft_i, aft_k)]
        return {"status": "ready", "addr": addr, "cursor": cursor,
                "before": before, "after": after,
                "total_before": cut, "total_after": int(len(sorted_idxs) - cut)}

    @app.get("/api/bg-status", response_model=BgStatusResponse)
    def bg_status():
        """所有后台构建任务的状态. 前端用来显示 progress / 决定是否 retry."""
        out = {k: {sk: sv for sk, sv in s.items() if sk != "data"} for k, s in BG.items()}
        # decomp 也单独抛出来 (前端用)
        out["decomp"] = {k: v for k, v in DECOMP.items() if k != "backend"}
        return out

    # ---- decompiler endpoints (optional) ----
    def _tok(t):
        """Token → compact wire dict."""
        d = {"t": t.text, "c": t.cls}
        if t.addr: d["a"] = hex(t.addr)
        return d

    # Lazy cache: per BN function, the trace-derived exec stats.
    # key=fn.start (caller-coord) → {bb_counts, edges_seen, succ_map, fn_total}
    # FIFO cap 防止打开很多函数后 dict 无界增长 (每条 entry ~1-10KB).
    _CFG_OVERLAY_CACHE: "dict" = {}
    _CFG_OVERLAY_ORDER: "list" = []        # FIFO eviction order
    _CFG_OVERLAY_LOCK = threading.Lock()
    _CFG_OVERLAY_MAX = 256

    def _compute_cfg_overlay(fn_start: int, blocks, edges) -> dict:
        """Walk pc_array (zero-copy numpy view) once, fill bb hit counts +
        edges-seen set + per-BB-end successor-pc map. ~5-50ms per fn on 5M
        traces; cached. succ_map 也 cache 出去, dyn-only 检测 O(1) 复用."""
        with _CFG_OVERLAY_LOCK:
            hit = _CFG_OVERLAY_CACHE.get(fn_start)
            if hit is not None: return hit
        import numpy as np
        pcs = t.pc_array()
        # exec_count = BB 内所有指令的累计命中数 (instruction-level heat map).
        # 不用 pure BB-entry count 的原因: trace 可能从函数中段开始 (trace 起点
        # 落在 BB 内部, BB.start 一次都没出现), 导致有效 BB 也显示 0. 累计指令
        # 数对 trace 起点鲁棒, 视觉范围也更广.
        bb_counts = {b.start: int(((pcs >= b.start) & (pcs < b.end)).sum())
                     for b in blocks}
        # build successor-pc set for each src_last_pc (ARM64 fixed 4-byte insns)
        succ_map: dict[int, set] = {}
        for src_last in {b.end - 4 for b in blocks}:
            idx = np.flatnonzero(pcs == src_last)
            if idx.size == 0: continue
            nxt = pcs[idx[idx + 1 < len(pcs)] + 1]
            succ_map[src_last] = {int(x) for x in nxt.tolist()}
        # static edges 跟 succ_map 求交 = 见过的 edges
        bb_by_start = {b.start: b for b in blocks}
        edges_seen = {
            (e.src, e.dst) for e in edges
            if (b := bb_by_start.get(e.src)) and e.dst in succ_map.get(b.end - 4, ())
        }
        out = {
            "bb_counts":  bb_counts,
            "edges_seen": edges_seen,
            "succ_map":   succ_map,
            "fn_total":   sum(bb_counts.values()),
        }
        with _CFG_OVERLAY_LOCK:
            _CFG_OVERLAY_CACHE[fn_start] = out
            _CFG_OVERLAY_ORDER.append(fn_start)
            while len(_CFG_OVERLAY_ORDER) > _CFG_OVERLAY_MAX:
                victim = _CFG_OVERLAY_ORDER.pop(0)
                _CFG_OVERLAY_CACHE.pop(victim, None)
        return out

    @app.get("/api/decomp-status", response_model=DecompStatusResponse)
    def decomp_status():
        """前端 polling: 反编译后端是否 ready."""
        out = {k: v for k, v in DECOMP.items() if k != "backend"}
        if DECOMP["started_at"]:
            ref = DECOMP["ready_at"] if DECOMP["status"] == "ready" else time.time()
            out["elapsed"] = ref - DECOMP["started_at"]
        return out

    @app.get("/api/asm-tokens-for-pcs", response_model=AsmTokensResponse)
    def asm_tokens_for_pcs(pcs: str):
        """Batch query: for a list of trace PCs (comma-separated hex), return the
        BN-tokenized ASM for each (so trace stream rows can render BN-grade syntax
        highlighting instead of capstone's plain string).

        Param:
            pcs: "0x6d52ed1770,0x6d52ed1774,..." (no spaces). Limit ~256 per call.

        Returns:
            {ready: bool, status: 'ok'|'loading'|...,
             tokens: { "0x...": [{text, cls, addr}, ...], ... }}
            Missing PCs (not in any BN-known fn) are simply absent from `tokens`.
        """
        if DECOMP["status"] != "ready":
            return {"ready": False, "status": DECOMP["status"], "tokens": {}}
        bk = DECOMP["backend"]
        out: dict[str, list[dict]] = {}
        seen: set[int] = set()
        for raw in pcs.split(","):
            s = raw.strip()
            if not s: continue
            try:
                pc = int(s, 16) if s.startswith("0x") else int(s)
            except ValueError:
                continue
            if pc in seen: continue
            seen.add(pc)
            tks = bk.asm_tokens_at(pc)
            if not tks: continue
            out[hex(pc)] = [_tok(tk) for tk in tks]
            if len(seen) >= 512: break  # safety cap
        return {"ready": True, "status": "ok", "tokens": out}

    # ─────────── Gap fixes: data-chase / last-write-of-addr / etc ───────────

    @app.get("/api/data-chase", response_model=DataChaseResponse)
    def api_data_chase(start: int, reg: str, max_steps: int = 50,
                       exclude_regs: str = "sp,fp,lr"):
        """Single-path data chase, skipping sp/fp/lr noise. Gap-F."""
        from viewer.taint import data_chase
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"from": start, "reg": reg, "count": 0, "steps": []}
        excl = {x.strip() for x in exclude_regs.split(",") if x.strip()}
        steps = data_chase(t, start, reg, max_steps=max_steps,
                           exclude_regs=excl, index=BG["index"]["data"])
        m_ = t.meta.module
        base_ = m_.base if m_ else 0
        out = []
        for s in steps:
            fn, _ = sym.lookup(s.pc)
            out.append({
                "idx": s.idx, "pc": hex(s.pc),
                "rel": hex(s.pc - base_) if base_ else None,
                "func": fn if fn != "?" else None,
                "asm": s.asm, "via": s.via, "src": s.reg_or_addr,
            })
        return {"from": start, "reg": reg, "count": len(out), "steps": out}

    @app.get("/api/last-write-of-addr", response_model=LastWriteOfAddrResponse)
    def api_last_write_of_addr(addr: str, before_idx: int = -1):
        """Find most recent mem write to addr before given idx. Gap-B."""
        import bisect
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"status": "not-found", "addr": addr,
                    "before_idx": before_idx, "writes_total": 0}
        idx_obj = BG["index"]["data"]
        try:
            addr_int = int(addr, 16) if addr.startswith("0x") else int(addr)
        except ValueError:
            raise HTTPException(400, f"bad addr: {addr!r}")
        before = before_idx if before_idx >= 0 else len(t)
        writes = idx_obj.mem_addr_to_writes.get(addr_int, [])
        pos = bisect.bisect_left(writes, before) - 1
        if pos < 0:
            return {"status": "not-found", "addr": addr,
                    "before_idx": before, "writes_total": len(writes)}
        w_idx = writes[pos]
        rw = t.record(w_idx); dw = decode(rw.pc, rw.inst)
        fn, _ = sym.lookup(rw.pc)
        m_ = t.meta.module
        base_ = m_.base if m_ else 0
        base_w = dw.mem_op[0][0] if dw.mem_op else None
        idx_w = dw.mem_op[0][1] if dw.mem_op else None
        src_candidates = [u for u in dw.regs_use if u not in (base_w, idx_w)]
        src = src_candidates[0] if src_candidates else None
        return {
            "status": "found", "addr": addr, "before_idx": before,
            "writer_idx": w_idx, "writer_pc": hex(rw.pc),
            "rel": hex(rw.pc - base_) if base_ else None,
            "func": fn if fn != "?" else None,
            "asm": f"{dw.mnemonic} {dw.op_str}",
            "src_reg": src,
            "src_value": hex(rw.reg(src)) if src else None,
            "writes_before": pos + 1, "writes_after": len(writes) - pos - 1,
        }

    @app.get("/api/find-mem-pattern", response_model=FindMemPatternResponse)
    def api_find_mem_pattern(bytes_hex: str, since: int = -1, max: int = 100,
                             idx_lo: Optional[int] = None,
                             idx_hi: Optional[int] = None):
        """Search MemShadow for hex byte pattern. Gap-H.

        Query param `bytes_hex` (FastAPI doesn't allow `bytes` as param name).
        idx_lo / idx_hi: filter hits by first_idx ∈ [idx_lo, idx_hi)."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"pattern": bytes_hex, "since_idx": since, "count": 0, "hits": []}
        mem_obj = BG["mem"]["data"]
        ph = bytes_hex.replace(" ", "").replace("0x", "")
        try:
            pat = bytes.fromhex(ph)
        except ValueError:
            raise HTTPException(400, f"bad hex: {bytes_hex!r}")
        cursor = since if since >= 0 else (1 << 63)
        if not mem_obj.bytes:
            return {"pattern": pat.hex(), "since_idx": since, "count": 0, "hits": []}
        addrs = sorted(mem_obj.bytes.keys())
        hits = []
        for a in addrs:
            match = True; first_idx = None
            for o, want in enumerate(pat):
                ev_list = mem_obj.bytes.get(a + o)
                if not ev_list: match = False; break
                ev_idx, byte_val = None, None
                for ev in ev_list:
                    if ev[0] > cursor: break
                    ev_idx, byte_val = ev[0], ev[1]
                if byte_val is None or byte_val != want:
                    match = False; break
                if first_idx is None or (ev_idx is not None and ev_idx < first_idx):
                    first_idx = ev_idx
            if match:
                if idx_lo is not None and (first_idx is None or first_idx < idx_lo):
                    continue
                if idx_hi is not None and (first_idx is None or first_idx >= idx_hi):
                    continue
                hits.append({"addr": hex(a), "first_idx": first_idx})
                if max > 0 and len(hits) >= max: break
        return {"pattern": pat.hex(), "since_idx": since,
                "count": len(hits), "hits": hits}

    @app.get("/api/jni-calls", response_model=JniCallsResponse)
    def api_jni_calls(in_fn: Optional[str] = None, max: int = 200):
        """Detect JNI vtable calls. Gap-J. Uses viewer/jni_offsets.json."""
        import pathlib, json as _json
        offsets_path = (pathlib.Path(__file__).resolve().parent.parent
                         / "viewer" / "jni_offsets.json")
        if not offsets_path.exists():
            return {"in_fn": in_fn, "count": 0, "hits": [], "vtable_size": 0}
        offsets_data = _json.loads(offsets_path.read_text())
        raw = offsets_data.get("offsets", offsets_data)
        jni_vtable = {int(k, 16) if isinstance(k, str) else int(k): v
                       for k, v in raw.items()}
        m_ = t.meta.module
        base_ = m_.base if m_ else 0
        n = len(t); hits = []
        prev_d = None
        for i in range(n):
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, _ = sym.lookup(r.pc)
            if in_fn and fname != in_fn:
                prev_d = d; continue
            if d.mnemonic == "blr" and d.indirect_branch_reg and prev_d is not None:
                target_reg = d.indirect_branch_reg
                if (prev_d.mnemonic == "ldr" and target_reg in prev_d.regs_def
                        and prev_d.mem_op):
                    base_reg, _, disp, _, is_w, _src = prev_d.mem_op[0]
                    if not is_w and disp in jni_vtable:
                        hits.append({
                            "idx": i, "pc": hex(r.pc),
                            "rel": hex(r.pc - base_) if base_ else None,
                            "func": fname if fname != "?" else None,
                            "jni_fn": jni_vtable[disp],
                            "vtable_offset": hex(disp),
                            "args": {a: hex(r.reg(a)) for a in
                                      ("x0", "x1", "x2", "x3", "x4")},
                        })
                        if max > 0 and len(hits) >= max:
                            prev_d = d; break
            prev_d = d
        return {"in_fn": in_fn, "count": len(hits), "hits": hits,
                "vtable_size": len(jni_vtable)}

    def _load_vtable_for_endpoint():
        """Internal helper: load vtable JSON, used by jobj-history / jni-strings."""
        import pathlib, json as _json
        offsets_path = (pathlib.Path(__file__).resolve().parent.parent
                         / "viewer" / "jni_offsets.json")
        if not offsets_path.exists(): return {}
        offsets_data = _json.loads(offsets_path.read_text())
        raw = offsets_data.get("offsets", offsets_data)
        return {int(k, 16) if isinstance(k, str) else int(k): v
                 for k, v in raw.items()}

    def _scan_jni_calls_in_range(start_idx, end_idx):
        """Yield (i, r, d, prev_d, jni_fn_name, vtbl_off, fname) for JNI calls
        in [start_idx, end_idx). Used by jobj-history / jni-strings endpoints.
        """
        jni_vtable = _load_vtable_for_endpoint()
        if not jni_vtable: return
        n = len(t)
        end = n if end_idx < 0 else min(end_idx, n)
        prev_d = None
        for i in range(0, end):
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, _ = sym.lookup(r.pc)
            if i >= start_idx and d.mnemonic == "blr" and d.indirect_branch_reg \
                    and prev_d is not None:
                target_reg = d.indirect_branch_reg
                if (prev_d.mnemonic == "ldr" and target_reg in prev_d.regs_def
                        and prev_d.mem_op):
                    base_reg, _, disp, _, is_w, _src = prev_d.mem_op[0]
                    if not is_w and disp in jni_vtable:
                        yield (i, r, d, prev_d, jni_vtable[disp], disp, fname)
            prev_d = d

    @app.get("/api/jobj-history", response_model=JobjHistoryResponse)
    def api_jobj_history(jobject: str, start: int = 0, end: int = -1,
                         max: int = 200):
        """Track a jobject through trace — find all JNI calls touching it. Gap-K."""
        try:
            target = int(jobject, 16) if jobject.startswith("0x") else int(jobject)
        except ValueError:
            raise HTTPException(400, f"bad jobject: {jobject!r}")
        m_ = t.meta.module
        base_ = m_.base if m_ else 0
        end_real = end if end >= 0 else len(t)
        hits = []
        for tup in _scan_jni_calls_in_range(start, end_real):
            i, r, d, prev_d, jni_fn, vtbl_off, fname = tup
            match_arg = None
            for arg in ("x1", "x2", "x3", "x4"):
                if r.reg(arg) == target:
                    match_arg = arg; break
            if match_arg is None: continue
            hits.append({
                "idx": i, "pc": hex(r.pc),
                "rel": hex(r.pc - base_) if base_ else None,
                "func": fname if fname != "?" else None,
                "jni_fn": jni_fn,
                "vtable_offset": hex(vtbl_off),
                "match_arg": match_arg,
                "args": {a: hex(r.reg(a)) for a in ("x1", "x2", "x3", "x4")},
            })
            if max > 0 and len(hits) >= max: break
        return {"jobject": hex(target), "start": start, "end": end_real,
                "count": len(hits), "hits": hits}

    # Same _JNI_STRING_OPS as CLI (kept in sync — single source would be
    # viewer/jni_string_ops.py but it's tiny enough to inline here).
    _JNI_STRING_OPS_SRV = {
        "NewString": ("x1", "out_x0"),
        "NewStringUTF": ("x1", "out_x0"),
        "GetStringChars": ("x1", "out_x0"),
        "GetStringUTFChars": ("x1", "out_x0"),
        "ReleaseStringChars": ("x2", "in"),
        "ReleaseStringUTFChars": ("x2", "in"),
        "GetStringRegion": ("x4", "out_x4"),
        "GetStringUTFRegion": ("x4", "out_x4"),
        "GetStringLength": ("x1", "in"),
        "GetStringUTFLength": ("x1", "in"),
        "GetStringCritical": ("x1", "out_x0"),
        "ReleaseStringCritical": ("x2", "in"),
    }

    @app.get("/api/jni-strings", response_model=JniStringsResponse)
    def api_jni_strings(max: int = 200, max_len: int = 128):
        """All JNI string operations + buffer content from MemShadow. Gap-L.
        Buffer content '(not observed)' for Stalker-excluded ranges (libart heap).
        """
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"count": 0, "with_observed_string": 0,
                    "without_observed_string": 0,
                    "note": "MemShadow building", "hits": []}
        mem_obj = BG["mem"]["data"]
        m_ = t.meta.module
        base_ = m_.base if m_ else 0

        def read_str(addr, cursor):
            if not addr: return None, 0
            out_b = bytearray(); seen = 0
            for o in range(max_len):
                b, _, _ = mem_obj.byte_at(addr + o, cursor)
                if b is None:
                    if seen == 0: return None, 0
                    break
                seen += 1
                if b == 0: break
                out_b.append(b)
            try: return out_b.decode("utf-8", errors="replace") or None, seen
            except Exception: return None, seen

        hits = []
        for tup in _scan_jni_calls_in_range(0, len(t)):
            i, r, d, prev_d, jni_fn, vtbl_off, fname = tup
            if jni_fn not in _JNI_STRING_OPS_SRV: continue
            arg_name, direction = _JNI_STRING_OPS_SRV[jni_fn]
            rec = {
                "idx": i, "pc": hex(r.pc),
                "rel": hex(r.pc - base_) if base_ else None,
                "func": fname if fname != "?" else None,
                "jni_fn": jni_fn, "arg_name": arg_name, "direction": direction,
                "x1": hex(r.reg("x1")), "x2": hex(r.reg("x2")),
            }
            buf_addr = None
            if direction == "out_x0" and i + 1 < len(t):
                buf_addr = t.record(i + 1).reg("x0"); cursor = i + 1
            elif direction == "out_x4":
                buf_addr = r.reg("x4"); cursor = i
            elif direction == "in":
                buf_addr = r.reg(arg_name); cursor = i
            else:
                cursor = i
            if buf_addr is not None:
                rec["buffer_addr"] = hex(buf_addr)
                s, seen = read_str(buf_addr, cursor)
                rec["observed_bytes"] = seen
                rec["string"] = s
            hits.append(rec)
            if max > 0 and len(hits) >= max: break
        with_str = sum(1 for h in hits if h.get("string"))
        return {
            "count": len(hits),
            "with_observed_string": with_str,
            "without_observed_string": len(hits) - with_str,
            "note": ("buffers in libart heap are Stalker-excluded; "
                      "agent-side hook on GetStringUTFChars needed for content"),
            "hits": hits,
        }

    @app.get("/api/field-at", response_model=FieldAtResponse)
    def api_field_at(pc: str, reg: str, offset: str = "0"):
        """BN HLIL 结构体字段语义查询.
        eg. ldr x9, [x8, 0x80] → query (pc, x8, 0x80) → [pthread_mutex_t.__lock]
        offset 接受 dec ("128") 或 hex ("0x80")。
        """
        try:
            off_int = int(offset, 16) if str(offset).lower().startswith("0x") else int(offset)
        except (ValueError, TypeError):
            off_int = 0
        out = {"pc": pc, "reg": reg, "offset": off_int, "hit": False,
               "struct": None, "field": None, "type_name": None}
        if DECOMP["status"] != "ready":
            return out
        bk = DECOMP["backend"]
        try:
            pc_int = int(pc, 16) if pc.startswith("0x") else int(pc)
        except ValueError:
            return out
        try:
            hint = bk.field_at(pc_int, reg, off_int)
        except Exception as e:
            log.debug("field_at(%s, %s, %s) raised: %s", pc, reg, offset, e)
            return out
        if hint is None:
            return out
        return {"pc": pc, "reg": reg, "offset": off_int, "hit": True,
                "struct": hint.struct or None,
                "field": hint.field or None,
                "type_name": hint.type_name or None}

    # ─────────────── 5.4 LLM-friendly higher-level queries ───────────────

    @app.get("/api/reg-timeline", response_model=RegTimelineResponse)
    def api_reg_timeline(reg: str, start: int = 0, end: int = -1, max_points: int = 1000):
        """All distinct values of `reg` across [start, end). Returns the first
        idx for each new value (changes only, not every record). Vectorized.
        """
        import numpy as np
        canon = _norm_reg(reg)
        if canon is None or canon == "ZERO":
            raise HTTPException(400, f"unknown reg: {reg!r}")
        reg = canon
        n = len(t)
        if end < 0 or end > n: end = n
        start = max(0, min(start, end))
        # Build reg-value column on demand. For ALL_REGS minus pc/sp/nzcv use
        # the regs[31] tuple at offset 0x008 inside record. We use Record API
        # for correctness over speed; window is bounded by max_points.
        out = []
        prev = object()    # sentinel
        truncated = False
        for i in range(start, end):
            v = t.record(i).reg(reg)
            if v != prev:
                if len(out) >= max_points:
                    # 已满, 但又见到新 distinct 值 → 真截断
                    truncated = True
                    break
                out.append({"idx": i, "value": hex(v)})
                prev = v
        return {"reg": reg, "start": start, "end": end,
                "count": len(out), "points": out, "truncated": truncated}

    @app.get("/api/mem-diff", response_model=MemDiffResponse)
    def api_mem_diff(idx: int, addr: str, size: int = 16):
        """Memory state at idx-1 vs idx for [addr, addr+size). Useful for
        seeing what a single store wrote (or what an insn observed)."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            # mem may not be ready instantly — caller can retry. Return empty.
            return {"idx": idx, "addr": addr, "size": size, "bytes": [],
                    "changed_count": 0}
        mem = BG["mem"]["data"]
        start = int(addr, 16) if addr.startswith("0x") else int(addr)
        before_t = max(0, idx - 1)
        after_t = idx
        out = []
        changed = 0
        for o in range(size):
            a = start + o
            b_before, _, _ = mem.byte_at(a, before_t)
            b_after, _, _ = mem.byte_at(a, after_t)
            ch = (b_before != b_after)
            if ch: changed += 1
            out.append({"addr": hex(a), "before": b_before,
                        "after": b_after, "changed": ch})
        return {"idx": idx, "addr": addr, "size": size,
                "bytes": out, "changed_count": changed}

    @app.get("/api/fn-summary", response_model=FnSummaryResponse)
    def api_fn_summary(fn: str, top_blocks: int = 5):
        """One-call function overview for LLM agents: entry pc, block count,
        total executions, hot blocks, callees seen in trace."""
        if BG["cfg"]["status"] != "ready":
            return {"status": BG["cfg"]["status"]}
        c = BG["cfg"]["data"]
        m = t.meta.module
        base = m.base if m else 0
        # Find blocks belonging to this fn
        fn_blocks = []
        entry_pc = None
        for pc, b in c.blocks.items():
            fname, _ = sym.lookup(pc)
            if fname == fn:
                fn_blocks.append(b)
                if entry_pc is None or pc < entry_pc:
                    entry_pc = pc
        if not fn_blocks:
            return {"status": "not-found", "fn": fn}
        total_exec = sum(b.executions for b in fn_blocks)
        # Entry idxs: trace positions where entry_pc was hit
        import numpy as np
        arr = t.pc_array()
        entry_idxs_all = np.nonzero(arr == np.uint64(entry_pc))[0]
        entry_idxs = entry_idxs_all[:50].tolist()
        # Hot blocks
        hot = sorted(fn_blocks, key=lambda b: -b.executions)[:top_blocks]
        hot_out = [{"pc": hex(b.start_pc),
                    "rel": hex(b.start_pc - base) if base else None,
                    "insns": len(b.insns), "executions": b.executions}
                   for b in hot]
        # Callees: walk fn blocks, find call edges (kind in 'bl', 'blr')
        # via cfg.edges + sym.lookup for the dst's func name
        callee_pcs: dict[int, int] = {}
        fn_starts = {b.start_pc for b in fn_blocks}
        for (s, d), info in c.edges.items():
            if s in fn_starts and info["kind"] in ("bl", "blr"):
                callee_pcs[d] = callee_pcs.get(d, 0) + info["count"]
        callees = []
        for cpc, cnt in sorted(callee_pcs.items(), key=lambda x: -x[1])[:20]:
            cfn, _ = sym.lookup(cpc)
            callees.append({"pc": hex(cpc),
                            "func": cfn if cfn != "?" else None,
                            "count": cnt})
        return {
            "status": "ready", "fn": fn,
            "pc": hex(entry_pc), "rel": hex(entry_pc - base) if base else None,
            "block_count": len(fn_blocks),
            "total_executions": total_exec,
            "entry_idxs": entry_idxs,
            "entry_idxs_total": int(len(entry_idxs_all)),
            "hot_blocks": hot_out,
            "callees": callees,
        }

    @app.get("/api/hlil-for-pc", response_model=HlilResponse)
    def hlil_for_pc(pc: str):
        """给定 trace 里一个 PC, 返回所属函数的 HLIL + 当前 PC 在哪一行.

        Returns:
            {ready, status,
             fn: {name, start, end, vars: [...]},
             lines: [{pc, text}, ...],
             current_line_idx: int (-1 if no exact match)}
        """
        if DECOMP["status"] != "ready":
            return {"ready": False, "status": DECOMP["status"],
                    "err": DECOMP["err"],
                    "elapsed": (time.time() - DECOMP["started_at"]) if DECOMP["started_at"] else 0}
        bk = DECOMP["backend"]
        try:
            pc_i = int(pc, 16) if pc.startswith("0x") else int(pc)
        except ValueError:
            raise HTTPException(400, f"bad pc: {pc!r}")

        fn = bk.function_at(pc_i)
        if fn is None:
            return {"ready": True, "status": "no-function", "pc": hex(pc_i)}

        # 标记 PC 是否真的落在 BN 识别的 fn 范围内 (False = nearest fallback)
        in_range = fn.start <= pc_i < fn.end
        # trace 侧用 sym 推断的函数名 (跟左侧 disasm 显示的一致)
        trace_fname, trace_foff = sym.lookup(pc_i)
        lines = bk.hlil_for(fn)
        # 当前 PC 对应的行: 精确匹配 → 否则 pc<=line的最近一行 (典型情况) →
        # 否则 line>pc 中最近的 (PC 在 prologue, HLIL 已合并到 entry-after-prologue)
        cur_idx = -1
        best_le = -1
        first_gt = -1
        for i, l in enumerate(lines):
            if l.pc_lo == pc_i:
                cur_idx = i; break
            if l.pc_lo <= pc_i and l.pc_lo > best_le:
                best_le = l.pc_lo; cur_idx = i
            elif l.pc_lo > pc_i and first_gt < 0:
                first_gt = i
        if cur_idx == -1 and first_gt >= 0:
            cur_idx = first_gt

        vars_ = bk.vars_for(fn)
        return {
            "ready": True, "status": "ok",
            "backend": bk.name,
            "pc": hex(pc_i),
            "in_range": in_range,
            "fn": {"name": fn.name, "start": hex(fn.start), "end": hex(fn.end)},
            "trace_fn": {"name": trace_fname, "off": hex(trace_foff)} if trace_fname and trace_fname != "?" else None,
            "vars": [{"name": v.name, "type": v.type_name, "storage": v.storage}
                     for v in vars_[:20]],
            "lines": [{
                "pc": hex(l.pc_lo),
                "text": l.text,
                "indent": l.indent,
                "tokens": [_tok(tk) for tk in l.tokens] if l.tokens else None,
            } for l in lines],
            "current_line_idx": cur_idx,
        }

    @app.get("/api/bn-cfg-svg-for-pc", response_model=BnCfgSvgResponse)
    def bn_cfg_svg_for_pc(pc: str, mode: str = "asm", timeout: int = 30):
        """SVG-rendered BN CFG with trace overlay coloring.

        BB 染色:
          - 执行 0 次 = 灰 (静态可达, trace 没走过)
          - 执行 1 次 = 浅蓝
          - 执行 2-9 次 = 蓝
          - 执行 10-99 = 绿
          - 执行 100-999 = 黄
          - 执行 1000+ = 红 + 发光
          - 当前 cursor BB = 加粗紫边

        Edge 染色:
          - both static + dynamic = 蓝实线
          - static-only (trace 没走过) = 灰虚线
          - dynamic-only = 红粗线 (BN 没标但 trace 真走了; OLLVM 间接跳常见)
        """
        if DECOMP["status"] != "ready":
            return {"status": DECOMP["status"]}
        bk = DECOMP["backend"]
        try:
            pc_i = int(pc, 16) if pc.startswith("0x") else int(pc)
        except ValueError:
            raise HTTPException(400, f"bad pc: {pc!r}")
        fn = bk.function_at(pc_i)
        if fn is None: return {"status": "no-function"}
        blocks, edges = bk.cfg_for(fn, mode=mode)
        if not blocks: return {"status": "empty-cfg"}
        # 巨型 OLLVM dispatcher 一打开就 5K+ BBs, dot 几十秒不出结果, 浏览器也卡.
        # 直接拒绝并让用户在前端看到清晰原因 (trace CFG 仍能用).
        BB_HARD_CAP = 800
        if len(blocks) > BB_HARD_CAP:
            return {"status": "too-large",
                    "fn": {"name": fn.name, "start": hex(fn.start), "end": hex(fn.end)},
                    "block_count": len(blocks), "edge_count": len(edges),
                    "err": f"BN reports {len(blocks)} basic blocks (cap={BB_HARD_CAP}); "
                           f"likely an OLLVM-flattened dispatcher. Use trace CFG instead."}
        ovr = _compute_cfg_overlay(fn.start, blocks, edges)

        # dynamic-only edges: 复用 ovr["succ_map"] (而不是再扫一遍 pc_array).
        # static edges 是 (src, dst); dynamic-only = succ_map 里 src→dst 但 BN 没标的.
        bn_edge_set = {(e.src, e.dst) for e in edges}
        bb_starts = {b.start for b in blocks}
        succ_map = ovr["succ_map"]
        dyn_only = []
        for b in blocks:
            for nxt in succ_map.get(b.end - 4, ()):
                if nxt in bb_starts and (b.start, nxt) not in bn_edge_set:
                    dyn_only.append((b.start, nxt))

        # ---- 构建 dot text (用模块顶层 _build_block_label / _format_insn_row helpers) ----
        cur_bb_start = next((b.start for b in blocks if b.start <= pc_i < b.end), None)
        m_base = t.meta.module.base if t.meta.module else 0

        out = ['digraph BN_CFG {',
               '  graph [bgcolor="#0e1117", rankdir=TB, '
               'fontname="JetBrainsMono,monospace", fontcolor="#d0d7de", '
               'splines=ortho, nodesep=0.45, ranksep=0.55, pad=0.3];',
               '  node [shape=plaintext, fontname="JetBrainsMono,monospace", fontsize=10];',
               '  edge [arrowsize=0.8, penwidth=1.4, '
               'fontname="JetBrainsMono,monospace", fontsize=8, fontcolor="#6e7681"];']
        for b in blocks:
            n = ovr["bb_counts"].get(b.start, 0)
            head_off = f"+{b.start - m_base:x}" if m_base else f"{b.start:x}"
            head_lbl = _html_esc(f"{head_off}  ×{n}")
            br = _bn_bb_border_color(n, is_current=(b.start == cur_bb_start))
            rows = [f'<TR><TD ALIGN="LEFT" BGCOLOR="#0e1117" '
                    f'HREF="#hdr_b{b.start:x}" TITLE="block {b.start:#x} (BN)">'
                    f'<FONT COLOR="#8b949e" POINT-SIZE="9">{head_lbl}</FONT></TD></TR>']
            for ln in b.lines:
                # 用 BN token 精准分 mnem/ops; fallback 字符串切分
                mnem_tk, ops_str = _split_mnem_ops_from_tokens(ln)
                rel_str = f"+{(ln.pc_lo - m_base):x}" if m_base else f"{ln.pc_lo:x}"
                title = f"{ln.pc_lo:#x}: {mnem_tk} {ops_str}".rstrip()
                rows.append(_format_insn_row(rel_str, mnem_tk, ops_str, ln.pc_lo, title,
                                             tokens=ln.tokens))
            out.append(f'  "b{b.start:x}" [label={_build_block_label(rows, br)}, id="b{b.start:x}"];')

        for e in edges:
            color, style = _BN_EDGE_KIND_COLOR.get(e.kind, ("#666666", None))
            seen = (e.src, e.dst) in ovr["edges_seen"]
            attrs = [f'color="{color}"', f'label="{e.kind}"']
            if not seen:
                attrs += ['style=dashed', 'penwidth=0.8']
            else:
                attrs.append('penwidth=1.6')
                if style: attrs.append(f'style={style}')
            out.append(f'  "b{e.src:x}" -> "b{e.dst:x}" [{", ".join(attrs)}];')
        # dynamic-only: trace 真走但 BN 没标 (OLLVM 间接跳真 target)
        for src, dst in dyn_only:
            out.append(f'  "b{src:x}" -> "b{dst:x}" '
                       f'[color="#f85149", penwidth=2.4, label="dyn-only", '
                       f'fontcolor="#f85149"];')
        out.append("}")
        dot_text = "\n".join(out)

        svg, err = _render_dot_to_svg(dot_text, timeout=timeout)
        if err is not None:
            return {"status": "error", "err": err}
        return {
            "status": "ok",
            "fn": {"name": fn.name, "start": hex(fn.start), "end": hex(fn.end)},
            "block_count": len(blocks),
            "total_block_count": len(blocks),     # for embedCfgSvg compat
            "edge_count": len(edges),
            "dyn_only_count": len(dyn_only),
            "fn_total_exec": ovr["fn_total"],
            "current_bb": hex(cur_bb_start) if cur_bb_start else None,
            "svg": svg,
        }

    @app.get("/api/bn-cfg-for-pc", response_model=BnCfgForPcResponse)
    def bn_cfg_for_pc(pc: str, mode: str = "asm"):
        """BN-derived CFG for the function containing pc, with trace overlay.

        Returns:
            {ready, fn, blocks: [{start, end, exec_count, lines: [{pc, tokens, text}]}],
             edges: [{src, dst, kind, seen_in_trace}]}
        """
        if DECOMP["status"] != "ready":
            return {"ready": False, "status": DECOMP["status"]}
        bk = DECOMP["backend"]
        try:
            pc_i = int(pc, 16) if pc.startswith("0x") else int(pc)
        except ValueError:
            raise HTTPException(400, f"bad pc: {pc!r}")
        fn = bk.function_at(pc_i)
        if fn is None:
            return {"ready": True, "status": "no-function"}
        blocks, edges = bk.cfg_for(fn, mode=mode)
        if not blocks:
            return {"ready": True, "status": "empty-cfg", "fn": {"name": fn.name}}
        ovr = _compute_cfg_overlay(fn.start, blocks, edges)

        # 找当前 cursor 处的 BB
        cur_bb = None
        for b in blocks:
            if b.start <= pc_i < b.end:
                cur_bb = hex(b.start); break

        return {
            "ready": True, "status": "ok",
            "backend": bk.name, "mode": mode, "pc": hex(pc_i),
            "fn": {"name": fn.name, "start": hex(fn.start), "end": hex(fn.end)},
            "current_bb": cur_bb,
            "fn_total_exec": ovr["fn_total"],
            "blocks": [{
                "start": hex(b.start),
                "end": hex(b.end),
                "exec_count": ovr["bb_counts"].get(b.start, 0),
                "lines": [{
                    "pc": hex(l.pc_lo),
                    "text": l.text,
                    "tokens": [_tok(tk) for tk in l.tokens] if l.tokens else None,
                } for l in b.lines],
            } for b in blocks],
            "edges": [{
                "src": hex(e.src), "dst": hex(e.dst), "kind": e.kind,
                "seen_in_trace": (e.src, e.dst) in ovr["edges_seen"],
            } for e in edges],
        }

    # ── P0-1: call tree ───────────────────────────────────────────────────────

    @app.get("/api/call-tree", response_model=CallTreeResponse)
    def api_call_tree(max_depth: int = 50):
        """Build nested call tree from bl/ret pairs in trace."""
        from viewer.calltree import build_call_tree
        tree = build_call_tree(t, sym=sym, max_depth=max_depth)
        return {"tree": tree}

    # ── P1-C (partial): fork events ───────────────────────────────────────────

    @app.get("/api/fork-events", response_model=ForkEventsResponse)
    def api_fork_events(status: Optional[str] = None,
                        is_fork_like: Optional[bool] = None):
        """Fork-event records from meta.json. Filter by attach_status / is_fork_like.
        Agent-side fork hook (M1) writes these to per-call meta.json."""
        evs = list(t.meta.fork_events)
        if status is not None:
            evs = [e for e in evs if e.get("attach_status") == status]
        if is_fork_like is not None:
            evs = [e for e in evs if e.get("is_fork_like") == is_fork_like]
        return {"count": len(evs), "events": evs}

    # ── P0-2: jni events ──────────────────────────────────────────────────────

    @app.get("/api/jni-events", response_model=JniEventsResponse)
    def api_jni_events(id: Optional[str] = None,
                       idx_lo: Optional[int] = None,
                       idx_hi: Optional[int] = None):
        """Trace.jni_events lazy-loaded from per-call dir's jni_hooks.jsonl.
        Filter by `id` (hook name) and/or trace_idx range."""
        evs = t.jni_events
        if id is not None:
            evs = [e for e in evs if e.get("id") == id]
        if idx_lo is not None:
            evs = [e for e in evs if e.get("trace_idx", -1) >= idx_lo]
        if idx_hi is not None:
            evs = [e for e in evs if e.get("trace_idx", -1) < idx_hi]
        return {"count": len(evs), "events": evs}

    # ── P0-3: Web sync of CLI commands ────────────────────────────────────────

    @app.get("/api/crypto-scan", response_model=CryptoScanAny)
    def api_crypto_scan():
        """Mirror viewer crypto-scan: 22 standard primitive constants in MemShadow."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "primitives": []}
        from viewer.__main__ import _CRYPTO_PATTERNS
        mem_obj = BG["mem"]["data"]
        if not mem_obj.bytes:
            return {"scanned": 0, "primitives": []}
        addrs_sorted = sorted(mem_obj.bytes.keys())

        def _scan_pattern(pat: bytes):
            hits = []
            for a in addrs_sorted:
                ok = True; first_idx = None
                for o, want in enumerate(pat):
                    evs = mem_obj.bytes.get(a + o)
                    if not evs: ok = False; break
                    last = evs[-1]
                    if last[1] != want: ok = False; break
                    if first_idx is None or last[0] < first_idx:
                        first_idx = last[0]
                if ok:
                    hits.append({"addr": hex(a), "first_idx": first_idx})
                    if len(hits) >= 5: break
            return hits

        primitives = []
        for name, hex_str in _CRYPTO_PATTERNS:
            pat = bytes.fromhex(hex_str)
            hits = _scan_pattern(pat)
            primitives.append({"name": name, "pattern": hex_str,
                               "hit_count": len(hits), "hits": hits})
        return {"scanned": len(addrs_sorted), "primitives": primitives}

    @app.post("/api/hash-input-search", response_model=HashInputSearchAny)
    def api_hash_input_search(req: HashInputSearchRequest):
        """Brute-force hash input candidates against target bytes. POST since
        inputs/keys/algos/combos are arrays. mirrors CLI hash-input-search."""
        import hashlib, hmac as _hmac, zlib
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "found": []}
        mem_obj = BG["mem"]["data"]
        try:
            target = bytes.fromhex(req.target_bytes.replace(" ", "").replace("0x", ""))
        except ValueError:
            raise HTTPException(400, f"bad target_bytes hex: {req.target_bytes!r}")
        prefix_n = max(4, req.prefix_bytes)
        target_prefix = target[:prefix_n]
        valid_algos = {"sha1","md5","sha256","sha384","sha512",
                       "hmac-sha1","hmac-md5","hmac-sha256","crc32"}
        for a in req.algos:
            if a not in valid_algos:
                raise HTTPException(400, f"unknown algo: {a!r}")

        def combo_iter(inp, key):
            for c in req.combos:
                if c == "plain": yield ("plain", inp.encode())
                elif c == "prefix_key": yield ("prefix_key", key.encode() + inp.encode())
                elif c == "suffix_key": yield ("suffix_key", inp.encode() + key.encode())
                elif c == "key_prefix_input": yield ("key_prefix_input", key.encode() + b"\0" + inp.encode())
                elif c == "input_pipe_key": yield ("input_pipe_key", inp.encode() + b"|" + key.encode())
                elif c == "key_dot_input": yield ("key_dot_input", key.encode() + b"." + inp.encode())
                else: raise HTTPException(400, f"unknown combo: {c!r}")

        def hash_it(algo, key_bytes, msg):
            if algo == "sha1": return hashlib.sha1(msg).digest()
            if algo == "md5": return hashlib.md5(msg).digest()
            if algo == "sha256": return hashlib.sha256(msg).digest()
            if algo == "sha384": return hashlib.sha384(msg).digest()
            if algo == "sha512": return hashlib.sha512(msg).digest()
            if algo == "hmac-sha1": return _hmac.new(key_bytes, msg, hashlib.sha1).digest()
            if algo == "hmac-md5": return _hmac.new(key_bytes, msg, hashlib.md5).digest()
            if algo == "hmac-sha256": return _hmac.new(key_bytes, msg, hashlib.sha256).digest()
            if algo == "crc32":
                crc = zlib.crc32(msg) & 0xffffffff
                return crc.to_bytes(4, "little") + crc.to_bytes(4, "big")

        def find_in_mem(prefix: bytes, max_hits=3):
            hits = []
            for a in mem_obj.bytes:
                ok = True; evs = None
                for o in range(len(prefix)):
                    evs = mem_obj.bytes.get(a + o)
                    if not evs or evs[-1][1] != prefix[o]: ok = False; break
                if ok:
                    hits.append((a, evs[-1][0]))
                    if len(hits) >= max_hits: break
            return hits

        keys = req.keys or [""]
        found = []
        tried = 0
        for inp in req.inputs:
            for key in keys:
                for combo_name, msg in combo_iter(inp, key):
                    for algo in req.algos:
                        if algo.startswith("hmac-") and not key:
                            continue
                        try:
                            h = hash_it(algo, key.encode(),
                                         msg if not algo.startswith("hmac-") else inp.encode())
                        except Exception:
                            continue
                        tried += 1
                        if h.startswith(target_prefix):
                            full_match = h.startswith(target)
                            found.append({
                                "algo": algo, "input": inp, "key": key,
                                "combo": combo_name,
                                "msg_hex": (msg[:40].hex() + "..." if len(msg) > 40 else msg.hex()),
                                "hash_full": h.hex(),
                                "full_match": full_match,
                                "matches_n_bytes": prefix_n if not full_match else len(target),
                            })
                            continue
                        if req.search_in_mem:
                            mh = find_in_mem(h[:prefix_n], max_hits=1)
                            if mh:
                                found.append({
                                    "algo": algo, "input": inp, "key": key,
                                    "combo": combo_name,
                                    "msg_hex": (msg[:40].hex() + "..."),
                                    "hash_full": h.hex(),
                                    "found_in_mem": [{"addr": hex(a), "idx": i} for a, i in mh],
                                    "match_type": "in_mem",
                                })
        return {"target_prefix": target_prefix.hex(),
                "tried_combos": tried,
                "found": found, "found_count": len(found)}

    @app.post("/api/diff-traces", response_model=DiffTracesResponse)
    def api_diff_traces(req: DiffTracesRequest):
        """Multi-trace differential. mirrors CLI diff-traces."""
        import json as _json, pathlib as _pl, urllib.parse, base64
        from collections import defaultdict
        if len(req.traces) < 2:
            raise HTTPException(400, "need >= 2 traces for diff")

        def extract_outputs(trace_dir):
            td = _pl.Path(trace_dir)
            candidates = list(td.glob("jni_hooks.jsonl")) + \
                          list(td.glob("calls/*/jni_hooks.jsonl"))
            if not candidates: return None
            events = []
            for jp in candidates:
                for line in jp.read_text().splitlines():
                    try: events.append(_json.loads(line))
                    except Exception: continue
            new_strs = sorted(
                [e for e in events
                 if e.get("id") == "NewStringUTF"
                 and (e.get("args") or {}).get("bytes")],
                key=lambda e: e.get("trace_idx", 0))
            outputs = {}
            for i, e in enumerate(new_strs):
                v = e["args"]["bytes"]
                if v in ("x-sign", "x-mini-wua", "x-sgext", "x-umt"):
                    if i + 1 < len(new_strs):
                        val_str = new_strs[i+1]["args"]["bytes"]
                        try:
                            url_dec = urllib.parse.unquote(val_str)
                            pad = '=' * ((4 - len(url_dec) % 4) % 4)
                            binary = base64.b64decode(url_dec + pad)
                            outputs[v] = {"raw": val_str, "binary": binary,
                                           "len_b64": len(url_dec),
                                           "len_bin": len(binary)}
                        except Exception as ex:
                            outputs[v] = {"raw": val_str, "decode_err": str(ex)}
            return outputs

        all_outputs = []
        for td in req.traces:
            out = extract_outputs(td)
            if out is None:
                raise HTTPException(400, f"no jni_hooks.jsonl in {td}")
            all_outputs.append({"trace": td, "outputs": out})

        headers = ["x-mini-wua", "x-umt", "x-sgext", "x-sign"]
        diff_report: dict = {}
        for hdr in headers:
            binaries = []
            for ao in all_outputs:
                o = ao["outputs"].get(hdr)
                binaries.append(o["binary"] if (o and "binary" in o) else None)
            if any(b is None for b in binaries):
                diff_report[hdr] = {"error": "missing in some trace",
                                     "per_trace_lens": [len(b) if b else None for b in binaries]}
                continue
            lens = [len(b) for b in binaries]
            n = min(lens)
            length_variable = len(set(lens)) > 1
            stable_bytes = []; variable_bytes = []; per_byte = []
            for o in range(n):
                vals = [b[o] for b in binaries]
                if len(set(vals)) == 1:
                    stable_bytes.append(o)
                    per_byte.append({"off": o, "kind": "STABLE", "value": hex(vals[0])})
                else:
                    variable_bytes.append(o)
                    per_byte.append({"off": o, "kind": "VARIABLE",
                                     "values": [hex(v) for v in vals]})
            alias_map: dict = defaultdict(list)
            for o in variable_bytes:
                tup = tuple(b[o] for b in binaries)
                alias_map[tup].append(o)
            alias_groups = [{
                "positions": pos, "size": len(pos),
                "values_per_trace": [hex(v) for v in tup],
            } for tup, pos in alias_map.items() if len(pos) > 1]
            alias_groups.sort(key=lambda g: -g["size"])
            nibble_findings = []
            for o in variable_bytes:
                vals = [b[o] for b in binaries]
                his = set((v >> 4) & 0xf for v in vals)
                los = set(v & 0xf for v in vals)
                if len(his) == 1:
                    nibble_findings.append({"off": o, "kind": "hi_fixed",
                                            "hi": hex(next(iter(his))),
                                            "lo_per_trace": [hex(v & 0xf) for v in vals]})
                elif len(los) == 1:
                    nibble_findings.append({"off": o, "kind": "lo_fixed",
                                            "lo": hex(next(iter(los))),
                                            "hi_per_trace": [hex((v >> 4) & 0xf) for v in vals]})
            diff_report[hdr] = {
                "len_compared": n,
                "lens_per_trace": lens,
                "length_variable": length_variable,
                "stable_count": len(stable_bytes),
                "variable_count": len(variable_bytes),
                "stable_pct": round(100 * len(stable_bytes) / n, 1) if n else 0,
                "stable_offsets": stable_bytes if req.show_offsets else None,
                "variable_offsets": variable_bytes if req.show_offsets else None,
                "alias_groups": alias_groups,
                "alias_group_count": len(alias_groups),
                "nibble_findings": nibble_findings,
                "per_byte": per_byte if req.show_per_byte else None,
            }
        return {"traces": [ao["trace"] for ao in all_outputs],
                "n_traces": len(all_outputs),
                "headers": diff_report}

    @app.get("/api/ollvm-detect-vm", response_model=OllvmDetectResponse)
    def api_ollvm_detect_vm(min_entries: int = 10, threshold: float = 0.5):
        """P1-D: heuristic VM dispatcher detection. Hint, not decode."""
        from viewer.ollvmdet import ollvm_detect_vm
        candidates = ollvm_detect_vm(t, min_entries=min_entries,
                                      conf_threshold=threshold)
        return {"min_entries": min_entries, "threshold": threshold,
                "count": len(candidates), "candidates": candidates}

    @app.get("/api/hash-finalize-detect", response_model=HashFinalizeDetectAny)
    def api_hash_finalize_detect(window: int = 500, min_size: int = 16):
        """P1-B: scan MemShadow for hash digest output regions
        (closes loop with /api/crypto-scan: IV → input, this → output)."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "candidates": []}
        from viewer.hashfin import hash_finalize_detect
        candidates = hash_finalize_detect(t, BG["mem"]["data"],
                                           window=window, min_size=min_size)
        return {"window": window, "min_size": min_size,
                "count": len(candidates), "candidates": candidates}

    @app.get("/api/auto-phase-detect", response_model=AutoPhaseDetectAny)
    def api_auto_phase_detect(detect_byte_streams: bool = True):
        """Heuristic phase timeline. mirrors CLI auto-phase-detect."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "phases": []}
        import json as _json, pathlib as _pl
        mem_obj = BG["mem"]["data"]
        phases = []
        # JNI events
        jni_path = _pl.Path(t.path).parent / "jni_hooks.jsonl"
        if jni_path.exists():
            for line in jni_path.read_text().splitlines():
                try: e = _json.loads(line)
                except Exception: continue
                tid = e.get("trace_idx")
                if tid is None: continue
                op = e.get("id", "")
                if op == "GetStringUTFChars":
                    ret_v = e.get("ret")
                    if isinstance(ret_v, str) and not ret_v.startswith("0x"):
                        phases.append({"idx": tid, "phase": "jni_input",
                                        "info": f"GetStringUTFChars '{ret_v[:32]}'"})
                elif op == "NewStringUTF":
                    v = (e.get("args") or {}).get("bytes")
                    if isinstance(v, str):
                        phases.append({"idx": tid, "phase": "jni_output",
                                        "info": f"NewStringUTF '{v[:48]}'"})
        # crypto IV detection (subset)
        crypto_patterns = [
            ("sha1_init",    bytes.fromhex("01234567")),
            ("sha1_init_h1", bytes.fromhex("89abcdef")),
            ("sha1_init_h4", bytes.fromhex("f0e1d2c3")),
            ("sha256_init",  bytes.fromhex("67e6096a")),
        ]
        for label, pat in crypto_patterns:
            for a in mem_obj.bytes:
                ok = True; first_idx = None
                for o in range(len(pat)):
                    evs = mem_obj.bytes.get(a + o)
                    if not evs or evs[-1][1] != pat[o]: ok = False; break
                    if first_idx is None or evs[0][0] < first_idx:
                        first_idx = evs[0][0]
                if ok and first_idx is not None:
                    phases.append({"idx": first_idx, "phase": label,
                                   "info": f"IV pattern at 0x{a:x}"})
        # byte_stream_write
        if detect_byte_streams:
            size1 = mem_obj.w_size == 1
            if size1.any():
                w_idx_b = mem_obj.w_idx[size1]
                w_addr_b = mem_obj.w_addr[size1]
                for i in range(len(w_idx_b) - 4):
                    if (w_addr_b[i+1] - w_addr_b[i] == 1 and
                        w_addr_b[i+2] - w_addr_b[i+1] == 1 and
                        w_addr_b[i+3] - w_addr_b[i+2] == 1 and
                        w_idx_b[i+3] - w_idx_b[i] < 500):
                        phases.append({"idx": int(w_idx_b[i]),
                                       "phase": "byte_stream_write",
                                       "info": f"4+ contiguous strb starting 0x{int(w_addr_b[i]):x}"})
        phases.sort(key=lambda p: p["idx"])
        dedup = []
        for p in phases:
            if dedup and abs(p["idx"] - dedup[-1]["idx"]) < 50 and p["phase"] == dedup[-1]["phase"]:
                continue
            dedup.append(p)
        return {"trace_records": len(t), "phases": dedup}

    def _parse_int_qs(s: Optional[str]) -> Optional[int]:
        if s is None or s == "": return None
        return int(s, 16) if s.startswith("0x") else int(s)

    @app.get("/api/mem-writes-in-range", response_model=MemWritesInRangeAny)
    def api_mem_writes_in_range(idx_lo: int, idx_hi: int = -1,
                                  src_byte: Optional[str] = None,
                                  addr_lo: Optional[str] = None,
                                  addr_hi: Optional[str] = None,
                                  max: int = 200):
        """All mem writes in [idx_lo, idx_hi); optional filters. mirrors CLI."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "writes": []}
        import numpy as np
        mem_obj = BG["mem"]["data"]
        m_ = t.meta.module
        base = m_.base if m_ else 0
        lo, hi = idx_lo, (idx_hi if idx_hi >= 0 else len(t))
        mask = (mem_obj.w_idx >= lo) & (mem_obj.w_idx < hi)
        a_lo = _parse_int_qs(addr_lo)
        a_hi = _parse_int_qs(addr_hi)
        if a_lo is not None: mask &= (mem_obj.w_addr >= a_lo)
        if a_hi is not None: mask &= (mem_obj.w_addr < a_hi)
        if src_byte is not None:
            sb = _parse_int_qs(src_byte) & 0xff
            mask &= ((mem_obj.w_value & 0xff) == sb)
        pos = np.where(mask)[0]
        matched_n = int(mask.sum())
        if max > 0 and len(pos) > max:
            pos = pos[:max]
        rows = []
        for k in pos.tolist():
            i = int(mem_obj.w_idx[k])
            addr = int(mem_obj.w_addr[k]); sz = int(mem_obj.w_size[k])
            val = int(mem_obj.w_value[k])
            r = t.record(i); d = decode(r.pc, r.inst)
            fn, foff = sym.lookup(r.pc)
            base_w = d.mem_op[0][0] if d.mem_op else None
            idx_w = d.mem_op[0][1] if d.mem_op else None
            src_candidates = [u for u in d.regs_use
                              if u not in (base_w, idx_w)]
            src = src_candidates[0] if src_candidates else None
            rows.append({
                "idx": i, "pc": hex(r.pc),
                "rel": hex(r.pc - base) if base else None,
                "func": fn if fn != "?" else None,
                "asm": f"{d.mnemonic} {d.op_str}",
                "dst_addr": hex(addr), "size": sz,
                "src_reg": src, "src_value": hex(val),
                "byte0": (val & 0xff),
            })
        return {"idx_range": [lo, hi], "matched": matched_n,
                "returned": len(rows), "writes": rows}

    @app.get("/api/mem-flow", response_model=MemFlowAny)
    def api_mem_flow(addr: str, count: int = 8,
                     idx_lo: Optional[int] = None, idx_hi: Optional[int] = None,
                     events_per_byte: int = 10,
                     writers_only: bool = False, readers_only: bool = False):
        """Per-byte read/write timeline. mirrors CLI mem-flow."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "bytes": []}
        mem_obj = BG["mem"]["data"]
        m_ = t.meta.module
        base = m_.base if m_ else 0
        try:
            addr_i = _parse_int_qs(addr) or 0
        except ValueError:
            raise HTTPException(400, f"bad addr: {addr!r}")
        cnt = max(1, count)
        cap = max(0, events_per_byte)
        kind_filter = None
        if writers_only: kind_filter = {"w", "x"}
        elif readers_only: kind_filter = {"r"}
        out_bytes = []
        for o in range(cnt):
            a = addr_i + o
            evs_raw = mem_obj.bytes.get(a, [])
            evs = []
            for ev_idx, ev_byte, ev_kind in evs_raw:
                if idx_lo is not None and ev_idx < idx_lo: continue
                if idx_hi is not None and ev_idx >= idx_hi: continue
                if kind_filter is not None and ev_kind not in kind_filter: continue
                r = t.record(ev_idx); d = decode(r.pc, r.inst)
                fn, foff = sym.lookup(r.pc)
                evs.append({
                    "idx": ev_idx, "byte": ev_byte, "kind": ev_kind,
                    "pc": hex(r.pc),
                    "rel": hex(r.pc - base) if base else None,
                    "func": fn if fn != "?" else None,
                    "asm": f"{d.mnemonic} {d.op_str}",
                })
            if cap > 0 and len(evs) > cap:
                evs = evs[-cap:]
            out_bytes.append({"addr": hex(a), "events": evs, "total": len(evs_raw)})
        return {"addr": addr, "count": cnt, "bytes": out_bytes}

    @app.get("/api/reg-at-idx", response_model=RegAtIdxResponse)
    def api_reg_at_idx(idx: int, regs: str = ""):
        """thin wrapper: 'reg 在 idx N 是多少'. mirrors `viewer reg-at-idx`."""
        if idx < 0 or idx >= len(t):
            raise HTTPException(400, f"idx out of range: {idx} not in [0, {len(t)})")
        r = t.record(idx)
        names = ([x.strip() for x in regs.split(",") if x.strip()] if regs
                 else ["x0","x1","x2","x3","x4","x5","x6","x7","x8",
                       "x14","x19","x20","x21","x25","sp","lr"])
        out = {}
        for rn in names:
            if rn not in ALL_REGS: continue
            v = r.reg(rn)
            out[rn] = {"hex": hex(v), "dec": v, "byte0": v & 0xff}
        return {"idx": idx, "pc": hex(t.pc(idx)), "regs": out}

    @app.get("/api/call-chain", response_model=CallChainResponse)
    def api_call_chain(idx: int, depth: int = 5):
        """LR-walking caller chain. mirrors `viewer call-chain`."""
        if idx < 0 or idx >= len(t):
            raise HTTPException(400, f"idx out of range: {idx} not in [0, {len(t)})")
        m = t.meta.module
        base = m.base if m else 0
        chain = []
        cur_idx = idx
        for d_i in range(depth):
            r = t.record(cur_idx)
            cur_pc = t.pc(cur_idx)
            cur_fn, cur_off = sym.lookup(cur_pc)
            lr = r.reg("lr")
            caller_pc = lr - 4 if lr else 0
            caller_fn, caller_off = (sym.lookup(caller_pc) if caller_pc
                                     else ("?", 0))
            chain.append({
                "depth": d_i, "idx": cur_idx,
                "pc": hex(cur_pc),
                "rel": hex(cur_pc - base) if base else None,
                "func": cur_fn if cur_fn != "?" else None,
                "off": hex(cur_off) if cur_fn != "?" else None,
                "lr": hex(lr),
                "caller_pc": hex(caller_pc),
                "caller_func": caller_fn if caller_fn != "?" else None,
                "caller_off": hex(caller_pc - caller_off) if caller_fn != "?" else None,
            })
            if not caller_fn or caller_fn == "?": break
            import numpy as np
            pcs = t.pc_array()
            hits = np.where(pcs == caller_off)[0]
            before = hits[hits < cur_idx]
            if len(before) == 0: break
            cur_idx = int(before[-1])
        return {"start_idx": idx, "depth": len(chain), "chain": chain}

    # ─────────────── P2-DEC4 Trace Decompiler 接入 webui ───────────────
    #
    # 4 个 endpoint, 复用 viewer.decompiler 全栈. TraceIR 按 (hooks, memshadow)
    # 缓存, 第一次访问建 IR (~1-3s for 60K trace), 后续命中 ms 级.
    #
    # API key 严守: 所有 LLM 调用走 LlmModel.call(), API key 在 model adapter
    # 内从环境变量读, **服务器永不接受/转发 client 提供的 key**.

    def _get_dec_ir(hooks_paths: tuple = (), with_memshadow: bool = False,
                    split_top_k: int = 10, split_min_records: int = 50):
        key = ("dec_ir", hooks_paths, with_memshadow, split_top_k,
               split_min_records)
        if key in cache:
            return cache[key]
        from viewer import build_trace_ir as _build_ir
        from viewer.memshadow import MemShadow as _MS
        mem = None
        if with_memshadow:
            mem = cache.get("dec_memshadow")
            if mem is None:
                mem = _MS(t); mem.build(); cache["dec_memshadow"] = mem
        top = _build_ir(
            t, sym=sym,
            type_spec_paths=[pathlib.Path(p) for p in hooks_paths] or None,
            memshadow=mem,
            split_top_k=split_top_k,
            split_min_records=split_min_records,
        )
        cache[key] = top
        return top

    @app.get("/api/dec/summary")
    def dec_summary(hooks: str = "", with_memshadow: bool = False,
                    split_top_k: int = 10, split_min_records: int = 50):
        """trace 顶层 IR + summary markdown.

        hooks: 逗号分隔 JSON spec 路径; with_memshadow: 抓 VM hex;
        split_top_k: 升级前 K 个 callee 为独立 fn (UI 默认 40, 比 CLI 的 10 大).
        """
        from viewer.decompiler import render_summary_md
        hk = tuple(s.strip() for s in hooks.split(",") if s.strip())
        top = _get_dec_ir(hooks_paths=hk, with_memshadow=with_memshadow,
                          split_top_k=split_top_k,
                          split_min_records=split_min_records)
        return {
            "records": top.records,
            "module_name": top.module_name,
            "module_base": top.module_base,
            "module_size": top.module_size,
            "truncated": top.truncated,
            "fns": [
                {"id": f.id, "name": f.name, "blocks": len(f.blocks),
                 "loops": len(f.loops), "calls": len(f.calls),
                 "type_anchors": len(f.type_anchors),
                 "entry_idx": f.entry_idx, "exit_idx": f.exit_idx}
                for f in top.fns
            ],
            "vm_candidates": [
                {"dispatcher_pc": vc.dispatcher_pc, "confidence": vc.confidence,
                 "reasons": vc.reasons, "reader_pc": vc.reader_pc,
                 "reader_inst": vc.reader_inst, "reader_hits": vc.reader_hits,
                 "bytecode_addr": vc.bytecode_addr,
                 "bytecode_len": vc.bytecode_len,
                 "hex_dump_lines": len(vc.hex_dump)}
                for vc in top.vm_candidates
            ],
            "summary_md": render_summary_md(top),
        }

    @app.get("/api/dec/fn/{fn_id}")
    def dec_fn(fn_id: str, tier: str = "hot",
               hooks: str = "", with_memshadow: bool = False,
               split_top_k: int = 10, split_min_records: int = 50):
        """单个 fn 的 IR markdown."""
        from viewer.decompiler import render_func_md
        hk = tuple(s.strip() for s in hooks.split(",") if s.strip())
        top = _get_dec_ir(hooks_paths=hk, with_memshadow=with_memshadow,
                          split_top_k=split_top_k,
                          split_min_records=split_min_records)
        fn = top.fn(fn_id)
        if fn is None:
            raise HTTPException(404, f"no such fn {fn_id}")
        return {"fn_id": fn_id, "name": fn.name, "tier": tier,
                "markdown": render_func_md(fn, tier=tier)}

    @app.get("/api/dec/models")
    def dec_models():
        """list 可用 models + 各自 API key 配置状态 (不返回 key 值)."""
        from viewer.decompiler import list_llm_models
        env_status = {
            "MIMO_API_KEY": bool(os.environ.get("MIMO_API_KEY")),
            "ANTHROPIC_API_KEY": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "DEEPSEEK_API_KEY": bool(os.environ.get("DEEPSEEK_API_KEY")),
            "DASHSCOPE_API_KEY": bool(os.environ.get("DASHSCOPE_API_KEY")),
        }
        return {"models": list_llm_models(), "api_keys_configured": env_status}

    @app.post("/api/dec/llm-call")
    def dec_llm_call(payload: dict):
        """同步调 LLM 反编译.

        body: {fn_id, model, max_tokens?, hooks?, with_memshadow?, lang?, tier?, split_top_k?}
        API key 服务端从 env 读, 不接受 client 提供.

        Token 经济: server-side cache (key = fn_id+model+lang+tier+memshadow).
        重复请求同参数不重发 LLM, 立即返回 cached result.
        """
        from viewer.decompiler import (
            build_fn_decompile_prompt, make_llm_model,
        )
        fn_id = str(payload.get("fn_id") or "")
        model_name = str(payload.get("model") or "mimo")
        max_tokens = int(payload.get("max_tokens") or 4096)
        hooks = payload.get("hooks") or []
        with_memshadow = bool(payload.get("with_memshadow") or False)
        lang = str(payload.get("lang") or "en")
        tier = str(payload.get("tier") or "hot")
        split_top_k = int(payload.get("split_top_k") or 10)
        split_min_records = int(payload.get("split_min_records") or 50)
        if isinstance(hooks, str):
            hooks = [s.strip() for s in hooks.split(",") if s.strip()]
        hk = tuple(hooks)
        top = _get_dec_ir(hooks_paths=hk, with_memshadow=with_memshadow,
                          split_top_k=split_top_k,
                          split_min_records=split_min_records)
        if top.fn(fn_id) is None:
            raise HTTPException(404, f"no such fn {fn_id}")

        # server-side LLM 输出 cache. key 含所有可能影响输出的参数.
        cache_key = ("dec_llm_out", fn_id, model_name, lang, tier,
                     with_memshadow, hk, max_tokens, split_top_k,
                     split_min_records)
        if cache_key in cache:
            cached = cache[cache_key]
            return {**cached, "cache_hit": True}

        try:
            bundle = build_fn_decompile_prompt(top, fn_id, tier=tier, lang=lang)
            model = make_llm_model(model_name)
        except KeyError as e:
            raise HTTPException(400, f"{e}")
        result = model.call(bundle.user, system=bundle.system,
                            max_tokens=max_tokens)
        out = {
            "ok": result.error is None,
            "model": result.model,
            "error": result.error,
            "c_code": result.c_code,
            "in_tokens": result.prompt_tokens,
            "out_tokens": result.output_tokens,
            "latency_ms": result.latency_ms,
            "estimated_prompt_tokens": bundle.estimated_tokens,
            "cache_hit": False,
        }
        # 仅 success 才 cache; error 不缓存让用户能重试
        if out["ok"]:
            cache[cache_key] = out
        return out

    # ─────────────── LLIL 8-pass pipeline (路线 B v2, BN 风格) ───────────────
    # 跑完整 pipeline (lift → SSA → constfold → dce → typelat → struct →
    # restructure → render) 直接出 C-like markdown. **不调 LLM**, 0 cost.

    def _llil_pipeline_for_fn(fn_id: str, hooks_paths: tuple,
                              with_memshadow: bool,
                              split_top_k: int, split_min_records: int) -> dict:
        """跑全 pipeline, 返回 {fn_id, name, c_code, stats}."""
        from viewer.decompiler.llil import (
            lift_static, ssa_block, ssa_blocks,
            constfold_block, dce_block, typelat_block,
            struct_recover_block, merge_shapes,
            restructure, from_viewer_cfg, render_hlil, expr_to_c,
            collect_uidf,
        )
        from viewer.cfg import build_cfg as _build_cfg
        import numpy as np
        from viewer.trace import REC_SIZE
        # 1. 静态 IR (用 v1 builder 切 fn 范围)
        top = _get_dec_ir(hooks_paths=hooks_paths,
                          with_memshadow=with_memshadow,
                          split_top_k=split_top_k,
                          split_min_records=split_min_records)
        fn = top.fn(fn_id)
        if fn is None:
            raise HTTPException(404, f"no such fn {fn_id}")

        # 2. CFG (cached) — 用 viewer/cfg.py 的输出, 转 LLIL CfgInfo
        cfg = cache.get("dec_cfg")
        if cfg is None:
            cfg = _build_cfg(t, only_module=True)
            cache["dec_cfg"] = cfg

        # 3. lift — 跑 fn 内的 PCs (block.insns 的 union)
        fn_block_pcs = {b.pc for b in fn.blocks}
        # 收集每个 fn block 内所有指令 PC 的 (pc, inst)
        from viewer.disasm import decode as _dec
        items: list = []
        for b in fn.blocks:
            cfgblk = cfg.blocks.get(b.pc)
            if cfgblk is None: continue
            for ins_pc in cfgblk.insns:
                # 找 inst — 用 pc_arr first hit
                pc_arr = t.pc_array()
                u32 = np.frombuffer(t._mm, dtype=np.uint32,
                                    count=t.n * (REC_SIZE // 4))
                inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]
                mask = pc_arr == np.uint64(ins_pc)
                if mask.any():
                    fi = int(np.argmax(mask))
                    items.append((ins_pc, int(inst_arr[fi])))

        ir_lift, lift_stats = lift_static(items)

        # 4. 把 lift 结果按 cfg block 重组 → {block_pc: list[LlilExpr]}
        block_to_exprs: dict[int, list] = {}
        for b in fn.blocks:
            cfgblk = cfg.blocks.get(b.pc)
            if cfgblk is None: continue
            exprs: list = []
            for ins_pc in cfgblk.insns:
                exprs.extend(ir_lift.get(ins_pc, []))
            block_to_exprs[b.pc] = exprs

        # 5. SSA
        ssa_map = ssa_blocks(block_to_exprs)

        # 5.5 UIDF — User-Informed DataFlow from trace 真值 (BN docs/dev/uidf).
        # trace 是天然 UIDF 输入: 每条 SET_REG 在 trace 中实际命中位置该 reg
        # 真值就是最强 evidence. 注入到 constfold/typelat 的 env, 让 lift
        # 看不到 (LLIL_LOAD / LLIL_INTRINSIC) 的事实仍能折.
        uidf = collect_uidf(t, ssa_map, max_blocks=200, max_roots_per_block=80)

        # 6. constfold (block-by-block, with UIDF)
        from viewer.decompiler.llil import constfold_block as _cf
        cf_count = 0
        for pc, blk in list(ssa_map.items()):
            new = _cf(blk, uidf=uidf)
            ssa_map[pc] = new
            cf_count += sum(1 for r in new.roots
                            if hasattr(r, "operands") and len(r.operands) >= 2
                            and hasattr(r.operands[1], "extra")
                            and r.operands[1].extra.get("_folded_from"))

        # 7. dce
        dce_removed = 0
        for pc, blk in list(ssa_map.items()):
            new = dce_block(blk)
            dce_removed += len(blk.roots) - len(new.roots)
            ssa_map[pc] = new

        # 8. typelat + struct
        types_per_block: dict = {}
        shapes_per_block: list = []
        for pc, blk in ssa_map.items():
            types_per_block[pc] = typelat_block(blk)
            shapes_per_block.append(struct_recover_block(blk, types_per_block[pc]))
        merged_shapes = merge_shapes(shapes_per_block)
        # 用 fn 第一 block 的 types 作 render env (粗近似)
        if fn.blocks and fn.blocks[0].pc in types_per_block:
            render_types = types_per_block[fn.blocks[0].pc]
        else:
            from viewer.decompiler.llil import TypeEnv as _TE
            render_types = _TE()

        # 9. restructure — 用 viewer cfg 的 fn-restricted view
        cfg_info = from_viewer_cfg(cfg)
        # restructure 假设 entry = 整个 cfg.entry; fn 内可能不同 entry, 我们
        # 用 fn.pc_start.
        cfg_info.entry = fn.pc_start
        # 限制 succs/preds 到 fn 内 blocks
        fn_blocks_set = set(block_to_exprs.keys())
        cfg_info.succs = {
            pc: [s for s in succs if s in fn_blocks_set]
            for pc, succs in cfg_info.succs.items()
            if pc in fn_blocks_set
        }
        cfg_info.preds = {
            pc: [p for p in preds if p in fn_blocks_set]
            for pc, preds in cfg_info.preds.items()
            if pc in fn_blocks_set
        }
        hlil = restructure(cfg_info, ssa_map)

        # 10. render
        lines = render_hlil(hlil, types=render_types, shapes=merged_shapes)
        c_code = "\n".join(lines)

        return {
            "ok": True,
            "fn_id": fn_id,
            "name": fn.name,
            "c_code": c_code,
            "stats": {
                "blocks": len(block_to_exprs),
                "lift_total": lift_stats.total,
                "lift_intrinsic": lift_stats.intrinsic,
                "lift_coverage": round(lift_stats.coverage(), 3),
                "uidf_observed": len(uidf),
                "uidf_const": sum(1 for ov in uidf.values() if ov.is_const()),
                "constfold_count": cf_count,
                "dce_removed": dce_removed,
                "struct_shapes": len(merged_shapes),
            },
        }

    @app.post("/api/llil/llm")
    def llil_llm(payload: dict):
        """LLIL→LLM (skeleton/skin style): 先跑 8-pass 出干净 C-like 中间表示,
        再喂 LLM 做 variable 命名 / 业务语义注释 / 简化高级控制流.
        SK²Decompile (arXiv 2509.22114) 实证此模式 > 纯 raw asm + LLM.

        body: {fn_id, model, max_tokens?, lang?, hooks?, with_memshadow?,
               split_top_k?, split_min_records?}
        """
        from viewer.decompiler import make_llm_model
        fn_id = str(payload.get("fn_id") or "")
        model_name = str(payload.get("model") or "mimo")
        max_tokens = int(payload.get("max_tokens") or 4096)
        lang = str(payload.get("lang") or "zh")
        hooks = payload.get("hooks") or []
        with_memshadow = bool(payload.get("with_memshadow") or False)
        split_top_k = int(payload.get("split_top_k") or 40)
        split_min_records = int(payload.get("split_min_records") or 10)
        if isinstance(hooks, str):
            hooks = [s.strip() for s in hooks.split(",") if s.strip()]
        hk = tuple(hooks)
        # cache (跟 LLM 输出 cache 同语义)
        cache_key = ("llil_llm", fn_id, model_name, lang, with_memshadow,
                     hk, max_tokens, split_top_k, split_min_records)
        if cache_key in cache:
            return {**cache[cache_key], "cache_hit": True}
        # 1. LLIL pipeline → c_code (skeleton)
        try:
            pipeline_res = _llil_pipeline_for_fn(
                fn_id, hk, with_memshadow, split_top_k, split_min_records)
        except HTTPException:
            raise
        except Exception as e:
            import traceback
            return {"ok": False, "error": f"pipeline: {e}",
                    "traceback": traceback.format_exc()[-800:]}
        skeleton = pipeline_res["c_code"]
        stats = pipeline_res["stats"]
        fn_name = pipeline_res["name"]
        # 2. system prompt — SK²Decompile 风格: 机器骨架, LLM 命名/语义
        if lang == "zh":
            sys_prompt = (
                "你是反编译 skin 助手 (SK²Decompile 风格). 输入是 trace 反编译器"
                "(traceMiku LLIL 8-pass) 出的 C-like skeleton, 已含: SSA 折叠后的"
                "常量, dead code 删除, struct field 还原 (`reg->f0xN`), trace 实测"
                "indirect jump 已 resolve 到具体 PC. \n\n"
                "你的任务 — 输出**重命名 + 注释**后的 C 伪代码:\n"
                "1. 给 reg (x0..x30/sp/fp) 起业务语义名 (e.g. `ctx` / `cmd_idx` / `key`)\n"
                "2. 给 `xN->fN` struct field 起名 (e.g. `ctx->mutex` / `ctx->cmd_table`)\n"
                "3. 把 LLIL `intrinsic(...)` 的 ARM64 op 翻译成等价 C 表达式或注释\n"
                "4. 不要重新推断逻辑 — skeleton 已经是机器算法的最终结论, 你只补语义\n"
                "5. 用 ```c 块包代码; 块外用中文写一段简短的高层语义说明\n"
                "6. 不要保留 `goto 0x...;` 的具体地址, 改成 `// jump back to dispatcher` 等注释"
            )
        else:
            sys_prompt = (
                "You are a decompilation skin assistant (SK²Decompile style). "
                "Input is a C-like skeleton from a trace decompiler's LLIL 8-pass "
                "pipeline. Already has: SSA-folded constants, dead code removed, "
                "struct fields recovered (reg->f0xN), trace-resolved indirect jumps.\n\n"
                "Your task: rename regs to semantic names, name struct fields, "
                "translate `intrinsic(...)` to C-equivalent or comment, write a "
                "brief high-level summary, output a single ```c block."
            )
        user_prompt = (
            f"## fn_id: {fn_id}\n## name: {fn_name}\n"
            f"## stats: {stats}\n\n"
            f"## skeleton (LLIL 8-pass output):\n```c\n{skeleton}\n```\n"
        )
        # 3. call LLM
        try:
            model = make_llm_model(model_name)
        except KeyError as e:
            raise HTTPException(400, f"{e}")
        result = model.call(user_prompt, system=sys_prompt,
                            max_tokens=max_tokens)
        out = {
            "ok": result.error is None,
            "fn_id": fn_id,
            "name": fn_name,
            "model": result.model,
            "error": result.error,
            "c_code": result.c_code,
            "skeleton": skeleton,
            "stats": stats,
            "in_tokens": result.prompt_tokens,
            "out_tokens": result.output_tokens,
            "latency_ms": result.latency_ms,
            "cache_hit": False,
        }
        if out["ok"]:
            cache[cache_key] = out
        return out

    @app.post("/api/llil/render")
    def llil_render(payload: dict):
        """跑 LLIL 8-pass pipeline → C-like markdown. 不调 LLM."""
        fn_id = str(payload.get("fn_id") or "")
        hooks = payload.get("hooks") or []
        with_memshadow = bool(payload.get("with_memshadow") or False)
        split_top_k = int(payload.get("split_top_k") or 40)
        split_min_records = int(payload.get("split_min_records") or 10)
        if isinstance(hooks, str):
            hooks = [s.strip() for s in hooks.split(",") if s.strip()]
        hk = tuple(hooks)
        # cache key
        cache_key = ("llil_render", fn_id, hk, with_memshadow,
                     split_top_k, split_min_records)
        if cache_key in cache:
            return {**cache[cache_key], "cache_hit": True}
        try:
            res = _llil_pipeline_for_fn(fn_id, hk, with_memshadow,
                                        split_top_k, split_min_records)
        except HTTPException:
            raise
        except Exception as e:
            import traceback
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}",
                    "traceback": traceback.format_exc()[-800:]}
        res["cache_hit"] = False
        cache[cache_key] = res
        return res

    # static SPA
    @app.get("/", response_class=HTMLResponse)
    def index():
        return FileResponse(HERE / "index.html")

    app.mount("/static", StaticFiles(directory=HERE), name="static")
    return app


def serve(trace_path: pathlib.Path, host: str = "0.0.0.0", port: int = 0,
          open_browser: bool = True,
          decomp_so: Optional[pathlib.Path] = None,
          decomp_backend: Optional[str] = None):
    """Run the server (blocking). port=0 → auto-pick.

    decomp_so: optional SO 文件; 启动时后台 BN/Ghidra/IDA 加载, ready 后 /api/hlil-for-pc 工作.
    decomp_backend: 'binja' / 'ghidra' / 'ida' / 'r2' / None 自动选最高优先可用项.
    """
    import uvicorn, socket, threading, webbrowser
    if port == 0:
        s = socket.socket(); s.bind((host, 0)); port = s.getsockname()[1]; s.close()
    app = make_app(trace_path, decomp_so=decomp_so, decomp_backend=decomp_backend)
    # SSH 远程开发: 0.0.0.0 时打印一个可点击的 host 地址 (本机 IP) 提示
    show_host = "127.0.0.1" if host in ("127.0.0.1", "localhost") else host
    url = f"http://{show_host}:{port}/"
    print(f"\n[traceMiku web] {url}")
    print(f"[traceMiku web] trace: {trace_path}")
    if decomp_so:
        print(f"[traceMiku web] decomp SO: {decomp_so} (backend={decomp_backend or 'auto'}, loading in BG)")
    print(f"[traceMiku web] Ctrl-C to stop\n")
    if open_browser and host in ("127.0.0.1", "localhost"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
