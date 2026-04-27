"""traceMiku Web SPA backend.

单进程, FastAPI 包一层在已有 viewer/ 模块之上, 前端在浏览器拉数据.
mmap 在后端, 客户端按 viewport 拉切片, 200 万条 trace 滚动丝滑.
"""
from __future__ import annotations
import pathlib, time, threading, multiprocessing as mp
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
        import bisect
        from viewer.trace import load as _load
        from viewer.cfg import build_cfg as _bc
        t = _load(trace_path)
        cfg = _bc(t, only_module=True)
        starts = sorted(cfg.blocks.keys())
        ends = [cfg.blocks[s].end_pc for s in starts]
        pc_inst = {}
        pc_to_block = {}
        block_idxs = {s: [] for s in starts}
        n = len(t)
        for i in range(n):
            pc = t.pc(i)
            if pc not in pc_inst:
                pc_inst[pc] = t.inst(i)
            j = bisect.bisect_right(starts, pc) - 1
            if j >= 0 and pc <= ends[j]:
                bs = starts[j]
                pc_to_block[pc] = bs
                block_idxs[bs].append(i)
        conn.send(("ok", cfg, pc_inst, pc_to_block, block_idxs))
    except Exception:
        import traceback
        conn.send(("error", traceback.format_exc()))
    finally:
        try: conn.close()
        except: pass


HERE = pathlib.Path(__file__).resolve().parent


def make_app(trace_path: pathlib.Path) -> FastAPI:
    """Build a FastAPI app bound to one trace.

    Heavy structures (CFG, symbols, index) are lazily computed on first hit
    and cached. mmap'd trace stays open for the lifetime of the server.
    """
    t = load(trace_path)
    sym = build_from_trace(t)
    cache: dict = {}

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
            except: pass
            proc.join(timeout=5)
            if proc.is_alive():
                try: proc.terminate()
                except: pass
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

    @app.get("/api/meta")
    def meta():
        m = t.meta.module
        return {
            "path": str(trace_path),
            "records": len(t),
            "module": {"name": m.name, "base": hex(m.base), "size": m.size,
                       "end": hex(m.end)} if m else None,
            "method": t.meta.method, "cmd": t.meta.cmd,
            "fn_addr": hex(t.meta.fn_addr) if t.meta.fn_addr else None,
            "regs": ALL_REGS,
        }

    @app.get("/api/records")
    def records(start: int = 0, count: int = 100, regs: str = ""):
        if start < 0 or start >= len(t): return {"count": 0, "records": []}
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
            ann = None
            # 注释 1: call/branch → 目标函数名 (PDF p.2 风格 "; libc::vfprintf")
            if d.is_call or d.is_branch:
                # 拿下一条 trace record 的 PC = 实际跳转 dst
                if i + 1 < len(t):
                    next_pc = t.pc(i + 1)
                    tfn, tfoff = sym.lookup(next_pc)
                    if tfn and tfn != "?" and tfn != fname:
                        ann = f"→ {tfn}+{tfoff:#x}"
            # 注释 2: memory load/store → 解读地址有什么
            # (capstone Decoded 已含 mem_op tuple, 此处只 mark 为 "mem op")
            # 简化版: 先只做 call 跳转注释; mem ASCII 解读放后续 PR.
            row = {
                "idx": i, "pc": hex(r.pc), "rel": hex(r.pc - base) if base else None,
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

    @app.get("/api/record/{idx}")
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

    @app.get("/api/cfg")
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

    @app.get("/api/block-for-pc")
    def block_for_pc_api(pc: str):
        # 不强制 trigger CFG build (record endpoint 调它高频)
        if BG["cfg"]["status"] != "ready":
            return {"pc": pc, "block": None, "cfg_status": BG["cfg"]["status"]}
        bp = block_for_pc(int(pc, 16))
        return {"pc": pc, "block": hex(bp) if bp else None}

    @app.get("/api/block")
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

    @app.get("/api/loops")
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

    @app.get("/api/cfg-svg")
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

        def html_esc(s: str) -> str:
            return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                     .replace('"', "&quot;"))

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
            head_lbl = html_esc(f"{head_rel_str}  ×{b.executions}")
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
                # 颜色: 分支橙红, ret 红, call 紫, 其他默认
                fcol = "#d0d7de"
                if d.is_ret: fcol = "#f85149"
                elif d.is_call: fcol = "#bc8cff"
                elif d.is_branch: fcol = "#f7b32b"
                line = f'<FONT COLOR="#6e7681">{html_esc(rel_str)}:</FONT> '\
                       f'<FONT COLOR="{fcol}">{html_esc(d.mnemonic)}</FONT>'
                if ops:
                    line += f' <FONT COLOR="#d0d7de">{html_esc(ops)}</FONT>'
                title = f"{ins_pc:#x}: {d.mnemonic} {d.op_str}"
                rows.append(f'<TR><TD ALIGN="LEFT" '
                            f'HREF="#insn_{ins_pc:x}" TITLE="{html_esc(title)}">{line}</TD></TR>')
            ints = min(b.executions, 50) / 50
            # 优先 loop 色 — PDF p.10 "不同循环不同颜色"
            if pc in loop_color:
                br = loop_color[pc]
            else:
                br = "#30363d"
                if ints > 0.1:
                    r = int(0x30 + ints * 0x80); g = int(0x36 + ints * 0x60); bl = int(0x3d + ints * 0x10)
                    br = f"#{r:02x}{g:02x}{bl:02x}"
            label = ('<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" CELLPADDING="3" '
                     f'COLOR="{br}" BGCOLOR="#161b22">'
                     + "".join(rows) +
                     "</TABLE>>")
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
                # external return into this fn — 用 ext_in 桩
                # 这正是 doCommandNative 那些 in:0 块的入边来源.
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

        import subprocess
        try:
            r = subprocess.run(["dot", "-Tsvg"], input=dot_text, text=True,
                               capture_output=True, timeout=max(5, timeout))
            if r.returncode != 0:
                return {"status": "error", "err": r.stderr[:500]}
            svg = r.stdout
        except FileNotFoundError:
            return {"status": "error", "err": "graphviz `dot` 没装"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "err": f"dot 超时 ({timeout}s) — 增大 settings.dotTimeout 或减小 fn 范围"}

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

    @app.get("/api/backtrace")
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

    @app.get("/api/idxs-for-pc")
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

    @app.get("/api/idxs-for-block")
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

    @app.get("/api/search")
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

    @app.get("/api/forward-taint")
    def forward_taint_api(start: int, reg: str, max_count: int = 500):
        from viewer.taint import forward_taint
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"status": BG["index"]["status"], "hits": []}
        # 用 index 做 bisect 加速 — O(|hits|·log N) vs 旧 O(N²)
        results = forward_taint(t, start, reg, max_count=max_count,
                                index=BG["index"]["data"])
        m = t.meta.module
        base = m.base if m else 0
        rows = []
        for i, why in results:
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            rows.append({"idx": i, "pc": hex(r.pc),
                         "rel": hex(r.pc - base) if base else None,
                         "func": fname if fname != "?" else None,
                         "asm": f"{d.mnemonic} {d.op_str}", "why": why})
        return {"count": len(rows), "from": start, "reg": reg, "hits": rows}

    @app.get("/api/backward-taint")
    def backward_taint_api(start: int, reg: str, max_count: int = 500):
        from viewer.taint import backward_taint
        if BG["index"]["status"] != "ready":
            _bg_run("index", _build_index)
            return {"status": BG["index"]["status"], "chain": []}
        results = backward_taint(t, start, reg, max_count=max_count,
                                 index=BG["index"]["data"])
        m = t.meta.module
        base = m.base if m else 0
        rows = []
        for i, via in results:
            r = t.record(i); d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            rows.append({"idx": i, "pc": hex(r.pc),
                         "rel": hex(r.pc - base) if base else None,
                         "func": fname if fname != "?" else None,
                         "asm": f"{d.mnemonic} {d.op_str}", "via": via})
        return {"count": len(rows), "from": start, "reg": reg, "chain": rows}

    @app.get("/api/strings")
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

    @app.get("/api/string-provenance")
    def string_provenance(addr: str, length: int = 32):
        """对 [addr, addr+length) 区域, 列每个字节的 write idxs (谁构造) +
        read idxs (谁消费). 向量化: 一次 numpy mask 拿所有命中范围的 mem op,
        再 scatter 到每 byte. 6.8M trace 上 ~17s → ~10ms."""
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            st = BG["mem"]["status"]
            if st != "ready":
                return {"status": st, "bytes": []}
        import numpy as np
        mem = BG["mem"]["data"]
        start = int(addr, 16); end = start + length
        # 一次性过滤命中 [start, end) 范围的 writes/reads (远少于全集)
        w_mask = (mem.w_addr < np.uint64(end)) & ((mem.w_addr.astype(np.int64) + mem.w_size) > start)
        r_mask = (mem.r_addr < np.uint64(end)) & ((mem.r_addr.astype(np.int64) + mem.r_size) > start)
        w_a, w_s, w_i = mem.w_addr[w_mask], mem.w_size[w_mask], mem.w_idx[w_mask]
        r_a, r_s, r_i = mem.r_addr[r_mask], mem.r_size[r_mask], mem.r_idx[r_mask]
        # scatter 到每个 byte offset
        writers_per: list[list[int]] = [[] for _ in range(length)]
        readers_per: list[list[int]] = [[] for _ in range(length)]
        for a, s, i in zip(w_a.tolist(), w_s.tolist(), w_i.tolist()):
            lo = max(0, int(a) - start); hi = min(length, int(a) + int(s) - start)
            for o in range(lo, hi):
                writers_per[o].append(int(i))
        for a, s, i in zip(r_a.tolist(), r_s.tolist(), r_i.tolist()):
            lo = max(0, int(a) - start); hi = min(length, int(a) + int(s) - start)
            for o in range(lo, hi):
                readers_per[o].append(int(i))
        # 各 list 已按 trace order 自然 ascending. 但 mem.writes 顺序按 trace
        # 顺序 build, 同 byte 多次 write 也是 ascending. sort() 兜底.
        out_bytes = []
        for offset in range(length):
            a = start + offset
            ws = writers_per[offset]; rs = readers_per[offset]
            byte_val = None; kind = "??"
            if mem.bytes:
                b, k, _ = mem.byte_at(a, 1 << 63)
                byte_val = b; kind = k
            out_bytes.append({
                "addr": hex(a), "byte": byte_val, "kind": kind,
                "writers": ws[:20], "readers": rs[:20],
                "writers_total": len(ws), "readers_total": len(rs),
            })
        return {"status": "ready", "addr": addr, "length": length, "bytes": out_bytes}

    @app.get("/api/mem-dump")
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

    @app.get("/api/last-write-of-reg")
    def last_write_of_reg(cursor: int, reg: str):
        """返回 cursor 之前最近一次该 reg 被 def 的指令 idx.
        index.reg_defs bisect: O(log N) vs 旧 O(cursor) 线性扫.
        """
        if reg not in ALL_REGS:
            return {"status": "error", "err": f"unknown reg {reg}"}
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

    @app.get("/api/reg-value-at")
    def reg_value_at(idx: int, reg: str):
        """读 idx 处 reg 的当前值 + classify 注释."""
        if idx < 0 or idx >= len(t): raise HTTPException(404)
        if reg not in ALL_REGS: return {"status": "error", "err": f"unknown reg {reg}"}
        r = t.record(idx)
        v = r.reg(reg)
        ann = ""
        if BG["mem"]["status"] == "ready":
            ann = _classify_reg_value(v, idx, sp=r.reg("sp"))
        return {"status": "ready", "idx": idx, "reg": reg,
                "value": hex(v), "annotation": ann}

    @app.get("/api/idxs-touching-range")
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

    @app.get("/api/idxs-touching-addr")
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

    @app.get("/api/bg-status")
    def bg_status():
        """所有后台构建任务的状态. 前端用来显示 progress / 决定是否 retry."""
        return {k: {sk: sv for sk, sv in s.items() if sk != "data"} for k, s in BG.items()}

    # static SPA
    @app.get("/", response_class=HTMLResponse)
    def index():
        return FileResponse(HERE / "index.html")

    app.mount("/static", StaticFiles(directory=HERE), name="static")
    return app


def serve(trace_path: pathlib.Path, host: str = "127.0.0.1", port: int = 0,
          open_browser: bool = True):
    """Run the server (blocking). port=0 → auto-pick."""
    import uvicorn, socket, threading, webbrowser
    if port == 0:
        s = socket.socket(); s.bind((host, 0)); port = s.getsockname()[1]; s.close()
    app = make_app(trace_path)
    url = f"http://{host}:{port}/"
    print(f"\n[traceMiku web] {url}")
    print(f"[traceMiku web] trace: {trace_path}")
    print(f"[traceMiku web] Ctrl-C to stop\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
