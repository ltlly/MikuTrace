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
from viewer.cfg import build_cfg
from viewer.index import Index


def _subprocess_build_cfg_and_pcinst(trace_path: str, conn):
    """Run in CHILD process — has own GIL, doesn't block parent's API threads.
    Builds CFG + pc→inst map, sends back via pipe.
    """
    try:
        from viewer.trace import load as _load
        from viewer.cfg import build_cfg as _bc
        t = _load(trace_path)
        cfg = _bc(t, only_module=True)
        pc_inst = {}
        for i in range(len(t)):
            pc = t.pc(i)
            if pc not in pc_inst:
                pc_inst[pc] = t.inst(i)
        conn.send(("ok", cfg, pc_inst))
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
        "cfg":     {"status": "idle", "data": None, "err": None,
                    "started_at": 0.0, "ready_at": 0.0},
        "pc_inst": {"status": "idle", "data": None, "err": None,
                    "started_at": 0.0, "ready_at": 0.0},
        "index":   {"status": "idle", "data": None, "err": None,
                    "started_at": 0.0, "ready_at": 0.0},
        "mem":     {"status": "idle", "data": None, "err": None,
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

    def _build_cfg_and_pcinst_in_subprocess():
        """启子进程跑 CFG+pc_inst, 子进程独立 GIL, 不阻塞主进程的 API 调用."""
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
            return rest  # [cfg, pc_inst]
        raise RuntimeError(rest[0] if rest else "subprocess failed")

    def _bg_run_combined():
        """合并 cfg + pc_inst 两个 key — 一次子进程拿到双结果, 同时 ready."""
        with BG_LOCK:
            if BG["cfg"]["status"] in ("building", "ready"): return
            for k in ("cfg", "pc_inst"):
                BG[k]["status"] = "building"
                BG[k]["started_at"] = time.time()
        def _t():
            try:
                cfg_obj, pc_inst = _build_cfg_and_pcinst_in_subprocess()
                with BG_LOCK:
                    BG["cfg"]["data"] = cfg_obj
                    BG["cfg"]["status"] = "ready"
                    BG["cfg"]["ready_at"] = time.time()
                    BG["pc_inst"]["data"] = pc_inst
                    BG["pc_inst"]["status"] = "ready"
                    BG["pc_inst"]["ready_at"] = time.time()
            except Exception as e:
                with BG_LOCK:
                    msg = repr(e)
                    BG["cfg"]["err"] = msg; BG["cfg"]["status"] = "error"
                    BG["pc_inst"]["err"] = msg; BG["pc_inst"]["status"] = "error"
        threading.Thread(target=_t, daemon=True, name="bg-cfg-supervisor").start()

    def _build_index():
        idx = Index(t); idx.build(); return idx
    def _build_mem():
        from viewer.memshadow import MemShadow
        m = MemShadow(t); m.build(); return m

    def block_for_pc(pc: int) -> Optional[int]:
        cfg = BG["cfg"]["data"]
        if cfg is None: return None
        for start, b in cfg.blocks.items():
            if start <= pc <= b.end_pc:
                return start
        return None

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
        rows = []
        for i in range(start, end):
            r = t.record(i)
            d = decode(r.pc, r.inst)
            fname, foff = sym.lookup(r.pc)
            row = {
                "idx": i, "pc": hex(r.pc), "rel": hex(r.pc - base) if base else None,
                "func": fname if fname != "?" else None,
                "off": hex(foff) if fname != "?" else None,
                "asm": f"{d.mnemonic} {d.op_str}",
                "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
            }
            if regs_filter:
                row["regs"] = {nm: hex(r.reg(nm)) for nm in regs_filter}
            rows.append(row)
        return {"start": start, "end": end, "count": end-start, "records": rows}

    @app.get("/api/record/{idx}")
    def one_record(idx: int):
        if idx < 0 or idx >= len(t): raise HTTPException(404)
        r = t.record(idx); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        m = t.meta.module
        base = m.base if m else 0
        # block_pc 仅当 CFG ready 时返回, 否则 null (前端不会卡)
        bpc = None
        if BG["cfg"]["status"] == "ready":
            bp = block_for_pc(r.pc)
            if bp is not None: bpc = hex(bp)
        return {
            "idx": idx, "pc": hex(r.pc), "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "off": hex(foff) if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}",
            "regs": {nm: hex(r.reg(nm)) for nm in ALL_REGS if nm not in ("nzcv",)},
            "block_pc": bpc, "cfg_status": BG["cfg"]["status"],
            "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
        }

    @app.get("/api/cfg")
    def cfg():
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
        blocks = []
        for pc, b in c.blocks.items():
            label_lines = []
            for ins_pc in b.insns[:3]:
                inst = pc_inst.get(ins_pc, 0)
                d = decode(ins_pc, inst)
                rel = (ins_pc - base) if base else ins_pc
                label_lines.append(f"+{rel:x}: {d.mnemonic} {d.op_str}")
            if len(b.insns) > 3:
                label_lines.append(f"...+{len(b.insns)-3}")
            fname, foff = sym.lookup(pc)
            blocks.append({
                "id": hex(pc),
                "start": hex(pc), "end": hex(b.end_pc),
                "rel": hex(pc - base) if base else None,
                "func": fname if fname != "?" else None,
                "insns": len(b.insns),
                "executions": b.executions,
                "label": "\n".join(label_lines),
            })
        edges = [{"id": f"{hex(s)}->{hex(d)}", "src": hex(s), "dst": hex(d),
                  "kind": v["kind"], "count": v["count"]}
                 for (s,d), v in c.edges.items()]
        return {"status": "ready",
                "blocks": blocks, "edges": edges,
                "entry": hex(c.entry_pc),
                "block_count": len(blocks), "edge_count": len(edges)}

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

    @app.get("/api/idxs-for-block")
    def idxs_for_block(pc: str, max_count: int = 200, near: int = -1):
        """所有 trace 中 PC 落在该 block 内的 idx. 用于 click block→jump.
        near>=0 时, 优先返回离该 idx 最近的 max_count 个 (按距离排序后再按 idx 升序输出)."""
        if BG["cfg"]["status"] != "ready":
            return {"status": BG["cfg"]["status"], "idxs": []}
        c = BG["cfg"]["data"]
        start = int(pc, 16)
        if start not in c.blocks: raise HTTPException(404)
        b = c.blocks[start]
        end = b.end_pc
        idxs = []
        for i in range(len(t)):
            pc_i = t.pc(i)
            if start <= pc_i <= end:
                idxs.append(i)
        truncated = False
        if near >= 0 and len(idxs) > max_count:
            idxs.sort(key=lambda i: abs(i - near))
            idxs = sorted(idxs[:max_count])
            truncated = True
        elif len(idxs) > max_count:
            idxs = idxs[:max_count]
            truncated = True
        return {"block": hex(start), "idxs": idxs, "truncated": truncated}

    @app.get("/api/search")
    def search(pattern: str, max_results: int = 200):
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
        results = forward_taint(t, start, reg, max_count=max_count)
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
        results = backward_taint(t, start, reg, max_count=max_count)
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
    def strings_api(min_len: int = 4):
        if BG["mem"]["status"] != "ready":
            _bg_run("mem", _build_mem)
            return {"status": BG["mem"]["status"], "strings": []}
        results = BG["mem"]["data"].find_strings(min_len=min_len)
        return {"status": "ready", "count": len(results),
                "strings": [{"addr": hex(a), "len": len(s), "str": s} for a, s in results]}

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
