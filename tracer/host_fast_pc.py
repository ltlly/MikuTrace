#!/usr/bin/env python3
"""极速 PC-only trace host."""
import frida, signal, time, json, pathlib, subprocess, sys, argparse

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_fast_pc.js").read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--cmd", type=int, default=70102)
    ap.add_argument("--so", default="libsgmainso")
    ap.add_argument("--fn-offset", type=lambda s: int(s, 16), default=0x57770)
    ap.add_argument("--snapshot-interval", type=int, default=0,
                    help="N>0: 每 N 条 insn 抓全寄存器快照 (callout, 慢 100x)")
    ap.add_argument("--max-records", type=int, default=50_000_000)
    ap.add_argument("--remote", default="127.0.0.1:6699")
    args = ap.parse_args()

    OUT = pathlib.Path(args.out); OUT.mkdir(parents=True, exist_ok=True)
    log_fp = open(OUT/"log.txt", "w")
    pc_fp = None; snap_fp = None
    state = {"pid": None, "tid": None, "module": None, "fn_addr": None,
             "pcs": 0, "snaps": 0, "starts": []}

    def wlog(s):
        line = f"[{time.strftime('%H:%M:%S')}] {s}"
        print(line, flush=True); log_fp.write(line + "\n"); log_fp.flush()

    def open_files(pid, tid):
        nonlocal pc_fp, snap_fp
        if pc_fp is None:
            pc_fp = open(OUT/f"pc_{pid}_{tid}.bin", "wb")
            snap_fp = open(OUT/f"snap_{pid}_{tid}.bin", "wb")
            state["pid"] = pid; state["tid"] = tid

    def on_msg(m, data):
        if m["type"] == "send":
            p = m["payload"]
            t = p.get("type") if isinstance(p, dict) else None
            if t == "log":
                wlog(f"[ag] {p['msg']}")
            elif t == "pc-frames":
                if pc_fp is None: open_files(state["pid"] or 0, state["tid"] or 0)
                if data: pc_fp.write(data); pc_fp.flush()
                state["pcs"] = p["total"]
                wlog(f"[ag] PC +{p['count']} (total={p['total']:,}, {p.get('reason','?')})")
            elif t == "snap-frames":
                if snap_fp is None: open_files(state["pid"] or 0, state["tid"] or 0)
                if data: snap_fp.write(data); snap_fp.flush()
                state["snaps"] = p["total"]
                wlog(f"[ag] SNAP +{p['count']} (total={p['total']:,})")
            elif t == "module":
                state["module"] = {k: p[k] for k in ("name","base","size")}
                state["pid"] = p["pid"]
                wlog(f"[ag] 模块 {p['name']} @ {p['base']}")
            elif t == "trace-begin":
                state["starts"].append({"tid": p["tid"], "ts": p.get("ts"), "call": p.get("call")})
                state["tid"] = p["tid"]
                open_files(state["pid"] or 0, p["tid"])
                wlog(f"[ag] trace 开始 tid={p['tid']} call=#{p.get('call')}")
            elif t == "trace-end":
                wlog(f"[ag] *** trace 结束 ret={p['retval']} pcs={p['pcs']:,} ms={p['ms']} ({(p['pcs']/max(p['ms']/1000,1e-3)):.0f} pc/s) ***")
                state["last_end"] = p
            elif t == "follow":
                wlog(f"[ag] follow tid={p['tid']} {p.get('label','?')}")
            elif t == "hello":
                wlog(f"[ag] hello frida={p['frida']} mode={p.get('mode')}")
            else:
                wlog(f"[ag] {p}")
        elif m["type"] == "error":
            wlog(f"[err] {m.get('description')}")

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(args.remote)
    pid = None
    for p in device.enumerate_processes():
        if p.name == "com.taobao.taobao": pid = p.pid; break
    if pid is None:
        r = subprocess.run(["adb","shell","pidof","com.taobao.taobao"],
                           capture_output=True, text=True)
        if r.stdout.strip(): pid = int(r.stdout.strip().split()[0])
    if pid is None: print("[!] TB not running"); return 1
    wlog(f"attach pid={pid}")
    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    scr.on("message", on_msg)
    scr.load()
    scr.exports_sync.init({
        "soPattern": args.so, "fnOffset": args.fn_offset,
        "cmdValue": args.cmd, "snapshotInterval": args.snapshot_interval,
        "maxRecords": args.max_records,
    })

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    while not stop[0] and time.time() - t0 < args.duration:
        time.sleep(0.5)

    wlog("teardown")
    try: print(f"stats: {scr.exports_sync.stats()}")
    except: pass
    try: scr.exports_sync.force_flush()
    except: pass
    try: scr.unload()
    except: pass
    try: sess.detach()
    except: pass
    if pc_fp: pc_fp.close()
    if snap_fp: snap_fp.close()
    state["closed_at"] = time.time()
    json.dump(state, open(OUT/"meta.json","w"), indent=2, ensure_ascii=False)
    log_fp.close()
    pc_size = (OUT/f"pc_{state['pid']}_{state['tid']}.bin").stat().st_size if pc_fp else 0
    print(f"\n[done] PC trace: {pc_size:,} bytes ({pc_size//8:,} PCs)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
