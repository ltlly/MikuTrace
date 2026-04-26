#!/usr/bin/env python3
"""CModule-加速 FULL trace host. 跑 agent_fast_full.js."""
import frida, signal, time, json, pathlib, subprocess, sys, argparse

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_fast_full.js").read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--cmd", type=int, default=0)  # 0 = 不过滤
    ap.add_argument("--so", default="libsgmainso")
    ap.add_argument("--fn-offset", type=lambda s: int(s, 16), default=0x57770)
    ap.add_argument("--max-records", type=int, default=0)  # 0 = 无上限
    ap.add_argument("--js-diag", action="store_true",
                    help="用 JS 诊断 callout 替代 CModule (调试)")
    ap.add_argument("--remote", default="127.0.0.1:6699")
    ap.add_argument("--pkg", default="com.taobao.taobao")
    args = ap.parse_args()

    OUT = pathlib.Path(args.out); OUT.mkdir(parents=True, exist_ok=True)
    log_fp = open(OUT/"log.txt", "w")
    bin_fp = None
    state = {"pid": None, "tid": None, "module": None, "total": 0, "dropped": 0}

    def wlog(s):
        line = f"[{time.strftime('%H:%M:%S')}] {s}"
        print(line, flush=True); log_fp.write(line + "\n"); log_fp.flush()

    def open_bin(pid, tid):
        nonlocal bin_fp
        if bin_fp is None:
            bin_fp = open(OUT/f"trace_{pid}_{tid}.bin", "wb")
            state["pid"] = pid; state["tid"] = tid

    def on_msg(m, data):
        if m["type"] == "send":
            p = m["payload"]
            t = p.get("type") if isinstance(p, dict) else None
            if t == "log":
                wlog(f"[ag] {p['msg']}")
            elif t == "frames":
                if bin_fp is None: open_bin(state["pid"] or 0, state["tid"] or 0)
                if data: bin_fp.write(data); bin_fp.flush()
                state["total"] = p["total"]
                state["dropped"] = p.get("dropped", 0)
                wlog(f"[ag] frames +{p['recs']} (total={p['total']:,} dropped={p.get('dropped',0)} {p.get('reason','?')})")
            elif t == "module":
                state["module"] = {k: p[k] for k in ("name","base","size")}
                state["pid"] = p["pid"]
                wlog(f"[ag] 模块 {p['name']} @ {p['base']}")
            elif t == "trace-begin":
                state["tid"] = p["tid"]
                open_bin(state["pid"] or 0, p["tid"])
                wlog(f"[ag] trace 开始 tid={p['tid']} call=#{p.get('call')}")
            elif t == "trace-end":
                rate = p["total"] / max(p["ms"]/1000, 1e-3)
                wlog(f"[ag] *** ret={p['retval']} total={p['total']:,} dropped={p['dropped']:,} ms={p['ms']} ({rate:.0f} rec/s) ***")
                state["last_end"] = p
            elif t == "follow":
                wlog(f"[ag] follow tid={p['tid']}")
            elif t == "hello":
                wlog(f"[ag] hello frida={p['frida']} mode={p.get('mode')} ring={p.get('ringMB')}MB max={p.get('maxRecords','∞')}")
            else:
                wlog(f"[ag] {p}")
        elif m["type"] == "error":
            wlog(f"[err] {m.get('description')}")

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(args.remote)
    pid = None
    # 优先用 adb pidof — frida.enumerate_processes 在 system_server 不稳时会崩
    try:
        r = subprocess.run(["adb","shell","pidof",args.pkg],
                           capture_output=True, text=True, timeout=5)
        if r.stdout.strip(): pid = int(r.stdout.strip().split()[0])
    except Exception as e:
        print(f"[!] adb pidof 失败: {e}")
    if pid is None:
        try:
            for p in device.enumerate_processes():
                if p.name == args.pkg: pid = p.pid; break
        except Exception as e:
            print(f"[!] enumerate_processes 失败: {e}")
    if pid is None: print(f"[!] {args.pkg} not running"); return 1
    wlog(f"attach pid={pid}")
    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    scr.on("message", on_msg)
    scr.load()
    r = scr.exports_sync.init({
        "soPattern": args.so, "fnOffset": args.fn_offset,
        "cmdValue": args.cmd, "maxRecords": args.max_records,
        "useJSCallout": args.js_diag,
    })
    wlog(f"init -> {r}")
    if r != "armed":
        wlog(f"init failed: {r}")
        try: scr.unload(); sess.detach()
        except: pass
        return 1

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    while not stop[0] and time.time() - t0 < args.duration:
        time.sleep(0.5)

    wlog("teardown")
    try:
        s = scr.exports_sync.stats()
        wlog(f"stats: {s}")
    except Exception as e:
        wlog(f"stats failed: {e}")
    try: scr.exports_sync.force_flush()
    except Exception as e: wlog(f"force_flush failed: {e}")
    try: scr.unload()
    except: pass
    try: sess.detach()
    except: pass
    if bin_fp: bin_fp.close()
    state["closed_at"] = time.time()
    json.dump(state, open(OUT/"meta.json","w"), indent=2, ensure_ascii=False)
    if state["module"]:
        json.dump({
            "pid": state["pid"], "tid": state["tid"],
            "module": state["module"],
            "frames": state["total"], "bytes": state["total"]*272,
        }, open(OUT/f"meta_{state['pid']}_{state['tid']}.json","w"), indent=2)
    log_fp.close()
    if bin_fp:
        sz = (OUT/f"trace_{state['pid']}_{state['tid']}.bin").stat().st_size
        print(f"\n[done] {sz:,} bytes ({sz//272:,} records)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
