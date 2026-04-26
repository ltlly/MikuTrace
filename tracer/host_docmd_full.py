#!/usr/bin/env python3
"""Multi-thread doCommandNative tracer host.

Uses agent_docmd_full.js which follows the primary thread + all worker
threads spawned during the call. Each thread gets its own trace_<pid>_<tid>.bin
"""
import argparse, json, signal, time, frida, pathlib, subprocess

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_docmd_full.js").read_text()
DEFAULT_OUT = ROOT.parent / "traces" / "doCommand_70102_full"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--cmd", type=int, default=70102)
    ap.add_argument("--method", default="doCommandNative")
    ap.add_argument("--so", default="libsgmainso")
    ap.add_argument("--remote", default="127.0.0.1:6699")
    ap.add_argument("--fn-offset", type=lambda s: int(s, 16), default=0x57770,
                    help="hex offset of native fn within SO (default 0x57770 for libsgmainso 6.8.260403)")
    ap.add_argument("--no-workers", action="store_true",
                    help="don't follow worker threads (primary only)")
    ap.add_argument("--mode", choices=["spawn","attach"], default="attach")
    args = ap.parse_args()

    OUT = pathlib.Path(args.out); OUT.mkdir(parents=True, exist_ok=True)
    log_fp = open(OUT/"log.txt", "w")
    sess_files: dict = {}   # (pid, tid) -> {"fp": file, "frames":n, "bytes":n}
    top_meta = {"method": args.method, "cmd": args.cmd, "started_at": time.time(),
                "sessions": []}

    def wlog(s):
        line = f"[{time.strftime('%H:%M:%S')}] {s}"
        print(line, flush=True); log_fp.write(line + "\n"); log_fp.flush()

    def open_sess(pid, tid):
        key = (pid, tid)
        if key in sess_files: return sess_files[key]
        fp = open(OUT/f"trace_{pid}_{tid}.bin", "wb")
        md = {"pid": pid, "tid": tid, "started_at": time.time(), "frames": 0, "bytes": 0}
        sess_files[key] = {"fp": fp, "meta": md}
        top_meta["sessions"].append([pid, tid])
        return sess_files[key]

    def make_cb(pid, tag):
        def cb(m, data):
            if m["type"] == "send":
                p = m["payload"]
                if isinstance(p, dict):
                    t = p.get("type")
                    if t == "log":
                        wlog(f"[{tag}] {p['msg']}")
                    elif t == "frames":
                        tid = p.get("tid", 0)
                        s = open_sess(pid, tid)
                        if data: s["fp"].write(data); s["fp"].flush()
                        s["meta"]["bytes"] += len(data) if data else 0
                        s["meta"]["frames"] += p["recs"]
                        wlog(f"[{tag}] tid={tid} frames seq={p['seq']} recs={p['recs']} total={p['total']} ({p.get('reason','?')})")
                    elif t == "module":
                        wlog(f"[{tag}] module {p['name']} @ {p['base']}")
                        # store in any session_open's meta
                    elif t == "fn-resolved":
                        wlog(f"[{tag}] {p['name']} @ {p['addr']}")
                    elif t == "trace-begin":
                        wlog(f"[{tag}] trace-begin tid={p['tid']} cmd={p.get('cmd')}")
                        # Open primary session early so meta is recorded
                        open_sess(pid, p['tid'])
                    elif t == "trace-end":
                        wlog(f"[{tag}] trace-end tid={p['tid']} ms={p['ms']} ret={p.get('retval')}")
                    elif t == "follow":
                        wlog(f"[{tag}] follow tid={p['tid']} ({p.get('label','?')})")
                    elif t == "hello":
                        wlog(f"[{tag}] hello pid={p['pid']} method={p.get('method')} cmd={p.get('cmdValue')}")
                    else:
                        wlog(f"[{tag}] {json.dumps(p)}")
                else:
                    wlog(f"[{tag}] {p}")
            elif m["type"] == "error":
                wlog(f"[{tag}] ERROR {m.get('description')}")
                if "stack" in m: wlog(m["stack"])
        return cb

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(args.remote)
    wlog(f"device={device}")

    AGENT_OPTS = {
        "soPattern": args.so, "methodName": args.method,
        "cmdArg": 2, "cmdValue": args.cmd,
        "maxRecords": 5000000,
        "fnOffset": args.fn_offset,
        "followAllThreads": not args.no_workers,
    }

    pid = None
    if args.mode == "attach":
        for p in device.enumerate_processes():
            if p.name == "com.taobao.taobao": pid = p.pid; break
        if pid is None:
            r = subprocess.run(["adb","shell","pidof","com.taobao.taobao"],
                               capture_output=True, text=True)
            if r.stdout.strip(): pid = int(r.stdout.strip().split()[0])
        if pid is None:
            wlog("[!] TB not running"); return
        wlog(f"attach pid={pid}")
        sess = device.attach(pid)
        scr = sess.create_script(AGENT)
        scr.on("message", make_cb(pid, f"tb:{pid}"))
        scr.load()
        wlog(f"init -> {scr.exports_sync.init(AGENT_OPTS)}")
        sessions = {pid: (sess, scr)}
    else:
        wlog("[!] spawn mode not implemented; use --mode attach"); return

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    while not stop[0] and time.time() - t0 < args.duration:
        time.sleep(0.5)

    wlog("teardown")
    for pid, (s, sc) in sessions.items():
        try: print(f"stats[{pid}]:", sc.exports_sync.stats(), flush=True)
        except: pass
        try: sc.exports_sync.force_flush()
        except: pass
        try: sc.unload()
        except: pass
        try: s.detach()
        except: pass

    for key, s in sess_files.items():
        try: s["fp"].close()
        except: pass
        s["meta"]["closed_at"] = time.time()
        json.dump(s["meta"], open(OUT/f"meta_{key[0]}_{key[1]}.json","w"), indent=2)
    top_meta["stopped_at"] = time.time()
    json.dump(top_meta, open(OUT/"meta.json","w"), indent=2)
    log_fp.close()

    total_b = sum(s["meta"]["bytes"] for s in sess_files.values())
    print(f"\n[done] {len(sess_files)} sessions, {total_b} bytes ({total_b//272} records)", flush=True)
    for key, s in sorted(sess_files.items(), key=lambda kv: -kv[1]["meta"]["bytes"])[:10]:
        if s["meta"]["bytes"] > 0:
            print(f"  trace_{key[0]}_{key[1]}.bin: {s['meta']['bytes']} bytes ({s['meta']['frames']} records)", flush=True)

if __name__ == "__main__":
    main()
