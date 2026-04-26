#!/usr/bin/env python3
"""Trace libsgmainso JNI_OnLoad on a *live* Taobao process by attaching
(NOT spawning) and re-invoking JNI_OnLoad from the agent. Avoids spawn-time
anti-debug. Requires undetected-frida-server reachable via --remote.

Usage:
    host_taobao.py --remote 127.0.0.1:6699 --pkg com.taobao.taobao --out /tmp/trace_tb
"""
import argparse, json, signal, time, frida, pathlib, subprocess

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_taobao.js").read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", required=True, help="frida-server address e.g. 127.0.0.1:6699")
    ap.add_argument("--pkg", default="com.taobao.taobao")
    ap.add_argument("--so",  default="libsgmainso")
    ap.add_argument("--export", dest="export_name", default="JNI_OnLoad")
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-invoke", action="store_true",
                    help="don't re-invoke JNI_OnLoad; just hook and wait passively")
    ap.add_argument("--wait-secs", type=int, default=8)
    args = ap.parse_args()

    out = pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)
    trace_fp = open(out / "trace.bin", "wb")
    log_fp   = open(out / "log.txt", "w")
    meta = {"pkg": args.pkg, "so_pattern": args.so, "export": args.export_name,
            "started_at": time.time()}

    def wlog(s):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {s}"; print(line, flush=True)
        log_fp.write(line + "\n"); log_fp.flush()

    def on_message(msg, data):
        if msg["type"] == "send":
            p = msg["payload"]
            if isinstance(p, dict):
                t = p.get("type")
                if t == "log":
                    wlog(f"AGENT {p['msg']}")
                elif t == "frames":
                    if data: trace_fp.write(data)
                    wlog(f"AGENT frames seq={p['seq']} recs={p['recs']} bytes={p['bytes']} total={p['total']} ({p.get('reason','?')})")
                elif t == "module":
                    meta["module"] = {k: p[k] for k in ("name","base","size")}
                    wlog(f"AGENT module {p['name']} @ {p['base']} sz=0x{p['size']:x}")
                elif t == "export-resolved":
                    meta["export_addr"] = p["addr"]
                    wlog(f"AGENT export {p['name']} @ {p['addr']}")
                elif t == "trace-begin":
                    meta["trace_begin"] = {"tid": p["tid"], "ts": p["ts"]}
                    wlog(f"AGENT trace-begin tid={p['tid']}")
                elif t == "trace-end":
                    meta["trace_end"] = {k: p[k] for k in ("tid","total","ms","retval")}
                    wlog(f"AGENT trace-end total={p['total']} ms={p['ms']} ret={p['retval']}")
                elif t == "hello":
                    meta["hello"] = p
                    wlog(f"AGENT hello pid={p['pid']} frida={p['frida']}")
                else:
                    wlog(f"AGENT payload {json.dumps(p)}")
            else:
                wlog(f"AGENT {p}")
        elif msg["type"] == "error":
            wlog(f"AGENT-ERROR {msg.get('description')}")
            if "stack" in msg: wlog(msg["stack"])

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(args.remote)
    wlog(f"device={device}")

    # find pid
    pid = None
    try:
        for p in device.enumerate_processes():
            if p.name == args.pkg: pid = p.pid; break
    except Exception as e:
        wlog(f"enum_processes warn: {e}")
    if pid is None:
        # ask adb
        r = subprocess.run(["adb","shell",f"pidof {args.pkg}"], capture_output=True, text=True)
        s = r.stdout.strip().split()
        if s: pid = int(s[0])
    if pid is None:
        wlog(f"!{args.pkg} not running. start it manually first."); return
    wlog(f"target pid={pid}")
    meta["target_pid"] = pid

    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    scr.on("message", on_message)
    scr.load()
    res = scr.exports_sync.init({"soPattern": args.so, "exportName": args.export_name})
    wlog(f"init -> {res}")

    if res != "armed":
        wlog(f"init failed ({res}); aborting")
    else:
        if not args.no_invoke:
            wlog("calling agent.invoke_jni_onload() ...")
            try:
                r = scr.exports_sync.invoke_jni_onload()
                wlog(f"invoke -> {r}")
            except Exception as e:
                wlog(f"invoke exception: {e}")
        wlog(f"sleeping {args.wait_secs}s for any deferred callouts")
        stop = [False]
        signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
        t0 = time.time()
        while not stop[0] and time.time() - t0 < args.wait_secs: time.sleep(0.2)
        try:
            scr.exports_sync.force_flush()
            print("stats:", scr.exports_sync.stats(), flush=True)
        except Exception: pass

    try: scr.unload()
    except Exception: pass
    try: sess.detach()
    except Exception: pass
    trace_fp.close()
    meta["stopped_at"] = time.time()
    json.dump(meta, open(out/"meta.json","w"), indent=2)
    log_fp.close()
    sz = (out/"trace.bin").stat().st_size
    print(f"[host] trace.bin = {sz} bytes ({sz//272} records)", flush=True)

if __name__ == "__main__":
    main()
