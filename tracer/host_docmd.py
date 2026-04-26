#!/usr/bin/env python3
"""Trace a JNI native method (default doCommandNative) when called with a
specific cmd id. Spawn-gates :channel + main TB. Saves trace to project dir.

Usage:
    python3 host_docmd.py [out_dir] [duration_secs] [cmd_value] [remote]
"""
import argparse, json, signal, time, frida, pathlib, subprocess, os

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_docmd.js").read_text()
DEFAULT_OUT = ROOT.parent / "traces" / "doCommand_70102"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--cmd", type=int, default=70102)
    ap.add_argument("--method", default="doCommandNative")
    ap.add_argument("--so", default="libsgmainso")
    ap.add_argument("--remote", default="127.0.0.1:6699")
    ap.add_argument("--mode", choices=["spawn","attach"], default="spawn")
    args = ap.parse_args()

    OUT = pathlib.Path(args.out)
    OUT.mkdir(parents=True, exist_ok=True)
    log_fp = open(OUT/"log.txt", "w")
    sess_files = {}
    top_meta = {"method": args.method, "cmd": args.cmd, "so_pattern": args.so,
                "started_at": time.time(), "sessions": []}

    def wlog(s):
        line = f"[{time.strftime('%H:%M:%S')}] {s}"
        print(line, flush=True)
        log_fp.write(line + "\n"); log_fp.flush()

    def open_sess(pid):
        if pid in sess_files: return sess_files[pid]
        fp = open(OUT/f"trace_{pid}.bin", "wb")
        md = {"pid": pid, "started_at": time.time(), "frames": 0, "bytes": 0}
        sess_files[pid] = {"fp": fp, "meta": md}
        top_meta["sessions"].append(pid)
        return sess_files[pid]

    def make_cb(pid, tag):
        s = open_sess(pid)
        fp, md = s["fp"], s["meta"]
        def cb(m, data):
            if m["type"] == "send":
                p = m["payload"]
                if isinstance(p, dict):
                    t = p.get("type")
                    if t == "log":
                        wlog(f"[{tag}] {p['msg']}")
                    elif t == "frames":
                        if data:
                            fp.write(data); fp.flush()
                            md["bytes"] += len(data)
                            md["frames"] = md.get("frames", 0) + p["recs"]
                        wlog(f"[{tag}] frames seq={p['seq']} recs={p['recs']} total={p['total']} ({p.get('reason','?')})")
                    elif t == "module":
                        md["module"] = {k: p[k] for k in ("name","base","size")}
                        wlog(f"[{tag}] module {p['name']} @ {p['base']} sz=0x{p['size']:x}")
                    elif t == "register-native":
                        md["registration"] = {k: p[k] for k in ("name","sig","fp")}
                        wlog(f"[{tag}] REGISTER {p['name']} {p['sig']} -> {p['fp']}")
                    elif t == "fn-resolved":
                        md["fn_addr"] = p["addr"]
                        wlog(f"[{tag}] {p['name']} fn @ {p['addr']}")
                    elif t == "trace-begin":
                        md["trace_begin"] = {"tid": p["tid"], "ts": p["ts"], "cmd": p.get("cmd")}
                        wlog(f"[{tag}] trace-begin tid={p['tid']} cmd={p.get('cmd')}")
                    elif t == "trace-end":
                        md["trace_end"] = {k: p[k] for k in ("tid","total","ms","retval")}
                        wlog(f"[{tag}] trace-end total={p['total']} ms={p['ms']} ret={p['retval']}")
                    elif t == "hello":
                        md["hello"] = p
                        wlog(f"[{tag}] hello pid={p['pid']} method={p.get('method')} cmd={p.get('cmdValue')}")
                    elif t == "cmd-hist":
                        # dump periodic cmd histogram (which cmd ids fire most)
                        h = p.get("hist", {})
                        top = sorted(h.items(), key=lambda kv: -kv[1])[:8]
                        s = " ".join(f"{k}:{v}" for k, v in top)
                        wlog(f"[{tag}] cmd-hist total={p['total']} top: {s}")
                    else:
                        wlog(f"[{tag}] payload {json.dumps(p)}")
                else:
                    wlog(f"[{tag}] {p}")
            elif m["type"] == "error":
                wlog(f"[{tag}] ERROR {m.get('description')}")
                if "stack" in m: wlog(m["stack"])
        return cb

    def hard_kill_tb():
        for i in range(6):
            subprocess.run(["adb","shell","am","force-stop","com.taobao.taobao"],
                           capture_output=True, timeout=8)
            subprocess.run(["adb","shell","killall","com.taobao.taobao",
                            "com.taobao.taobao:channel","2>/dev/null||true"],
                           capture_output=True, timeout=8)
            time.sleep(0.4)
            r = subprocess.run(["adb","shell","pidof","com.taobao.taobao"],
                               capture_output=True, text=True, timeout=8)
            if not r.stdout.strip():
                wlog(f"TB dead after {i+1} attempts")
                return True
        return False

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(args.remote)
    wlog(f"device={device}")

    sessions = {}
    pending_init = []
    AGENT_OPTS = {"soPattern": args.so, "methodName": args.method,
                  "cmdArg": 2, "cmdValue": args.cmd, "maxRecords": 5000000,
                  # 0x57770 = doCommandNative offset for libsgmainso 6.8.260403
                  # captured from earlier RegisterNatives hook on :channel
                  "fnOffset": 0x57770}

    if args.mode == "attach":
        # find pid by name
        target_pid = None
        for p in device.enumerate_processes():
            if p.name == "com.taobao.taobao":
                target_pid = p.pid; break
        if target_pid is None:
            r = subprocess.run(["adb","shell","pidof","com.taobao.taobao"],
                               capture_output=True, text=True)
            if r.stdout.strip(): target_pid = int(r.stdout.strip().split()[0])
        if target_pid is None:
            wlog("[!] TB not running; aborting"); return
        wlog(f"attach pid={target_pid}")
        sess = device.attach(target_pid)
        scr = sess.create_script(AGENT)
        scr.on("message", make_cb(target_pid, f"tb:{target_pid}"))
        scr.load()
        r = scr.exports_sync.init(AGENT_OPTS)
        wlog(f"init -> {r}")
        sessions[target_pid] = (sess, scr)
    else:
        hard_kill_tb()
        time.sleep(0.5)

        def on_spawn(s):
            if s.identifier and s.identifier.startswith("com.taobao.taobao"):
                wlog(f"[SPAWN] {s.identifier} pid={s.pid}")
                try:
                    sess = device.attach(s.pid)
                    scr = sess.create_script(AGENT)
                    scr.on("message", make_cb(s.pid, f"{s.identifier}:{s.pid}"))
                    scr.load()
                    sessions[s.pid] = (sess, scr)
                    pending_init.append(s.pid)
                except Exception as e:
                    wlog(f"[SPAWN] ATTACH FAIL: {e}")
            try: device.resume(s.pid)
            except Exception as e: wlog(f"resume warn: {e}")

        device.on("spawn-added", on_spawn)
        device.enable_spawn_gating()
        wlog("gating on; am start")
        subprocess.run(["adb","shell","am","start","-n",
                        "com.taobao.taobao/com.taobao.tao.welcome.Welcome"],
                       capture_output=True, timeout=15)

        # Fallback: spawn-gating sometimes misses MAIN process on this kernel
        # (4.19 + no BPF execve). Poll for main TB pid + attach if not gated.
        def attach_main_if_missing():
            time.sleep(2.5)  # let spawn-gating do its thing first
            for p in device.enumerate_processes():
                if p.name == "com.taobao.taobao" and p.pid not in sessions:
                    wlog(f"[FALLBACK] gating missed main; attaching pid={p.pid}")
                    try:
                        sess = device.attach(p.pid)
                        scr = sess.create_script(AGENT)
                        scr.on("message", make_cb(p.pid, f"com.taobao.taobao:{p.pid}"))
                        scr.load()
                        sessions[p.pid] = (sess, scr)
                        pending_init.append(p.pid)
                    except Exception as e:
                        wlog(f"[FALLBACK] attach fail: {e}")
                    return
        import threading
        threading.Thread(target=attach_main_if_missing, daemon=True).start()

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    inited = set()
    while not stop[0] and time.time() - t0 < args.duration:
        while pending_init:
            pid = pending_init.pop(0)
            if pid in inited: continue
            sess, scr = sessions[pid]
            try:
                wlog(f"[main] init pid={pid}")
                r = scr.exports_sync.init(AGENT_OPTS)
                wlog(f"[main] init pid={pid} -> {r}")
                inited.add(pid)
            except Exception as e:
                wlog(f"[main] init pid={pid} FAILED: {e}")
        time.sleep(0.05)

    wlog("teardown")
    for pid, (s, sc) in list(sessions.items()):
        try: print(f"stats[{pid}]:", sc.exports_sync.stats(), flush=True)
        except: pass
        try: sc.exports_sync.force_flush()
        except: pass
        try: sc.unload()
        except: pass
        try: s.detach()
        except: pass
    if args.mode == "spawn":
        try: device.disable_spawn_gating()
        except: pass

    for pid, s in sess_files.items():
        try: s["fp"].close()
        except: pass
        s["meta"]["closed_at"] = time.time()
        json.dump(s["meta"], open(OUT/f"meta_{pid}.json","w"), indent=2)
    top_meta["stopped_at"] = time.time()
    json.dump(top_meta, open(OUT/"meta.json","w"), indent=2)
    log_fp.close()

    total_b = sum(s["meta"]["bytes"] for s in sess_files.values())
    print(f"\n[done] {len(sess_files)} sessions, total {total_b} bytes ({total_b//272} records)", flush=True)
    for pid, s in sess_files.items():
        if s["meta"]["bytes"] > 0:
            print(f"  trace_{pid}.bin: {s['meta']['bytes']} bytes ({s['meta']['frames']} records)", flush=True)

if __name__ == "__main__":
    main()
