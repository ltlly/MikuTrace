#!/usr/bin/env python3
"""Spawn-gates the Taobao :channel sub-process (which we observed reliably
gets caught — main TB usually races past us on this 4.19 kernel without
BPF execve), attaches the full tracer agent, captures libsgmainso JNI_OnLoad
first execution.
"""
import sys, time, frida, subprocess, pathlib, json, os, signal

ROOT = pathlib.Path(__file__).parent
AGENT_NAME = os.environ.get("TRACE_AGENT", "agent_tracer_dlopen.js")
AGENT = (ROOT / AGENT_NAME).read_text()

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/trace_channel")
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 30
REMOTE = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1:6699"
TARGET_IDENT = "com.taobao.taobao:channel"

OUT.mkdir(parents=True, exist_ok=True)
log_fp = open(OUT/"log.txt", "w")
# Per-session state: pid -> {"fp": file, "meta": dict}
sess_files = {}
# Top-level meta records all session pids + global info
top_meta = {"target": TARGET_IDENT, "started_at": time.time(), "sessions": []}

def wlog(s):
    line = f"[{time.strftime('%H:%M:%S')}] {s}"
    print(line, flush=True)
    log_fp.write(line + "\n"); log_fp.flush()

def open_session(pid):
    if pid in sess_files: return sess_files[pid]
    fp = open(OUT/f"trace_{pid}.bin", "wb")
    md = {"pid": pid, "started_at": time.time(), "frames": 0, "bytes": 0}
    sess_files[pid] = {"fp": fp, "meta": md}
    top_meta["sessions"].append(pid)
    return sess_files[pid]

def close_sessions():
    for pid, s in sess_files.items():
        try: s["fp"].close()
        except: pass
        s["meta"]["closed_at"] = time.time()
        json.dump(s["meta"], open(OUT/f"meta_{pid}.json","w"), indent=2)

def make_cb(pid, tag):
    s = open_session(pid)
    fp, md = s["fp"], s["meta"]
    def cb(m, d):
        if m["type"] == "send":
            p = m["payload"]
            if isinstance(p, dict):
                t = p.get("type")
                if t == "log":
                    wlog(f"[{tag}] {p['msg']}")
                elif t == "frames":
                    if d:
                        fp.write(d); fp.flush()
                        md["bytes"] += len(d)
                        md["frames"] = md.get("frames", 0) + p["recs"]
                    wlog(f"[{tag}] frames seq={p['seq']} recs={p['recs']} total={p['total']} ({p.get('reason','?')})")
                elif t == "module":
                    md["module"] = {k: p[k] for k in ("name","base","size")}
                    wlog(f"[{tag}] module {p['name']} @ {p['base']} sz=0x{p['size']:x}")
                elif t == "export-resolved":
                    md["export_addr"] = p["addr"]
                    wlog(f"[{tag}] export {p['name']} @ {p['addr']}")
                elif t == "trace-begin":
                    md["trace_begin"] = {"tid": p["tid"], "ts": p["ts"]}
                    wlog(f"[{tag}] trace-begin tid={p['tid']}")
                elif t == "trace-end":
                    md["trace_end"] = {k: p[k] for k in ("tid","total","ms","retval")}
                    wlog(f"[{tag}] trace-end total={p['total']} ms={p['ms']} ret={p['retval']}")
                elif t == "hello":
                    md["hello"] = p
                    wlog(f"[{tag}] hello pid={p['pid']} frida={p['frida']}")
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

def main():
    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(REMOTE)
    wlog(f"device={device}")
    hard_kill_tb()
    time.sleep(0.5)

    sessions = {}
    target_attached = [False]

    pending_init = []  # list of (pid, sess, scr) needing init

    def on_spawn(s):
        if s.identifier == TARGET_IDENT:
            wlog(f"[SPAWN] {s.identifier} pid={s.pid}")
            try:
                sess = device.attach(s.pid)
                scr = sess.create_script(AGENT)
                scr.on("message", make_cb(s.pid, f"chan:{s.pid}"))
                scr.load()
                wlog(f"[SPAWN] script loaded for pid={s.pid}; queueing init for main thread")
                sessions[s.pid] = (sess, scr)
                pending_init.append(s.pid)
                target_attached[0] = True
            except Exception as e:
                wlog(f"[SPAWN] ATTACH FAIL: {e}")
        # ALWAYS resume so the gated process actually runs
        try: device.resume(s.pid)
        except Exception as e: wlog(f"resume warn: {e}")

    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    wlog("gating on; am start")
    subprocess.run(["adb","shell","am","start","-n",
                    "com.taobao.taobao/com.taobao.tao.welcome.Welcome"],
                   capture_output=True, timeout=15)

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    inited = set()
    while not stop[0] and time.time() - t0 < DURATION:
        # Process any pending init from main thread (so resume in on_spawn
        # has actually taken effect before init enumerates modules).
        while pending_init:
            pid = pending_init.pop(0)
            if pid in inited: continue
            sess, scr = sessions[pid]
            try:
                wlog(f"[main] init pid={pid}")
                r = scr.exports_sync.init({"soPattern":"libsgmainso", "exportName":"JNI_OnLoad"})
                wlog(f"[main] init pid={pid} -> {r}")
                inited.add(pid)
            except Exception as e:
                wlog(f"[main] init pid={pid} FAILED: {e}")
        time.sleep(0.05)

    wlog("teardown")
    for pid, (s, sc) in sessions.items():
        try: print("stats:", sc.exports_sync.stats(), flush=True)
        except: pass
        try: sc.exports_sync.force_flush()
        except: pass
        try: sc.unload()
        except: pass
        try: s.detach()
        except: pass
    try: device.disable_spawn_gating()
    except: pass
    close_sessions()
    top_meta["stopped_at"] = time.time()
    json.dump(top_meta, open(OUT/"meta.json","w"), indent=2)
    log_fp.close()
    total_b = sum(s["meta"]["bytes"] for s in sess_files.values())
    print(f"[done] {len(sess_files)} sessions, total {total_b} bytes ({total_b//272} records)", flush=True)
    for pid, s in sess_files.items():
        print(f"  trace_{pid}.bin: {s['meta']['bytes']} bytes ({s['meta']['frames']} records)", flush=True)

if __name__ == "__main__":
    main()
