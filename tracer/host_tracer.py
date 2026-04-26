#!/usr/bin/env python3
"""traceMiku Stage-1 host. Spawns (via spawn-gating + am start) or attaches to
a target, loads agent_tracer.js, and writes the trace to disk.

Output layout under <out_dir>:
    meta.json       - target info, SO base/size, JNI_OnLoad addr, timing
    modules.json    - all loaded modules at trace start
    trace.bin       - dense binary records (272 bytes each, see agent_tracer.js)
    log.txt         - free-form agent log lines

Usage:
    host_tracer.py --pkg com.android.settings --so libsettings --export JNI_OnLoad \\
                   --out trace_settings --duration 20

    host_tracer.py --pkg com.taobao.taobao --so libsgmainso --out trace_taobao --duration 60
"""
import argparse, sys, time, frida, signal, subprocess, threading, pathlib, json, os

ROOT = pathlib.Path(__file__).parent
AGENT_PATH = ROOT / "agent_tracer.js"

class Run:
    def __init__(self, args):
        self.args = args
        self.out = pathlib.Path(args.out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.trace_fp = open(self.out / "trace.bin", "wb")
        self.log_fp   = open(self.out / "log.txt", "w")
        self.meta = {
            "pkg": args.pkg,
            "so_pattern": args.so,
            "export": args.export_name,
            "started_at": time.time(),
        }
        self.modules = {}
        self.lock = threading.Lock()
        self.stopped = False

    def write_log(self, msg):
        ts = time.strftime("%H:%M:%S", time.localtime())
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        self.log_fp.write(line + "\n")
        self.log_fp.flush()

    def on_message(self, tag):
        def cb(msg, data):
            try:
                if msg["type"] == "send":
                    p = msg["payload"]
                    if isinstance(p, dict):
                        t = p.get("type")
                        if t == "log":
                            self.write_log(f"{tag} {p['msg']}")
                        elif t == "frames":
                            with self.lock:
                                if data: self.trace_fp.write(data)
                            self.write_log(f"{tag} frames seq={p['seq']} recs={p['recs']} "
                                           f"bytes={p['bytes']} total={p['total']} ({p.get('reason','?')})")
                        elif t == "module":
                            self.meta["module"] = {k: p[k] for k in ("name","base","size")}
                            self.write_log(f"{tag} module {p['name']} @ {p['base']} size=0x{p['size']:x}")
                        elif t == "export-resolved":
                            self.meta["export_addr"] = p["addr"]
                            self.write_log(f"{tag} {p['name']} resolved @ {p['addr']}")
                        elif t == "trace-begin":
                            self.meta["trace_begin"] = {"tid": p["tid"], "ts": p["ts"]}
                            self.write_log(f"{tag} trace-begin tid={p['tid']}")
                        elif t == "trace-end":
                            self.meta["trace_end"] = {
                                "tid": p["tid"], "total": p["total"],
                                "ms": p["ms"], "retval": p["retval"]
                            }
                            self.write_log(f"{tag} trace-end total={p['total']} ms={p['ms']} ret={p['retval']}")
                            self.stopped = True
                        elif t == "hello":
                            self.meta["hello"] = p
                            self.write_log(f"{tag} hello pid={p['pid']} frida={p['frida']}")
                        else:
                            self.write_log(f"{tag} payload {json.dumps(p)}")
                    else:
                        self.write_log(f"{tag} payload {p}")
                elif msg["type"] == "error":
                    self.write_log(f"{tag} ERROR {msg.get('description')}")
                    if "stack" in msg: self.write_log(msg["stack"])
            except Exception as e:
                self.write_log(f"{tag} on_message exception: {e}")
        return cb

    def close(self):
        try: self.trace_fp.close()
        except Exception: pass
        self.meta["stopped_at"] = time.time()
        with open(self.out / "meta.json", "w") as f:
            json.dump(self.meta, f, indent=2)
        self.log_fp.close()


def resolve_main_activity(pkg):
    r = subprocess.run(["adb","shell","cmd","package","resolve-activity","--brief", pkg],
                       capture_output=True, text=True, timeout=10)
    for line in r.stdout.splitlines():
        if "/" in line and not line.startswith("priority"):
            return line.strip()
    return None


def kill_stale(device, prefix):
    for p in device.enumerate_processes():
        if p.name.startswith(prefix):
            try: device.kill(p.pid)
            except Exception: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--so",  required=True, help="substring of target SO filename")
    ap.add_argument("--export", dest="export_name", default="JNI_OnLoad")
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--mode", choices=["spawn","attach"], default="spawn")
    ap.add_argument("--attach-pid", type=int, default=None)
    ap.add_argument("--remote", default=None,
                    help="connect to remote frida-server, e.g. 127.0.0.1:6699 "
                         "(when set, --pkg-process names will be matched on the remote)")
    args = ap.parse_args()

    run = Run(args)
    try:
        if args.remote:
            mgr = frida.get_device_manager()
            device = mgr.add_remote_device(args.remote)
        else:
            device = frida.get_usb_device(timeout=10)
        run.write_log(f"device={device}")
        agent_src = AGENT_PATH.read_text()
        sessions = {}

        def attach(pid, ident):
            try:
                sess = device.attach(pid)
                scr = sess.create_script(agent_src)
                scr.on("message", run.on_message(f"{ident}:{pid}"))
                scr.load()
                scr.exports_sync.init({"soPattern": args.so, "exportName": args.export_name})
                sessions[pid] = (sess, scr)
                run.write_log(f"+script {ident}:{pid}")
            except Exception as e:
                run.write_log(f"!attach {ident}:{pid}: {e}")

        if args.mode == "attach":
            if args.attach_pid:
                attach(args.attach_pid, args.pkg)
            else:
                # find by package
                found = None
                for p in device.enumerate_processes():
                    if p.name == args.pkg:
                        found = p.pid; break
                if found is None:
                    run.write_log(f"[!] no process named {args.pkg}; not running?")
                    return
                attach(found, args.pkg)
        else:  # spawn mode
            kill_stale(device, args.pkg)
            time.sleep(0.6)
            activity = resolve_main_activity(args.pkg)
            if not activity:
                run.write_log(f"[!] no main activity for {args.pkg}")
                return
            run.write_log(f"activity={activity}")

            def on_spawn(spawn):
                if spawn.identifier and spawn.identifier.startswith(args.pkg):
                    run.write_log(f"gated spawn {spawn.identifier} pid={spawn.pid}")
                    attach(spawn.pid, spawn.identifier)
                try: device.resume(spawn.pid)
                except Exception: pass

            device.on("spawn-added", on_spawn)
            device.enable_spawn_gating()
            run.write_log("spawn-gating on; launching via am start")
            subprocess.run(["adb","shell","am","start","-S","-n", activity],
                           capture_output=True, text=True, timeout=15)

        stop = [False]
        signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
        t0 = time.time()
        while not stop[0] and not run.stopped and time.time() - t0 < args.duration:
            time.sleep(0.2)

        run.write_log("tearing down")
        # ask agents to flush
        for pid, (s, sc) in sessions.items():
            try: sc.exports_sync.force_flush()
            except Exception: pass
            try: print("stats:", sc.exports_sync.stats())
            except Exception: pass
        if args.mode == "spawn":
            try: device.disable_spawn_gating()
            except Exception: pass
        for pid, (s, sc) in sessions.items():
            try: sc.unload()
            except Exception: pass
            try: s.detach()
            except Exception: pass
        if args.mode == "spawn":
            for pid in list(sessions.keys()):
                try: device.kill(pid)
                except Exception: pass
    finally:
        run.close()
        size = (pathlib.Path(args.out) / "trace.bin").stat().st_size
        print(f"[host] trace.bin size = {size} bytes ({size//272} records)", flush=True)

if __name__ == "__main__":
    main()
