#!/usr/bin/env python3
"""Smoke-test host. Spawns a target via spawn-gating + am start, attaches the
agent, lets it run for N seconds. Configurable target so we can shake the
pipeline out on a friendly app first.

Usage:
    python3 host_smoke.py [PKG] [DURATION] [SO_PATTERN] [EXPORT]
Defaults: com.android.settings 15 libsettings JNI_OnLoad
"""
import sys, time, frida, signal, subprocess, threading, pathlib, json

ROOT = pathlib.Path(__file__).parent
AGENT_PATH = ROOT / "agent_smoke.js"

def make_on_message(tag):
    def cb(msg, data):
        if msg["type"] == "send":
            p = msg["payload"]
            if isinstance(p, dict) and "type" in p:
                if p["type"] == "log":
                    print(f"[ag {tag}] {p['msg']}", flush=True)
                elif p["type"] == "progress":
                    print(f"[pr {tag}] blocks={p['blocks']} pc={p['pc']}", flush=True)
                else:
                    print(f"[ag {tag}] {json.dumps(p)}", flush=True)
            else:
                print(f"[ag {tag}] {p}", flush=True)
        elif msg["type"] == "error":
            print(f"[ag-err {tag}] {msg.get('description')}", flush=True)
            if "stack" in msg: print(msg["stack"], flush=True)
    return cb

def resolve_main_activity(pkg):
    r = subprocess.run(["adb","shell","cmd","package","resolve-activity","--brief", pkg],
                       capture_output=True, text=True, timeout=10)
    for line in r.stdout.splitlines():
        if "/" in line and not line.startswith("priority"):
            return line.strip()
    return f"{pkg}/.MainActivity"

def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else "com.android.settings"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    so_pattern = sys.argv[3] if len(sys.argv) > 3 else "libsettings"
    export_name = sys.argv[4] if len(sys.argv) > 4 else "JNI_OnLoad"

    activity = resolve_main_activity(pkg)
    print(f"[host] target pkg={pkg} activity={activity}", flush=True)
    print(f"[host] so_pattern={so_pattern} export={export_name} duration={duration}s", flush=True)

    device = frida.get_usb_device(timeout=10)

    # kill stale
    for p in device.enumerate_processes():
        if p.name.startswith(pkg.split(":")[0]):
            try: device.kill(p.pid)
            except Exception: pass
    time.sleep(0.6)

    sessions = {}     # pid -> (session, script)
    lock = threading.Lock()
    agent_src = AGENT_PATH.read_text()

    def attach_pid(pid, ident):
        try:
            sess = device.attach(pid)
            scr = sess.create_script(agent_src)
            scr.on("message", make_on_message(f"{ident}:{pid}"))
            scr.load()
            scr.exports_sync.init({
                "soPattern": so_pattern,
                "exportName": export_name,
                "mode": "module",
            })
            with lock: sessions[pid] = (sess, scr)
            print(f"[host] +script {ident}:{pid}", flush=True)
        except Exception as e:
            print(f"[host] !attach {ident}:{pid}: {e}", flush=True)

    def on_spawn(spawn):
        if spawn.identifier and spawn.identifier.startswith(pkg):
            print(f"[host] gated {spawn.identifier} pid={spawn.pid}", flush=True)
            attach_pid(spawn.pid, spawn.identifier)
        try: device.resume(spawn.pid)
        except Exception: pass

    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    print("[host] spawn-gating on", flush=True)
    subprocess.run(["adb","shell","am","start","-S","-n", activity],
                   capture_output=True, text=True, timeout=15)

    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    while not stop[0] and time.time() - t0 < duration:
        time.sleep(0.2)

    print("[host] tearing down", flush=True)
    try: device.disable_spawn_gating()
    except Exception: pass
    with lock:
        for pid, (s, sc) in list(sessions.items()):
            try: sc.unload()
            except Exception: pass
            try: s.detach()
            except Exception: pass
    for pid in list(sessions.keys()):
        try: device.kill(pid)
        except Exception: pass

if __name__ == "__main__":
    main()
