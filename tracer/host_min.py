#!/usr/bin/env python3
"""Minimal Stalker plumbing test. Attaches to an already-running process and
follows one of its threads. No spawn-gating, no SO matching.

Usage: host_min.py <process_name_or_pid> [duration_ms] [perInsn]
"""
import sys, time, frida, json, pathlib

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_min.js").read_text()

def on_message(msg, data):
    if msg["type"] == "send":
        p = msg["payload"]
        if isinstance(p, dict):
            t = p.get("type")
            if t == "log":
                print(f"[ag] {p['msg']}", flush=True)
            elif t == "progress":
                print(f"[pr] blocks={p['blocks']} insns={p['insns']} pc={p['pc']}", flush=True)
            elif t == "final":
                print(f"[final] blocks={p['blocks']} insns={p['insns']} ms={p['ms']}", flush=True)
            else:
                print(f"[ag] {json.dumps(p)}", flush=True)
        else:
            print(f"[ag] {p}", flush=True)
    elif msg["type"] == "error":
        print(f"[err] {msg.get('description')}", flush=True)
        if "stack" in msg: print(msg["stack"], flush=True)

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "system_server"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    per_insn = (len(sys.argv) > 3 and sys.argv[3] == "1")

    device = frida.get_usb_device(timeout=10)
    pid = None
    if target.isdigit():
        pid = int(target)
    else:
        for p in device.enumerate_processes():
            if p.name == target:
                pid = p.pid; break
        if not pid:
            print(f"[!] no process named {target}")
            sys.exit(1)
    print(f"[host] attaching pid={pid} target={target}", flush=True)
    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    scr.on("message", on_message)
    scr.load()
    scr.exports_sync.init({"durationMs": duration, "perInsn": per_insn})
    print(f"[host] running for {(duration+1000)/1000}s", flush=True)
    time.sleep((duration + 1500) / 1000.0)
    try: scr.unload()
    except Exception: pass
    try: sess.detach()
    except Exception: pass
    print("[host] done", flush=True)

if __name__ == "__main__":
    main()
