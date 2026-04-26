#!/usr/bin/env python3
"""Tests three scenarios to isolate why TB dies under spawn-gating.

  case A: spawn-gating + resume immediately (NO attach)         -> baseline
  case B: spawn-gating + attach + EMPTY agent (just rpc.exports) -> agent inj
  case C: spawn-gating + attach + tiny script that does send()   -> active agent
  case D: launch normally + attach + EMPTY agent                 -> known good
"""
import sys, time, frida, subprocess, pathlib

ROOT = pathlib.Path(__file__).parent
PKG = "com.taobao.taobao"
ACT = "com.taobao.taobao/com.taobao.tao.welcome.Welcome"
NOOP = (ROOT/"agent_noop.js").read_text()

def adb(cmd, t=8):
    r = subprocess.run(["adb","shell"]+cmd.split(), capture_output=True, text=True, timeout=t)
    return r.stdout.strip()

def killtb():
    adb("am force-stop com.taobao.taobao")
    time.sleep(0.4)

def alive(tag):
    p = adb("pidof com.taobao.taobao")
    print(f"  [{tag}] tb pid: {p!r}")
    return bool(p)

def case_label(s):
    print(f"\n========== {s} ==========")

def main():
    case = sys.argv[1] if len(sys.argv) > 1 else "all"
    mgr = frida.get_device_manager()
    device = mgr.add_remote_device("127.0.0.1:6699")

    if case in ("A","all"):
        case_label("A: spawn-gating + resume only (no attach)")
        killtb()
        caught = []
        def on_spawn(s):
            if s.identifier and s.identifier.startswith(PKG):
                caught.append(s); print(f"  caught {s.identifier} pid={s.pid}")
            try: device.resume(s.pid)
            except Exception: pass
        device.on("spawn-added", on_spawn)
        device.enable_spawn_gating()
        adb(f"am start -n {ACT}")
        time.sleep(5)
        device.disable_spawn_gating()
        try: device.off("spawn-added", on_spawn)
        except Exception: pass
        alive("A end")

    if case in ("B","all"):
        case_label("B: spawn-gating + attach + EMPTY agent")
        killtb()
        sessions = []
        def on_spawn(s):
            if s.identifier and s.identifier.startswith(PKG):
                print(f"  caught {s.identifier} pid={s.pid}")
                try:
                    sess = device.attach(s.pid)
                    scr = sess.create_script(NOOP)
                    scr.on("message", lambda m,_: print(f"  msg: {m}"))
                    scr.load()
                    sessions.append((sess,scr))
                    print(f"  attached + script loaded for pid={s.pid}")
                except Exception as e:
                    print(f"  ATTACH FAIL: {e}")
            try: device.resume(s.pid)
            except Exception: pass
        device.on("spawn-added", on_spawn)
        device.enable_spawn_gating()
        adb(f"am start -n {ACT}")
        for i in range(15):
            time.sleep(0.5)
            if not alive(f"B t={(i+1)*0.5}"): break
        device.disable_spawn_gating()
        try: device.off("spawn-added", on_spawn)
        except Exception: pass
        for s,sc in sessions:
            try: sc.unload()
            except: pass
            try: s.detach()
            except: pass

    if case in ("D","all"):
        case_label("D: launch normally + attach + EMPTY agent (known-good baseline)")
        killtb()
        adb(f"am start -n {ACT}")
        time.sleep(4)
        pid_str = adb("pidof com.taobao.taobao")
        if not pid_str:
            print("  TB not running - skip"); return
        pid = int(pid_str.split()[0])
        print(f"  TB pid={pid}, attaching...")
        sess = device.attach(pid)
        scr = sess.create_script(NOOP)
        scr.on("message", lambda m,_: print(f"  msg: {m}"))
        scr.load()
        for i in range(6):
            time.sleep(0.5)
            if not alive(f"D t={(i+1)*0.5}"): break
        try: scr.unload()
        except: pass
        try: sess.detach()
        except: pass

if __name__ == "__main__":
    main()
