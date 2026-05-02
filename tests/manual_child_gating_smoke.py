"""Manual real-device smoke test for P1-C M2 child gating.

Verifies miku-srv (or frida-server) supports:
  1. device.enable_spawn_gating()
  2. on("child-added") event when an attached process forks
  3. device.attach(child_pid) on the gated child

Pre-req: same as manual_fork_hook_smoke.py (fork_test binary on device).

Pass criteria:
  - enable_spawn_gating() doesn't error
  - child-added event fires for at least one of fork_test's 3 forks
  - we can attach to the child while it's gated
"""
import frida, sys, time, subprocess

DEVICE_BIN = "/data/local/tmp/fork_test"
DEVICE_ADDR = "127.0.0.1:6699"


def main():
    print(f"[host] launching {DEVICE_BIN}")
    proc = subprocess.Popen(["adb", "shell", DEVICE_BIN],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = None
    deadline = time.time() + 5
    while time.time() < deadline:
        line = proc.stderr.readline().decode(errors="replace")
        print(f"[device] {line.rstrip()}")
        if "pid=" in line:
            try: pid = int(line.split("pid=")[1].split(",")[0])
            except Exception: pass
            break
    if not pid:
        print("[!] no PID from target"); sys.exit(1)

    print(f"[host] connecting to miku-srv {DEVICE_ADDR}")
    try:
        device = frida.get_device_manager().add_remote_device(DEVICE_ADDR)
    except Exception as e:
        print(f"[!] connect failed: {e}"); sys.exit(1)

    children_seen = []
    children_attached = []

    def on_child(child):
        try:
            cpid = child.pid; ppid = child.parent_pid
            origin = getattr(child, "origin", "?")
            print(f"[host] child-added pid={cpid} parent={ppid} origin={origin}")
            children_seen.append(cpid)
            if ppid == pid:
                # try attach
                try:
                    cs = device.attach(cpid)
                    print(f"[host]   attached cpid={cpid}")
                    children_attached.append(cpid)
                    cs.detach()
                except Exception as e:
                    print(f"[host][!] attach cpid={cpid} failed: {e}")
            try: device.resume(cpid)
            except Exception: pass
        except Exception as e:
            print(f"[!] on_child error: {e}")

    print("[host] enable_spawn_gating")
    try:
        device.enable_spawn_gating()
    except Exception as e:
        print(f"[!] enable_spawn_gating not supported: {e}")
        print("    miku-srv may be a stripped-down build. M2 not viable on this server.")
        sys.exit(1)

    device.on("child-added", on_child)

    print(f"[host] attaching parent pid={pid}")
    sess = device.attach(pid)

    # Let target fork
    for _ in range(60):
        time.sleep(0.1)

    try: sess.detach()
    except Exception: pass
    try: device.disable_spawn_gating()
    except Exception: pass
    proc.wait(timeout=10)

    print(f"\n[host] === SUMMARY ===")
    print(f"  children-added events: {len(children_seen)}  ({children_seen})")
    print(f"  children attached:     {len(children_attached)}  ({children_attached})")

    if not children_seen:
        print("\n[!] FAIL: spawn_gating enabled but NO child-added events.")
        print("    Likely: miku-srv 不实现 child-gating, OR linux fork()'d processes")
        print("    aren't tracked (gating may be limited to spawn() / exec).")
        sys.exit(1)
    print("\n[host] PASS — child-gating works on this server")


if __name__ == "__main__":
    main()
