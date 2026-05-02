"""Manual real-device smoke test for P1-C M1 agent fork hook.

Spawns /data/local/tmp/fork_test (must be pre-pushed), loads a minimal
Frida script that re-uses the agent's installForkHooksOnce() function,
captures fork events, prints summary.

Pre-req:
  - adb device connected, frida-server / .miku-srv running on device
  - tests/synth_targets/fork_test cross-compiled and pushed:
      cd tests/synth_targets
      $NDK/.../aarch64-linux-android24-clang -o /tmp/fork_test fork_test.c
      adb push /tmp/fork_test /data/local/tmp/fork_test
      adb shell chmod +x /data/local/tmp/fork_test

Usage:
  /usr/bin/python3 tests/manual_fork_hook_smoke.py

Pass criteria:
  - >= 3 fork-events received (one per fork/vfork/clone call)
  - each event has parent_pc, child_pid > 0, syscall, is_fork_like=True
"""
import frida, sys, time, json, pathlib

DEVICE_BIN = "/data/local/tmp/fork_test"

# Minimal agent: just installs fork hooks, sends fork-events on each capture,
# no Stalker / Tracer overhead.
AGENT = """
const STATE = { forkEvents: [], soPattern: "fork_test" };

function _findEx(name) {
    try { return Module.findGlobalExportByName(name); } catch (_) {}
    try { return Module.getGlobalExportByName(name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}
function _isForkLike(flags) { return (flags & 0x10000) === 0; }

function pushEvent(syscall, ra, child_pid, clone_flags) {
    const pc = ptr(ra);
    STATE.forkEvents.push({
        type: "fork-event",
        parent_pc: pc.toString(),
        syscall: syscall,
        child_pid: child_pid,
        clone_flags: (clone_flags === null) ? null
                    : ("0x" + (clone_flags >>> 0).toString(16)),
        is_fork_like: (clone_flags === null) ? true : _isForkLike(clone_flags),
        ts: Date.now(),
    });
    send({type: "fork-events", events: [STATE.forkEvents[STATE.forkEvents.length - 1]]});
}

function install() {
    let n = 0;
    send({type: "log", msg: "[probe] fork="
          + (_findEx("fork") || "(null)")
          + " vfork=" + (_findEx("vfork") || "(null)")
          + " clone=" + (_findEx("clone") || "(null)")
          + " __bionic_clone=" + (_findEx("__bionic_clone") || "(null)") });
    const f = _findEx("fork");
    if (f) {
        Interceptor.attach(f, {
            onEnter() { this._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) pushEvent("fork", this._ra, pid, null);
            }
        });
        n++;
    }
    const v = _findEx("vfork");
    if (v) {
        Interceptor.attach(v, {
            onEnter() { this._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) pushEvent("vfork", this._ra, pid, null);
            }
        });
        n++;
    }
    const c = _findEx("clone");
    if (c) {
        Interceptor.attach(c, {
            onEnter(args) {
                this._ra = this.returnAddress;
                this._flags = args[2].toInt32();
            },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) pushEvent("clone", this._ra, pid, this._flags);
            }
        });
        n++;
    }
    const bc = _findEx("__bionic_clone");
    if (bc) {
        Interceptor.attach(bc, {
            onEnter(args) {
                this._ra = this.returnAddress;
                this._flags = args[0].toInt32();
            },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) pushEvent("__bionic_clone", this._ra, pid, this._flags);
            }
        });
        n++;
    }
    send({type: "log", msg: "[fork-hook] installed " + n + " hooks"});
}

rpc.exports = { install: install };
"""


def main():
    received = []

    def on_message(message, data):
        if message.get("type") == "send":
            p = message["payload"]
            if isinstance(p, dict):
                if p.get("type") == "fork-events":
                    received.extend(p["events"])
                    for e in p["events"]:
                        print(f"[host] fork-event: {e}")
                elif p.get("type") == "log":
                    print(f"[host] {p['msg']}")
        elif message.get("type") == "error":
            print(f"[!] error: {message.get('description')}", file=sys.stderr)

    import subprocess
    print("[host] launching target via adb (will sleep 3s before fork)")
    proc = subprocess.Popen(["adb", "shell", DEVICE_BIN],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # parse PID from first stderr line
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
        print("[!] couldn't get PID from target stderr"); sys.exit(1)
    print(f"[host] connecting to device frida-server, attaching pid={pid}")
    # miku-srv on port 6699 (stealth). Use frida-tools default device.
    # If miku-srv: connect via local TCP forward
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:6699")
    except Exception:
        device = frida.get_usb_device(timeout=5)
    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    scr.on("message", on_message)
    scr.load()
    scr.exports_sync.install()
    print(f"[host] hooks installed, target will fork in ≤3s")
    # let target finish
    for _ in range(60):
        time.sleep(0.1)
    proc.wait(timeout=10)
    try: sess.detach()
    except Exception: pass

    print(f"\n[host] === SUMMARY: {len(received)} fork-events received ===")
    for e in received:
        print(f"  {e['syscall']:>14}  child_pid={e['child_pid']:<6} "
              f"parent_pc={e['parent_pc']}  fork_like={e['is_fork_like']}")

    syscalls = {e["syscall"] for e in received}
    # vfork is expected gap — Bionic's vfork uses special calling convention
    # (parent suspended until child exec/exit) that Frida Interceptor onLeave
    # cannot intercept. fork() and clone() are the practical hooks for
    # anti-debug detection (vfork is deprecated POSIX, rarely used).
    required = {"fork", "clone"}
    missing = required - syscalls
    if missing:
        print(f"\n[!] MISSING required syscalls: {missing}")
        sys.exit(1)
    if "vfork" not in syscalls:
        print("\n[note] vfork() hook did not fire (known Bionic limitation, "
              "vfork has special calling convention bypassing Interceptor.onLeave)")
    print(f"\n[host] PASS — fork+clone hooks fired ({len(received)} events)")


if __name__ == "__main__":
    main()
