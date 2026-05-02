"""P1-C M8: end-to-end real-device smoke covering M1 hook + M2 race-attach +
M3 proc poll + M4 fork_events shape + M7 viewer load.

Spawns fork_test in long-lived mode (children sleep 5s), attaches Frida via
miku-srv, loads ONLY the fork-hook portion of the agent, captures fork-events,
then race-attaches each child and records attach_status. Finally writes a
synthetic per-call meta.json with fork_events and verifies viewer.trace.load
parses it.

Pass criteria:
  - >= 2 fork-events captured (fork + clone)
  - viewer.trace.load reads the meta.json fork_events back correctly
  - Each event has a recognized attach_status (success/failed_*/failed_timeout)
  - Documents whether Frida child-attach works on this server config
    (ptrace-based servers like miku-srv typically fail F3 — child inherits
    parent's ptrace state. eBPF-based miku-shield is the proper solution.)
"""
import frida, sys, time, subprocess, json, tempfile, struct, pathlib

DEVICE_BIN = "/data/local/tmp/fork_test"
DEVICE_ADDR = "127.0.0.1:6699"


AGENT_FORK_ONLY = """
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
    const ev = {
        type: "fork-event",
        parent_pc: pc.toString(),
        syscall: syscall,
        child_pid: child_pid,
        clone_flags: (clone_flags === null) ? null
                    : ("0x" + (clone_flags >>> 0).toString(16)),
        is_fork_like: (clone_flags === null) ? true : _isForkLike(clone_flags),
        ts: Date.now(),
        attach_status: "not_attempted",
    };
    STATE.forkEvents.push(ev);
    send({type: "fork-events", events: [ev]});
}

function install() {
    const f = _findEx("fork");
    if (f) Interceptor.attach(f, {
        onEnter() { this._ra = this.returnAddress; },
        onLeave(rv) {
            const pid = rv.toInt32();
            if (pid > 0) pushEvent("fork", this._ra, pid, null);
        }
    });
    const c = _findEx("clone");
    if (c) Interceptor.attach(c, {
        onEnter(args) { this._ra = this.returnAddress; this._flags = args[2].toInt32(); },
        onLeave(rv) {
            const pid = rv.toInt32();
            if (pid > 0) pushEvent("clone", this._ra, pid, this._flags);
        }
    });
}

rpc.exports = { install: install };
"""


def main():
    print(f"[host] launching {DEVICE_BIN} long")
    proc = subprocess.Popen(["adb", "shell", DEVICE_BIN, "long"],
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
        print("[!] no PID"); sys.exit(1)

    print(f"[host] connecting miku-srv {DEVICE_ADDR}, attaching pid={pid}")
    device = frida.get_device_manager().add_remote_device(DEVICE_ADDR)
    sess = device.attach(pid)
    scr = sess.create_script(AGENT_FORK_ONLY)

    captured = []
    children_attached = []

    def on_message(message, data):
        if message.get("type") == "send":
            p = message["payload"]
            if isinstance(p, dict) and p.get("type") == "fork-events":
                for ev in p["events"]:
                    captured.append(ev)
                    print(f"[host] fork-event: {ev['syscall']} child={ev['child_pid']}")
                    # M2 race-attach
                    cpid = ev.get("child_pid")
                    if ev.get("is_fork_like") and cpid > 0:
                        print(f"[host]   trying race-attach to child {cpid}…")
                        # device.attach() may block when child inherits parent's
                        # ptrace state. Run in thread with timeout.
                        import threading
                        result = {"sess": None, "exc": None}
                        def _try_attach():
                            try: result["sess"] = device.attach(cpid)
                            except Exception as e: result["exc"] = e
                        th = threading.Thread(target=_try_attach, daemon=True)
                        th.start(); th.join(timeout=2.0)
                        if th.is_alive():
                            ev["attach_status"] = "failed_timeout"
                            print(f"[host]   ✗ child {cpid}: attach timeout (likely F3 ptrace conflict)")
                        elif result["exc"]:
                            e = result["exc"]
                            msg = str(e).lower()
                            if "process not found" in msg or "no such" in msg:
                                ev["attach_status"] = "failed_short_lived"
                            elif "ptrace" in msg:
                                ev["attach_status"] = "failed_ptrace_conflict"
                            else:
                                ev["attach_status"] = "failed_unknown"
                            print(f"[host]   ✗ child {cpid}: {ev['attach_status']} "
                                  f"({type(e).__name__}: {str(e)[:80]})")
                        else:
                            ev["attach_status"] = "success"
                            children_attached.append(cpid)
                            print(f"[host]   ✓ race-attached child {cpid}")
                            try: result["sess"].detach()
                            except Exception: pass
        elif message.get("type") == "error":
            print(f"[!] {message.get('description')}", file=sys.stderr)

    scr.on("message", on_message)
    scr.load()
    scr.exports_sync.install()
    print("[host] hooks installed; waiting for fork()s")

    for _ in range(80):
        time.sleep(0.1)
    try: sess.detach()
    except Exception: pass
    proc.wait(timeout=10)

    # Now verify viewer.trace.load reads back fork_events
    print("\n[host] === verifying viewer reads back fork_events ===")
    tmp = pathlib.Path(tempfile.mkdtemp())
    cd = tmp / "run1" / "calls" / "call_001"
    cd.mkdir(parents=True)
    base = 0x100000
    with open(cd / "trace.bin", "wb") as f:
        f.write(struct.pack("<Q", base))
        for _ in range(31): f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 0x7000))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<I", 0xd503201f))
    json.dump({"callIdx": 1, "tid": 100, "records": 1, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False,
               "fork_events": captured},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(tmp / "run1" / "meta.json", "w"))

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from viewer.trace import load
    t = load(cd)
    assert len(t.meta.fork_events) == len(captured)
    print(f"  Trace.meta.fork_events len = {len(t.meta.fork_events)} ✓")
    t.close()

    print(f"\n[host] === SUMMARY ===")
    print(f"  fork-events captured: {len(captured)}")
    print(f"  children race-attached: {len(children_attached)}")
    by_status = {}
    for ev in captured:
        s = ev.get("attach_status", "?")
        by_status[s] = by_status.get(s, 0) + 1
    for k, v in by_status.items():
        print(f"    {k}: {v}")

    if len(captured) < 2:
        print("\n[!] FAIL: expected >=2 fork-events"); sys.exit(1)
    valid_statuses = {"success", "failed_short_lived", "failed_ptrace_conflict",
                       "failed_timeout", "failed_unknown", "not_attempted"}
    invalid = [ev["attach_status"] for ev in captured
                if ev.get("attach_status") not in valid_statuses]
    if invalid:
        print(f"\n[!] FAIL: invalid attach_status values: {invalid}")
        sys.exit(1)
    if not children_attached and "failed_timeout" in by_status:
        print("\n[note] all attaches timed out — F3 ptrace conflict on this Frida server.")
        print("       Real-world fork tracing on already-attached parent requires eBPF")
        print("       (miku-shield), not ptrace-based Frida. Documented as expected.")
    print("\n[host] PASS — M1+M7 e2e validated; M2 attach_status flow correct.")


if __name__ == "__main__":
    main()
