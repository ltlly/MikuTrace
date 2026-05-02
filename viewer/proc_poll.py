"""P1-C M3: child process lifecycle poll via /proc/<pid>/stat.

When agent fork hook captures a child PID but Frida M2 attach failed (F3 ptrace
conflict / F7 spawn-gate unavailable / agent injection too slow), we still want
Tier 3 data: how long did the child run? Did it crash, exit cleanly, or get
SIGKILL'd?

This polls `/proc/<pid>/stat` from the host side via adb shell. The output:
  PID (comm) STATE PPID PGRP ... utime stime ... starttime ...

We only use:
  - existence (stat readable → child alive; missing → child gone)
  - state char (R/S/D/Z/T/W) — Z = zombie (waiting for parent to reap)
  - starttime (jiffies since boot, for runtime calc)

Pure function design: takes an `adb_shell_fn(args) -> (returncode, stdout, stderr)`
so tests can inject canned responses without touching real adb.
"""
from __future__ import annotations
import time
import subprocess
from typing import Callable, Optional


def _default_adb_shell_fn(args: list[str], timeout: float = 2.0):
    """Default subprocess-based adb shell runner."""
    try:
        r = subprocess.run(["adb", "shell"] + args,
                           capture_output=True, text=True, timeout=timeout)
        return (r.returncode, r.stdout, r.stderr)
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except FileNotFoundError:
        return (-1, "", "adb not found")


def parse_proc_stat(text: str) -> Optional[dict]:
    """Parse /proc/<pid>/stat output. Returns dict with pid/comm/state/starttime
    or None if malformed."""
    s = text.strip()
    if not s: return None
    # Format: PID (comm with spaces) state ppid ...
    # comm is wrapped in (), but can contain ')' — find the LAST ')' as terminator.
    lp = s.find("(")
    rp = s.rfind(")")
    if lp == -1 or rp == -1 or rp < lp: return None
    try:
        pid = int(s[:lp].strip())
        comm = s[lp+1:rp]
        rest = s[rp+1:].split()
        if len(rest) < 21: return None
        state = rest[0]
        starttime_jiffies = int(rest[19])  # field 22 in proc(5), 0-indexed=21 from after comm
        return {"pid": pid, "comm": comm, "state": state,
                "starttime_jiffies": starttime_jiffies}
    except (ValueError, IndexError):
        return None


def poll_child_lifecycle(pid: int,
                         max_wait_sec: float = 30.0,
                         poll_interval_sec: float = 0.1,
                         adb_shell_fn: Optional[Callable] = None) -> dict:
    """Poll `/proc/<pid>/stat` until child exits or max_wait.

    Returns:
      {
        "child_pid": int,
        "first_observed_at": float | None,    # wall-clock ts of first successful read
        "last_observed_at": float | None,     # last successful read
        "exit_observed_at": float | None,     # ts when stat became unreadable
        "alive_at_max_wait": bool,            # True if still alive at timeout
        "runtime_ms": int | None,             # last - first if both observed
        "last_state": str | None,             # final state char (R/S/Z/D...)
        "comm": str | None,
        "polls_total": int,
        "polls_alive": int,
      }
    """
    fn = adb_shell_fn or _default_adb_shell_fn
    start = time.time()
    out = {
        "child_pid": pid,
        "first_observed_at": None,
        "last_observed_at": None,
        "exit_observed_at": None,
        "alive_at_max_wait": False,
        "runtime_ms": None,
        "last_state": None,
        "comm": None,
        "polls_total": 0,
        "polls_alive": 0,
    }
    while True:
        elapsed = time.time() - start
        if elapsed >= max_wait_sec:
            out["alive_at_max_wait"] = True
            break
        out["polls_total"] += 1
        rc, so, se = fn(["cat", f"/proc/{pid}/stat"])
        now = time.time()
        if rc == 0 and so:
            parsed = parse_proc_stat(so)
            if parsed:
                if out["first_observed_at"] is None:
                    out["first_observed_at"] = now
                    out["comm"] = parsed["comm"]
                out["last_observed_at"] = now
                out["last_state"] = parsed["state"]
                out["polls_alive"] += 1
                # Z = zombie: process exited, awaiting reap. count as exit.
                if parsed["state"] == "Z":
                    out["exit_observed_at"] = now
                    break
            else:
                # malformed → treat as exit
                out["exit_observed_at"] = now
                break
        else:
            # stat unreadable: child gone
            if out["first_observed_at"] is not None:
                out["exit_observed_at"] = now
            break
        time.sleep(poll_interval_sec)

    if out["first_observed_at"] and out["last_observed_at"]:
        out["runtime_ms"] = int((out["last_observed_at"]
                                  - out["first_observed_at"]) * 1000)
    return out
