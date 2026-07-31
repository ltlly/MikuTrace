"""Fork/child-process lifecycle helpers for the traceMiku host CLI.

Extracted from `tracemiku` (AGENTS.md 1500-line red line). Pure subprocess +
time helpers; no cross-module state.
"""

import subprocess
import time


def _spawn_child_poller(fork_event, parent_meta, wlog, tag,
                          max_wait_sec=30.0):
    """P1-C M3: kick off background thread that polls /proc/<child_pid>/stat
    until child exits, mutates fork_event in-place with Tier 3 lifecycle data.

    fork_event is the dict already in parent_meta["fork_events"] — Python list
    references mean any update to that dict propagates to the meta we'll later
    serialize. No locking needed: only this thread mutates this fork_event.
    """
    import threading
    cpid = fork_event["child_pid"]

    def _poll():
        try:
            r = _poll_child_lifecycle(cpid, max_wait_sec=max_wait_sec)
            fork_event["lifecycle"] = {
                "runtime_ms": r["runtime_ms"],
                "alive_at_max_wait": r["alive_at_max_wait"],
                "last_state": r["last_state"],
                "comm": r["comm"],
                "polls_alive": r["polls_alive"],
            }
            # Promote attach_status from "not_attempted" to a more informative
            # post-mortem state (M2 will overwrite if it actually attached).
            if fork_event.get("attach_status") == "not_attempted":
                if r["alive_at_max_wait"]:
                    fork_event["attach_status"] = "not_attempted_long_lived"
                elif r["first_observed_at"] is None:
                    fork_event["attach_status"] = "not_attempted_short_lived"
                else:
                    fork_event["attach_status"] = "not_attempted_observed"
            wlog(f"[{tag}] [FORK]   poll done child={cpid} "
                 f"runtime={r['runtime_ms']}ms "
                 f"alive_at_timeout={r['alive_at_max_wait']} "
                 f"last_state={r['last_state']}")
        except Exception as e:
            wlog(f"[{tag}] [FORK]   poll error child={cpid}: {e}")

    th = threading.Thread(target=_poll, daemon=True,
                           name=f"fork-poll-{cpid}")
    th.start()


def _parse_proc_stat(text):
    s = text.strip()
    if not s: return None
    lp = s.find("("); rp = s.rfind(")")
    if lp == -1 or rp == -1 or rp < lp: return None
    try:
        pid = int(s[:lp].strip())
        comm = s[lp + 1:rp]
        rest = s[rp + 1:].split()
        if len(rest) < 21: return None
        return {"pid": pid, "comm": comm, "state": rest[0]}
    except Exception:
        return None


def _poll_child_lifecycle(pid, max_wait_sec=30.0, poll_interval_sec=0.1):
    start = time.time()
    out = {
        "child_pid": pid, "first_observed_at": None, "last_observed_at": None,
        "exit_observed_at": None, "alive_at_max_wait": False, "runtime_ms": None,
        "last_state": None, "comm": None, "polls_total": 0, "polls_alive": 0,
    }
    while True:
        if time.time() - start >= max_wait_sec:
            out["alive_at_max_wait"] = True
            break
        out["polls_total"] += 1
        try:
            r = subprocess.run(["adb", "shell", "cat", f"/proc/{pid}/stat"],
                               capture_output=True, text=True, timeout=2)
        except Exception:
            r = None
        now = time.time()
        if r and r.returncode == 0 and r.stdout:
            parsed = _parse_proc_stat(r.stdout)
            if parsed:
                if out["first_observed_at"] is None:
                    out["first_observed_at"] = now
                    out["comm"] = parsed["comm"]
                out["last_observed_at"] = now
                out["last_state"] = parsed["state"]
                out["polls_alive"] += 1
                if parsed["state"] == "Z":
                    out["exit_observed_at"] = now
                    break
            else:
                out["exit_observed_at"] = now
                break
        else:
            if out["first_observed_at"] is not None:
                out["exit_observed_at"] = now
            break
        time.sleep(poll_interval_sec)
    if out["first_observed_at"] and out["last_observed_at"]:
        out["runtime_ms"] = int((out["last_observed_at"] - out["first_observed_at"]) * 1000)
    return out


def _print_fork_summary(all_fork_events):
    """P1-C M5: print Fork Summary table at trace end.

    all_fork_events: list of (call_dir_name, fork_event_dict).
    """
    fork_like = [e for _, e in all_fork_events if e.get("is_fork_like")]
    thread_like = [e for _, e in all_fork_events if not e.get("is_fork_like")]
    by_status = {}
    for e in fork_like:
        st = e.get("attach_status", "not_attempted")
        by_status[st] = by_status.get(st, 0) + 1

    n_fork = len(fork_like)
    n_thread = len(thread_like)
    n_success = by_status.get("success", 0)
    n_partial = by_status.get("success_partial", 0)
    n_failed = sum(v for k, v in by_status.items() if k.startswith("failed_"))
    n_not_attempted = by_status.get("not_attempted", 0)

    print("\n=== Fork Summary ===")
    print(f"Total fork-like:   {n_fork}   "
          f"(thread-like clones via pthread_create: {n_thread}, 不计)")
    if n_success:    print(f"  ✓ Fully traced:  {n_success}")
    if n_partial:    print(f"  ⚠ Partial:       {n_partial}")
    if n_failed:     print(f"  ✗ Attach failed: {n_failed}   "
                            f"({by_status})")
    if n_not_attempted:
        print(f"  · Not attempted: {n_not_attempted}   "
              f"(--no-fork-trace 或 M2 child attach 未启用)")
    print(f"详见 traces/<run>/calls/<dir>/meta.json `fork_events` 字段")
    if n_failed and n_failed >= 2:
        print("提示: 多个 child 抓不全, 可能这个 SO 用 fork-based anti-debug.")
        print("      推 miku-shield (eBPF kernel): github.com/ltlly/miku-shield")


