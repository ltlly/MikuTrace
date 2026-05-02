"""P1-C M3: /proc/<pid>/stat polling — pure function with mockable adb.

Test scenarios:
  - Child alive throughout: alive_at_max_wait=True, runtime_ms accumulates
  - Child exits (stat unreadable mid-poll): exit_observed_at set, runtime_ms = last - first
  - Child becomes zombie (state='Z'): treated as exit
  - Stat parsing edge cases: comm with parens, malformed text
"""
import pytest
from viewer.proc_poll import parse_proc_stat, poll_child_lifecycle


def test_parse_proc_stat_basic():
    sample = ("12345 (com.example.app) S 1 12345 12345 0 -1 4194560 "
              "100 0 0 0 0 0 0 0 20 0 1 0 100000 5000000 1234 18446744073709551615 "
              "1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
    p = parse_proc_stat(sample)
    assert p is not None
    assert p["pid"] == 12345
    assert p["comm"] == "com.example.app"
    assert p["state"] == "S"
    # starttime = field 22 (post-comm idx 19) = "100000"
    assert p["starttime_jiffies"] == 100000


def test_parse_proc_stat_comm_with_parens():
    """comm can contain ')'. Use rfind for ')'"""
    sample = ("999 (sh) Foo) Z 1 999 999 0 -1 0 "
              "0 0 0 0 0 0 0 0 20 0 1 0 200 1000 0 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0\n")
    p = parse_proc_stat(sample)
    assert p is not None
    assert p["pid"] == 999
    assert p["comm"] == "sh) Foo"
    assert p["state"] == "Z"


def test_parse_proc_stat_empty_or_malformed():
    assert parse_proc_stat("") is None
    assert parse_proc_stat("garbage no parens") is None
    assert parse_proc_stat("(only paren") is None


def test_poll_child_lifecycle_alive_then_exits():
    """Mock adb returns stat 3 times, then non-zero → child gone."""
    sample_alive = ("123 (test) R 1 123 123 0 -1 0 "
                    "0 0 0 0 0 0 0 0 20 0 1 0 1000 1000 0 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0")
    call_count = [0]
    def fake_adb(args):
        call_count[0] += 1
        if call_count[0] <= 3:
            return (0, sample_alive, "")
        return (1, "", "No such file or directory")
    r = poll_child_lifecycle(123, max_wait_sec=5.0,
                              poll_interval_sec=0.01, adb_shell_fn=fake_adb)
    assert r["child_pid"] == 123
    assert r["first_observed_at"] is not None
    assert r["last_observed_at"] is not None
    assert r["exit_observed_at"] is not None
    assert r["alive_at_max_wait"] is False
    assert r["runtime_ms"] is not None
    assert r["polls_alive"] == 3
    assert r["comm"] == "test"


def test_poll_child_lifecycle_immediate_exit():
    """Stat unreadable from first poll → never observed alive."""
    def fake_adb(args):
        return (1, "", "No such file or directory")
    r = poll_child_lifecycle(456, max_wait_sec=1.0,
                              poll_interval_sec=0.01, adb_shell_fn=fake_adb)
    assert r["first_observed_at"] is None
    assert r["alive_at_max_wait"] is False
    assert r["runtime_ms"] is None


def test_poll_child_lifecycle_zombie_treated_as_exit():
    """state='Z' → exit_observed_at set, loop exits."""
    sample_z = ("789 (zomb) Z 1 789 789 0 -1 0 "
                "0 0 0 0 0 0 0 0 20 0 1 0 5000 1000 0 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0")
    def fake_adb(args):
        return (0, sample_z, "")
    r = poll_child_lifecycle(789, max_wait_sec=5.0,
                              poll_interval_sec=0.01, adb_shell_fn=fake_adb)
    assert r["last_state"] == "Z"
    assert r["exit_observed_at"] is not None
    assert r["alive_at_max_wait"] is False


def test_poll_child_lifecycle_max_wait():
    """Child stays alive past max_wait → alive_at_max_wait=True."""
    sample_alive = ("321 (longrun) S 1 321 321 0 -1 0 "
                    "0 0 0 0 0 0 0 0 20 0 1 0 1000 1000 0 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0")
    def fake_adb(args):
        return (0, sample_alive, "")
    r = poll_child_lifecycle(321, max_wait_sec=0.05,
                              poll_interval_sec=0.01, adb_shell_fn=fake_adb)
    assert r["alive_at_max_wait"] is True
    assert r["polls_alive"] >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
