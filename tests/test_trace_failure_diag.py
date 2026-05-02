"""P0-6: trace failure diagnostic — match logcat/tombstone signatures
to actionable hints (SI_USER → anti-debug, SIGABRT in frida-agent → self-recursion,
TimedOut → spawn-gating).

This is the ONLY official coupling point between traceMiku and miku-shield —
when L3+ anti-debug detected, recommend the sister project URL.
"""
import pytest
from tracemiku_diag import diagnose_trace_failure


def test_anti_debug_si_user_one_frame_tombstone():
    """SI_USER + 1-frame stack (kernel-injected SIGSEGV from anti-debug self-kill)
    should yield 'L3+ anti-debug suspected, recommend miku-shield'."""
    tombstone = """
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'foo/bar'
ABI: 'arm64'
Process uptime: 12s
pid: 12345, tid: 12345, name: com.example.app  >>> com.example.app <<<
signal 11 (SIGSEGV), code 0 (SI_USER), fault addr 0x0
backtrace:
      #00 pc 00000000000abc12  /system/lib64/libc.so (tgkill+8)
"""
    hints = diagnose_trace_failure(logcat="", tombstone=tombstone, exception=None)
    assert any("反调试" in h or "anti-debug" in h.lower() for h in hints), \
        f"SI_USER+1-frame should flag anti-debug: {hints}"
    assert any("miku-shield" in h for h in hints), \
        f"should recommend miku-shield: {hints}"


def test_sigabrt_in_frida_agent_so():
    """SIGABRT crash with libfrida-agent.so in stack → Frida self-recursion."""
    tombstone = """
pid: 23456, tid: 23456, name: com.target.app
signal 6 (SIGABRT)
backtrace:
      #00 pc 00000000aaaa  /data/local/tmp/re.frida.server/libfrida-agent.so
      #01 pc 00000000bbbb  /data/local/tmp/re.frida.server/libfrida-agent.so
      #02 pc 00000000cccc  /apex/com.android.runtime/lib64/bionic/libc.so (pthread_mutex_lock+...)
"""
    hints = diagnose_trace_failure(logcat="", tombstone=tombstone, exception=None)
    assert any("自递归" in h or "frida self" in h.lower()
               or "boundary-diff" in h for h in hints), \
        f"frida-agent SIGABRT should flag self-recursion: {hints}"


def test_spawn_gating_timeout():
    """frida.TimedOutError on attach → spawn-gating issue."""
    class FakeTimedOut(Exception): pass
    e = FakeTimedOut("Timed out while waiting for spawn")
    e.__class__.__name__ = "TimedOutError"
    hints = diagnose_trace_failure(logcat="", tombstone="", exception=e)
    assert any("spawn-gating" in h.lower() or "spawn gating" in h.lower()
               or "frida-server" in h.lower() for h in hints), \
        f"TimedOutError should flag spawn-gating: {hints}"


def test_no_diag_when_clean():
    """Clean logcat + no exception → no false-positive hints."""
    hints = diagnose_trace_failure(logcat="...normal log lines...",
                                    tombstone="", exception=None)
    assert hints == [] or all("?" in h for h in hints), \
        f"clean state should produce no hints (or only soft hints): {hints}"


def test_diag_returns_list_of_strings():
    """Return type contract: list[str], non-empty hint contains URL."""
    tombstone = "signal 11 (SIGSEGV), code 0 (SI_USER)\nbacktrace:\n  #00 pc 0 lib"
    hints = diagnose_trace_failure(logcat="", tombstone=tombstone, exception=None)
    assert isinstance(hints, list)
    assert all(isinstance(h, str) for h in hints)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
