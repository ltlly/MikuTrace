"""P1-C (partial): viewer reads fork_events from meta.json + endpoint."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


SAMPLE_FORK_EVENT = {
    "type": "fork-event",
    "trace_idx": 1234,
    "parent_pc": "0x7608ed1234",
    "parent_pc_rel": "0x6b234",
    "parent_func": "sub_1a200",
    "syscall": "clone",
    "clone_flags": "0x1200011",
    "is_fork_like": True,
    "child_pid": 12345,
    "ts": 1730000000123,
    "attach_status": "success",
    "instructions_traced": 87234,
    "exit_code": 0,
    "runtime_ms": 234,
    "notes": "",
}


def _make_trace_with_fork(tmp_path, fork_events):
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_fork"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    bf.write(struct.pack("<Q", base))
    for _ in range(31): bf.write(struct.pack("<Q", 0))
    bf.write(struct.pack("<Q", 0x7000))
    bf.write(struct.pack("<I", 0))
    bf.write(struct.pack("<I", 0xd503201f))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 1, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False,
               "fork_events": fork_events},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    return cd


def test_trace_meta_fork_events_loaded(tmp_path):
    """Trace.meta.fork_events populated from per-call meta.json."""
    from viewer.trace import load
    cd = _make_trace_with_fork(tmp_path, [SAMPLE_FORK_EVENT])
    t = load(cd)
    assert len(t.meta.fork_events) == 1
    assert t.meta.fork_events[0]["child_pid"] == 12345
    assert t.meta.fork_events[0]["attach_status"] == "success"
    t.close()


def test_trace_meta_fork_events_empty_when_absent(tmp_path):
    from viewer.trace import load
    cd = _make_trace_with_fork(tmp_path, [])
    t = load(cd)
    assert t.meta.fork_events == []
    t.close()


def test_fork_events_endpoint_returns_all(tmp_path):
    from webui.server import make_app
    cd = _make_trace_with_fork(tmp_path, [
        SAMPLE_FORK_EVENT,
        {**SAMPLE_FORK_EVENT, "trace_idx": 9999, "child_pid": 9999,
         "attach_status": "failed_ptrace_conflict"},
    ])
    client = TestClient(make_app(cd))
    r = client.get("/api/fork-events").json()
    assert r["count"] == 2
    assert len(r["events"]) == 2


def test_fork_events_endpoint_filter_by_status(tmp_path):
    from webui.server import make_app
    cd = _make_trace_with_fork(tmp_path, [
        SAMPLE_FORK_EVENT,
        {**SAMPLE_FORK_EVENT, "child_pid": 9999,
         "attach_status": "failed_ptrace_conflict"},
    ])
    client = TestClient(make_app(cd))
    r = client.get("/api/fork-events?status=failed_ptrace_conflict").json()
    assert r["count"] == 1
    assert r["events"][0]["child_pid"] == 9999


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
