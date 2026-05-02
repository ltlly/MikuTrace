"""P0-2: /api/jni-events exposes Trace.jni_events for Web SPA "JNI Calls" tab."""
import json, struct, pytest
from fastapi.testclient import TestClient


def _make_trace_with_jni(tmp_path, events):
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_jni"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    for i in range(3):
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", 0xd503201f))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 3, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    with open(cd / "jni_hooks.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return cd


@pytest.fixture
def client(tmp_path):
    events = [
        {"id": "GetStringUTFChars", "trace_idx": 0, "ret": "user_id_123"},
        {"id": "NewStringUTF", "trace_idx": 1, "args": {"bytes": "x-sign"}},
        {"id": "NewStringUTF", "trace_idx": 2, "args": {"bytes": "AABBCC"}},
    ]
    cd = _make_trace_with_jni(tmp_path, events)
    from webui.server import make_app
    return TestClient(make_app(cd))


def test_jni_events_endpoint_returns_all(client):
    r = client.get("/api/jni-events").json()
    assert "events" in r
    assert r["count"] == 3
    assert r["events"][0]["id"] == "GetStringUTFChars"
    assert r["events"][1]["args"]["bytes"] == "x-sign"


def test_jni_events_filter_by_id(client):
    """?id=NewStringUTF should filter to 2 events."""
    r = client.get("/api/jni-events?id=NewStringUTF").json()
    assert r["count"] == 2
    assert all(e["id"] == "NewStringUTF" for e in r["events"])


def test_jni_events_idx_range(client):
    """idx_lo=1 idx_hi=3 should return 2 events (idx 1, 2)."""
    r = client.get("/api/jni-events?idx_lo=1&idx_hi=3").json()
    assert r["count"] == 2
    for e in r["events"]:
        assert 1 <= e["trace_idx"] < 3


def test_jni_events_empty_when_no_file(tmp_path):
    """Trace without jni_hooks.jsonl → empty events."""
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_jni_empty"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    bf.write(struct.pack("<Q", base))
    for _ in range(31): bf.write(struct.pack("<Q", 0))
    bf.write(struct.pack("<Q", 0x7000))
    bf.write(struct.pack("<I", 0))
    bf.write(struct.pack("<I", 0xd503201f))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 1, "ms": 1,
               "retval": "0x0", "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    from webui.server import make_app
    client = TestClient(make_app(cd))
    r = client.get("/api/jni-events").json()
    assert r["count"] == 0
    assert r["events"] == []


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
