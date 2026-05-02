"""P0-2: Trace.jni_events lazy-loaded from per-call dir's jni_hooks.jsonl."""
import json, struct, pytest


def _make_trace_with_jni(tmp_path, jni_events=None):
    """Per-call dir layout with optional jni_hooks.jsonl."""
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
        bf.write(struct.pack("<I", 0xd503201f))  # nop
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 3, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "method": "f",
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    if jni_events is not None:
        with open(cd / "jni_hooks.jsonl", "w") as f:
            for e in jni_events:
                f.write(json.dumps(e) + "\n")
    return cd


def test_jni_events_empty_when_no_file(tmp_path):
    """No jni_hooks.jsonl → jni_events is empty list, not None."""
    from viewer.trace import load
    cd = _make_trace_with_jni(tmp_path)
    t = load(cd)
    assert t.jni_events == []
    t.close()


def test_jni_events_loads_jsonl(tmp_path):
    """jni_hooks.jsonl with N events → t.jni_events has N dicts."""
    from viewer.trace import load
    events = [
        {"id": "GetStringUTFChars", "trace_idx": 0, "ret": "hello"},
        {"id": "NewStringUTF", "trace_idx": 1, "args": {"bytes": "x-sign"}},
        {"id": "NewStringUTF", "trace_idx": 2, "args": {"bytes": "AABBCC"}},
    ]
    cd = _make_trace_with_jni(tmp_path, jni_events=events)
    t = load(cd)
    assert len(t.jni_events) == 3
    assert t.jni_events[0]["id"] == "GetStringUTFChars"
    assert t.jni_events[1]["args"]["bytes"] == "x-sign"
    t.close()


def test_jni_events_lazy_only_loads_once(tmp_path):
    """Accessing jni_events twice should not re-read the file."""
    from viewer.trace import load
    events = [{"id": "NewStringUTF", "trace_idx": 0, "args": {"bytes": "test"}}]
    cd = _make_trace_with_jni(tmp_path, jni_events=events)
    t = load(cd)
    a = t.jni_events
    b = t.jni_events
    assert a is b, "lazy property should return same list object"
    t.close()


def test_jni_events_skips_malformed_lines(tmp_path):
    """Malformed JSONL lines should be skipped, not crash."""
    from viewer.trace import load
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_jni"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    for i in range(2):
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", 0xd503201f))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 2, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    with open(cd / "jni_hooks.jsonl", "w") as f:
        f.write('{"id": "NewStringUTF", "trace_idx": 0}\n')
        f.write('{this is broken json\n')
        f.write('{"id": "GetStringUTFChars", "trace_idx": 1}\n')
    t = load(cd)
    assert len(t.jni_events) == 2
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
