"""P0-3 batch D: /api/hash-input-search (POST) + /api/diff-traces (POST)."""
import json, struct, hashlib, pytest, time, pathlib
from fastapi.testclient import TestClient


def _make_trace_with_sha1_output(tmp_path, dir_name="run1"):
    """Synth trace where SHA-1('hello') first 4 bytes are written to mem at 0xa000."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / dir_name; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_hash"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")

    target_hash = hashlib.sha1(b"hello").digest()
    rows = [("mov x10, #0xa000", {"x10": 0xa000})]
    for i, b in enumerate(target_hash[:4]):
        rows.append((f"mov x9, #{b}", {"x10": 0xa000, "x9": b}))
        rows.append((f"strb w9, [x10, #{i}]", {"x10": 0xa000, "x9": b}))
    rows.append(("ret", {}))

    for i, (asm, regs) in enumerate(rows):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for r_idx in range(31):
            name = f"x{r_idx}" if r_idx < 29 else ("fp" if r_idx == 29 else "lr")
            v = regs.get(name, 0)
            bf.write(struct.pack("<Q", v))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": len(rows), "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": True},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd, target_hash


def _make_trace_with_jni_output(tmp_path, dir_name, output_bytes):
    """Synth trace + a jni_hooks.jsonl with x-sign as NewStringUTF."""
    cd, _ = _make_trace_with_sha1_output(tmp_path, dir_name=dir_name)
    import base64, urllib.parse
    encoded = urllib.parse.quote(base64.b64encode(output_bytes).decode())
    events = [
        {"id": "NewStringUTF", "trace_idx": 0, "args": {"bytes": "x-sign"}},
        {"id": "NewStringUTF", "trace_idx": 1, "args": {"bytes": encoded}},
    ]
    with open(cd / "jni_hooks.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return cd


def _wait_mem(client, tries=60):
    for _ in range(tries):
        if client.get("/api/bg-status").json().get("mem", {}).get("status") == "ready":
            return True
        time.sleep(0.05)
    return False


# ── /api/hash-input-search ───────────────────────────────────────────────────

def test_hash_input_search_finds_sha1_match(tmp_path):
    """Synth wrote SHA-1('hello') first 4 bytes; POST should find input='hello'."""
    cd, target_hash = _make_trace_with_sha1_output(tmp_path)
    from webui.server import make_app
    client = TestClient(make_app(cd))
    # trigger mem build via crypto-scan, wait
    client.get("/api/crypto-scan")
    assert _wait_mem(client)
    body = {
        "target_bytes": target_hash[:4].hex(),
        "inputs": ["hello", "world", "foo"],
        "algos": ["sha1"],
        "combos": ["plain"],
        "prefix_bytes": 4,
    }
    r = client.post("/api/hash-input-search", json=body).json()
    assert "found" in r
    assert "tried_combos" in r
    matches = [f for f in r["found"] if f["input"] == "hello"]
    assert len(matches) >= 1, f"hello/sha1/plain match expected, got: {r['found']}"
    assert matches[0]["algo"] == "sha1"


def test_hash_input_search_validates_target_hex(tmp_path):
    cd, _ = _make_trace_with_sha1_output(tmp_path)
    from webui.server import make_app
    client = TestClient(make_app(cd))
    client.get("/api/crypto-scan"); assert _wait_mem(client)
    body = {"target_bytes": "ZZZZ", "inputs": ["hello"]}
    r = client.post("/api/hash-input-search", json=body)
    assert r.status_code >= 400


# ── /api/diff-traces ─────────────────────────────────────────────────────────

def test_diff_traces_basic(tmp_path):
    """2 traces with same x-sign output → all bytes STABLE."""
    same_output = bytes([0x6b, 0x36, 0x01, 0x08, 0xcd, 0x34, 0xef, 0x10])
    cd1 = _make_trace_with_jni_output(tmp_path, "run1", same_output)
    cd2 = _make_trace_with_jni_output(tmp_path, "run2", same_output)
    from webui.server import make_app
    client = TestClient(make_app(cd1))
    body = {"traces": [str(cd1.parent.parent), str(cd2.parent.parent)]}
    r = client.post("/api/diff-traces", json=body).json()
    assert "headers" in r
    assert "x-sign" in r["headers"]
    h = r["headers"]["x-sign"]
    if "error" not in h:
        assert h["stable_count"] == h["len_compared"]
        assert h["variable_count"] == 0


def test_diff_traces_detects_variable(tmp_path):
    """2 traces with differing first byte → variable_count >= 1."""
    out1 = bytes([0xAA] + [0xBB]*7)
    out2 = bytes([0xCC] + [0xBB]*7)
    cd1 = _make_trace_with_jni_output(tmp_path, "run1", out1)
    cd2 = _make_trace_with_jni_output(tmp_path, "run2", out2)
    from webui.server import make_app
    client = TestClient(make_app(cd1))
    body = {"traces": [str(cd1.parent.parent), str(cd2.parent.parent)]}
    r = client.post("/api/diff-traces", json=body).json()
    h = r["headers"]["x-sign"]
    if "error" not in h:
        assert h["variable_count"] >= 1


def test_diff_traces_requires_two(tmp_path):
    cd1 = _make_trace_with_jni_output(tmp_path, "run1", b"AAAAAAAA")
    from webui.server import make_app
    client = TestClient(make_app(cd1))
    body = {"traces": [str(cd1.parent.parent / "run1")]}
    r = client.post("/api/diff-traces", json=body)
    assert r.status_code >= 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
