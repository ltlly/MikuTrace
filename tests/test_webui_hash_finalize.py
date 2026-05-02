"""P1-B: /api/hash-finalize-detect endpoint smoke."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


def _make_trace_with_sha1_output(tmp_path):
    """20-byte u32 store at 0xa000 (SHA-1 output shape)."""
    nopw = 0xd503201f
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_finz"; cd.mkdir()
    n = 20
    bf = open(cd / "trace.bin", "wb")
    for i in range(n):
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", nopw))
    bf.close()
    # 5 u32 writes at 0xa000+0,4,8,12,16 across idx 5..9
    ef = open(cd / "external_writes.bin", "wb")
    h_vals = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    base_addr = 0xa000
    for i, v in enumerate(h_vals):
        for o in range(4):
            b = (v >> (o * 8)) & 0xff
            ef.write(struct.pack("<QQB", 5 + i, base_addr + i * 4 + o, b))
    ef.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(tmp_path):
    cd = _make_trace_with_sha1_output(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def _wait_mem(client, tries=60):
    for _ in range(tries):
        if client.get("/api/bg-status").json().get("mem", {}).get("status") == "ready":
            return True
        time.sleep(0.05)
    return False


def test_hash_finalize_detect_endpoint_finds_sha1(client):
    """Synth has 5 × u32 stores at 0xa000 → endpoint finds sha1 candidate."""
    client.get("/api/hash-finalize-detect")
    assert _wait_mem(client)
    r = client.get("/api/hash-finalize-detect").json()
    assert "candidates" in r
    sha1_hit = next((c for c in r["candidates"]
                     if c["size"] == 20 and c["guess"] == "sha1"), None)
    assert sha1_hit is not None, f"no sha1 hit: {r}"
    assert sha1_hit["addr"] == hex(0xa000)


def test_hash_finalize_detect_window_param(client):
    """?window=10 (smaller than the 5-write spread) should not exclude this case
    (writes are within idx 5..9, span = 4)."""
    client.get("/api/hash-finalize-detect?window=10")
    assert _wait_mem(client)
    r = client.get("/api/hash-finalize-detect?window=10").json()
    assert r["window"] == 10


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
