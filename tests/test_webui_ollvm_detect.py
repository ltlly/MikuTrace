"""P1-D: /api/ollvm-detect-vm endpoint smoke."""
import json, struct, pytest
from fastapi.testclient import TestClient


def _make_trace_with_indirect_brs(tmp_path):
    """Synth: many ldr+br pairs to trigger VM-detect heuristic."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_vm"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    rows = []
    for _ in range(50):
        rows.append("ldr x9, [x10, x11, lsl #3]")
        rows.append("br x9")
    n = len(rows)
    for i, asm in enumerate(rows):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(tmp_path):
    cd = _make_trace_with_indirect_brs(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def test_ollvm_detect_endpoint_basic(client):
    r = client.get("/api/ollvm-detect-vm").json()
    assert "candidates" in r
    assert r["count"] >= 1
    c = r["candidates"][0]
    assert "confidence" in c
    assert "reason" in c
    assert "hint" in c


def test_ollvm_detect_endpoint_threshold(client):
    """High threshold may return empty."""
    r = client.get("/api/ollvm-detect-vm?threshold=0.99").json()
    assert "candidates" in r


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
