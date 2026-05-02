"""P0-5 cleanup: server clamps unreasonable max_count to prevent 200MB+ DoS."""
import json, struct, pytest
from fastapi.testclient import TestClient


def _make_trace(tmp_path):
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_clamp"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    for i in range(10):
        inst, _ = ks.asm("nop")
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 10, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(tmp_path):
    cd = _make_trace(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def test_forward_taint_clamps_max_count(client):
    """Sending max_count=10000000 must not propagate to inner taint —
    server clamps to a safe ceiling (e.g. 50000)."""
    import time
    for _ in range(40):
        if client.get("/api/bg-status").json().get("index", {}).get("status") == "ready":
            break
        client.get("/api/forward-taint?start=0&reg=x0&max_count=10000000")
        time.sleep(0.05)
    r = client.get("/api/forward-taint?start=0&reg=x0&max_count=10000000").json()
    # echo: server reports back the clamped value via max_count_used or similar
    assert "max_count_used" in r, f"server should expose effective cap: {r}"
    assert r["max_count_used"] <= 50000, (
        f"server must clamp huge max_count to a safe ceiling (got {r['max_count_used']})")


def test_backward_taint_clamps_max_count(client):
    import time
    for _ in range(40):
        if client.get("/api/bg-status").json().get("index", {}).get("status") == "ready":
            break
        client.get("/api/backward-taint?start=5&reg=x0&max_count=10000000")
        time.sleep(0.05)
    r = client.get("/api/backward-taint?start=5&reg=x0&max_count=10000000").json()
    assert "max_count_used" in r
    assert r["max_count_used"] <= 50000


def test_taint_normal_max_count_passes_through(client):
    """Normal max_count values are NOT clamped."""
    import time
    for _ in range(40):
        if client.get("/api/bg-status").json().get("index", {}).get("status") == "ready":
            break
        client.get("/api/forward-taint?start=0&reg=x0&max_count=1000")
        time.sleep(0.05)
    r = client.get("/api/forward-taint?start=0&reg=x0&max_count=1000").json()
    assert r["max_count_used"] == 1000


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
