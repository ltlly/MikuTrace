"""P0-5 webui: /api/forward-taint and /api/backward-taint emit stopped_at_max."""
import json, struct, pytest, time, pathlib
from fastapi.testclient import TestClient


def _make_long_chain_trace(tmp_path, n_records=20):
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_taint"
    cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    seq = ["mov x0, #1"]
    for i in range(1, n_records):
        seq.append("mov x1, x0" if i % 2 == 1 else "mov x0, x1")
    for i, asm in enumerate(seq):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n_records, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


def _wait_index(client, tries=40):
    for _ in range(tries):
        j = client.get("/api/bg-status").json()
        st = j.get("index", {}).get("status") if isinstance(j, dict) else None
        if st == "ready": return j
        time.sleep(0.05)
    return None


@pytest.fixture
def client(tmp_path):
    cd = _make_long_chain_trace(tmp_path, n_records=20)
    from webui.server import make_app
    return TestClient(make_app(cd))


def test_backward_taint_emits_stopped_at_max_capped(client):
    """20-step chain, max_count=3 → stopped_at_max=true."""
    client.get("/api/backward-taint?start=19&reg=x0&max_count=3")
    _wait_index(client)
    r = client.get("/api/backward-taint?start=19&reg=x0&max_count=3").json()
    assert "stopped_at_max" in r, f"missing stopped_at_max: {r}"
    assert r["stopped_at_max"] is True


def test_backward_taint_emits_stopped_at_max_natural(client):
    client.get("/api/backward-taint?start=19&reg=x0&max_count=5000")
    _wait_index(client)
    r = client.get("/api/backward-taint?start=19&reg=x0&max_count=5000").json()
    assert r["stopped_at_max"] is False


def test_forward_taint_emits_stopped_at_max_capped(client):
    client.get("/api/forward-taint?start=0&reg=x0&max_count=3")
    _wait_index(client)
    r = client.get("/api/forward-taint?start=0&reg=x0&max_count=3").json()
    assert "stopped_at_max" in r
    assert r["stopped_at_max"] is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
