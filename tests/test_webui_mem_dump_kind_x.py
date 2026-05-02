"""P0-4: /api/mem-dump returns kind='x' for external writes (so frontend
can render distinct color)."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


def _make_trace(tmp_path):
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_extdump"; cd.mkdir()
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
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    # external_writes.bin: byte 0xAB at 0xb0000000 attributed to trace idx 1
    with open(cd / "external_writes.bin", "wb") as f:
        f.write(struct.pack("<QQB", 1, 0xb0000000, 0xab))
    return cd


def test_mem_dump_returns_kind_x_for_external_write(tmp_path):
    """Frontend P0-4 needs kind='x' so it can render purple/violet color."""
    cd = _make_trace(tmp_path)
    from webui.server import make_app
    client = TestClient(make_app(cd))
    # trigger mem build and wait
    for _ in range(40):
        r = client.get("/api/mem-dump?addr=0xb0000000&count=1").json()
        if r.get("status") == "ready": break
        time.sleep(0.05)
    assert r["bytes"][0]["byte"] == 0xab
    assert r["bytes"][0]["kind"] == "x", \
        f"external write must be kind='x' so frontend can color it distinct: {r['bytes'][0]}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
