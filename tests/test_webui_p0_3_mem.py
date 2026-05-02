"""P0-3 batch B: mem endpoints (mem-writes-in-range, mem-flow,
find-mem-pattern with idx_lo/idx_hi flags)."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


def _make_trace_with_writes(tmp_path):
    """Synth trace with explicit memory writes:
       idx 0: mov x9, #0x42  (sets x9=0x42)
       idx 1: mov x10, #0x8000 (addr base)
       idx 2: strb w9, [x10]   (write 1 byte 0x42 at 0x8000)
       idx 3: strb w9, [x10, #1] (write 0x42 at 0x8001)
       idx 4: ldrb w11, [x10]   (read at 0x8000 — for mem-flow)
       idx 5: ret
    """
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_mem"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    rows = [
        ("mov x9, #0x42",      {"x9": 0x42}),
        ("mov x10, #0x8000",   {"x9": 0x42, "x10": 0x8000}),
        ("strb w9, [x10]",     {"x9": 0x42, "x10": 0x8000}),
        ("strb w9, [x10, #1]", {"x9": 0x42, "x10": 0x8000}),
        ("ldrb w11, [x10]",    {"x9": 0x42, "x10": 0x8000, "x11": 0x42}),
        ("ret",                {"x9": 0x42, "x10": 0x8000, "x11": 0x42}),
    ]
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
    return cd


@pytest.fixture
def client(tmp_path):
    cd = _make_trace_with_writes(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def _wait_mem(client, tries=60):
    for _ in range(tries):
        if client.get("/api/bg-status").json().get("mem", {}).get("status") == "ready":
            return True
        time.sleep(0.05)
    return False


# ── /api/mem-writes-in-range ─────────────────────────────────────────────────

def test_mem_writes_in_range_basic(client):
    """idx_lo=0 idx_hi=6: should find 2 byte writes (idx 2 and 3)."""
    client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6")
    assert _wait_mem(client)
    r = client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6").json()
    assert "writes" in r
    assert r["matched"] >= 2
    assert "idx_range" in r
    assert r["idx_range"] == [0, 6]
    # check first write structure
    w = r["writes"][0]
    assert "idx" in w
    assert "pc" in w
    assert "dst_addr" in w
    assert "size" in w
    assert "byte0" in w


def test_mem_writes_in_range_src_byte_filter(client):
    """--src-byte 0x42 should only return writes with low byte = 0x42."""
    client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6&src_byte=0x42")
    assert _wait_mem(client)
    r = client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6&src_byte=0x42").json()
    for w in r["writes"]:
        assert w["byte0"] == 0x42


def test_mem_writes_in_range_addr_filter(client):
    """addr filter: only addr=0x8000 (idx 2)."""
    client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6&addr_lo=0x8000&addr_hi=0x8001")
    assert _wait_mem(client)
    r = client.get("/api/mem-writes-in-range?idx_lo=0&idx_hi=6&addr_lo=0x8000&addr_hi=0x8001").json()
    for w in r["writes"]:
        assert int(w["dst_addr"], 16) == 0x8000


# ── /api/mem-flow ────────────────────────────────────────────────────────────

def test_mem_flow_basic(client):
    """addr=0x8000, count=1 should show write+read events."""
    client.get("/api/mem-flow?addr=0x8000&count=1")
    assert _wait_mem(client)
    r = client.get("/api/mem-flow?addr=0x8000&count=1").json()
    assert r["addr"] == "0x8000"
    assert r["count"] == 1
    assert len(r["bytes"]) == 1
    b = r["bytes"][0]
    assert b["addr"] == "0x8000"
    # at least 1 write event (idx=2)
    assert len(b["events"]) >= 1
    kinds = {e["kind"] for e in b["events"]}
    assert "w" in kinds


def test_mem_flow_writers_only(client):
    client.get("/api/mem-flow?addr=0x8000&count=1&writers_only=true")
    assert _wait_mem(client)
    r = client.get("/api/mem-flow?addr=0x8000&count=1&writers_only=true").json()
    for b in r["bytes"]:
        for e in b["events"]:
            assert e["kind"] in ("w", "x"), f"writers_only should filter reads"


# ── /api/find-mem-pattern + idx_lo/idx_hi flags ──────────────────────────────

def test_find_mem_pattern_with_idx_range(client):
    """find-mem-pattern with idx_lo/idx_hi flags filter by first_idx."""
    client.get("/api/find-mem-pattern?bytes_hex=42&idx_lo=0&idx_hi=10")
    assert _wait_mem(client)
    r = client.get("/api/find-mem-pattern?bytes_hex=42&idx_lo=0&idx_hi=10").json()
    # all hits' first_idx should be in [0, 10)
    for h in r["hits"]:
        assert 0 <= h["first_idx"] < 10


def test_find_mem_pattern_idx_range_excludes(client):
    """idx_lo=999 should return zero hits (no writes after idx 999)."""
    client.get("/api/find-mem-pattern?bytes_hex=42&idx_lo=999")
    assert _wait_mem(client)
    r = client.get("/api/find-mem-pattern?bytes_hex=42&idx_lo=999").json()
    assert r["count"] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
