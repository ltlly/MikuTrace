"""Regression test: BN field_at endpoint and consumer wiring.

Without a real BN bndb loaded, /api/field-at must gracefully return
{hit: False} instead of erroring. The endpoint and the one_record
consumer should both tolerate DECOMP being unavailable.
"""
import struct, json, pytest


@pytest.fixture
def synth_trace_dir(tmp_path):
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_5r_50ms"; cd.mkdir()
    base = 0x100000
    # ldr x9, [x8, #0x80] = 0xf9404109
    ldr = 0xf9404109
    nop = 0xd503201f
    ret = 0xd65f03c0
    bf = open(cd / "trace.bin", "wb")
    for i, insn in enumerate([ldr, nop, nop, nop, ret]):
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", insn))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 5}, open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(synth_trace_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    return TestClient(make_app(synth_trace_dir))


def test_field_at_no_decomp(client):
    """Endpoint must return hit=False when BN backend not loaded."""
    r = client.get("/api/field-at?pc=0x100000&reg=x8&offset=0x80").json()
    assert r["hit"] is False
    assert r["pc"] == "0x100000"
    assert r["reg"] == "x8"
    assert r["offset"] == 128
    assert r["struct"] is None
    assert r["field"] is None


def test_field_at_invalid_pc(client):
    """Invalid pc string still returns hit=False, not 500."""
    r = client.get("/api/field-at?pc=not-a-number&reg=x0").json()
    assert r["hit"] is False


def test_record_with_ldr_mem_op_no_decomp(client):
    """one_record must not crash on ldr insn when DECOMP not ready."""
    r = client.get("/api/record/0").json()
    assert "regs_annotated" in r
    assert "asm" in r
    assert r["asm"].startswith("ldr")
