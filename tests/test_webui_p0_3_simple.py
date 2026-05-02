"""P0-3 batch A: simple read-only endpoints (reg-at-idx, call-chain)."""
import json, struct, pytest
from fastapi.testclient import TestClient


def _make_trace(tmp_path):
    """Synth: 'mov x0, #0x1234' + 'mov x14, #5' + 'nop' x2 + 'ret'."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_simple"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")

    # Build records explicitly with non-zero regs at specific idx
    rows = [
        ("mov x0, #0x1234", {"x0": 0x1234, "x14": 5, "lr": 0x100100}),
        ("mov x14, #5",      {"x0": 0x1234, "x14": 5, "lr": 0x100100}),
        ("nop",              {"x0": 0x1234, "x14": 5, "lr": 0x100100}),
        ("nop",              {"x0": 0x1234, "x14": 5, "lr": 0x100100}),
        ("ret",              {"x0": 0x1234, "x14": 5, "lr": 0x100100}),
    ]
    for i, (asm, regs) in enumerate(rows):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        # 31 GPRs + sp + nzcv + inst
        for r_idx in range(31):
            name = f"x{r_idx}" if r_idx < 29 else ("fp" if r_idx == 29 else "lr")
            v = regs.get(name, 0)
            bf.write(struct.pack("<Q", v))
        bf.write(struct.pack("<Q", 0x7000))  # sp
        bf.write(struct.pack("<I", 0))       # nzcv
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
    cd = _make_trace(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


# ── /api/reg-at-idx ──────────────────────────────────────────────────────────

def test_reg_at_idx_basic(client):
    """idx=0, default regs: x0 should be 0x1234, x14 should be 5."""
    r = client.get("/api/reg-at-idx?idx=0").json()
    assert r["idx"] == 0
    assert r["pc"].startswith("0x")
    assert "regs" in r
    assert r["regs"]["x0"]["hex"] == "0x1234"
    assert r["regs"]["x0"]["dec"] == 0x1234
    assert r["regs"]["x0"]["byte0"] == 0x34
    assert r["regs"]["x14"]["dec"] == 5


def test_reg_at_idx_explicit_regs(client):
    """User passes ?regs=x0,sp."""
    r = client.get("/api/reg-at-idx?idx=0&regs=x0,sp").json()
    assert "x0" in r["regs"]
    assert "sp" in r["regs"]
    assert "x14" not in r["regs"], "explicit regs filter should drop x14"


def test_reg_at_idx_out_of_range(client):
    """idx beyond trace → 400 or error JSON."""
    resp = client.get("/api/reg-at-idx?idx=99999")
    assert resp.status_code >= 400


# ── /api/call-chain ──────────────────────────────────────────────────────────

def test_call_chain_basic(client):
    r = client.get("/api/call-chain?idx=0&depth=2").json()
    assert r["start_idx"] == 0
    assert "chain" in r
    assert isinstance(r["chain"], list)
    assert r["depth"] >= 1
    e0 = r["chain"][0]
    assert e0["idx"] == 0
    assert "lr" in e0
    assert "caller_pc" in e0


def test_call_chain_default_depth(client):
    """depth not specified → reasonable default."""
    r = client.get("/api/call-chain?idx=0").json()
    assert r["depth"] >= 1


def test_call_chain_out_of_range(client):
    resp = client.get("/api/call-chain?idx=99999&depth=1")
    assert resp.status_code >= 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
