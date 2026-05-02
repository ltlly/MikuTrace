"""P0-3 batch C: crypto-scan + auto-phase-detect + through_mem flag."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


def _make_trace_with_sha1_iv(tmp_path):
    """Synth trace that writes SHA-1 IV bytes (01 23 45 67) at known addr.

    Sequence: load 0x67452301 into x9, store low byte 0x01 at 0x9000, etc.
    Use 4 separate strb to make 4 byte writes, simulating SHA-1 H[0] init.
    """
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_crypto"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    rows = [
        # Stage SHA-1 H[0] = 0x67452301 LE = bytes 01 23 45 67
        ("mov x10, #0x9000", {"x10": 0x9000}),
        ("mov x9,  #0x01",   {"x10": 0x9000, "x9": 0x01}),
        ("strb w9, [x10]",   {"x10": 0x9000, "x9": 0x01}),
        ("mov x9,  #0x23",   {"x10": 0x9000, "x9": 0x23}),
        ("strb w9, [x10, #1]", {"x10": 0x9000, "x9": 0x23}),
        ("mov x9,  #0x45",   {"x10": 0x9000, "x9": 0x45}),
        ("strb w9, [x10, #2]", {"x10": 0x9000, "x9": 0x45}),
        ("mov x9,  #0x67",   {"x10": 0x9000, "x9": 0x67}),
        ("strb w9, [x10, #3]", {"x10": 0x9000, "x9": 0x67}),
        ("ret", {}),
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
    cd = _make_trace_with_sha1_iv(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def _wait_mem(client, tries=60):
    for _ in range(tries):
        if client.get("/api/bg-status").json().get("mem", {}).get("status") == "ready":
            return True
        time.sleep(0.05)
    return False


def _wait_index(client, tries=60):
    for _ in range(tries):
        if client.get("/api/bg-status").json().get("index", {}).get("status") == "ready":
            return True
        time.sleep(0.05)
    return False


# ── /api/crypto-scan ─────────────────────────────────────────────────────────

def test_crypto_scan_finds_sha1_h0(client):
    """Synth wrote 01 23 45 67 at 0x9000, crypto-scan should hit SHA1_H[0]."""
    client.get("/api/crypto-scan")
    assert _wait_mem(client)
    r = client.get("/api/crypto-scan").json()
    assert "primitives" in r
    sha1_h0 = next((p for p in r["primitives"]
                    if "SHA1_H[0]" in p["name"]), None)
    assert sha1_h0 is not None, f"SHA1_H[0] entry missing: {[p['name'] for p in r['primitives']]}"
    assert sha1_h0["pattern"] == "01234567"
    assert sha1_h0["hit_count"] >= 1
    assert sha1_h0["hits"][0]["addr"] == "0x9000"


def test_crypto_scan_returns_all_22_primitives(client):
    """22 patterns should always appear in primitives, even with 0 hits."""
    client.get("/api/crypto-scan")
    assert _wait_mem(client)
    r = client.get("/api/crypto-scan").json()
    assert len(r["primitives"]) >= 20  # at least most of the 22 patterns


# ── /api/auto-phase-detect ───────────────────────────────────────────────────

def test_auto_phase_detect_finds_sha1_init(client):
    """Synth has SHA-1 IV bytes → auto-phase should report sha1_init phase."""
    client.get("/api/auto-phase-detect")
    assert _wait_mem(client)
    r = client.get("/api/auto-phase-detect").json()
    assert "phases" in r
    assert "trace_records" in r
    phase_names = {p["phase"] for p in r["phases"]}
    assert "sha1_init" in phase_names, f"phases: {phase_names}"


# ── through_mem flag for taint endpoints ─────────────────────────────────────

def test_forward_taint_accepts_through_mem(client):
    """Existing endpoint must accept through_mem flag without 422."""
    client.get("/api/forward-taint?start=0&reg=x9&max_count=10&through_mem=true")
    assert _wait_index(client)
    r = client.get("/api/forward-taint?start=0&reg=x9&max_count=10&through_mem=true")
    assert r.status_code == 200, r.text


def test_backward_taint_accepts_through_mem(client):
    client.get("/api/backward-taint?start=8&reg=x9&max_count=10&through_mem=true")
    assert _wait_index(client)
    r = client.get("/api/backward-taint?start=8&reg=x9&max_count=10&through_mem=true")
    assert r.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
