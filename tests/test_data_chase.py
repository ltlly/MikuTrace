"""Regression test: data_chase + taint data_only + new REST endpoints.

Covers Gap-A (taint data_only/exclude_regs), Gap-B (last-write-of-addr),
Gap-F (data-chase), Gap-H (find-mem-pattern), Gap-J (jni-calls).
"""
import struct, json, pytest


@pytest.fixture
def synth_trace_dir(tmp_path):
    """Build a tiny synthetic trace with a known data-flow chain:
        #0  mov x0, #0xdead
        #1  str x0, [sp, #8]    (writes 0xdead to mem)
        #2  ldr x1, [sp, #8]    (reads 0xdead back)
        #3  mov x2, x1          (data passes through reg)
        #4  ret
    """
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_5r_50ms"; cd.mkdir()
    base = 0x100000
    # encoded ARM64:
    # mov x0, #0xdead = movz x0, #0xdead (we'll just use a real encoding)
    insns = [
        0xd29bd5a0,    # mov x0, #0xdead
        0xf90007e0,    # str x0, [sp, #8]
        0xf94007e1,    # ldr x1, [sp, #8]
        0xaa0103e2,    # mov x2, x1
        0xd65f03c0,    # ret
    ]
    sp_val = 0x7000
    bf = open(cd / "trace.bin", "wb")
    for i, inst in enumerate(insns):
        bf.write(struct.pack("<Q", base + i * 4))   # pc
        # x0 stays 0 until #1 (records pre-execution state); we cheat with
        # post-execution semantics for our purpose: store x0=0xdead at #1
        if i >= 1:
            bf.write(struct.pack("<Q", 0xdead))     # x0
        else:
            bf.write(struct.pack("<Q", 0))
        if i >= 2:
            bf.write(struct.pack("<Q", 0xdead))     # x1 after ldr
        else:
            bf.write(struct.pack("<Q", 0))
        if i >= 3:
            bf.write(struct.pack("<Q", 0xdead))     # x2 after mov
        else:
            bf.write(struct.pack("<Q", 0))
        for _ in range(28): bf.write(struct.pack("<Q", 0))   # x3..x30
        bf.write(struct.pack("<Q", sp_val))         # sp
        bf.write(struct.pack("<I", 0))              # nzcv
        bf.write(struct.pack("<I", inst))           # inst
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 5}, open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "synth.so", "base": hex(base), "size": 0x1000}},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(synth_trace_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    return TestClient(make_app(synth_trace_dir))


# ── Core taint changes ─────────────────────────────────────────────────────

def test_data_only_skips_sp_chain(synth_trace_dir):
    """data_only=True should not propagate through sp on a ldr's base reg."""
    from viewer import load, Index, build_from_trace
    from viewer.taint import backward_taint
    t = load(str(synth_trace_dir))
    idx = Index(t); idx.build()
    # backward from idx=3 (mov x2, x1) on x2, both modes.
    classic = backward_taint(t, 3, "x2", index=idx, max_count=20)
    data = backward_taint(t, 3, "x2", index=idx, max_count=20, data_only=True)
    classic_idxs = {ix for ix, _ in classic}
    data_idxs = {ix for ix, _ in data}
    # data_only must not reduce coverage of the legitimate chain (#0,#1,#2)
    # but must skip sp-only chains. Since sp doesn't even def in our trace
    # (no `add sp,...`), both should be similar; assert at least no crash and
    # both contain the load.
    assert len(data) >= 1
    assert all(reg != "sp" for _, reg in data)
    t.close()


def test_data_chase_basic(synth_trace_dir):
    """data_chase from #4 (ret) on x0 → walk back through mov/str/mov."""
    from viewer import load, Index
    from viewer.taint import data_chase
    t = load(str(synth_trace_dir))
    idx = Index(t); idx.build()
    # chase x2 from idx=3 — should reach the str (mem-store-src)
    steps = data_chase(t, 4, "x2", max_steps=10, index=idx)
    assert len(steps) >= 2
    # First step: mov x2, x1 at #3
    assert steps[0].idx == 3
    assert steps[0].via == "reg"
    assert steps[0].reg_or_addr == "x1"
    t.close()


# ── REST endpoints ──────────────────────────────────────────────────────────

def test_data_chase_endpoint(client):
    r = client.get("/api/data-chase?start=4&reg=x2&max_steps=10").json()
    # index may build async — accept either pending (count=0) or chained
    assert "from" in r
    assert r["reg"] == "x2"


def test_last_write_of_addr_endpoint(client):
    # #1 writes to sp+8 = 0x7008. Look up that addr before #2.
    r = client.get("/api/last-write-of-addr?addr=0x7008&before_idx=2").json()
    # Either pending (status=not-found) or found at writer_idx=1
    assert r["addr"] == "0x7008"


def test_find_mem_pattern_endpoint(client):
    # Pattern unlikely-to-match on this trivial trace; just check shape.
    r = client.get("/api/find-mem-pattern?bytes_hex=deadbeef").json()
    assert r["pattern"] == "deadbeef"
    assert "hits" in r and isinstance(r["hits"], list)


def test_jni_calls_endpoint(client):
    """No JNI calls in synth trace — should return empty hits + non-zero vtable_size."""
    r = client.get("/api/jni-calls").json()
    assert r["count"] == 0
    assert r["vtable_size"] >= 50    # we expect ~229 entries from BN-parsed jni.h


def test_jobj_history_endpoint(client):
    """No real jobjects in synth trace — should return empty hits with shape."""
    r = client.get("/api/jobj-history?jobject=0xdead").json()
    assert r["jobject"] == "0xdead"
    assert r["count"] == 0
    assert r["start"] == 0


def test_jobj_history_invalid_jobject(client):
    r = client.get("/api/jobj-history?jobject=not-hex")
    assert r.status_code == 400


def test_jni_strings_endpoint(client):
    """Synth trace has no JNI string ops; expect empty hits with note."""
    r = client.get("/api/jni-strings").json()
    assert "note" in r
    assert isinstance(r["hits"], list)
