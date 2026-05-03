"""Web SPA API contract tests (uses fastapi.testclient on synth trace)."""
import struct, json, pathlib, pytest

@pytest.fixture
def synth_trace_dir(tmp_path):
    """Make a minimal per-call trace dir: 8 nops + 1 ret."""
    run = tmp_path / "run1"
    run.mkdir()
    (run/"calls").mkdir()
    cd = run/"calls"/"call_001_tid100_9r_50ms"
    cd.mkdir()
    bf = open(cd/"trace.bin", "wb")
    base = 0x100000
    nop = 0xd503201f
    ret = 0xd65f03c0
    for i in range(8):
        bf.write(struct.pack("<Q", base + i*4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))           # sp
        bf.write(struct.pack("<I", 0))                 # nzcv
        bf.write(struct.pack("<I", nop))
    bf.write(struct.pack("<Q", base + 32))
    for _ in range(31): bf.write(struct.pack("<Q", 0))
    bf.write(struct.pack("<Q", 0x7000))
    bf.write(struct.pack("<I", 0))
    bf.write(struct.pack("<I", ret))
    bf.close()
    json.dump({"callIdx":1,"tid":100,"records":9,"ms":50,"retval":"0x0",
               "truncated":False,"last_insn_is_ret":True}, open(cd/"meta.json","w"))
    json.dump({"pkg":"tst","so":"libt","method":"f","cmd":1,
               "module":{"name":"libt.so","base":hex(base),"size":0x10000},
               "fn_addr": hex(base)}, open(run/"meta.json","w"))
    return cd


@pytest.fixture
def trace_with_call_dir(tmp_path):
    """Root frame calls one child frame; LLIL body_only should exclude child PCs."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    run = tmp_path / "run_call"
    run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_5r_1ms"
    cd.mkdir()
    base = 0x100000
    rows = ["nop", "bl #+8", "nop", "ret", "ret"]
    with open(cd / "trace.bin", "wb") as bf:
        for i, asm in enumerate(rows):
            inst, _ = ks.asm(asm)
            bf.write(struct.pack("<Q", base + i * 4))
            for r_idx in range(31):
                is_lr = r_idx == 30
                bf.write(struct.pack("<Q", base + 8 if is_lr and i == 1 else 0))
            bf.write(struct.pack("<Q", 0x7000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", int.from_bytes(bytes(inst), "little")))
    json.dump({"callIdx": 1, "tid": 100, "records": len(rows), "ms": 1,
               "retval": "0x0", "truncated": False,
               "last_insn_is_ret": True}, open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)}, open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(synth_trace_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    return TestClient(make_app(synth_trace_dir))


def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    j = r.json()
    assert j["records"] == 9
    assert j["module"]["name"] == "libt.so"


def test_records_window(client):
    j = client.get("/api/records?start=0&count=4").json()
    assert j["count"] == 4
    assert len(j["records"]) == 4
    assert j["records"][0]["asm"].startswith("nop")


def test_record_one(client):
    j = client.get("/api/record/8").json()
    assert j["asm"].startswith("ret")
    assert j["is_ret"] is True
    assert "x0" in j["regs"]


def _wait_cfg(client, max_tries=30):
    """CFG is built async; poll until ready."""
    import time
    for _ in range(max_tries):
        j = client.get("/api/cfg").json()
        if j.get("status") == "ready": return j
        time.sleep(0.1)
    raise AssertionError("CFG never became ready")


def test_cfg(client):
    j = _wait_cfg(client)
    assert j["block_count"] >= 1
    assert all("label" in b for b in j["blocks"])


def test_cfg_async_first_call(client):
    """第一次 /api/cfg 调用可能返回 building, 不应卡住."""
    j = client.get("/api/cfg").json()
    assert j.get("status") in ("building", "ready")


def test_block_for_pc(client):
    cfg = _wait_cfg(client)
    first_pc = cfg["blocks"][0]["start"]
    r = client.get(f"/api/block-for-pc?pc={first_pc}").json()
    assert r["block"] == first_pc


def test_index_html_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "<title>traceMiku web</title>" in r.text


def test_search(client):
    r = client.get("/api/search?pattern=ret").json()
    assert r["count"] >= 1
    assert any(h["asm"].startswith("ret") for h in r["hits"])


def test_llil_render_endpoint_smoke(client):
    """LLIL web pipeline should run through CFG-aware SSA without crashing."""
    payload = {"fn_id": "F0", "split_top_k": 10, "split_min_records": 1}
    j = client.post("/api/llil/render", json=payload).json()
    assert j["ok"] is True, j
    assert j["stats"]["blocks"] >= 1
    assert "lift_total" in j["stats"]
    assert isinstance(j["c_code"], str)


def test_llil_render_body_only_excludes_child_call(trace_with_call_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    client = TestClient(make_app(trace_with_call_dir))
    payload = {"fn_id": "F0", "split_top_k": 0, "split_min_records": 1}
    j = client.post("/api/llil/render", json=payload).json()
    assert j["ok"] is True, j
    assert j["stats"]["scope"] == "body"
    assert j["stats"]["body_only"] is True
    assert j["stats"]["body_only_excluded_records"] == 3
    assert j["stats"]["body_only_excluded_blocks"] >= 1


def test_llil_render_trace_scope_keeps_child_call(trace_with_call_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    client = TestClient(make_app(trace_with_call_dir))
    payload = {"fn_id": "F0", "split_top_k": 0, "scope": "trace"}
    j = client.post("/api/llil/render", json=payload).json()
    assert j["ok"] is True, j
    assert j["stats"]["scope"] == "trace"
    assert j["stats"]["body_only"] is False
    assert j["stats"]["scope_excluded_records"] == 0
    assert j["stats"]["blocks"] >= 3


def test_dec_summary_includes_cfg_functions(trace_with_call_dir):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    client = TestClient(make_app(trace_with_call_dir))
    _wait_cfg(client)
    j = client.get("/api/dec/summary?split_top_k=0").json()
    # Server emits "symbol" (not "cfg") for symbol-derived functions.
    symbol_fns = [f for f in j["fns"] if f.get("source") == "symbol"]
    trace_fns = [f for f in j["fns"] if f.get("source") == "trace-ir"]
    assert symbol_fns or trace_fns
    fn_id = (symbol_fns or trace_fns)[0]["id"]
    if symbol_fns:
        # Migration: "cfg:<name>" -> "sym:<name>"; accept both forms.
        assert fn_id.startswith("sym:") or fn_id.startswith("cfg:"), fn_id
    else:
        # Migration: bare "F0" -> "trace:F0"; accept both forms.
        assert fn_id.startswith("trace:F") or fn_id.startswith("F"), fn_id
    r = client.get(f"/api/dec/fn/{fn_id}").json()
    assert r["fn_id"] == fn_id
    assert "markdown" in r


def test_dec_llm_call_does_not_poison_summary_cache(trace_with_call_dir, monkeypatch):
    """Calling /api/dec/llm-call for a symbol fn must not relabel it as trace-ir
    in subsequent /api/dec/summary calls.

    Both calls use the default split_top_k (10) so they share the same cached
    TopIR object — this is the path where the mutation would actually corrupt
    source labels.
    """
    from fastapi.testclient import TestClient
    from webui.server import make_app

    class _StubResult:
        error = None
        model = "stub"
        c_code = "int f(){}"
        prompt_tokens = 1
        output_tokens = 1
        latency_ms = 1

    class _StubModel:
        def call(self, user, system=None, max_tokens=4096):
            return _StubResult()

    # make_llm_model is imported inside the route via
    # `from viewer.decompiler import make_llm_model` so patch at that location.
    import viewer.decompiler as _vd
    monkeypatch.setattr(_vd, "make_llm_model", lambda name: _StubModel())

    client = TestClient(make_app(trace_with_call_dir))
    _wait_cfg(client)
    # Use the default split_top_k (10) so both the summary and the llm-call
    # share the same cached TopIR object.
    j_before = client.get("/api/dec/summary").json()
    symbol_fns_before = [f for f in j_before["fns"] if f["source"] == "symbol"]
    if not symbol_fns_before:
        pytest.skip("fixture has no symbol-derived fns")
    fn_id = symbol_fns_before[0]["id"]

    # llm-call with default split_top_k to hit the same cache entry.
    r = client.post("/api/dec/llm-call",
                    json={"fn_id": fn_id, "model": "stub"}).json()
    assert r["ok"] is True

    j_after = client.get("/api/dec/summary").json()
    after_entry = next(f for f in j_after["fns"] if f["id"] == fn_id)
    assert after_entry["source"] == "symbol", \
        f"expected source 'symbol', got {after_entry['source']!r}"
