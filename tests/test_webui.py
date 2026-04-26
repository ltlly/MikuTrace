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
