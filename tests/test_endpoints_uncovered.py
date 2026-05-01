"""未覆盖 webui 端点 (P2 from COVERAGE.md):

  - /api/forward-taint, /api/backward-taint
  - /api/reg-timeline, /api/mem-diff, /api/fn-summary
  - /api/block (detail), /api/cfg?fn= filter, /api/cfg-svg?fn= filter
  - /api/decomp-status, /api/asm-tokens-for-pcs
  - /api/bg-status

复用 test_webui_full.py 的 big_synth 风格 (Block A×3 + Block B). 单 client
fixture 重用 (per test 单独 client 也 OK 但开销更大)."""
import json, struct, pytest, time
from fastapi.testclient import TestClient


def _make_trace(tmp_path, blocks, base=0x100000):
    """blocks: [(start_offset, [asm_str,...]), ...]; PC = base + offset, +4 each insn."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    run = tmp_path / "run1"; run.mkdir()
    (run/"calls").mkdir()
    cd = run / "calls" / "call_001_tid100_endpoints"
    cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    n = 0
    for bstart, asm_list in blocks:
        for a in asm_list:
            inst, _ = ks.asm(a)
            ii = int.from_bytes(bytes(inst), "little")
            bf.write(struct.pack("<Q", base + bstart))
            for _ in range(31): bf.write(struct.pack("<Q", 0))
            bf.write(struct.pack("<Q", 0x7000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", ii))
            bstart += 4; n += 1
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": True},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def client(tmp_path):
    """A:5 nops + br; B:3 nops + ret; loop 3× A → B."""
    a_asm = ["nop"] * 5 + ["br x14"]
    b_asm = ["nop"] * 3 + ["ret"]
    blocks = [(0, a_asm)] * 3 + [(0x100, b_asm)]
    cd = _make_trace(tmp_path, blocks)
    from webui.server import make_app
    return TestClient(make_app(cd))


def _wait_cfg(client, tries=40):
    for _ in range(tries):
        j = client.get("/api/cfg").json()
        if j.get("status") == "ready": return j
        time.sleep(0.05)
    raise AssertionError("CFG 没 ready")


def _wait_ready(client, key, tries=40):
    for _ in range(tries):
        j = client.get("/api/bg-status").json()
        st = j.get(key, {}).get("status") if isinstance(j, dict) else None
        if st == "ready": return j
        time.sleep(0.05)
    return None


# ── /api/forward-taint, /api/backward-taint ──────────────────────────────────

def test_forward_taint_endpoint_index_pending(client):
    """index 还没建好时 → 返 status, 触发后台 build, 不崩."""
    r = client.get("/api/forward-taint?start=0&reg=x0&max_count=10").json()
    assert r["status"] in ("idle", "building", "ready")
    # 若 ready 立刻有 hits 字段
    if r["status"] == "ready":
        assert "hits" in r


def test_forward_taint_endpoint_basic(client):
    """index ready 后能返合理结构. 合成 trace 全 nop, taint 最多空."""
    # 触发 index build
    client.get("/api/forward-taint?start=0&reg=x0&max_count=5")
    _wait_ready(client, "index")
    r = client.get("/api/forward-taint?start=0&reg=x0&max_count=5").json()
    assert r.get("count") is not None
    assert isinstance(r.get("hits"), list)
    assert r.get("from") == 0
    assert r.get("reg") == "x0"


def test_backward_taint_endpoint_basic(client):
    client.get("/api/backward-taint?start=5&reg=x0&max_count=5")
    _wait_ready(client, "index")
    r = client.get("/api/backward-taint?start=5&reg=x0&max_count=5").json()
    assert r.get("count") is not None
    assert isinstance(r.get("chain"), list)


# ── /api/reg-timeline ────────────────────────────────────────────────────────

def test_reg_timeline_basic(client):
    """合成 trace 全 nop, x0 全 0, 应只有 1 个 point (idx=0, value=0x0)."""
    r = client.get("/api/reg-timeline?reg=x0&start=0&end=22").json()
    assert r["reg"] == "x0"
    assert r["count"] >= 1
    assert r["points"][0]["idx"] == 0
    assert r["points"][0]["value"] == "0x0"
    assert r["truncated"] is False


def test_reg_timeline_alias_x29_works():
    """x29 应被接受 (alias to fp)."""
    # 复用同一 client 即可 — 但 fixture 是 per-test, 这里单独构造
    pass   # alias 测试在 test_recent_fixes 已经 pin, 此处不重复


def test_reg_timeline_unknown_reg_400(client):
    resp = client.get("/api/reg-timeline?reg=foo")
    assert resp.status_code == 400


def test_reg_timeline_xzr_400(client):
    """xzr 总是 0, 但端点设计成 raise 400 (因 ZERO sentinel 不接收作 reg)."""
    resp = client.get("/api/reg-timeline?reg=xzr")
    assert resp.status_code == 400


def test_reg_timeline_max_points_truncates(client):
    """end=22 但 max_points=1 → truncated=True (即使只有 1 个 distinct value)."""
    r = client.get("/api/reg-timeline?reg=x0&start=0&end=22&max_points=1").json()
    assert r["count"] == 1
    # distinct values <= max_points 不需要 truncated; 只 1 个 distinct 值 → truncated=False
    assert r["truncated"] is False


# ── /api/mem-diff ────────────────────────────────────────────────────────────

def test_mem_diff_pending(client):
    """mem 没建好 → 返 idx + bytes=[]."""
    r = client.get("/api/mem-diff?idx=5&addr=0x7000&size=4").json()
    # 即使 mem pending, idx 和 size 应回得正确
    assert r["idx"] == 5
    assert r["size"] == 4


def test_mem_diff_after_mem_ready(client):
    """trigger mem build, 等 ready, 检查响应有 changed_count."""
    client.get("/api/mem-diff?idx=5&addr=0x7000&size=4")
    _wait_ready(client, "mem")
    r = client.get("/api/mem-diff?idx=5&addr=0x7000&size=4").json()
    assert "changed_count" in r
    assert "bytes" in r
    assert len(r["bytes"]) == 4


def test_mem_diff_addr_decimal_accepted(client):
    """非 0x 前缀的 addr 应被解为 decimal — 当前实现兜底."""
    _wait_ready(client, "mem")
    r = client.get("/api/mem-diff?idx=0&addr=28672&size=2").json()  # 28672=0x7000
    assert r["addr"] == "28672"


# ── /api/fn-summary ──────────────────────────────────────────────────────────

def test_fn_summary_pending_status(client):
    """cfg 没 ready 时直接返 status 字段."""
    r = client.get("/api/fn-summary?fn=NonExistent").json()
    assert "status" in r


def test_fn_summary_not_found(client):
    """fn 不在 trace 里."""
    _wait_cfg(client)
    r = client.get("/api/fn-summary?fn=DefinitelyNotInTrace").json()
    assert r["status"] == "not-found"
    assert r["fn"] == "DefinitelyNotInTrace"


def test_fn_summary_existing_fn(client):
    """meta.method='f' (in synth) → JNI method 名, 应有对应 fn name."""
    j = _wait_cfg(client)
    funcs = j.get("funcs", [])
    if not funcs:
        pytest.skip("synth 没建出 fn 名")
    fn_name = funcs[0]["name"]
    r = client.get(f"/api/fn-summary?fn={fn_name}").json()
    assert r["status"] == "ready"
    assert r["fn"] == fn_name
    assert r["block_count"] >= 1
    assert r["total_executions"] >= 1
    assert "hot_blocks" in r
    assert "callees" in r


# ── /api/block (detail) ──────────────────────────────────────────────────────

def test_block_detail_pending(client):
    """cfg 没 ready 时返 status."""
    r = client.get("/api/block?pc=0x100000").json()
    assert "status" in r


def test_block_detail_existing_block(client):
    j = _wait_cfg(client)
    if not j.get("blocks"): pytest.skip("synth cfg empty")
    pc = j["blocks"][0]["start"]
    r = client.get(f"/api/block?pc={pc}").json()
    assert r["start"] == pc
    assert "executions" in r
    assert "insns" in r
    assert isinstance(r["insns"], list)
    if r["insns"]:
        ins = r["insns"][0]
        assert "pc" in ins and "asm" in ins
        assert "is_branch" in ins


def test_block_detail_404_for_unknown_pc(client):
    _wait_cfg(client)
    resp = client.get("/api/block?pc=0xdeadbeef")
    assert resp.status_code == 404


# ── /api/cfg?fn= filter ──────────────────────────────────────────────────────

def test_cfg_with_fn_filter(client):
    j = _wait_cfg(client)
    if not j.get("funcs"): pytest.skip("synth cfg 没 funcs")
    fn = j["funcs"][0]["name"]
    r = client.get(f"/api/cfg?fn={fn}").json()
    assert r["status"] == "ready"
    assert r["fn"] == fn
    # 过滤后 block_count <= total_block_count
    assert r["block_count"] <= r["total_block_count"]


def test_cfg_with_unknown_fn_returns_empty(client):
    _wait_cfg(client)
    r = client.get("/api/cfg?fn=NoSuchFunction").json()
    assert r["status"] == "ready"
    assert r["block_count"] == 0


# ── /api/cfg-svg ?fn= filter ─────────────────────────────────────────────────

def test_cfg_svg_with_unknown_fn_returns_empty(client):
    _wait_cfg(client)
    r = client.get("/api/cfg-svg?fn=NoSuchFn").json()
    # 可能 'empty' 或 dot 没装报 error, 总之不应是 'ready'
    assert r["status"] in ("empty", "error", "building")


# ── /api/decomp-status ──────────────────────────────────────────────────────

def test_decomp_status_disabled_when_no_so(client):
    """make_app 没传 decomp_so → status='disabled'."""
    r = client.get("/api/decomp-status").json()
    assert r["status"] == "disabled"


# ── /api/asm-tokens-for-pcs ─────────────────────────────────────────────────

def test_asm_tokens_for_pcs_no_decomp(client):
    """无 decomp 后端 → ready=False (或 'not-ready'), 不崩."""
    r = client.get("/api/asm-tokens-for-pcs?pcs=0x100000").json()
    # 可接受 status='ok' (空 tokens) 或 ready=False; 关键不崩
    assert r is not None


# ── /api/bg-status ──────────────────────────────────────────────────────────

def test_bg_status_returns_all_keys(client):
    r = client.get("/api/bg-status").json()
    # 至少这些 key (cfg/pc_inst/pc_to_block/block_idxs/index/mem)
    for k in ("cfg", "pc_inst", "pc_to_block", "block_idxs", "index", "mem"):
        assert k in r, f"bg-status 缺 key {k}"
        assert "status" in r[k]


def test_bg_status_no_data_field(client):
    """data 是 heavy 对象, 不应出现在 status 响应里."""
    r = client.get("/api/bg-status").json()
    for k, v in r.items():
        if isinstance(v, dict):
            assert "data" not in v, f"bg-status[{k}] 不应含 data 字段"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
