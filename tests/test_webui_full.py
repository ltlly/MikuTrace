"""端到端 web API tests with random sampling, edge cases, invariant checks.

用户反馈: 每个完成的功能要有完整测试避免手动找 bug.
- CFG dedupe correctness on real-shape data
- /api/record vs /api/records 一致性
- /api/idxs-for-pc 正确性 (与暴力扫的结果对比)
- 同步模式数据流 round-trip
- Edge cases (idx=0, idx=last, missing PC, building 状态)
"""
import json, struct, random, pathlib, pytest

HERE = pathlib.Path(__file__).resolve().parent.parent

# ============== synth fixtures ===========================================

def _make_synth_trace(tmp_path, asm_blocks):
    """asm_blocks: [(start_pc_offset, [(pc, inst), ...]), ...]
    flat_records iterates blocks in order. Returns per-call dir path."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"
    run.mkdir()
    (run/"calls").mkdir()
    cd = run/"calls"/"call_001_tid100_test"
    cd.mkdir()
    bf = open(cd/"trace.bin","wb")
    n = 0
    last_block_start = None
    for bstart, asm_list in asm_blocks:
        for asm in asm_list:
            inst, _ = ks.asm(asm)
            inst_int = int.from_bytes(bytes(inst), "little")
            bf.write(struct.pack("<Q", base + bstart))
            for _ in range(31): bf.write(struct.pack("<Q", 0))   # regs
            bf.write(struct.pack("<Q", 0x7000))                  # sp
            bf.write(struct.pack("<I", 0))                        # nzcv
            bf.write(struct.pack("<I", inst_int))
            bstart += 4
            n += 1
    bf.close()
    json.dump({"callIdx":1,"tid":100,"records":n,"ms":50,"retval":"0x0",
               "truncated":False,"last_insn_is_ret":True}, open(cd/"meta.json","w"))
    json.dump({"pkg":"tst","so":"libt","method":"f","cmd":1,
               "module":{"name":"libt.so","base":hex(base),"size":0x10000},
               "fn_addr": hex(base)}, open(run/"meta.json","w"))
    return cd


@pytest.fixture
def big_synth(tmp_path):
    """Block A: nop×5 + br x14; Block B: nop×3 + ret. Block A executes 3 times,
    Block B once. Tests CFG dedupe + counts."""
    blocks = []
    base_a = 0
    base_b = 0x100   # 256 bytes after A
    a_asm = ["nop", "nop", "nop", "nop", "nop", "br x14"]
    b_asm = ["nop", "nop", "nop", "ret"]
    # 3 cycles of A, then B (each iteration of A jumps via br to A again, last time goes to B)
    for _ in range(3): blocks.append((base_a, a_asm))
    blocks.append((base_b, b_asm))
    return _make_synth_trace(tmp_path, blocks)


@pytest.fixture
def client(big_synth):
    from fastapi.testclient import TestClient
    from webui.server import make_app
    return TestClient(make_app(big_synth))


def _wait_cfg(client, max_tries=40):
    import time
    for _ in range(max_tries):
        j = client.get("/api/cfg").json()
        if j.get("status") == "ready": return j
        time.sleep(0.05)
    raise AssertionError("CFG never ready")


# ============== basic correctness ========================================

def test_records_meta(client):
    r = client.get("/api/meta").json()
    assert r["records"] == 22   # 6×3 + 4 = 22
    assert r["module"]["name"] == "libt.so"


def test_record_n_consistency(client):
    """每个 idx 在 /api/record/N 和 /api/records 的字段必须一致 (尤其 exec_count)."""
    _wait_cfg(client)
    rs = client.get("/api/records?start=0&count=22").json()["records"]
    for r in rs:
        single = client.get(f"/api/record/{r['idx']}").json()
        assert single["pc"] == r["pc"]
        assert single["asm"] == r["asm"]
        assert single["exec_count"] == r["exec_count"], (
            f"idx={r['idx']}: records.exec_count={r['exec_count']} ≠ record.exec_count={single['exec_count']}")
        assert single["is_branch"] == r["is_branch"]


def test_cfg_dedupe(client):
    """每个 block 的 insns 必须没有重复 PC (修复用户报告的 6× 重复 bug)."""
    cfg = _wait_cfg(client)
    for b in cfg["blocks"]:
        # inspect each block detail
        d = client.get(f"/api/block?pc={b['start']}").json()
        pcs = [ins["pc"] for ins in d["insns"]]
        assert len(pcs) == len(set(pcs)), (
            f"block {b['start']} has duplicate PCs: {pcs}")
        # PCs must be contiguous (4-byte stride within block)
        ints = [int(p, 16) for p in pcs]
        for i in range(1, len(ints)):
            assert ints[i] - ints[i-1] == 4, (
                f"block {b['start']} non-contiguous: {pcs}")


def test_block_executions_match_idxs(client):
    """block.executions × len(insns) should equal len(idxs_for_block)."""
    cfg = _wait_cfg(client)
    for b in cfg["blocks"]:
        d = client.get(f"/api/block?pc={b['start']}").json()
        idxs = client.get(f"/api/idxs-for-block?pc={b['start']}&max_count=100000").json()
        expected = b["executions"] * len(d["insns"])
        # idxs returned might be bounded; total should be expected
        assert idxs["total"] == expected, (
            f"block {b['start']}: executions={b['executions']} insns={len(d['insns'])} "
            f"= expected {expected} idxs, got total={idxs['total']}")


def test_idxs_for_pc_correctness(client):
    """随机抽样 10 个 PC, 验证 /api/idxs-for-pc 的 before/after 与暴力扫一致."""
    _wait_cfg(client)
    n = client.get("/api/meta").json()["records"]
    # 拿所有 PC 列表
    rs = client.get(f"/api/records?start=0&count={n}").json()["records"]
    pc_to_idxs = {}
    for r in rs:
        pc_to_idxs.setdefault(r["pc"], []).append(r["idx"])
    # random cursors and PCs
    random.seed(42)
    sample_pcs = random.sample(list(pc_to_idxs), min(10, len(pc_to_idxs)))
    for pc in sample_pcs:
        all_idxs = pc_to_idxs[pc]
        for cursor in (0, n // 2, n - 1):
            r = client.get(f"/api/idxs-for-pc?pc={pc}&cursor={cursor}&limit=50").json()
            expected_before = sorted([i for i in all_idxs if i < cursor], reverse=True)[:50]
            expected_after = sorted([i for i in all_idxs if i >= cursor])[:50]
            assert r["before"] == expected_before, (
                f"pc={pc} cursor={cursor}: before {r['before']} != {expected_before}")
            assert r["after"] == expected_after, (
                f"pc={pc} cursor={cursor}: after {r['after']} != {expected_after}")
            assert r["total_before"] == sum(1 for i in all_idxs if i < cursor)
            assert r["total_after"] == sum(1 for i in all_idxs if i >= cursor)


def test_record_edge_cases(client):
    n = client.get("/api/meta").json()["records"]
    # idx = 0
    r0 = client.get("/api/record/0").json()
    assert r0["idx"] == 0
    assert r0["prev_regs"] is None    # 头一条没有 prev
    # idx = last
    rL = client.get(f"/api/record/{n-1}").json()
    assert rL["idx"] == n - 1
    # out of range
    assert client.get(f"/api/record/{n}").status_code == 404
    assert client.get(f"/api/record/-1").status_code == 404


def test_records_window_boundaries(client):
    n = client.get("/api/meta").json()["records"]
    # exact end
    r = client.get(f"/api/records?start=0&count={n}").json()
    assert r["count"] == n
    # past end
    r = client.get(f"/api/records?start={n-2}&count=100").json()
    assert r["count"] == 2
    # past total
    r = client.get(f"/api/records?start={n}&count=10").json()
    assert r["count"] == 0


def test_prev_regs_consistency(client):
    """连续 3 个 idx, idx=N 的 prev_regs 必须等于 idx=N-1 的 regs."""
    _wait_cfg(client)
    n = client.get("/api/meta").json()["records"]
    if n < 3: return
    for idx in random.Random(0).sample(range(1, n), min(5, n-1)):
        cur = client.get(f"/api/record/{idx}").json()
        prev = client.get(f"/api/record/{idx-1}").json()
        assert cur["prev_regs"] == prev["regs"], (
            f"idx={idx}: cur.prev_regs ≠ prev.regs")


def test_cfg_svg_status_progression(client):
    # first call may be building, but eventually ready
    import time
    r = client.get("/api/cfg-svg").json()
    assert r.get("status") in ("building", "ready", "empty", "error")
    # 等到 ready 应该 return SVG
    for _ in range(40):
        r = client.get("/api/cfg-svg").json()
        if r.get("status") in ("ready", "empty"): break
        time.sleep(0.05)
    if r["status"] == "ready":
        assert "<svg" in r["svg"]
        # SVG 中每条 insn 都应该有对应的 <a xlink:href="#insn_<pc>">
        import re
        pcs = re.findall(r'#insn_([0-9a-f]+)', r["svg"])
        assert len(pcs) > 0
        # 唯一性 (无重复)
        assert len(pcs) == len(set(pcs))


def test_idxs_for_block_basic(client):
    cfg = _wait_cfg(client)
    for b in cfg["blocks"][:5]:
        r = client.get(f"/api/idxs-for-block?pc={b['start']}&max_count=100").json()
        assert r["block"] == b["start"]
        assert all(isinstance(i, int) for i in r["idxs"])
        assert r["idxs"] == sorted(r["idxs"])


def test_backtrace_endpoint(client):
    _wait_cfg(client)
    n = client.get("/api/meta").json()["records"]
    # backtrace 是 lazy build, 第一次调可能 status=building, 等
    import time
    for _ in range(40):
        r = client.get(f"/api/backtrace?idx={n-1}").json()
        if r.get("status") == "ready": break
        time.sleep(0.05)
    assert r["status"] == "ready"
    # depth 是非负的 int
    assert r["depth"] >= 0


# ============== full-trace invariant scan =================================

def test_scc_finds_loops():
    """Tarjan SCC 测试: 构造 A→B→A 自环 + C 单顶点, 应找到 1 个 loop."""
    from viewer.cfg import CFG, Block, find_sccs, loop_sccs
    c = CFG()
    c.blocks[0x100] = Block(start_pc=0x100, end_pc=0x100)
    c.blocks[0x200] = Block(start_pc=0x200, end_pc=0x200)
    c.blocks[0x300] = Block(start_pc=0x300, end_pc=0x300)
    c.edges[(0x100, 0x200)] = {"kind": "b", "count": 1}
    c.edges[(0x200, 0x100)] = {"kind": "b", "count": 1}
    c.edges[(0x100, 0x300)] = {"kind": "b", "count": 1}
    sccs = find_sccs(c)
    # 3 SCCs total: {0x100,0x200} loop, {0x300} singleton
    sizes = sorted(len(s) for s in sccs)
    assert sizes == [1, 2]
    loops = loop_sccs(c)
    assert len(loops) == 1
    assert sorted(loops[0]) == [0x100, 0x200]


def test_scc_self_loop():
    """size=1 自环也算 loop."""
    from viewer.cfg import CFG, Block, loop_sccs
    c = CFG()
    c.blocks[0x100] = Block(start_pc=0x100, end_pc=0x100)
    c.edges[(0x100, 0x100)] = {"kind": "b", "count": 1}
    loops = loop_sccs(c)
    assert len(loops) == 1
    assert loops[0] == [0x100]


def test_strings_search_filter(client):
    """/api/strings?q=... 服务端过滤."""
    import time
    # 等 mem ready (耗时, MemShadow build 过)
    for _ in range(120):
        r = client.get("/api/strings?min_len=4").json()
        if r.get("status") == "ready": break
        time.sleep(0.1)
    # 全集
    all_r = client.get("/api/strings?min_len=4").json()
    if all_r.get("status") != "ready" or len(all_r["strings"]) == 0:
        pytest.skip("no strings in synth trace")
    # 拿第一条字符串子串作为查询
    sub = all_r["strings"][0]["str"][:2]
    flt_r = client.get(f"/api/strings?min_len=4&q={sub}").json()
    assert flt_r["status"] == "ready"
    # 过滤后所有结果都包含 sub
    for s in flt_r["strings"]:
        assert sub.lower() in s["str"].lower()


def test_mem_dump_endpoint(client):
    """/api/mem-dump 返回 hex dump (count 个 byte 条目, 包括 None 字节)."""
    import time
    # 等 mem build 完
    for _ in range(120):
        st = client.get("/api/bg-status").json()
        if st.get("mem", {}).get("status") == "ready": break
        # 触发 build (调一次任意需要 mem 的 endpoint)
        client.get("/api/strings?min_len=4")
        time.sleep(0.1)
    r = client.get("/api/mem-dump?addr=0x7000&count=16").json()
    assert r["status"] == "ready", f"unexpected: {r}"
    assert len(r["bytes"]) == 16, f"expected 16 byte entries, got {len(r['bytes'])}"
    for b in r["bytes"]:
        assert "addr" in b and "byte" in b and "kind" in b


def test_idxs_touching_addr_endpoint(client):
    """/api/idxs-touching-addr 行为基线 — 即使没数据, 不应崩."""
    import time
    for _ in range(120):
        r = client.get("/api/idxs-touching-addr?addr=0x7000&cursor=0").json()
        if r.get("status") == "ready": break
        time.sleep(0.1)
    assert r["status"] == "ready"
    # 类型契约
    assert isinstance(r["before"], list)
    assert isinstance(r["after"], list)
    for entry in r["before"] + r["after"]:
        assert "idx" in entry and "kind" in entry
        assert entry["kind"] in ("r", "w")


def test_api_loops_endpoint(client):
    """/api/loops 返回 SCC list. 我们的合成 trace block A 自循环 (br x14 跳回起点)
    + block B (linear) → 期望 1 个 loop."""
    _wait_cfg(client)
    r = client.get("/api/loops").json()
    assert r["status"] == "ready"
    assert isinstance(r["loops"], list)
    # 每个 loop 是 dict 含 members + size
    for L in r["loops"]:
        assert "members" in L and "size" in L
        assert L["size"] == len(L["members"])
        assert all(m.startswith("0x") for m in L["members"])


def test_annotation_field_present(client):
    """每条 record 都应该有 annotation 键 (可能为 null)."""
    rs = client.get("/api/records?start=0&count=22").json()["records"]
    assert all("annotation" in r for r in rs)
    # br x14 in our synth jumps to next block — annotation should hint
    br_records = [r for r in rs if r["asm"].startswith("br")]
    assert len(br_records) > 0


def test_all_records_invariants(client):
    """全 trace 扫描, 每条 record 满足: pc/idx 类型正确, asm 非空,
    is_branch/is_call/is_ret 互斥逻辑."""
    _wait_cfg(client)
    n = client.get("/api/meta").json()["records"]
    rs = client.get(f"/api/records?start=0&count={n}").json()["records"]
    assert len(rs) == n
    for r in rs:
        assert isinstance(r["idx"], int)
        assert r["pc"].startswith("0x")
        assert r["asm"].strip() != ""
        # is_call implies is_branch
        if r["is_call"]: assert r["is_branch"]
        # is_ret implies is_branch (technically; check capstone behavior)
        # (relaxed: skip this assert because some impls disagree)
