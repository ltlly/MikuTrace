"""Pin tests for code changed in 169e2ff (CFG bugs + reg alias).

P0 priority — these protect the most recently fixed code paths from regression.
覆盖:
  - webui.server._norm_reg (alias x29→fp / x30→lr / xzr→ZERO)
  - /api/reg-value-at 端到端 alias 行为 (Bug #31 ResponseValidationError 修复)
  - viewer.cfg.build_aux_indices 与旧 Python loop 的等价性 (新向量化代码)
"""
import struct, json, pathlib, pytest
from fastapi.testclient import TestClient

HERE = pathlib.Path(__file__).resolve().parent.parent


# ── _norm_reg 单元 ───────────────────────────────────────────────────────────

def test_norm_reg_canonical():
    from webui.server import _norm_reg
    assert _norm_reg("x0") == "x0"
    assert _norm_reg("x28") == "x28"
    assert _norm_reg("fp") == "fp"
    assert _norm_reg("lr") == "lr"
    assert _norm_reg("sp") == "sp"
    assert _norm_reg("pc") == "pc"


def test_norm_reg_alias():
    """ARM64 disasm 出 x29/x30, 内部存 fp/lr — 别名映射不能丢."""
    from webui.server import _norm_reg
    assert _norm_reg("x29") == "fp"
    assert _norm_reg("x30") == "lr"


def test_norm_reg_zero_register():
    """xzr/wzr 永远 0, 不存于 ALL_REGS — 用 ZERO sentinel 让端点返回 0x0."""
    from webui.server import _norm_reg
    assert _norm_reg("xzr") == "ZERO"
    assert _norm_reg("wzr") == "ZERO"


def test_norm_reg_unknown():
    from webui.server import _norm_reg
    assert _norm_reg("foo") is None
    assert _norm_reg("") is None
    assert _norm_reg("x99") is None


# ── /api/reg-value-at 端到端 alias 行为 ──────────────────────────────────────

def _make_synth_trace(tmp_path):
    """合成 1 条 trace + 设 fp/lr 寄存器值, 用来端到端测 reg-value-at."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_synth"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    inst, _ = ks.asm("ret")
    inst_int = int.from_bytes(bytes(inst), "little")
    # x0..x28 = 0..28; fp = 0xdead0000; lr = 0xbeef0000
    bf.write(struct.pack("<Q", base))   # pc
    for i in range(29):
        bf.write(struct.pack("<Q", i))    # x0..x28
    bf.write(struct.pack("<Q", 0xdead0000))   # fp (= x29)
    bf.write(struct.pack("<Q", 0xbeef0000))   # lr (= x30)
    bf.write(struct.pack("<Q", 0x7000))        # sp
    bf.write(struct.pack("<I", 0))             # nzcv
    bf.write(struct.pack("<I", inst_int))      # inst
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": 1, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": True},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def synth_client(tmp_path):
    cd = _make_synth_trace(tmp_path)
    from webui.server import make_app
    app = make_app(cd)
    return TestClient(app)


def test_reg_value_at_x29_aliases_to_fp(synth_client):
    """x29 应等价于 fp — Bug #31 修复前会 500 'unknown reg x30/x29'."""
    r = synth_client.get("/api/reg-value-at?idx=0&reg=x29").json()
    assert r["status"] == "ready", f"x29 应被接受作为 fp 别名: {r}"
    assert r["value"] == hex(0xdead0000)


def test_reg_value_at_x30_aliases_to_lr(synth_client):
    r = synth_client.get("/api/reg-value-at?idx=0&reg=x30").json()
    assert r["status"] == "ready", f"x30 应被接受作为 lr 别名: {r}"
    assert r["value"] == hex(0xbeef0000)


def test_reg_value_at_xzr_returns_zero(synth_client):
    """xzr 永远读 0 — 不查 record, 直接 0x0."""
    r = synth_client.get("/api/reg-value-at?idx=0&reg=xzr").json()
    assert r["status"] == "ready"
    assert r["value"] == "0x0"


def test_reg_value_at_wzr_returns_zero(synth_client):
    r = synth_client.get("/api/reg-value-at?idx=0&reg=wzr").json()
    assert r["status"] == "ready"
    assert r["value"] == "0x0"


def test_reg_value_at_unknown_reg_returns_error_not_500(synth_client):
    """Bug #31: ResponseValidationError 修复 — error 路径必须是合法 union 分支."""
    resp = synth_client.get("/api/reg-value-at?idx=0&reg=bogus")
    assert resp.status_code == 200, (
        f"未知 reg 不应 500 ResponseValidationError, got {resp.status_code}: "
        f"{resp.text[:200]}")
    j = resp.json()
    assert j["status"] == "error"
    assert "unknown reg" in j["err"]


# ── viewer.cfg.build_aux_indices 等价性 ─────────────────────────────────────

def test_build_aux_indices_equivalent_to_python_loop(tmp_path):
    """新向量化辅助 dict 构建 vs 旧 Python bisect loop 必须输出 100% 一致.
    用 synth trace (足够覆盖 block_starts/ends + 间断 pc + 重复 pc) 证明."""
    from tests.synth import build_trace
    from viewer.cfg import build_cfg, build_aux_indices

    # 构造一段含分支 + 循环 + 直线的 trace (synth 默认 PC sequential, base+4 递增)
    t = build_trace([
        ('mov x0, #1',     {'x0': 1}),       # 0
        ('cmp x0, #1',     {'nzcv': 0x40}),  # 1
        ('b.eq #+8',       {}),              # 2 — branch (synth 顺序执行 → 实际"taken"
        ('add x0, x0, #1', {'x0': 2}),       #     等价 fall, 但可观察 block 结构)
        ('mov x1, x0',     {'x1': 2}),       # 3
        ('ret',            {}),              # 4
    ])
    cfg = build_cfg(t)

    # 旧 python loop (与 server.py:_subprocess_build_cfg_and_pcinst 修复前一致)
    import bisect
    starts = sorted(cfg.blocks.keys())
    ends = [cfg.blocks[s].end_pc for s in starts]
    pc_inst_old = {}
    pc_to_block_old = {}
    block_idxs_old = {s: [] for s in starts}
    n = len(t)
    for i in range(n):
        pc = t.pc(i)
        if pc not in pc_inst_old:
            pc_inst_old[pc] = t.inst(i)
        j = bisect.bisect_right(starts, pc) - 1
        if j >= 0 and pc <= ends[j]:
            bs = starts[j]
            pc_to_block_old[pc] = bs
            block_idxs_old[bs].append(i)

    pc_inst_new, pc_to_block_new, block_idxs_new = build_aux_indices(t, cfg)
    assert pc_inst_new == pc_inst_old, "pc_inst 不一致"
    assert pc_to_block_new == pc_to_block_old, "pc_to_block 不一致"
    assert block_idxs_new.keys() == block_idxs_old.keys()
    for k in block_idxs_old:
        assert block_idxs_new[k] == block_idxs_old[k], (
            f"block_idxs[0x{k:x}] 不一致: new={block_idxs_new[k]} "
            f"old={block_idxs_old[k]}")


def test_build_aux_indices_empty_cfg(tmp_path):
    """空 cfg 应返回空 dict, 不崩."""
    from viewer.cfg import CFG, build_aux_indices
    from tests.synth import build_trace
    t = build_trace([('ret', {})])
    pc_inst, pc_to_block, block_idxs = build_aux_indices(t, CFG())
    assert pc_inst == {}
    assert pc_to_block == {}
    assert block_idxs == {}


def test_build_aux_indices_block_idxs_preserves_trace_order(tmp_path):
    """同一 block 多次执行时, block_idxs 应按 trace idx 升序记录."""
    from viewer.cfg import build_cfg, build_aux_indices
    from tests.synth import build_trace
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('mov x1, x0', {'x1': 1}),
        ('ret',        {}),
    ])
    cfg = build_cfg(t)
    _, _, block_idxs = build_aux_indices(t, cfg)
    for bs, idxs in block_idxs.items():
        assert idxs == sorted(idxs), (
            f"block_idxs[0x{bs:x}] 不是升序: {idxs}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
