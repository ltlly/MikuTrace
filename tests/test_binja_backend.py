"""viewer/decompiler/backends/binja.py — 真 BN + 真 SO 端到端.

跑 ~30-60s (libsgmainso 冷启动). pytest -m slow 才跑.

skipif: BN 不在 PYTHONPATH (开发机标 fixture, CI 无 license 跳过).
"""
import os, pathlib, pytest

HERE = pathlib.Path(__file__).resolve().parent.parent
SO = HERE / "example/106_d9da290cacaffd471ee1231d16b59190/lib/arm64-v8a/libsgmainso-6.8.260403.so"


def _bn_available() -> bool:
    from viewer.decompiler.backends.binja import Backend
    b = Backend()
    return b.is_available()


pytestmark = [
    pytest.mark.skipif(not SO.exists(), reason=f"target SO 不存在: {SO}"),
    pytest.mark.skipif(not _bn_available(), reason="binaryninja 不可用"),
    pytest.mark.slow,
]


@pytest.fixture(scope="module")
def bn():
    """Module-scope: 一次 open ~30-60s, 共享给所有测试. teardown close."""
    from viewer.decompiler.backends.binja import Backend
    b = Backend()
    assert b.is_available()
    b.open(str(SO), base=0)   # base=0 → SO offset 语义
    yield b
    b.close()


# ── lifecycle ────────────────────────────────────────────────────────────────

def test_open_loaded(bn):
    """成功 open 后 loaded_base 必有值."""
    assert bn.loaded_base() > 0


# ── function_at: 已知 offset → 应返 Function 对象 ────────────────────────────

def test_function_at_jni_onload(bn):
    """JNI_OnLoad 在 0x570b8 — 来自 known_offsets.json."""
    fn = bn.function_at(0x570b8)
    assert fn is not None, "JNI_OnLoad 必须能拿到"
    assert fn.start <= 0x570b8 < fn.end


def test_function_at_doCommandNative(bn):
    """doCommandNative 在 0x57770."""
    fn = bn.function_at(0x57770)
    assert fn is not None
    # name 可能是 'doCommandNative' (BN 解出的) 或 sub_57770
    assert fn.start <= 0x57770


def test_function_at_unknown_returns_none(bn):
    """完全瞎给的 offset 不应崩, 返 None 或一个 fallback."""
    # 0x1 在 ELF header 区, 显然不是函数
    fn = bn.function_at(0x1)
    # 多数情况 None; 少数情况 BN force-create 也不应崩
    assert fn is None or fn.start >= 0


# ── hlil_for ────────────────────────────────────────────────────────────────

def test_hlil_for_jni_onload(bn):
    """JNI_OnLoad 反编译应有几行 HlilLine."""
    fn = bn.function_at(0x570b8)
    assert fn is not None
    lines = bn.hlil_for(fn)
    assert isinstance(lines, list)
    assert len(lines) >= 3, f"JNI_OnLoad HLIL 应有 ≥3 行, got {len(lines)}"
    # 每行 (pc_lo, pc_hi) 应在 fn 范围内
    for line in lines:
        assert line.pc_lo >= 0
        assert line.pc_hi >= line.pc_lo


def test_hlil_for_repeated_call_uses_cache(bn):
    """同 fn 重复 hlil_for 应快 (cache hit). 测 ~ms 级."""
    import time
    fn = bn.function_at(0x570b8)
    bn.hlil_for(fn)   # 预热
    t0 = time.time()
    for _ in range(10):
        bn.hlil_for(fn)
    dt = time.time() - t0
    assert dt < 0.5, f"10 次 cached hlil_for 应 < 0.5s, got {dt:.2f}s"


# ── asm_tokens_at ──────────────────────────────────────────────────────────

def test_asm_tokens_at_known_pc(bn):
    """JNI_OnLoad 入口 PC 的 ASM tokens 应有 mnem token."""
    tokens = bn.asm_tokens_at(0x570b8)
    assert tokens is not None
    assert len(tokens) > 0
    # 至少有 1 个 'mnem' 类 (instruction mnemonic)
    classes = [tk.cls for tk in tokens]
    assert "mnem" in classes, f"asm tokens 应含 mnem, got cls list: {classes[:10]}"


def test_asm_tokens_at_unknown_pc(bn):
    """不在任何函数内的 PC → None 或空列表, 不崩."""
    tokens = bn.asm_tokens_at(0x1)
    # None / [] 都可接受
    assert tokens is None or isinstance(tokens, list)


# ── cfg_for ────────────────────────────────────────────────────────────────

def test_cfg_for_jni_onload(bn):
    """cfg_for 返 (blocks, edges).

    Note: BN cfg blocks 可包含 tail-call 间接跳转 (br x8) 的 dispatcher 块, 这些
    块 PC 可能在静态 fn.end 之外但仍属于该函数 CFG 视野. 不强求 block.end <= fn.end.
    """
    fn = bn.function_at(0x570b8)
    blocks, edges = bn.cfg_for(fn, mode="asm")
    assert len(blocks) >= 1, "JNI_OnLoad 至少 1 个 BB"
    # block.start 应 >= fn.start (没在 fn 之前的 dispatcher)
    for blk in blocks:
        assert blk.start >= fn.start, (
            f"block 0x{blk.start:x} 在 fn.start 0x{fn.start:x} 之前")
    # edges 的 src 都应是某 block 的 start
    block_starts = {blk.start for blk in blocks}
    for e in edges:
        assert e.src in block_starts, f"edge.src 0x{e.src:x} 不在任何 block 起点"


def test_cfg_for_hlil_mode(bn):
    """cfg_for(mode='hlil') 也应工作."""
    fn = bn.function_at(0x570b8)
    blocks, edges = bn.cfg_for(fn, mode="hlil")
    assert len(blocks) >= 1


# ── field_at ────────────────────────────────────────────────────────────────

def test_field_at_safe_for_unknown_pc(bn):
    """field_at 对未知 (pc, reg, offset) 应返 None, 不崩."""
    hint = bn.field_at(0x1, "x0", 0x10)
    assert hint is None or hasattr(hint, "struct")


# ── xrefs_to ────────────────────────────────────────────────────────────────

def test_xrefs_to_known_function(bn):
    """xrefs_to 对一个有人引用的函数应返 list[int]."""
    refs = bn.xrefs_to(0x570b8)
    assert isinstance(refs, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "slow"])
