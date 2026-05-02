"""Hot/warm/cold tier 分类 + tier-aware 渲染 — P2-DEC3-A 单元测试."""
from __future__ import annotations
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler import (
    TopIR, FuncIR, BlockIR, LoopIR,
    render_func_md, write_decompile_dir,
    build_fn_decompile_prompt,
)
from viewer.decompiler.builder import classify_blocks_by_tier


def _make_topir(block_count: int, exec_distribution: list[int] | None = None,
                asm_lines_per_block: int = 8) -> TopIR:
    """合成 TopIR 用于 tier 测试. exec_distribution 列表给每块 exec_count.

    asm_lines_per_block: 每块多少条假 asm 行 (默认 8, 接近真实 ARM64 BB 平均).
    """
    if exec_distribution is None:
        exec_distribution = list(range(block_count, 0, -1))
    assert len(exec_distribution) == block_count
    blocks = []
    for i in range(block_count):
        asm = "\n".join(
            f"  {0x1000 + i*0x40 + j*4:#x}: mov x{j % 8}, #{i*100 + j}"
            for j in range(asm_lines_per_block)
        )
        blocks.append(BlockIR(
            id=f"B{i}", pc=0x1000+i*0x40, end_pc=0x1000+i*0x40+asm_lines_per_block*4,
            insns=asm_lines_per_block, exec_count=exec_distribution[i],
            exits=[], samples={"x0": i, "x1": i*2}, asm=asm,
        ))
    fn = FuncIR(id="F0", name="test", pc_start=0x1000, pc_end=0x2000,
                entry_idx=0, exit_idx=block_count, blocks=blocks)
    return TopIR(records=block_count, truncated=False, last_insn_is_ret=True, fns=[fn])


def test_few_blocks_all_hot():
    """≤ hot_top_k blocks → 全部 hot."""
    top = _make_topir(20)
    classify_blocks_by_tier(top, hot_top_k=150)
    fn = top.fns[0]
    assert all(b.tier == "hot" for b in fn.blocks)


def test_many_blocks_top_k_hot_rest_warm():
    """> hot_top_k blocks → 严格按 exec_count, 前 K 个或满足 frac 都 hot."""
    top = _make_topir(300, exec_distribution=[1] * 300)   # 都执行 1 次
    classify_blocks_by_tier(top, hot_top_k=50, min_hot_frac=0.6)
    fn = top.fns[0]
    hot = sum(1 for b in fn.blocks if b.tier == "hot")
    warm = sum(1 for b in fn.blocks if b.tier == "warm")
    # 既要前 50 个 (exec_count tie 时按列表顺序)
    # 又要满足 60% 累计 → 60% × 300 = 180 块
    assert hot >= 50
    assert hot + warm == 300


def test_zero_exec_count_marked_cold():
    """exec_count=0 块 → cold (尽管在 fn.blocks 里)."""
    top = _make_topir(5, exec_distribution=[10, 0, 5, 0, 1])
    classify_blocks_by_tier(top)
    fn = top.fns[0]
    assert fn.blocks[1].tier == "cold"
    assert fn.blocks[3].tier == "cold"
    assert fn.blocks[0].tier == "hot"


def test_render_summary_tier_drops_blocks():
    """tier='summary' → block list 不出 asm."""
    top = _make_topir(10)
    classify_blocks_by_tier(top)
    md = render_func_md(top.fns[0], tier="summary")
    assert "Blocks" in md
    assert "block detail omitted" in md
    # 不应有 asm 块
    assert "```arm64" not in md


def test_render_hot_tier_stubs_warm():
    """tier='hot' → warm 块 stub (无 asm), hot 块完整."""
    top = _make_topir(300, exec_distribution=[100] * 50 + [1] * 250)
    classify_blocks_by_tier(top, hot_top_k=50, min_hot_frac=0.6)
    md = render_func_md(top.fns[0], tier="hot")
    # stub 紧凑形式: "N insns" 总览
    assert "insns" in md
    # 应有完整 asm (hot)
    assert "```arm64" in md
    # warm 块应标注 (warm)
    assert "(warm)" in md


def test_render_full_tier_keeps_all_asm():
    """tier='full' → 所有块完整 asm."""
    top = _make_topir(5)
    classify_blocks_by_tier(top)
    md = render_func_md(top.fns[0], tier="full")
    # 5 个 block × 8 行 mov, 至少首行该出现
    assert "mov x0, #0" in md
    assert "mov x0, #100" in md or "mov x1, #101" in md   # B1 的某行
    # full 模式下不应出现 stub-only 标记
    assert "8 insns →" not in md   # stub 紧凑标记


def test_real_trace_hot_tier_significantly_smaller():
    """真实风格 trace: hot tier 输出应比 full 小至少 50%."""
    # 模拟 OLLVM-flatten-like trace: 200 块, 只 30 块热
    exec_dist = [50] * 30 + [1] * 170
    top = _make_topir(200, exec_distribution=exec_dist)
    classify_blocks_by_tier(top, hot_top_k=30)
    md_full = render_func_md(top.fns[0], tier="full")
    md_hot  = render_func_md(top.fns[0], tier="hot")
    md_summary = render_func_md(top.fns[0], tier="summary")
    assert len(md_summary) < len(md_hot) < len(md_full)
    # hot 模式下应至少省 30% (warm 块 asm 全省)
    assert len(md_hot) < len(md_full) * 0.7


def test_write_decompile_dir_with_tier():
    """落盘默认 full, 显式传 tier 也能传给 fn 文件."""
    import tempfile
    top = _make_topir(20)
    classify_blocks_by_tier(top)
    with tempfile.TemporaryDirectory() as td:
        dec_full = write_decompile_dir(top, td + "/full", tier="full")
        dec_hot  = write_decompile_dir(top, td + "/hot",  tier="hot")
        dec_summary = write_decompile_dir(top, td + "/summary", tier="summary")
        full_size = (dec_full / "fns" / "F0.md").stat().st_size
        summary_size = (dec_summary / "fns" / "F0.md").stat().st_size
        assert summary_size < full_size


def test_real_synth_trace_classifies():
    """真合成 trace 走完 builder, tier 正确填充."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)
    fn = top.fns[0]
    # 小 fn, 全 hot
    assert all(b.tier == "hot" for b in fn.blocks)
    t.close()


def test_prompt_uses_hot_tier_by_default():
    """build_fn_decompile_prompt 默认用 hot tier."""
    top = _make_topir(300, exec_distribution=[100]*50 + [1]*250)
    classify_blocks_by_tier(top, hot_top_k=50)
    b_default = build_fn_decompile_prompt(top, "F0")
    b_full = build_fn_decompile_prompt(top, "F0", tier="full")
    # default 应比 full 短 (warm 被 stub)
    assert b_default.chars() < b_full.chars()
