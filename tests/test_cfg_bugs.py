"""CFG 边界 + 正确性回归.

涵盖代码 review 找到的实际 bug:

  Bug #1 (insns 重复) — 块 A 的最后一条不是 branch, 而是 fall-through 进入一个已知
    block_start B; 后续再次执行 A, _filled 没被设, A.insns 重复堆叠.
    (real-trace call_004 上 47 / 2001 块有重复, 最坏一块 3 条指令 ×4519 次堆到
     13557 条.)

  Bug #2 (entry 不在 module) — trace 第 0 条 PC 不在 module 时, cfg.entry_pc 设了
    一个永远不会被 build_cfg pass 2 创建出 block 的地址. 下游 (cfg_graph 拓扑根,
    SCC 起点) 会用它当根.

  Bug #3 (call_stack 不在 module 边界 pop) — 我们的 bl 调到外部 SO, 外部 ret 不在
    only_module 视野里, call_stack 没 pop, 下次本 module ret pop 出错的 caller, 加
    出错误的 call-return 边.

跑法 (project root):
    /usr/bin/python3 -m pytest tests/test_cfg_bugs.py -v
"""
import struct, tempfile, os
import pytest
from viewer.trace import Trace, TraceMeta, Module, REC_SIZE
from viewer.cfg import build_cfg
from tests.synth import asm_to_inst


# ── helpers ──────────────────────────────────────────────────────────────────

def _build_trace_with_pcs(seq, module_base=0x100000, module_size=0x10000):
    """seq: list of (pc, asm_str). 与 synth.build_trace 不同, pc 是显式给的,
    可以构造非线性 / 跨模块 / 循环回跳的执行序列."""
    fd, tmp = tempfile.mkstemp(suffix='.bin', prefix='cfgbug_')
    os.close(fd)
    fp = open(tmp, 'wb')
    state_regs = [0] * 31  # x0..x28, fp, lr
    sp = 0x7000
    for pc, asm in seq:
        inst = asm_to_inst(asm)
        fp.write(struct.pack('<Q', pc))
        for v in state_regs:
            fp.write(struct.pack('<Q', v))
        fp.write(struct.pack('<Q', sp))
        fp.write(struct.pack('<I', 0))      # nzcv
        fp.write(struct.pack('<I', inst))
    fp.close()
    meta = TraceMeta()
    meta.module = Module('synth.so', module_base, module_size)
    return Trace(tmp, meta)


# ── tests ────────────────────────────────────────────────────────────────────

def test_block_insns_no_dup_after_fallthrough_to_known_start():
    """Bug #1: 块 C 末尾是非 branch 指令, fall 进 B (B 已是 block_start). 第二次
    走 C 时 _filled 没被设, insns 重复堆.

    Layout:
        A (entry):  mov; mov; b.eq → +0xc
        C        :  mov; mov          (fall-through 进 B)
        B        :  mov; ret           (b.eq taken 时 = B; fall 时也是 B)

    Trace:
      iter1: A → b.eq taken → B (建立 B 为 b.eq 的目标 → block_start)
      iter2: A → b.eq 不取 → C → fall → B
      iter3: 同 iter2 (再走 C 一次, 触发 dup append)
    """
    base = 0x100000
    A_entry  = base
    A_pre_br = base + 4
    A_branch = base + 8
    C_entry  = base + 0xc
    C_mid    = base + 0x10
    B_entry  = base + 0x14
    B_ret    = base + 0x18

    iter1 = [
        (A_entry,  'mov x0, #1'),
        (A_pre_br, 'mov x1, #2'),
        (A_branch, 'b.eq #+0xc'),    # taken → B_entry
        (B_entry,  'mov x2, #3'),
        (B_ret,    'ret'),
    ]
    iter_fall = [
        (A_entry,  'mov x0, #1'),
        (A_pre_br, 'mov x1, #2'),
        (A_branch, 'b.eq #+0xc'),    # not taken → C_entry
        (C_entry,  'mov x3, #4'),
        (C_mid,    'mov x4, #5'),
        (B_entry,  'mov x2, #3'),    # fall through 进 B
        (B_ret,    'ret'),
    ]
    seq = iter1 + iter_fall + iter_fall
    t = _build_trace_with_pcs(seq, module_base=base)
    cfg = build_cfg(t)

    assert C_entry in cfg.blocks, "C block 应被识别"
    c = cfg.blocks[C_entry]
    assert c.executions == 2, f"C 执行 2 次, got {c.executions}"
    # 关键断言: 重复执行不应让 insns 堆叠
    assert c.insns == [C_entry, C_mid], (
        f"C.insns 应去重: 期望 [C_entry, C_mid], 实际 "
        f"{[hex(p) for p in c.insns]} (len={len(c.insns)})")

    # 全图 sanity: 任何块都不应该有重复 insns
    for pc, b in cfg.blocks.items():
        assert len(set(b.insns)) == len(b.insns), (
            f"block 0x{pc:x} 有重复 insns ({b.executions}× executed): "
            f"{[hex(p) for p in b.insns]}")


def test_entry_pc_in_module_when_trace_starts_external():
    """Bug #2: trace 第 0 条 PC 在 module 外, entry_pc 当前实现直接取 t.pc(0),
    不在 module 内, 下游会有问题.

    一个好的 entry_pc 应当是第一个 in-module 的 PC.
    """
    base = 0x100000
    ext = 0x200000
    seq = [
        (ext,         'mov x0, #1'),    # 第 0 条: 不在 module
        (ext + 4,     'mov x1, #2'),
        (base,        'mov x2, #3'),    # 第一个 in-module
        (base + 4,    'ret'),
    ]
    t = _build_trace_with_pcs(seq, module_base=base, module_size=0x10000)
    cfg = build_cfg(t, only_module=True)

    m = t.meta.module
    in_module = m.base <= cfg.entry_pc < m.end
    # 修法: entry_pc 应该是第一个 in-module pc, 而不是 trace 第 0 条
    assert in_module, (
        f"entry_pc 应在 module [{hex(m.base)}, {hex(m.end)}), "
        f"got {hex(cfg.entry_pc)} (trace[0]={hex(t.pc(0))})")


def test_call_stack_balanced_across_external_call():
    """Bug #3: bl 调外部 SO 后, 外部 ret 不在 only_module 视野里 ⇒ call_stack
    没 pop. 下一次本 module 的 ret 会 pop 错的 caller, 把 call-return 边加到错
    的来源块上.

    Layout (call A 调 ext, 然后 主流再调 B 完成本 module 的真正 call/ret):
      A: bl ext (调外部) ; A_post: mov ; bl B ; A_post2: ret
      ext: skipped
      B: mov ; ret

    本 module 真正的一对 call/ret = (A_post 的 bl B) ↔ (B 的 ret). 这对应当
    产生唯一的 call-return 边 (A_post_block → A_post2).

    Bug 表现: 错误的 call-return 边, 来源块是 A 而不是 A_post (因为 ext 的
    返回没把 A pop 掉, 之后真正本-module ret 配错了 caller).
    """
    base = 0x100000
    ext = 0x200000
    seq = [
        # ── frame A: 调 ext ──
        (base + 0x00, 'bl #+0x100000'),    # A: bl ext (调外部)
        (ext,         'mov x9, #9'),        # ext (skipped)
        # ── 回 module: 接着调本 module 内的 B ──
        (base + 0x04, 'mov x1, #1'),       # A_post: mov
        (base + 0x08, 'bl #+0x100'),       # A_post: bl B
        (base + 0x108,'mov x2, #2'),       # B: mov
        (base + 0x10c,'ret'),              # B: ret → 应回到 A_post2
        (base + 0x0c, 'mov x3, #3'),       # A_post2: 一条普通指令
        (base + 0x10, 'ret'),              # A_post2: ret → 应回 caller 的 call site
        # 末尾再跟一条 in-module pc, 让上面 ret 的 next_pc 形成边 → 暴露错配 frame
        (base + 0x80, 'mov x4, #4'),
    ]
    t = _build_trace_with_pcs(seq, module_base=base, module_size=0x10000)
    cfg = build_cfg(t, only_module=True)

    cr_pairs = {(s, d) for (s, d), v in cfg.edges.items()
                if v.get("kind") == "call-return"}
    # 期望两条 call-return:
    #   1) bl ext 块 (base+0x00) → ext 返回后的 post-call (base+0x04)
    #   2) bl B 块 (base+0x04) → B 的 ret 后的 post-call (base+0x0c)
    expected = {(base + 0x00, base + 0x04), (base + 0x04, base + 0x0c)}
    assert cr_pairs == expected, (
        f"call-return 边不对. 期望 {[(hex(s), hex(d)) for s, d in expected]}, "
        f"实际 {[(hex(s), hex(d)) for s, d in cr_pairs]}")
    # 关键: 决不应该有从 A (bl ext 块) 直接连到 trace 末尾任意 in-module pc
    # (base+0x80) 的 call-return 边 — 那是修前的错配.
    bogus = (base + 0x00, base + 0x80)
    assert bogus not in cr_pairs, (
        f"call_stack 不该把外部调用 frame 拿来给本 module 的 ret pop. "
        f"出现错误边 0x{bogus[0]:x} → 0x{bogus[1]:x}")


# ── 真实 trace 上的不变量 (smoke) ────────────────────────────────────────────

REAL_TRACE = (
    "/home/ltlly/Code/traceMiku/traces/multiso_v2/calls/"
    "call_004_tid15962_10214936r_6720ms"
)

@pytest.mark.skipif(not os.path.exists(REAL_TRACE),
                    reason="real trace 不在 dev box 里")
def test_real_trace_no_dup_insns():
    """对真实 trace 跑 build_cfg, 不允许任何 block insns 有重复.

    背景: 用户报告的 call_004 trace 在 fix 前 47/2001 块有重复, 最坏 13557 / 3
    unique. 修后必须 0/2001.
    """
    from viewer.trace import load
    t = load(REAL_TRACE)
    cfg = build_cfg(t, only_module=True)
    bad = []
    for pc, b in cfg.blocks.items():
        s = set(b.insns)
        if len(s) != len(b.insns):
            bad.append((pc, len(b.insns), len(s), b.executions))
    if bad:
        bad.sort(key=lambda x: -(x[1] - x[2]))
        msg = ", ".join(f"0x{p:x}({tot}/{uniq}u ×{ex})"
                        for p, tot, uniq, ex in bad[:5])
        pytest.fail(f"{len(bad)} blocks 有重复 insns. 最坏 5: {msg}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
