"""Pass 1.5 UIDF — User-Informed DataFlow from trace 真值."""
from __future__ import annotations
from viewer.decompiler.llil import (
    ObservedValues, collect_uidf, apply_uidf_to_constfold_env,
    ssa_block, constfold_block,
    set_reg, reg, const, add, load,
    LLIL_SET_REG, LLIL_CONST, LLIL_LOAD,
)


def test_observed_values_const_detection():
    ov = ObservedValues(pc=0x1000, reg="x0", n_hits=10,
                        distinct_count=1, first=42, last=42, sample=[42])
    assert ov.is_const()
    assert ov.const_value() == 42


def test_observed_values_not_const():
    ov = ObservedValues(pc=0x1000, reg="x0", n_hits=10,
                        distinct_count=3, first=1, last=3, sample=[1, 2, 3])
    assert not ov.is_const()
    assert ov.const_value() is None


def test_apply_uidf_injects_const_into_env():
    """SET_REG 但 value 是 LLIL_LOAD (不可推) — 但 trace 实测每次都是 0x42 → 注入 env."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(reg("x9"), size=8), pc=0x1000),
    ])
    # 模拟 uidf: 该 root 实测每次 x0=0x42
    uidf = {
        (0x1000, 0): ObservedValues(
            pc=0x1000, reg="x0", n_hits=5,
            distinct_count=1, first=0x42, last=0x42, sample=[0x42],
        ),
    }
    env: dict = {}
    apply_uidf_to_constfold_env(uidf, blk, env)
    # x0 v1 应该有 const 0x42
    assert env.get(("x0", 1)) == 0x42


def test_constfold_uses_uidf():
    """constfold(blk, uidf) — load 出的 reg 实测 const → 后续 use 自动 fold."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(reg("x9"), size=8), pc=0x1000),
        set_reg("x1", add(reg("x0"), const(3)), pc=0x1004),
    ])
    # uidf 标记 x0 实测是 5
    uidf = {
        (0x1000, 0): ObservedValues(
            pc=0x1000, reg="x0", n_hits=10, distinct_count=1,
            first=5, last=5, sample=[5],
        ),
    }
    new = constfold_block(blk, uidf=uidf)
    # 第二条 set_reg(x1, x0+3) 应折成 set_reg(x1, const(8))
    v2 = new.roots[1].operands[1]
    assert v2.op == LLIL_CONST
    assert v2.operands == [8]


def test_constfold_without_uidf_unchanged():
    """没 uidf 时 constfold 行为跟之前一致."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(reg("x9"), size=8), pc=0x1000),
        set_reg("x1", add(reg("x0"), const(3)), pc=0x1004),
    ])
    new = constfold_block(blk)   # no uidf
    # x0 来自 load 不可推 → x1 不折
    from viewer.decompiler.llil import LLIL_ADD
    assert new.roots[1].operands[1].op == LLIL_ADD


def test_uidf_non_const_does_not_inject():
    """ObservedValues distinct > 1 时不注入 (不假装 const)."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(reg("x9"), size=8), pc=0x1000),
    ])
    uidf = {
        (0x1000, 0): ObservedValues(
            pc=0x1000, reg="x0", n_hits=10,
            distinct_count=3, first=1, last=5, sample=[1, 3, 5],
        ),
    }
    env: dict = {}
    apply_uidf_to_constfold_env(uidf, blk, env)
    assert env == {}


def test_collect_uidf_on_synth_trace():
    """合成 trace 跑 collect_uidf 端到端."""
    from tests.synth import build_trace
    t = build_trace([
        ('mov x0, #5',  {'x0': 5}),     # SET_REG x0 = 5, x0 实测 = 5
        ('mov x0, #5',  {'x0': 5}),     # 又是 5
        ('ret',         {}),
    ])
    # build llil pipeline minimal
    from viewer.decompiler.llil import lift_arm64, ssa_block
    import numpy as np
    n = len(t)
    pc_arr = t.pc_array()
    from viewer.trace import REC_SIZE
    u32 = np.frombuffer(t._mm, dtype=np.uint32, count=t.n * (REC_SIZE // 4))
    inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]
    # lift each PC
    block_to_exprs: dict = {}
    for i in range(n):
        pc = int(pc_arr[i])
        inst = int(inst_arr[i])
        exprs = list(lift_arm64(pc, inst))
        block_to_exprs.setdefault(pc, [])
        if not block_to_exprs[pc]:
            block_to_exprs[pc].extend(exprs)
    # ssa
    ssa_map = {pc: ssa_block(pc, exprs)
               for pc, exprs in block_to_exprs.items()}
    uidf = collect_uidf(t, ssa_map)
    # 至少 mov x0, #5 应有 ObservedValues, 且 is_const
    found_const = False
    for key, ov in uidf.items():
        if ov.reg == "x0" and ov.is_const() and ov.const_value() == 5:
            found_const = True
    assert found_const
    t.close()


def test_collect_uidf_observes_call_return():
    """LLIL_CALL 后 trace 在 call.pc+4 处的 record 含 x0 = return value.
    collect_uidf 应抓到这个 'ret_x0' ObservedValues."""
    from tests.synth import build_trace
    t = build_trace([
        ('mov x0, #1',     {'x0': 1}),
        # synth 模型: bl 的 deltas 是 callee 执行后 caller 视角的 net change —
        # x30 (lr) + x0 (return value) 一并写入. 真实 trace 里 bl 后下条 record
        # 是 callee 入口 (PC=0x2000), 但 PC=call.pc+4 处的 record (return 后)
        # 含真正的 return 值. 我们这里压缩到一条记录.
        ('bl #0x2000',     {'x30': 0x100008, 'x0': 0xff}),
        ('mov x9, x0',     {'x9': 0xff}),    # PC=base+0x8: record.x0 = 0xff
        ('ret',            {}),
    ])
    from viewer.decompiler.llil import lift_arm64, ssa_block
    import numpy as np
    n = len(t)
    pc_arr = t.pc_array()
    from viewer.trace import REC_SIZE
    u32 = np.frombuffer(t._mm, dtype=np.uint32, count=t.n * (REC_SIZE // 4))
    inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]
    block_to_exprs: dict = {}
    for i in range(n):
        pc = int(pc_arr[i])
        inst = int(inst_arr[i])
        exprs = list(lift_arm64(pc, inst))
        block_to_exprs.setdefault(pc, [])
        if not block_to_exprs[pc]:
            block_to_exprs[pc].extend(exprs)
    ssa_map = {pc: ssa_block(pc, exprs) for pc, exprs in block_to_exprs.items()}
    uidf = collect_uidf(t, ssa_map)
    # 找 ret_x0 ObservedValues
    found_ret = False
    for key, ov in uidf.items():
        if ov.reg == "ret_x0" and ov.is_const() and ov.const_value() == 0xff:
            found_ret = True
            break
    assert found_ret, f"expected ret_x0 obs with value 0xff, got: {dict((k, ov.short()) for k, ov in uidf.items())}"
    t.close()
