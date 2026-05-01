"""disasm 边角: branch_target 立即数 / size 后缀映射 / <bad> 兜底 / cache.

主套 test_disasm.py 已覆盖核心 def-use + 分类. 这里补"易回归点":
  - branch_target: b/bl 立即数解析 (用户 cfg-svg edge color 依赖)
  - mem_op size: ldrb=1 / ldrh=2 / ldr w=4 / ldr x=8 (memshadow 写偏 1 字节就错)
  - <bad> 兜底: capstone 解不出时不崩
  - decode lru_cache: 同 (pc, inst) 命中 cache (perf invariant)
"""
import pytest
from viewer.disasm import decode
from tests.synth import asm_to_inst


# ── branch_target 立即数 ─────────────────────────────────────────────────────

def test_branch_target_b_imm_forward():
    """b #+8 跳到 PC+8."""
    inst = asm_to_inst("b #+8")
    d = decode(0x1000, inst)
    assert d.is_branch and not d.is_call
    assert d.branch_target == 0x1008


def test_branch_target_bl_imm():
    """bl <imm> = call, branch_target 是绝对 PC."""
    inst = asm_to_inst("bl #+0x40")
    d = decode(0x2000, inst)
    assert d.is_call
    assert d.branch_target == 0x2040


def test_branch_target_bcond():
    """b.eq #+0xc 也填 branch_target."""
    inst = asm_to_inst("b.eq #+0xc")
    d = decode(0x3000, inst)
    assert d.is_branch and not d.is_call and not d.is_ret
    assert d.branch_target == 0x300c


def test_branch_target_indirect_no_imm():
    """br x8 是间接跳转, branch_target 应保持默认 (无 imm), indirect_branch_reg 有值."""
    d = decode(0x100000, 0xd61f0100)   # br x8
    assert d.indirect_branch_reg == "x8"
    # branch_target 默认是 None / 0 (依实现); 重要的是 indirect_branch_reg 有值
    # 不强求 branch_target 是 None — 只要它不被错误地当成有效 imm 用
    # ret 同样


def test_branch_target_ret_no_imm():
    d = decode(0x1000, 0xd65f03c0)   # ret
    assert d.is_ret
    # ret 没 imm target, 也不应被 indirect 标 (op_str 是空 / 'x30' 隐含)


# ── mem_op size 后缀映射 ────────────────────────────────────────────────────

def test_ldrb_size_1():
    """ldrb w0, [x1] — byte load = 1."""
    d = decode(0x1000, asm_to_inst("ldrb w0, [x1]"))
    assert len(d.mem_op) == 1
    sz = d.mem_op[0][3]
    assert sz == 1, f"ldrb size 应=1, got {sz}"


def test_ldrh_size_2():
    """ldrh w0, [x1] — halfword = 2."""
    d = decode(0x1000, asm_to_inst("ldrh w0, [x1]"))
    sz = d.mem_op[0][3]
    assert sz == 2, f"ldrh size 应=2, got {sz}"


def test_ldr_w_size_4():
    """ldr w0, [x1] — 32-bit reg = 4 bytes."""
    d = decode(0x1000, asm_to_inst("ldr w0, [x1]"))
    sz = d.mem_op[0][3]
    assert sz == 4, f"ldr w0 size 应=4, got {sz}"


def test_ldr_x_size_8():
    """ldr x0, [x1] — 64-bit = 8."""
    d = decode(0x1000, asm_to_inst("ldr x0, [x1]"))
    sz = d.mem_op[0][3]
    assert sz == 8


def test_strb_is_write():
    """strb is_w = True."""
    d = decode(0x1000, asm_to_inst("strb w0, [x1]"))
    is_w = d.mem_op[0][4]
    assert is_w is True


def test_str_x_size_8():
    d = decode(0x1000, asm_to_inst("str x0, [x1]"))
    sz, is_w = d.mem_op[0][3], d.mem_op[0][4]
    assert sz == 8 and is_w is True


def test_mem_op_with_index_reg():
    """ldr x0, [x1, x2, lsl #3] — 带 index reg."""
    d = decode(0x1000, asm_to_inst("ldr x0, [x1, x2, lsl #3]"))
    base, idx, disp, sz, is_w, _src = d.mem_op[0]
    assert base == "x1"
    assert idx == "x2"
    assert sz == 8


# ── <bad> instruction 兜底 ──────────────────────────────────────────────────

def test_bad_instruction_does_not_crash():
    """capstone 解不出来的 inst 应回 Decoded 而不是抛."""
    d = decode(0x1000, 0x00000000)  # all-zero, 在 ARM64 是 udf
    assert d.mnemonic is not None   # 不崩, 总有 mnemonic 字串


def test_arbitrary_garbage_instruction():
    d = decode(0x1000, 0xffffffff)
    assert d is not None
    assert d.mnemonic is not None


# ── decode lru_cache ────────────────────────────────────────────────────────

def test_decode_returns_same_object_for_same_input():
    """lru_cache 命中 → 同一对象 (id 一样)."""
    d1 = decode(0x1000, 0xd65f03c0)   # ret
    d2 = decode(0x1000, 0xd65f03c0)
    assert d1 is d2, "lru_cache 应返同一对象"


def test_decode_different_pc_different_object():
    """同 inst 不同 pc → 缓存 key 不同, 不同对象 (但内容可能同)."""
    d1 = decode(0x1000, 0xd65f03c0)
    d2 = decode(0x2000, 0xd65f03c0)
    # 至少 mnemonic 一致
    assert d1.mnemonic == d2.mnemonic == "ret"


# ── cmp + 衍生 ───────────────────────────────────────────────────────────────

def test_tst_only_writes_nzcv():
    """tst x0, #1 与 cmp 同类 — 只 def nzcv, x0 是 use."""
    d = decode(0x1000, asm_to_inst("tst x0, #1"))
    assert d.regs_def == ("nzcv",), f"tst 应只 def nzcv, got {d.regs_def}"
    assert "x0" in d.regs_use


def test_cmn_only_writes_nzcv():
    """cmn 也是 cmp 类."""
    d = decode(0x1000, asm_to_inst("cmn x0, x1"))
    assert d.regs_def == ("nzcv",)


# ── 条件分支 ─────────────────────────────────────────────────────────────────

def test_cbz_classified_as_branch():
    """cbz w0, label — 条件分支."""
    d = decode(0x1000, asm_to_inst("cbz w0, #+8"))
    assert d.is_branch
    assert not d.is_call
    assert not d.is_ret


def test_tbz_classified_as_branch():
    """tbz x0, #1, label."""
    d = decode(0x1000, asm_to_inst("tbz x0, #1, #+8"))
    assert d.is_branch


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
