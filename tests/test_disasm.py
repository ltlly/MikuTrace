"""测试 disasm 模块的 def/use 提取，重点是 cmp 类指令的修复."""
import pytest
from viewer.disasm import decode


def test_mov_def_use():
    # mov x0, #1 — def x0, no use
    d = decode(0x100000, 0xd2800020)
    assert 'x0' in d.regs_def
    assert d.regs_use == ()


def test_mov_reg_to_reg():
    # mov x1, x0 — def x1, use x0
    d = decode(0x100000, 0xaa0003e1)
    assert 'x1' in d.regs_def
    assert 'x0' in d.regs_use


def test_add_imm():
    # add x0, x0, #1
    d = decode(0x100000, 0x91000400)
    assert 'x0' in d.regs_def
    assert 'x0' in d.regs_use


def test_cmp_x0_x1():
    # cmp x0, x1 — should def nzcv, USE x0 + x1, NOT def x0/x1
    d = decode(0x100000, 0xeb01001f)
    assert d.regs_def == ('nzcv',), f"cmp 不应 def x0/x1, got {d.regs_def}"
    assert 'x0' in d.regs_use
    assert 'x1' in d.regs_use


def test_cmp_imm():
    # cmp x0, #0 — capstone bug fix: x0 should be use, not def
    d = decode(0x100000, 0xf100001f)
    assert d.regs_def == ('nzcv',), f"got {d.regs_def}"
    assert 'x0' in d.regs_use


def test_branch_classification():
    # ret — is_ret
    d = decode(0x100000, 0xd65f03c0)
    assert d.is_ret
    assert d.is_branch
    # b #+8
    d = decode(0x100000, 0x14000002)
    assert d.is_branch and not d.is_ret and not d.is_call
    # bl
    d = decode(0x100000, 0x94000002)
    assert d.is_call


def test_indirect_branch():
    # br x8
    d = decode(0x100000, 0xd61f0100)
    assert d.is_branch
    assert d.indirect_branch_reg == 'x8'


def test_load_store_mem_op():
    from tests.synth import asm_to_inst
    # ldr x0, [sp, #0x10]
    d = decode(0x100000, asm_to_inst('ldr x0, [sp, #0x10]'))
    assert len(d.mem_op) == 1
    base, idx, disp, sz, is_w, _src = d.mem_op[0]
    assert base == 'sp'
    assert disp == 0x10
    assert is_w is False
    # str x0, [sp, #0x10]
    d = decode(0x100000, asm_to_inst('str x0, [sp, #0x10]'))
    assert d.mem_op[0][4] is True   # is_w


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
