"""ARM64 stp/ldp pair load/store: 内存读写实际 16 字节, 但当前 mem_op 报 8 字节
+ 只取一个 source reg → 第二个 reg 的 8 字节丢失.

这是 prologue/epilogue 高频指令; 任何函数都用 stp x29, x30 押栈, MemShadow 丢
8 字节 = trace 上看不到 fp/lr 的内存值.
"""
import struct, tempfile, os, pytest
from viewer.trace import Trace, TraceMeta, Module, REC_SIZE
from viewer.disasm import decode
from viewer.memshadow import MemShadow
from tests.synth import asm_to_inst


def _build_trace_with_state(seq, base=0x100000, module_size=0x10000):
    """seq: list of (pc, asm, regs_dict, sp). regs_dict={'x0': v, 'x29': v, ...}.
    每条记录的 reg state 被精确控制, 用来观察 stp 的两个源寄存器值."""
    fd, tmp = tempfile.mkstemp(suffix='.bin', prefix='pair_')
    os.close(fd)
    fp = open(tmp, 'wb')
    for pc, asm, regs, sp in seq:
        inst = asm_to_inst(asm)
        # default 0
        rstate = {f'x{i}': 0 for i in range(31)}
        rstate.update(regs)
        # x29=fp, x30=lr (synth.py 风格)
        fp_v = rstate.get('x29', rstate.get('fp', 0))
        lr_v = rstate.get('x30', rstate.get('lr', 0))
        fp.write(struct.pack('<Q', pc))
        for i in range(29):
            fp.write(struct.pack('<Q', rstate[f'x{i}']))
        fp.write(struct.pack('<Q', fp_v))
        fp.write(struct.pack('<Q', lr_v))
        fp.write(struct.pack('<Q', sp))
        fp.write(struct.pack('<I', 0))      # nzcv
        fp.write(struct.pack('<I', inst))
    fp.close()
    meta = TraceMeta()
    meta.module = Module('synth.so', base, module_size)
    return Trace(tmp, meta)


def test_stp_two_mem_ops_each_8_bytes():
    """stp x0, x1, [sp, #-16]! 应有 2 条 mem_op (各 8 字节, disp 不同)."""
    d = decode(0x1000, asm_to_inst("stp x0, x1, [sp, #-16]!"))
    assert len(d.mem_op) == 2, f"stp 应分 2 个 mem_op, got {len(d.mem_op)}: {d.mem_op}"
    # 大小总和 = 16 (8 + 8)
    total_sz = sum(op[3] for op in d.mem_op)
    assert total_sz == 16, f"两 mem_op 总 size 应=16, got {total_sz}"
    # 都是 write
    assert all(op[4] is True for op in d.mem_op)
    # disp 间隔 8 (顺序无所谓, 看绝对值)
    disps = sorted(op[2] for op in d.mem_op)
    assert disps[1] - disps[0] == 8, f"两 mem_op disp 应差 8, got {disps}"


def test_ldp_two_mem_ops():
    """ldp x0, x1, [sp], #16 也是 2 mem_op."""
    d = decode(0x1000, asm_to_inst("ldp x0, x1, [sp], #16"))
    assert len(d.mem_op) == 2
    assert all(op[4] is False for op in d.mem_op)


def test_stp_w_pair_4byte_each():
    """stp w0, w1, [sp, #-8]! — 32-bit pair = 4+4 字节."""
    d = decode(0x1000, asm_to_inst("stp w0, w1, [sp, #-8]!"))
    assert len(d.mem_op) == 2
    sizes = sorted(op[3] for op in d.mem_op)
    assert sizes == [4, 4], f"stp w0,w1 size 应都是 4, got {sizes}"


def test_memshadow_captures_both_registers_of_stp(tmp_path):
    """关键: memshadow 必须把 stp x0, x1 的两个寄存器值都写到内存阴影.
    复现: x0=0xaaaa..., x1=0xbbbb... 在 sp-16, sp-8 应分别可读出."""
    base = 0x100000
    sp_init = 0x8000
    seq = [
        # 0: stp x0, x1, [sp, #-16]!  — 押 x0 到 sp-16, x1 到 sp-8, sp 减 16
        (base, "stp x0, x1, [sp, #-16]!",
         {"x0": 0xaaaaaaaaaaaaaaaa, "x1": 0xbbbbbbbbbbbbbbbb}, sp_init),
        # 1: 普通指令 (供 memshadow 推断 stp 的 sp 起点)
        (base + 4, "mov x2, #0",
         {"x0": 0xaaaaaaaaaaaaaaaa, "x1": 0xbbbbbbbbbbbbbbbb}, sp_init - 16),
    ]
    t = _build_trace_with_state(seq)
    mem = MemShadow(t)
    mem.build()

    # x0 写到 [sp_init - 16, sp_init - 8): 8 字节 little-endian = 0xaa*8
    for o in range(8):
        b, kind, _ = mem.byte_at(sp_init - 16 + o, t=10)
        assert b == 0xaa, (
            f"x0 第 {o} 字节应=0xaa (写到 sp-16+{o}), got {b}; kind={kind}")

    # x1 写到 [sp_init - 8, sp_init): 这是 stp 的"第二字段", 当前 bug 会丢
    for o in range(8):
        b, kind, _ = mem.byte_at(sp_init - 8 + o, t=10)
        assert b == 0xbb, (
            f"x1 第 {o} 字节应=0xbb (写到 sp-8+{o}), got {b}; kind={kind} "
            f"— stp/ldp pair 第二寄存器丢失 = 已知 bug, 修后应通过")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
