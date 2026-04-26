"""合成 trace 生成器：手工构造已知正确性的 ARM64 trace 用于测试.

用法:
    from tests.synth import build_trace, asm
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('add x0, x0, #2', {'x0': 3}),
        ('cmp x0, #3', {'nzcv': 0x40}),
        ('b.eq #+8', {}),
    ], base=0x100000)

会构造一个 mmap-able binary trace 文件 + Trace 对象。
"""
import struct, tempfile, os, pathlib
from viewer.trace import REC_SIZE, Trace, TraceMeta, Module


_KS = None
_CACHE = {}
def asm_to_inst(s: str) -> int:
    """用 keystone 编码 ARM64 汇编串为 4 字节指令."""
    if s in _CACHE: return _CACHE[s]
    global _KS
    if _KS is None:
        from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
        _KS = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoded, _ = _KS.asm(s)
    if not encoded or len(encoded) != 4:
        raise ValueError(f'编码失败: {s}')
    inst = int.from_bytes(bytes(encoded), 'little')
    _CACHE[s] = inst
    return inst


def build_trace(seq, base=0x100000, module_size=0x10000) -> Trace:
    """seq: list of (asm_str, regs_after_dict)
    regs_after_dict: which regs change after this instruction (we only track GPR + sp)
    Returns a Trace mmap'd to a temp file."""
    pc = base
    # initial regs: all zero
    state = {f'x{i}': 0 for i in range(31)}
    state['sp'] = 0x7000
    state['nzcv'] = 0
    records = []
    for asm, deltas in seq:
        # snapshot BEFORE this insn (record's "regs at" = state before execution)
        rec = {
            'pc': pc,
            'regs': [state[f'x{i}'] for i in range(29)] + [state['x29'], state['x30']],
            'sp': state['sp'],
            'nzcv': state['nzcv'],
            'inst': asm_to_inst(asm),
        }
        # rename x29->fp, x30->lr in our record format (positions 29, 30)
        records.append(rec)
        # apply deltas
        for k, v in deltas.items():
            if k == 'fp': k = 'x29'
            if k == 'lr': k = 'x30'
            state[k] = v
        pc += 4
    # write to tmp file
    fd, tmp = tempfile.mkstemp(suffix='.bin', prefix='synth_')
    os.close(fd)
    fp = open(tmp, 'wb')
    for r in records:
        fp.write(struct.pack('<Q', r['pc']))
        for v in r['regs']: fp.write(struct.pack('<Q', v))
        fp.write(struct.pack('<Q', r['sp']))
        fp.write(struct.pack('<I', r['nzcv']))
        fp.write(struct.pack('<I', r['inst']))
    fp.close()
    meta = TraceMeta()
    meta.module = Module('synth.so', base, module_size)
    meta.method = 'synth_func'
    return Trace(tmp, meta)
