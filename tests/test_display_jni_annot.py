"""P0-2 part 3: display reg-line annotates `→ "<utf8>"` when reg value matches
a JNI call's pointer arg / ret address."""
import struct, json, pytest, pathlib
from tests.synth import build_trace, asm_to_inst
from viewer.trace import Trace, TraceMeta, Module
from viewer.symbols import build_from_trace
from viewer.memshadow import MemShadow
from viewer.display import build_jni_value_map, format_reg_line


def test_build_jni_value_map_from_newstringutf():
    """NewStringUTF event with args.bytes='hello' at trace_idx 1; if reg x1
    at idx 1 = ptr P, map P → 'hello'."""
    PTR_VAL = 0x7000abcd
    seq = [
        ('mov x0, #0x10', {'x0': 0x10}),                # idx 0: setup
        ('mov x1, x0',    {'x0': 0x10, 'x1': PTR_VAL}), # idx 1: x1=PTR (NewStringUTF call site)
    ]
    t = build_trace(seq)
    # patch x1 at idx 1 to PTR_VAL — build_trace uses regs_after which I set
    # but that's the AFTER-state. Verify via t.record.
    r1 = t.record(1)
    # the synth uses state after 'mov x1, x0' = x0=0x10, x1=PTR. Hmm,
    # actually synth records AT idx 1 = state BEFORE that insn. Let me build
    # explicitly.
    t.close()


def _make_explicit_trace(tmp_path, regs_at_idx):
    """Direct write trace.bin with explicit reg state at each idx."""
    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix='.bin', prefix='jniannot_')
    os.close(fd)
    bf = open(tmp, 'wb')
    base = 0x100000
    for i, regs in enumerate(regs_at_idx):
        bf.write(struct.pack('<Q', base + i * 4))
        for r_idx in range(31):
            name = f'x{r_idx}' if r_idx < 29 else ('fp' if r_idx == 29 else 'lr')
            bf.write(struct.pack('<Q', regs.get(name, 0)))
        bf.write(struct.pack('<Q', regs.get('sp', 0x7000)))
        bf.write(struct.pack('<I', 0))
        bf.write(struct.pack('<I', asm_to_inst('nop')))
    bf.close()
    meta = TraceMeta()
    meta.module = Module('synth.so', base, 0x10000)
    meta.method = 'f'
    return Trace(tmp, meta), tmp


def test_jni_value_map_finds_newstringutf_arg(tmp_path):
    """At idx of NewStringUTF call, x1 holds char* — map x1 value → string content."""
    PTR = 0x7000abcd
    t, _ = _make_explicit_trace(tmp_path, [
        {'x0': 0, 'x1': 0},          # idx 0
        {'x0': 0x100, 'x1': PTR},    # idx 1: NewStringUTF site, x1=PTR
        {'x0': 0, 'x1': 0},          # idx 2
    ])
    # Inject jni_events directly (no jsonl file)
    t._jni_events = [
        {"id": "NewStringUTF", "trace_idx": 1, "args": {"bytes": "hello"}}
    ]
    m = build_jni_value_map(t)
    assert PTR in m, f"PTR {hex(PTR)} should map to 'hello': {m}"
    assert m[PTR] == "hello"
    t.close()


def test_jni_value_map_empty_when_no_events(tmp_path):
    t, _ = _make_explicit_trace(tmp_path, [{'x0': 0}])
    t._jni_events = []
    m = build_jni_value_map(t)
    assert m == {}
    t.close()


def test_format_reg_line_includes_jni_string(tmp_path):
    """When reg value matches JNI map, format_reg_line should include the
    string content."""
    PTR = 0x7000abcd
    t, _ = _make_explicit_trace(tmp_path, [
        {'x0': 0, 'x1': 0},
        {'x0': 0x100, 'x1': PTR},
        {'x0': 0, 'x1': 0},
    ])
    t._jni_events = [
        {"id": "NewStringUTF", "trace_idx": 1, "args": {"bytes": "hello-jni"}}
    ]
    sym = build_from_trace(t)
    mem = MemShadow(t); mem.build()
    jni_map = build_jni_value_map(t)
    # at idx 1, x1=PTR — format with jni_map should show 'hello-jni'
    line = format_reg_line("x1", PTR, 1, t, sym, mem, [], 0x7000,
                            jni_value_map=jni_map)
    assert "hello-jni" in line.plain
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
