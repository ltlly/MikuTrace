"""--trace-deep boundary-diff pipeline:
   agent 发 ext-write events → host 写 external_writes.bin →
   MemShadow.build() 加载并 splat 为 kind='x'.

测试覆盖:
- MemShadow 加载 external_writes.bin (17 字节/record: <Q attr_idx <Q addr <B byte)
- byte_at(addr, t) 在 attr_idx 之前返回 ?? / 之后返回 (byte, 'x', attr_idx)
- ext writes 进 self.writes / numpy w_addr index
- 外部+真实 writes 交错时 byte_at 取 idx 最大者
- agent_cmodule_v5.js 含必备 strings (静态扫, 验 wiring 没掉)
- tracemiku 含 ext-write 处理 + --trace-deep CLI flag
"""
import struct, pathlib, tempfile, pytest


HERE = pathlib.Path(__file__).resolve().parent.parent


def _write_trace_bin(dir_, n_records=4, base_pc=0x100000):
    """写 n 条 nop trace.bin (每条 272B). 返回 Trace path."""
    path = dir_ / "trace.bin"
    NOP = 0xd503201f   # nop
    with open(path, "wb") as f:
        for i in range(n_records):
            f.write(struct.pack("<Q", base_pc + i * 4))    # pc
            for _ in range(31): f.write(struct.pack("<Q", 0))   # x0..x28, fp, lr
            f.write(struct.pack("<Q", 0x7000))              # sp
            f.write(struct.pack("<I", 0))                   # nzcv
            f.write(struct.pack("<I", NOP))                 # inst
    return path


def _write_ext_bin(dir_, events):
    """events: list of (attr_idx, addr, byte). Returns external_writes.bin path."""
    path = dir_ / "external_writes.bin"
    with open(path, "wb") as f:
        for ai, addr, b in events:
            f.write(struct.pack("<QQB", ai, addr, b & 0xff))
    return path


def _open_memshadow(trace_dir):
    from viewer.trace import Trace, TraceMeta, Module
    bin_path = trace_dir / "trace.bin"
    meta = TraceMeta()
    meta.module = Module("synth.so", 0x100000, 0x10000)
    t = Trace(bin_path, meta)
    from viewer.memshadow import MemShadow
    m = MemShadow(t)
    m.build()
    return t, m


def test_load_with_no_ext_file(tmp_path):
    """没有 external_writes.bin 时 build 不抛."""
    _write_trace_bin(tmp_path)
    _, m = _open_memshadow(tmp_path)
    assert m.built
    # writes 列表只来自 trace 内部 (4 个 nop, 没有 store, 应为空)
    assert len(m.writes) == 0


def test_ext_write_loaded_and_splat_as_x(tmp_path):
    _write_trace_bin(tmp_path, n_records=8)
    # ext: idx=2 处外部写入 addr 0xb0000000, byte=0xab
    _write_ext_bin(tmp_path, [(2, 0xb0000000, 0xab)])
    _, m = _open_memshadow(tmp_path)
    # idx=1: 还没写入 → ??
    b, k, src = m.byte_at(0xb0000000, 1)
    assert b is None and k == "??" and src is None
    # idx=2: 刚写入 → kind='x'
    b, k, src = m.byte_at(0xb0000000, 2)
    assert b == 0xab and k == "x" and src == 2
    # idx=5: 仍可见
    b, k, src = m.byte_at(0xb0000000, 5)
    assert b == 0xab and k == "x" and src == 2


def test_ext_write_in_writes_list(tmp_path):
    _write_trace_bin(tmp_path, n_records=4)
    _write_ext_bin(tmp_path, [
        (1, 0xc0000000, 0x11),
        (1, 0xc0000001, 0x22),
        (3, 0xc0000010, 0x33),
    ])
    _, m = _open_memshadow(tmp_path)
    # 3 个 ext write → 3 个 writes 条目
    assert len(m.writes) == 3
    # numpy index 也包含
    assert len(m.w_addr) == 3
    assert int(m.w_addr[0]) in (0xc0000000, 0xc0000001, 0xc0000010)


def test_ext_writes_sorted_ascending(tmp_path):
    """attr_idx 按 trace 顺序 ascending (host 写文件保持顺序). build 后 writes
    list + bytes[].evs 也必须 ascending,binary search 才正确."""
    _write_trace_bin(tmp_path, n_records=10)
    # 故意非排序写
    _write_ext_bin(tmp_path, [
        (5, 0xd0000000, 0x55),
        (2, 0xd0000000, 0x22),
        (8, 0xd0000000, 0x88),
    ])
    _, m = _open_memshadow(tmp_path)
    # writes ascending
    idxs = [w[0] for w in m.writes]
    assert idxs == sorted(idxs)
    # byte_at idx=3 → 取 idx<=3 最大者 = 2 → byte 0x22
    b, k, _ = m.byte_at(0xd0000000, 3)
    assert b == 0x22 and k == "x"
    # byte_at idx=10 → 取最大 = 8 → byte 0x88
    b, k, _ = m.byte_at(0xd0000000, 10)
    assert b == 0x88 and k == "x"


def test_ext_file_with_garbage_size_skips(tmp_path):
    """external_writes.bin 大小不是 17 倍数 (e.g. 部分写入坏文件) 不应 crash."""
    _write_trace_bin(tmp_path)
    # 写 17+5=22 字节: 1 个完整 record + 5 字节垃圾尾
    path = tmp_path / "external_writes.bin"
    with open(path, "wb") as f:
        f.write(struct.pack("<QQB", 1, 0xe0000000, 0xee))
        f.write(b"\x00" * 5)
    _, m = _open_memshadow(tmp_path)
    # 应只读到 1 条
    assert len(m.writes) == 1
    b, k, _ = m.byte_at(0xe0000000, 2)
    assert b == 0xee and k == "x"


def test_empty_ext_file_ok(tmp_path):
    """0 字节 external_writes.bin 不影响 build."""
    _write_trace_bin(tmp_path)
    (tmp_path / "external_writes.bin").write_bytes(b"")
    _, m = _open_memshadow(tmp_path)
    assert m.built and len(m.writes) == 0


# ─── 静态 wiring 测试: 防 agent / host 改动后链路掉 ─────────────────────────

def test_agent_has_deep_trace_strings():
    js = (HERE / "tracer" / "agent_cmodule_v5.js").read_text()
    # RPC opt
    assert "deepTrace" in js, "agent 缺 deepTrace opt"
    assert "DEFAULT_HOSTILE_PATTERNS" in js, "agent 缺 DEFAULT_HOSTILE_PATTERNS"
    # boundary diff core
    assert "installBoundaryDiffHooksOnce" in js
    assert "ext-write" in js, "agent 必须 send type='ext-write'"
    assert "flushExtWriteEvents" in js
    # ART hostile patterns 必含一些已知值
    assert "art::interpreter::Execute" in js
    assert "art::jit" in js or "art::jit::Jit" in js


def test_agent_flushes_ext_at_trace_end():
    """agent flushExtWriteEvents 必须在两个 trace-end 路径之前调用 (watchdog + onLeave)."""
    js = (HERE / "tracer" / "agent_cmodule_v5.js").read_text()
    # 两次 flushExtWriteEvents() 调用
    n_flush = js.count("flushExtWriteEvents()")
    assert n_flush >= 2, f"flushExtWriteEvents() 必须在 watchdog+onLeave 路径都调用 (got {n_flush})"


def test_tracemiku_handles_ext_write():
    src = (HERE / "tracemiku").read_text()
    assert 'elif t == "ext-write"' in src, "tracemiku 缺 ext-write dispatcher"
    assert "external_writes.bin" in src, "tracemiku 缺 external_writes.bin 写入"
    assert "ext_fp" in src, "tracemiku 缺 ext_fp session attr"
    # CLI flag
    assert "--trace-deep" in src or "trace_deep" in src, "tracemiku 缺 --trace-deep flag"


def test_tracemiku_passes_deep_to_agent():
    src = (HERE / "tracemiku").read_text()
    assert '"deepTrace":' in src, "tracemiku AGENT_OPTS 缺 deepTrace"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
