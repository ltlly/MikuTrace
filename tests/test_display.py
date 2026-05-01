"""viewer/display.py — 整文件 (8 个 helpers + classify + format_reg_line).

被 webui /api/record 大量调用 (智能解引用注释), 行为变化无人觉察 → 必须 pin.
用 FakeMem (byte_at 返 dict) 隔离 MemShadow 细节, 专注 display 逻辑本身.
"""
import pytest
from viewer.display import (
    is_in_known_module, looks_like_ascii, maybe_string_at, deref_u64,
    _heuristic_region, classify, format_reg_line, collect_modules_from_trace,
)


# ── FakeMem: byte_at(addr, t) ─────────────────────────────────────────────────

class FakeMem:
    """最小 MemShadow 替身. data: {addr: byte}. byte_at(addr, t) 总返已知 byte
    或 (None, '??', None). 忽略 t (我们不测时序)."""
    def __init__(self, data: dict[int, int]):
        self.data = data

    def byte_at(self, addr, t):
        b = self.data.get(addr)
        if b is None: return (None, "??", None)
        return (b, "w", 0)


def _set_str(mem: FakeMem, addr: int, s: str, terminator: bool = True):
    """填 NUL-terminated ASCII 进 FakeMem.data."""
    for i, c in enumerate(s.encode("ascii")):
        mem.data[addr + i] = c
    if terminator:
        mem.data[addr + len(s)] = 0


def _set_u64(mem: FakeMem, addr: int, val: int):
    for o in range(8):
        mem.data[addr + o] = (val >> (o * 8)) & 0xff


# ── is_in_known_module ───────────────────────────────────────────────────────

def test_is_in_known_module_match():
    mods = [(0x1000, 0x2000, "libA.so"), (0x3000, 0x4000, "libB.so")]
    assert is_in_known_module(mods, 0x1500) == ("libA.so", 0x500)
    assert is_in_known_module(mods, 0x3000) == ("libB.so", 0)
    assert is_in_known_module(mods, 0x3fff) == ("libB.so", 0xfff)


def test_is_in_known_module_no_match():
    mods = [(0x1000, 0x2000, "libA.so")]
    assert is_in_known_module(mods, 0x500) is None
    assert is_in_known_module(mods, 0x2000) is None   # end is exclusive
    assert is_in_known_module(mods, 0x5000) is None


def test_is_in_known_module_empty():
    assert is_in_known_module([], 0x1234) is None


# ── looks_like_ascii ─────────────────────────────────────────────────────────

def test_looks_like_ascii_pure_text():
    assert looks_like_ascii(b"Hello, world!") is True


def test_looks_like_ascii_empty_false():
    """空字节 → False (避免误判)."""
    assert looks_like_ascii(b"") is False


def test_looks_like_ascii_binary_false():
    assert looks_like_ascii(b"\x00\x01\x02\x03\xff\xfe") is False


def test_looks_like_ascii_mixed():
    """含少量控制字符 (tab/lf/cr) 算 print."""
    assert looks_like_ascii(b"line1\nline2\tend\r") is True


def test_looks_like_ascii_threshold():
    """min_print=0.85: 14/16 满足. mostly ascii but with 2 garbage."""
    s = b"hello\x00\x01" + b"a" * 10
    # 12 printable + 2 non-print + 2 'a' ... actually: 'hello' = 5 printable,
    # \x00\x01 = 2 not, 'aaaaaaaaaa' = 10 printable. total 15 printable / 17
    # = 0.88 >= 0.85 → True
    assert looks_like_ascii(s) is True


# ── maybe_string_at ──────────────────────────────────────────────────────────

def test_maybe_string_at_basic():
    mem = FakeMem({})
    _set_str(mem, 0x1000, "hello")
    assert maybe_string_at(mem, 0x1000, t=10) == "hello"


def test_maybe_string_at_too_short_returns_none():
    """< 4 字符不算 string."""
    mem = FakeMem({})
    _set_str(mem, 0x1000, "hi")  # 2 chars + NUL
    assert maybe_string_at(mem, 0x1000, t=10) is None


def test_maybe_string_at_no_nul_no_data():
    """读不到任何字节 → None."""
    mem = FakeMem({})
    assert maybe_string_at(mem, 0x1000, t=10) is None


def test_maybe_string_at_truncated_at_max_len():
    mem = FakeMem({})
    _set_str(mem, 0x1000, "abcdefghij" * 10, terminator=False)   # 100 chars no NUL
    out = maybe_string_at(mem, 0x1000, t=10, max_len=8)
    # max_len=8: 读 8 字节, 看起来是 ascii, 加 "..."
    assert out is not None
    assert out.endswith("...")


def test_maybe_string_at_garbage_returns_none():
    """非 ascii 字节 → None."""
    mem = FakeMem({0x1000: 0x80, 0x1001: 0xff, 0x1002: 0x90, 0x1003: 0x00})
    assert maybe_string_at(mem, 0x1000, t=10) is None


# ── deref_u64 ────────────────────────────────────────────────────────────────

def test_deref_u64_known_value():
    mem = FakeMem({})
    _set_u64(mem, 0x1000, 0xdeadbeef12345678)
    assert deref_u64(mem, 0x1000, t=10) == 0xdeadbeef12345678


def test_deref_u64_unknown_byte_returns_none():
    """缺一字节 → None (要求所有 8 字节都有 shadow data)."""
    mem = FakeMem({})
    _set_u64(mem, 0x1000, 0x1234)
    del mem.data[0x1004]   # 戳一个洞
    assert deref_u64(mem, 0x1000, t=10) is None


def test_deref_u64_zero():
    mem = FakeMem({})
    _set_u64(mem, 0x1000, 0)
    assert deref_u64(mem, 0x1000, t=10) == 0


# ── _heuristic_region ────────────────────────────────────────────────────────

def test_heuristic_region_java_heap_high_byte_b4():
    assert _heuristic_region(0xb400123456789abc) == "JavaHeap"


def test_heuristic_region_libart_range():
    assert _heuristic_region(0x6d12345678) == "libart?"


def test_heuristic_region_libc_range():
    assert _heuristic_region(0x7800000000) == "libc?"


def test_heuristic_region_unknown_returns_none():
    assert _heuristic_region(0) is None
    assert _heuristic_region(0x1000) is None
    assert _heuristic_region(0x123456) is None


# ── classify (smoke + 各路径) ────────────────────────────────────────────────

@pytest.fixture
def mock_trace():
    """最小 trace 替身, 只暴露 .meta.module."""
    class M: name = "libA.so"; base = 0x1000; end = 0x2000
    class Meta: module = M()
    class T: meta = Meta()
    return T()


@pytest.fixture
def empty_sym():
    from viewer.symbols import SymbolMap
    return SymbolMap()


def test_classify_zero_returns_null(mock_trace, empty_sym):
    out = classify(0, 0, mock_trace, empty_sym, FakeMem({}), [], sp=0)
    assert "NULL" in str(out)


def test_classify_stack_pointer_close(mock_trace, empty_sym):
    sp = 0x7000
    out = classify(sp + 0x10, 0, mock_trace, empty_sym, FakeMem({}), [], sp=sp)
    s = str(out)
    assert "[SP+0x10]" in s


def test_classify_stack_pointer_below(mock_trace, empty_sym):
    sp = 0x7000
    out = classify(sp - 0x40, 0, mock_trace, empty_sym, FakeMem({}), [], sp=sp)
    assert "[SP-0x40]" in str(out)


def test_classify_module_hit_with_sym(mock_trace):
    """value 在 known module 内, sym 有名 → [name+off]."""
    from viewer.symbols import SymbolMap
    sym = SymbolMap()
    sym.add(0x1500, "myFn")
    mods = [(0x1000, 0x2000, "libA.so")]
    out = classify(0x1520, 0, mock_trace, sym, FakeMem({}), mods, sp=0)
    s = str(out)
    assert "myFn" in s and "0x20" in s


def test_classify_module_hit_no_sym(mock_trace, empty_sym):
    """value 在 known module 但 sym 没名 → [mod+off]."""
    mods = [(0x1000, 0x2000, "libA.so")]
    out = classify(0x1500, 0, mock_trace, empty_sym, FakeMem({}), mods, sp=0)
    s = str(out)
    assert "libA.so" in s and "0x500" in s


def test_classify_string_pointer(mock_trace, empty_sym):
    """value 指向 ASCII 字串 → 显示字串内容."""
    mem = FakeMem({})
    _set_str(mem, 0x500000, "doCommand")
    out = classify(0x500000, 0, mock_trace, empty_sym, mem, [], sp=0)
    assert "doCommand" in str(out)


def test_classify_pointer_chain(mock_trace, empty_sym):
    """A→B→C 链, classify 应递归到 max_depth."""
    mem = FakeMem({})
    _set_u64(mem, 0x1000, 0x2000)
    _set_u64(mem, 0x2000, 0x3000)
    out = classify(0x1000, 0, mock_trace, empty_sym, mem, [], sp=0, max_depth=3)
    s = str(out)
    # 至少 1 次 → 链
    assert "→" in s


def test_classify_cycle_detected(mock_trace, empty_sym):
    """A→A self-ref 不应无限递归."""
    mem = FakeMem({})
    _set_u64(mem, 0x1000, 0x1000)
    out = classify(0x1000, 0, mock_trace, empty_sym, mem, [], sp=0, max_depth=5)
    # 不崩即可 (self-loop 在 deref_u64 后第二次 cur==value, 也不增 depth)
    assert out is not None


def test_classify_small_int_annotation(mock_trace, empty_sym):
    """value 小整数 (e.g., 0x111d6 = 70102) → (70102) 注释."""
    out = classify(0x111d6, 0, mock_trace, empty_sym, FakeMem({}), [], sp=0)
    s = str(out)
    assert "70102" in s


# ── format_reg_line ──────────────────────────────────────────────────────────

def test_format_reg_line_zero_no_classify(mock_trace, empty_sym):
    """value=0 不触发 classify (因为 NULL 走 classify zero)."""
    out = format_reg_line("x0", 0, 0, mock_trace, empty_sym, FakeMem({}), [], sp=0)
    s = str(out)
    assert "x0" in s
    # 0x0..0 hex
    assert "0000000000000000" in s


def test_format_reg_line_with_module_hit(mock_trace, empty_sym):
    mods = [(0x1000, 0x2000, "libA.so")]
    out = format_reg_line("x0", 0x1500, 0, mock_trace, empty_sym, FakeMem({}), mods, sp=0)
    s = str(out)
    assert "x0" in s
    assert "libA.so" in s


# ── collect_modules_from_trace ──────────────────────────────────────────────

def test_collect_modules_uses_modules_list():
    from viewer.trace import Module, TraceMeta
    class T:
        meta = TraceMeta()
    t = T()
    t.meta.modules = [
        Module("a.so", 0x1000, 0x1000),
        Module("b.so", 0x3000, 0x500),
    ]
    out = collect_modules_from_trace(t, mem=None)
    assert (0x1000, 0x2000, "a.so") in out
    assert (0x3000, 0x3500, "b.so") in out


def test_collect_modules_falls_back_to_module():
    """meta.modules 空但 meta.module 有 — 老 trace 兼容."""
    from viewer.trace import Module, TraceMeta
    class T:
        meta = TraceMeta()
    t = T()
    t.meta.module = Module("only.so", 0x1000, 0x500)
    t.meta.modules = []
    out = collect_modules_from_trace(t, mem=None)
    assert out == [(0x1000, 0x1500, "only.so")]


def test_collect_modules_empty_when_no_meta():
    from viewer.trace import TraceMeta
    class T:
        meta = TraceMeta()
    t = T()
    t.meta.module = None
    t.meta.modules = []
    out = collect_modules_from_trace(t, mem=None)
    assert out == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
