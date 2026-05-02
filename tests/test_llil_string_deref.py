"""Pass 8 render: string deref via memshadow — 单元测试.

测试 try_decode_string + collect_const_strings + render 时 LLIL_CONST/CONST_PTR
命中 string addr 时输出 "literal" 替代 0x... 地址.

这是 trace 反编译器对 OLLVM 加密 string 的关键能力 — 静态 BN/IDA 看不到解密
后的明文, 但 trace 能从 memshadow 读到运行时真值.
"""
from __future__ import annotations
from viewer.decompiler.llil import (
    set_reg, reg, const, const_ptr, load, add, ret, call,
    ssa_block, restructure, CfgInfo, render_hlil, unify_vars,
)
from viewer.decompiler.llil.render import (
    try_decode_string, collect_const_strings,
)


class FakeMem:
    """Minimal memshadow stub matching the byte_at(addr, t) interface."""
    def __init__(self, mapping: dict, built: bool = True):
        self.mapping = mapping
        self.built = built

    def byte_at(self, addr, t):
        if addr in self.mapping:
            return (self.mapping[addr], "r", 0)
        return (None, "??", None)


def _str_to_mem(addr: int, s: str, nul: bool = True) -> dict:
    """Helper: build a {addr+i → byte} dict for an ASCII string."""
    out = {addr + i: ord(c) for i, c in enumerate(s)}
    if nul:
        out[addr + len(s)] = 0
    return out


def test_try_decode_string_basic_ascii():
    """0x1000 → 'AES_KEY\\0' → returns 'AES_KEY'."""
    mem = FakeMem(_str_to_mem(0x1000, "AES_KEY"))
    s = try_decode_string(0x1000, mem)
    assert s == "AES_KEY"


def test_try_decode_string_min_len_threshold():
    """3-char string < min_len=4 → returns None."""
    mem = FakeMem(_str_to_mem(0x2000, "abc"))
    assert try_decode_string(0x2000, mem) is None
    assert try_decode_string(0x2000, mem, min_len=3) == "abc"


def test_try_decode_string_non_ascii_rejected():
    """First byte 0x80 (high bit) → rejects → None."""
    mem = FakeMem({0x3000: 0x80, 0x3001: 0x41, 0x3002: 0x41, 0x3003: 0x41, 0x3004: 0})
    assert try_decode_string(0x3000, mem) is None


def test_try_decode_string_missing_byte_returns_none():
    """memshadow 没该字节 → byte_at 返 None → 解码 abort → None."""
    mem = FakeMem({0x4000: ord("A"), 0x4001: ord("B")})  # 缺 0x4002+ 之后
    # 没有 NUL, 没有完整 chars — try_decode 应 abort
    assert try_decode_string(0x4000, mem) is None


def test_try_decode_string_max_len_truncate_no_nul():
    """连续可打印 ASCII 但没 NUL — 走完 max_len, 但若没遇 NUL 回 None.

    我们的实现: max_len 内没遇 NUL → for-loop 结束, 不直接 return; 但函数
    最后 fallthrough 到 'return ''.join(chars)' — 此时 len(chars) ≥ min_len
    → 返回截断 string. 这个测试验证当前行为.
    """
    bytes_map = {0x5000 + i: ord("A") for i in range(80)}
    # 注意没 NUL → 结尾 fallthrough
    mem = FakeMem(bytes_map)
    s = try_decode_string(0x5000, mem, max_len=80)
    # 80-char 'A'*80
    assert s == "A" * 80


def test_try_decode_string_built_false_returns_none():
    mem = FakeMem({0x6000: ord("A")}, built=False)
    assert try_decode_string(0x6000, mem) is None


def test_try_decode_string_none_mem_returns_none():
    assert try_decode_string(0x1000, None) is None


def test_collect_const_strings_basic():
    """ssa_block 中 LLIL_CONST 0x1000 → memshadow 解出 'SHA1' → collect 收到."""
    bytes_map = _str_to_mem(0x1000, "SHA1")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x100, [
        set_reg("x0", const(0x1000)),
    ])
    out = collect_const_strings({0x100: blk}, mem)
    assert out == {0x1000: "SHA1"}


def test_collect_const_strings_skips_low_addrs():
    """addr < 0x1000 → 跳过 (避免 noise: 数字常量 0/1/100)."""
    mem = FakeMem({0x10 + i: ord("A") for i in range(8)})
    blk = ssa_block(0x100, [
        set_reg("x0", const(0x10)),    # 太低 — 跳
    ])
    out = collect_const_strings({0x100: blk}, mem)
    assert out == {}


def test_collect_const_strings_walks_subexprs():
    """LLIL_CONST 嵌在 ADD 子树里 — walk() 应找到."""
    bytes_map = _str_to_mem(0x2000, "URL_PARAM")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x100, [
        set_reg("x0", add(reg("x1"), const(0x2000))),
    ])
    out = collect_const_strings({0x100: blk}, mem)
    assert out == {0x2000: "URL_PARAM"}


def test_collect_const_strings_const_ptr_op():
    """LLIL_CONST_PTR (call target / global ptr) 也查 string."""
    bytes_map = _str_to_mem(0x3000, "libc.so")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x100, [
        call(const_ptr(0x3000), pc=0x100),
    ])
    out = collect_const_strings({0x100: blk}, mem)
    assert out == {0x3000: "libc.so"}


def test_collect_const_strings_dedup_same_addr():
    """同一 addr 在多 root 出现 — 只查/返回一次."""
    bytes_map = _str_to_mem(0x4000, "DEDUP")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x100, [
        set_reg("x0", const(0x4000)),
        set_reg("x1", const(0x4000)),
    ])
    out = collect_const_strings({0x100: blk}, mem)
    assert out == {0x4000: "DEDUP"}


def test_collect_const_strings_no_mem_returns_empty():
    blk = ssa_block(0x100, [set_reg("x0", const(0x1000))])
    assert collect_const_strings({0x100: blk}, None) == {}


def test_render_shows_string_literal_not_addr():
    """E2E: render_hlil 时 LLIL_CONST(0x1000) where mem says 'SHA256' →
    输出 \"SHA256\" 而非 0x1000."""
    bytes_map = _str_to_mem(0x1000, "SHA256")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x500, [
        set_reg("x0", const(0x1000)),
        ret(),
    ])
    cs = collect_const_strings({0x500: blk}, mem)
    assert cs == {0x1000: "SHA256"}
    cfg = CfgInfo(succs={}, preds={}, entry=0x500)
    hlil = restructure(cfg, {0x500: blk})
    text = "\n".join(render_hlil(hlil, const_strings=cs))
    assert '"SHA256"' in text
    # 不应再含原始地址形式
    assert "0x1000" not in text


def test_render_const_ptr_call_target_shows_string():
    """LLIL_CALL(const_ptr(addr)) where addr decodes to a string → 'call("...",
    args)' (说明这是 string ref 而非 fn ptr)."""
    bytes_map = _str_to_mem(0x2000, "open")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x500, [
        call(const_ptr(0x2000), pc=0x500),
    ])
    cs = collect_const_strings({0x500: blk}, mem)
    cfg = CfgInfo(succs={}, preds={}, entry=0x500)
    hlil = restructure(cfg, {0x500: blk})
    var_names = unify_vars({0x500: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names, const_strings=cs))
    assert '"open"' in text


def test_render_string_in_load_addr():
    """LLIL_LOAD(const_ptr(addr)) — addr 是 string 地址时 render 也显示
    string literal (虽然 LOAD 通常会 fold; 这里直接构造)."""
    bytes_map = _str_to_mem(0x3000, "TEST_KEY")
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x500, [
        set_reg("x0", load(const_ptr(0x3000), size=8)),
        ret(),
    ])
    cs = collect_const_strings({0x500: blk}, mem)
    cfg = CfgInfo(succs={}, preds={}, entry=0x500)
    hlil = restructure(cfg, {0x500: blk})
    text = "\n".join(render_hlil(hlil, const_strings=cs))
    assert '"TEST_KEY"' in text


def test_render_no_const_strings_dict_falls_back_to_addr():
    """没传 const_strings → render 用原始 0x... 输出 (向后兼容)."""
    blk = ssa_block(0x500, [
        set_reg("x0", const(0x1000)),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x500)
    hlil = restructure(cfg, {0x500: blk})
    text = "\n".join(render_hlil(hlil))
    assert "0x1000" in text
