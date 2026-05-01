"""viewer.symbols.SymbolMap + load_ida_symbols 直接单元.

ModuleResolver 已在 test_data_chase.py 覆盖. 这里补 SymbolMap (PC → name+offset)
和 IDA JSON 加载, 它们被 webui /api/record + /api/cfg-svg 大量用.
"""
import json, pathlib, pytest
from viewer.symbols import SymbolMap, load_ida_symbols


def test_symbol_map_empty_lookup():
    sm = SymbolMap()
    assert sm.lookup(0x1000) == ("?", 0)


def test_symbol_map_basic_lookup():
    sm = SymbolMap()
    sm.add(0x1000, "alpha")
    sm.add(0x2000, "beta")
    sm.add(0x3000, "gamma")
    assert sm.lookup(0x1000) == ("alpha", 0)
    assert sm.lookup(0x1500) == ("alpha", 0x500)
    assert sm.lookup(0x1fff) == ("alpha", 0xfff)
    assert sm.lookup(0x2000) == ("beta", 0)
    assert sm.lookup(0x2200) == ("beta", 0x200)
    assert sm.lookup(0x3000) == ("gamma", 0)


def test_symbol_map_lookup_before_first_func():
    sm = SymbolMap()
    sm.add(0x2000, "f")
    assert sm.lookup(0x1000) == ("?", 0)


def test_symbol_map_unsorted_add_then_sort():
    """add 任意序, lookup 仍按 PC 排序后二分."""
    sm = SymbolMap()
    sm.add(0x3000, "c")
    sm.add(0x1000, "a")
    sm.add(0x2000, "b")
    assert sm.lookup(0x1500) == ("a", 0x500)
    assert sm.lookup(0x2500) == ("b", 0x500)
    assert sm.lookup(0x3500) == ("c", 0x500)


def test_symbol_map_duplicate_pc_keeps_last():
    """同 PC add 两次, lookup 行为应 deterministic. 当前实现 (sort+bisect 取
    largest start≤pc) 可能拿到任一; 测试只 pin "不崩 + 返回这俩名之一"."""
    sm = SymbolMap()
    sm.add(0x1000, "first")
    sm.add(0x1000, "second")
    name, off = sm.lookup(0x1000)
    assert name in ("first", "second")
    assert off == 0


def test_load_ida_symbols(tmp_path):
    """JSON 格式 [{"address": "0x...", "name": "..."}, ...]. base=0 时 address
    当绝对 PC."""
    p = tmp_path / "syms.json"
    json.dump([
        {"address": "0x1000", "name": "fnA"},
        {"address": "0x2000", "name": "fnB"},
        {"address": "0x3000", "name": "fnC"},
    ], open(p, "w"))
    sm = load_ida_symbols(p)
    assert sm.lookup(0x1500) == ("fnA", 0x500)
    assert sm.lookup(0x2500) == ("fnB", 0x500)


def test_load_ida_symbols_with_base(tmp_path):
    """base > 0 时, 小 address (< 1<<32) 视为 offset, 加 base 得绝对 PC."""
    p = tmp_path / "syms.json"
    json.dump([
        {"address": "0x100", "name": "fnA"},
        {"address": "0x200", "name": "fnB"},
    ], open(p, "w"))
    base = 0x6f7a000000
    sm = load_ida_symbols(p, base=base)
    assert sm.lookup(base + 0x100) == ("fnA", 0)
    assert sm.lookup(base + 0x150) == ("fnA", 0x50)


def test_load_ida_symbols_int_address(tmp_path):
    """address 是 int 而非 str 也行."""
    p = tmp_path / "syms.json"
    json.dump([{"address": 0x500, "name": "intAddr"}], open(p, "w"))
    sm = load_ida_symbols(p)
    assert sm.lookup(0x500) == ("intAddr", 0)


def test_load_ida_symbols_missing_file_raises():
    """当前实现: 文件不存在抛 FileNotFoundError. Pin 行为, 防默默 swallow.
    (若后续改成兜底返回空 map, 改本测试.)"""
    p = pathlib.Path("/nonexistent/path/x.json")
    with pytest.raises(FileNotFoundError):
        load_ida_symbols(p)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
