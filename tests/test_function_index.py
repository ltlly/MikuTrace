"""Unit tests for viewer.function_index — pure-Python FunctionIndex model."""
import pytest


def test_id_helpers_roundtrip():
    from viewer.function_index import (
        make_trace_id, make_sym_id, make_bn_id, parse_id,
    )
    assert make_trace_id("F0") == "trace:F0"
    assert make_sym_id("f_alpha") == "sym:f_alpha"
    assert make_bn_id(0x100000) == "bn:0x100000"
    assert parse_id("trace:F0") == ("trace", "F0")
    assert parse_id("sym:f_alpha") == ("sym", "f_alpha")
    assert parse_id("bn:0x100000") == ("bn", "0x100000")
    with pytest.raises(ValueError):
        parse_id("nope")


def test_legacy_aliases_resolve():
    """Bare F0 → trace:F0, cfg:<name> → sym:<name> for handoff compat."""
    from viewer.function_index import parse_id
    assert parse_id("cfg:f_alpha") == ("sym", "f_alpha")
    assert parse_id("F0") == ("trace", "F0")
    assert parse_id("F12") == ("trace", "F12")


def test_make_helpers_reject_empty():
    from viewer.function_index import make_trace_id, make_sym_id
    with pytest.raises(ValueError):
        make_trace_id("")
    with pytest.raises(ValueError):
        make_sym_id("")


def test_build_from_trace_top_ir_and_cfg(trace_root_two_callees):
    from viewer import load, build_from_trace, build_cfg
    from viewer.decompiler import build_trace_ir
    from viewer.function_index import build, FunctionIndex, FunctionEntry

    t = load(trace_root_two_callees)
    sym = build_from_trace(t)
    cfg = build_cfg(t, only_module=True)
    top = build_trace_ir(t, sym=sym, split_top_k=2, split_min_records=1)
    fi = build(trace=t, sym=sym, top_ir=top, cfg=cfg)

    assert isinstance(fi, FunctionIndex)
    assert len(fi) >= 1
    sources = {e.source for e in fi}
    assert "trace-ir" in sources
    f0 = fi.by_id("trace:F0")
    assert f0 is not None
    assert isinstance(f0, FunctionEntry)
    assert f0.source == "trace-ir"
    assert f0.trace_ir_id == "F0"
    # legacy bare F0 alias
    assert fi.by_id("F0") is f0


def test_build_no_duplicate_names(trace_root_two_callees):
    from viewer import load, build_from_trace, build_cfg
    from viewer.decompiler import build_trace_ir
    from viewer.function_index import build

    t = load(trace_root_two_callees)
    sym = build_from_trace(t)
    cfg = build_cfg(t, only_module=True)
    top = build_trace_ir(t, sym=sym, split_top_k=10, split_min_records=1)
    fi = build(trace=t, sym=sym, top_ir=top, cfg=cfg)
    names = [e.name for e in fi]
    assert len(names) == len(set(names))


def test_build_with_only_sym_no_cfg(trace_root_two_callees):
    """When cfg=None but sym is given, fall back to enumerating sym.functions."""
    from viewer import load, build_from_trace
    from viewer.function_index import build

    t = load(trace_root_two_callees)
    sym = build_from_trace(t)
    fi = build(trace=t, sym=sym, top_ir=None, cfg=None)
    names = {e.name for e in fi}
    assert {"f_root", "f_alpha", "f_beta"}.issubset(names)
    for e in fi:
        assert e.source == "symbol"
        assert e.id.startswith("sym:")


def test_build_bn_funcs_emitted_with_bn_prefix(trace_root_two_callees):
    """If bn_funcs=[(addr, name)] is supplied, those become bn:<hex> entries."""
    from viewer import load, build_from_trace
    from viewer.function_index import build

    t = load(trace_root_two_callees)
    sym = build_from_trace(t)
    fi = build(trace=t, sym=sym, top_ir=None, cfg=None,
               bn_funcs=[(0x12345, "fancy_bn_only_fn")])
    bn_entries = [e for e in fi if e.source == "bn"]
    assert len(bn_entries) == 1
    assert bn_entries[0].id == "bn:0x12345"
    assert bn_entries[0].name == "fancy_bn_only_fn"
    assert bn_entries[0].bn_start == 0x12345
    assert bn_entries[0].can_bn_hlil is True


def test_by_id_returns_none_for_unknown():
    from viewer.function_index import FunctionIndex
    fi = FunctionIndex()
    assert fi.by_id("trace:F999") is None
    assert fi.by_id("sym:nope") is None
    assert fi.by_id("bn:0xdead") is None
    assert fi.by_id("garbage") is None
    # Bare F0 parses as trace:F0 but entries are empty → None
    assert fi.by_id("F0") is None
    # Legacy cfg: parses as sym: but entries are empty → None
    assert fi.by_id("cfg:nope") is None


def test_parse_id_rejects_empty_payloads():
    from viewer.function_index import parse_id
    for bad in ("sym:", "trace:", "bn:", "cfg:"):
        with pytest.raises(ValueError):
            parse_id(bad)


def test_parse_id_rejects_non_hex_bn_payload():
    from viewer.function_index import parse_id
    with pytest.raises(ValueError):
        parse_id("bn:notahex")
    # Hex payloads with explicit '0x' prefix work
    assert parse_id("bn:0x100") == ("bn", "0x100")
    # Hex payloads without '0x' prefix also work (int(_, 16) handles both)
    assert parse_id("bn:100") == ("bn", "100")
