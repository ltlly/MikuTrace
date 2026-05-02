"""类型锚点 (DEC3-B) — JSON-spec 驱动, 单元测试.

§7.0 普适性自查:
  ✓ 测试不假设特定 SDK (合成 trace + 自定义 spec, 不依赖 JNI/libc 实表)
  ✓ 测试覆盖 spec 缺失 / 格式异常 / 不命中 等普适场景
  ✓ 验证 anchor 的 provenance 字段确保可溯源
"""
from __future__ import annotations
import json, pathlib, tempfile
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler import (
    TypeSpec, TypeAnchor, TypeAnchorIR,
    load_type_specs, find_anchors, attach_type_anchors,
)


def _write_spec(tmp_path: pathlib.Path, specs: list[dict],
                name: str = "test.json") -> pathlib.Path:
    p = tmp_path / name
    p.write_text(json.dumps({"version": 1, "specs": specs}), encoding="utf-8")
    return p


def test_load_specs_basic(tmp_path):
    p = _write_spec(tmp_path, [
        {"name": "A", "callee_pc": "0x1000",
         "params": [["x0", "int"], ["x1", "char*"]],
         "ret": ["x0", "void*"]}
    ])
    specs = load_type_specs([p])
    assert len(specs) == 1
    s = specs[0]
    assert s.callee_pc == 0x1000
    assert s.name == "A"
    assert s.params == [("x0", "int"), ("x1", "char*")]
    assert s.ret_reg == "x0" and s.ret_type == "void*"
    assert "test.json" in s.provenance and "A" in s.provenance


def test_load_specs_dict_form(tmp_path):
    """params 也支持 dict 形式 (alternate JSON layout)."""
    p = _write_spec(tmp_path, [
        {"name": "B", "callee_pc": "0x2000",
         "params": [{"reg": "x0", "type": "Foo*"}],
         "ret": {"reg": "x0", "type": "Bar"}}
    ])
    specs = load_type_specs([p])
    assert specs[0].params == [("x0", "Foo*")]
    assert specs[0].ret_type == "Bar"


def test_load_specs_int_pc(tmp_path):
    """callee_pc 也接受 int 不只 hex string."""
    p = _write_spec(tmp_path, [
        {"name": "C", "callee_pc": 4096, "params": [], "ret": ["x0", ""]}
    ])
    specs = load_type_specs([p])
    assert specs[0].callee_pc == 4096


def test_load_specs_missing_file_skipped(tmp_path):
    """缺文件 → 静默跳过, 返回 [], 不崩."""
    specs = load_type_specs([tmp_path / "nonexistent.json"])
    assert specs == []


def test_load_specs_malformed_skipped(tmp_path):
    """JSON 格式错 → 静默跳过."""
    p = tmp_path / "bad.json"
    p.write_text("not json {{", encoding="utf-8")
    assert load_type_specs([p]) == []


def test_load_multi_files(tmp_path):
    p1 = _write_spec(tmp_path, [
        {"name": "A", "callee_pc": "0x1000", "params": [], "ret": ["x0", ""]}
    ], "p1.json")
    p2 = _write_spec(tmp_path, [
        {"name": "B", "callee_pc": "0x2000", "params": [], "ret": ["x0", ""]}
    ], "p2.json")
    specs = load_type_specs([p1, p2])
    pcs = sorted(s.callee_pc for s in specs)
    assert pcs == [0x1000, 0x2000]


def test_find_anchors_no_match():
    """spec callee_pc 在 trace 里没出现 → 无 anchor."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    specs = [TypeSpec(callee_pc=0xdeadbeef, name="X", params=[("x0", "int")])]
    anchors = find_anchors(t, specs)
    assert anchors == []
    t.close()


def test_find_anchors_no_specs():
    """空 spec 列表 → 直接 [] 不扫."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    assert find_anchors(t, []) == []
    t.close()


def test_find_anchors_matches_bl():
    """bl <pc> 命中 spec.callee_pc → 出 anchor."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('bl #+8',     {'x30': 0}),         # bl 跳到 +8 = 0x100008
        ('mov x2, #2', {'x2': 2}),          # callee 入口 PC = 0x100008
        ('ret', {}),
    ])
    # callee_pc = 0x100000 + 0x8 = 0x100008
    specs = [TypeSpec(callee_pc=0x100008, name="C",
                      params=[("x0", "int")], ret_reg="x0", ret_type="int")]
    anchors = find_anchors(t, specs)
    assert len(anchors) == 1
    a = anchors[0]
    assert a.idx == 1   # bl 在 idx=1
    assert a.callee_pc == 0x100008
    assert a.spec.name == "C"
    t.close()


def test_attach_type_anchors_into_fn(tmp_path):
    """end-to-end: spec → anchor → 落到 FuncIR.type_anchors."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('bl #+8',     {'x30': 0}),
        ('mov x2, #2', {'x2': 2}),
        ('ret', {}),
    ])
    p = _write_spec(tmp_path, [
        {"name": "ApiX", "callee_pc": "0x100008",
         "params": [["x0", "MyType*"]],
         "ret": ["x0", "int"]}
    ])
    top = build_trace_ir(t, type_spec_paths=[p])
    # F0 应有至少 1 个 anchor
    f0 = top.fns[0]
    assert len(f0.type_anchors) >= 1
    a = f0.type_anchors[0]
    assert a.callee_pc == 0x100008
    assert a.callee_name == "ApiX"
    assert ("x0", "MyType*") in a.params
    assert "ApiX" in a.provenance
    t.close()


def test_no_specs_means_no_anchors():
    """没传 type_spec_paths → 没 anchor (DEC1 行为, backward compat)."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)   # type_spec_paths=None default
    for fn in top.fns:
        assert fn.type_anchors == []
    t.close()


def test_anchor_assigned_to_narrowest_fn(tmp_path):
    """如果 anchor idx 同时在父 fn 和子 fn 范围内, 分到子 fn (idx 范围更窄)."""
    # 构造嵌套调用: F0 调 fn_a (子), fn_a 内有一个 spec'd bl
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('bl #+8',     {'x30': 0}),         # call fn_a at idx=1
        # fn_a body:
        ('mov x1, #2', {'x1': 2}),
        ('bl #+8',     {'x30': 0}),         # nested bl at idx=3, target = 0x100018
        ('mov x2, #3', {'x2': 3}),
        ('ret', {}),
        ('ret', {}),
    ])
    # nested bl target_pc = 0x100000 + 0x10 + 8 = 0x100018
    p = _write_spec(tmp_path, [
        {"name": "Inner", "callee_pc": "0x100018",
         "params": [], "ret": ["x0", ""]}
    ])
    top = build_trace_ir(t, type_spec_paths=[p],
                         split_top_k=10, split_min_records=2)
    # 找含该 anchor 的 fn — 应该是子 fn (如果 split 出来了) 而非 F0
    for fn in top.fns:
        for a in fn.type_anchors:
            if a.callee_pc == 0x100018:
                # 这个 fn 的 idx 范围必须包含 idx=3
                assert fn.entry_idx <= 3 <= fn.exit_idx
                # 如果不止 F0, 子 fn 应优先
                if len([f for f in top.fns
                        if f.entry_idx <= 3 <= f.exit_idx]) > 1:
                    # 选中的 fn 应是范围最窄的
                    spans = [(f.exit_idx - f.entry_idx)
                             for f in top.fns
                             if f.entry_idx <= 3 <= f.exit_idx]
                    assert (fn.exit_idx - fn.entry_idx) == min(spans)
    t.close()


def test_anchor_in_render_md(tmp_path):
    """type anchor 应该出现在 fn markdown 输出里."""
    from viewer.decompiler import render_func_md
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('bl #+8',     {'x30': 0}),
        ('mov x2, #2', {'x2': 2}),
        ('ret', {}),
    ])
    p = _write_spec(tmp_path, [
        {"name": "MyApi", "callee_pc": "0x100008",
         "params": [["x0", "JNIEnv*"]],
         "ret": ["x0", "jclass"]}
    ])
    top = build_trace_ir(t, type_spec_paths=[p])
    md = render_func_md(top.fns[0])
    assert "Type anchors" in md
    assert "MyApi" in md
    assert "JNIEnv*" in md
    assert "jclass" in md
    t.close()
