"""Regression test: multi-module pipeline (agent→host→viewer).

Verifies that `modules` field from meta.json propagates correctly through
all load paths in viewer/trace.py, including backward-compat fallback.
"""
import json, struct, tempfile, os, pathlib
import pytest
from viewer.trace import load, TraceMeta, Module


def _write_minimal_trace(path: pathlib.Path, n=3):
    """Write a minimal trace.bin with n dummy records."""
    with open(path, "wb") as f:
        for i in range(n):
            f.write(struct.pack("<Q", 0x40000 + i * 4))   # pc
            for _ in range(31): f.write(struct.pack("<Q", 0))  # x0..x30
            f.write(struct.pack("<Q", 0))   # sp
            f.write(struct.pack("<I", 0))   # nzcv
            f.write(struct.pack("<I", 0xd503201f))  # nop


MODULES = [
    {"name": "libtarget-1.2.3.so",  "base": "0x7a00000000", "size": 0x100000},
    {"name": "libhelper.so",        "base": "0x7b00000000", "size": 0x80000},
    {"name": "libplugin-4.5.so",    "base": "0x7c00000000", "size": 0x60000},
]


def test_percall_dir_with_modules(tmp_path):
    """Per-call directory layout: d/calls/call_001_tid100_3r_50ms/ + run-level meta."""
    run = tmp_path / "run1"
    run.mkdir()
    (run / "calls").mkdir()
    call = run / "calls" / "call_001_tid100_3r_50ms"
    call.mkdir()
    _write_minimal_trace(call / "trace.bin")
    # per-call meta (no modules here — comes from run-level)
    json.dump({"callIdx": 1, "tid": 100, "records": 3},
              open(call / "meta.json", "w"))
    # run-level meta with modules
    json.dump({"method": "myFunc", "cmd": 70102,
               "module": MODULES[0], "modules": MODULES},
              open(run / "meta.json", "w"))

    t = load(call)
    assert len(t.meta.modules) == 3
    assert t.meta.modules[0].name == "libtarget-1.2.3.so"
    assert t.meta.modules[0].base == 0x7a00000000
    assert t.meta.modules[1].name == "libhelper.so"
    assert t.meta.modules[2].name == "libplugin-4.5.so"
    t.close()


def test_legacy_trace_bin_layout_with_modules(tmp_path):
    """Legacy layout: trace_<pid>_<tid>.bin in top-level dir + meta.json."""
    _write_minimal_trace(tmp_path / "trace_12345_100.bin")
    json.dump({"method": "myFunc", "cmd": 70102,
               "module": MODULES[0], "modules": MODULES},
              open(tmp_path / "meta.json", "w"))

    t = load(tmp_path)
    assert len(t.meta.modules) == 3
    assert t.meta.modules[0].name == "libtarget-1.2.3.so"
    t.close()


def test_legacy_only_module_singular_fallback(tmp_path):
    """Legacy trace with only 'module' (singular), no 'modules' array.
    Fallback should populate meta.modules = [meta.module]."""
    _write_minimal_trace(tmp_path / "trace_12345_100.bin")
    json.dump({"method": "myFunc",
               "module": {"name": "libfoo.so", "base": "0x50000000", "size": 0x10000}},
              open(tmp_path / "meta.json", "w"))

    t = load(tmp_path)
    assert t.meta.module is not None
    assert t.meta.module.name == "libfoo.so"
    assert len(t.meta.modules) == 1
    assert t.meta.modules[0].name == "libfoo.so"
    assert t.meta.modules[0].base == 0x50000000
    t.close()


def test_percall_meta_modules_override_run_level(tmp_path):
    """Per-call meta.json has its own modules — should take precedence."""
    run = tmp_path / "run1"
    run.mkdir()
    (run / "calls").mkdir()
    call = run / "calls" / "call_001_tid100_3r_50ms"
    call.mkdir()
    _write_minimal_trace(call / "trace.bin")
    # per-call meta WITH modules
    per_call_modules = [
        {"name": "libA.so", "base": "0x10000000", "size": 0x5000},
        {"name": "libB.so", "base": "0x20000000", "size": 0x3000},
    ]
    json.dump({"callIdx": 1, "tid": 100, "records": 3,
               "modules": per_call_modules},
              open(call / "meta.json", "w"))
    # run-level meta with DIFFERENT modules (should not override)
    json.dump({"method": "myFunc",
               "modules": MODULES},
              open(run / "meta.json", "w"))

    t = load(call)
    # per-call modules should win
    assert len(t.meta.modules) == 2
    assert t.meta.modules[0].name == "libA.so"
    assert t.meta.modules[1].name == "libB.so"
    t.close()


def test_no_meta_at_all(tmp_path):
    """No meta.json anywhere — modules should be empty list."""
    _write_minimal_trace(tmp_path / "trace_12345_100.bin")

    t = load(tmp_path)
    assert t.meta.modules == []
    assert t.meta.module is None
    t.close()
