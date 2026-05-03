"""viewer.trace.load() glob support — 文档示例 'traces/.../call_*' 应工作."""
from __future__ import annotations
import pytest
from pathlib import Path
from viewer.trace import load


def _make_call_dir(parent: Path, name: str) -> Path:
    """造一个最小可 load() 的 call dir: trace.bin (空) + meta.json."""
    d = parent / name
    d.mkdir(parents=True)
    (d / "trace.bin").write_bytes(b"")
    (d / "meta.json").write_text("{}")
    return d


def test_load_glob_single_match(tmp_path):
    base = tmp_path / "run1" / "calls"
    base.mkdir(parents=True)
    _make_call_dir(base, "call_002_tid12_50r_10ms")
    t = load(str(base / "call_002_*"))
    assert t.n == 0
    t.close()


def test_load_glob_no_match(tmp_path):
    with pytest.raises(FileNotFoundError, match="no path matches"):
        load(str(tmp_path / "nope_*"))


def test_load_glob_multiple_matches(tmp_path):
    base = tmp_path / "run1" / "calls"
    base.mkdir(parents=True)
    _make_call_dir(base, "call_002_a")
    _make_call_dir(base, "call_002_b")
    with pytest.raises(ValueError, match="matches 2 paths"):
        load(str(base / "call_002_*"))


def test_load_no_glob_unchanged(tmp_path):
    """没 glob 字符 → 原行为不变."""
    base = tmp_path / "run1" / "calls"
    base.mkdir(parents=True)
    d = _make_call_dir(base, "call_only")
    t = load(str(d))
    assert t.n == 0
    t.close()


def test_version_string_is_set():
    """__version__ 不应为空, 不应 fallback 到 unknown — 包元数据齐."""
    from viewer import __version__
    assert __version__ and "unknown" not in __version__


def test_load_dirname_contains_bracket_not_glob(tmp_path):
    """普通目录名含 '[' (没成对 ']') → 不当 glob, 直接 load.
    防止 batch-2 'any(c in "*?[")' 检测把合法路径误判.
    """
    base = tmp_path / "weird[name"
    base.mkdir()
    (base / "trace.bin").write_bytes(b"")
    (base / "meta.json").write_text("{}")
    t = load(str(base))
    assert t.n == 0
    t.close()
