"""P1-C M5: tracemiku _print_fork_summary table format."""
import subprocess, sys, pytest, importlib.util, pathlib


def _load_tracemiku_module():
    """Load tracemiku script as a Python module so we can call _print_fork_summary."""
    p = pathlib.Path(__file__).resolve().parent.parent / "tracemiku"
    spec = importlib.util.spec_from_loader("tracemiku_script",
                                            importlib.machinery.SourceFileLoader(
                                                "tracemiku_script", str(p)))
    m = importlib.util.module_from_spec(spec)
    # Skip executing main(); we just want the module-level defs
    src = p.read_text()
    # Strip the `if __name__ == '__main__':` tail so import doesn't run it
    cut = src.find('if __name__')
    if cut != -1:
        src = src[:cut]
    exec(compile(src, str(p), "exec"), m.__dict__)
    return m


def test_fork_summary_empty(capsys):
    """No fork events: function not called from cmd_trace; standalone test
    just exercises shape — empty list yields no output (counts stay 0)."""
    tm = _load_tracemiku_module()
    tm._print_fork_summary([])
    out = capsys.readouterr().out
    # 空 list 时仍打印 header (定义如此)
    assert "Fork Summary" in out
    assert "Total fork-like:   0" in out


def test_fork_summary_all_success(capsys):
    tm = _load_tracemiku_module()
    events = [
        ("call_001", {"is_fork_like": True, "attach_status": "success"}),
        ("call_002", {"is_fork_like": True, "attach_status": "success"}),
        ("call_003", {"is_fork_like": False, "attach_status": "not_attempted"}),
    ]
    tm._print_fork_summary(events)
    out = capsys.readouterr().out
    assert "Total fork-like:   2" in out
    assert "thread-like clones via pthread_create: 1" in out
    assert "Fully traced:  2" in out
    # No failure section
    assert "Attach failed:" not in out
    assert "miku-shield" not in out


def test_fork_summary_with_failures_recommends_miku_shield(capsys):
    """≥2 failed → miku-shield recommendation 出现."""
    tm = _load_tracemiku_module()
    events = [
        ("call_001", {"is_fork_like": True, "attach_status": "success"}),
        ("call_002", {"is_fork_like": True, "attach_status": "failed_ptrace_conflict"}),
        ("call_003", {"is_fork_like": True, "attach_status": "failed_ptrace_conflict"}),
        ("call_004", {"is_fork_like": True, "attach_status": "failed_unknown"}),
    ]
    tm._print_fork_summary(events)
    out = capsys.readouterr().out
    assert "Total fork-like:   4" in out
    assert "Fully traced:  1" in out
    assert "Attach failed: 3" in out
    assert "miku-shield" in out


def test_fork_summary_not_attempted(capsys):
    """only Tier 1 (M1) fork events, M2 disabled → all not_attempted."""
    tm = _load_tracemiku_module()
    events = [
        ("call_001", {"is_fork_like": True, "attach_status": "not_attempted"}),
        ("call_002", {"is_fork_like": True, "attach_status": "not_attempted"}),
    ]
    tm._print_fork_summary(events)
    out = capsys.readouterr().out
    assert "Not attempted: 2" in out
    # not_attempted is NOT a failure — no miku-shield prompt
    assert "miku-shield" not in out


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
