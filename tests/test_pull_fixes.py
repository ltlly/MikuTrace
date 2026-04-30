"""Regression tests for the two host-side bugs fixed during 2026-04-30 OnePlus
Pad Pro KSU-rooted-ColorOS bring-up:

  Bug 1: device-side toybox `gzip -1 -c` does NOT emit a valid gzip stream on
         some ROMs (ColorOS observed). The host-side pull treated any non-gzip
         bytes as fatal, dropping ~3 GB of valid raw trace data on the floor.
         Fix: try gzip; on any exception, fall back to raw `cat`.

  Bug 2: agent_cmodule_v5.js `init()` accepted only `--fn-offset`. When called
         with `--export <name>` (host passes `fnOffset: null`),
         `m.base.add(null)` raised `expected a pointer`.
         Fix: agent now resolves `STATE.exportName` via Frida 17.x
         `m.findExportByName()` (with fallbacks).

  Plus a third issue exposed during verification:
         App-cache trace files (`/data/data/<pkg>/cache/.miku/*.bin`) are owned
         by the app uid; on user-build / KSU-rooted devices `adb shell` runs as
         shell uid and cannot read them. Fix: probe `id`; if not uid=0, wrap
         all file ops with `su -c`.

These tests use lightweight stubbing (no device required) to lock the contracts.
"""
import gzip
import io
import sys
import pathlib
import subprocess
import importlib.util
import textwrap
import types
import pytest


# ---------------------------------------------------------------------------
# Helper: load tracemiku as a module despite its lack of `.py` suffix.
# We avoid running its `main()` by intercepting `__name__ == "__main__"`.
# ---------------------------------------------------------------------------
TRACEMIKU = pathlib.Path(__file__).resolve().parent.parent / "tracemiku"


def _load_tracemiku_module():
    spec = importlib.util.spec_from_loader(
        "tracemiku_cli",
        loader=importlib.machinery.SourceFileLoader("tracemiku_cli", str(TRACEMIKU)),
    )
    mod = importlib.util.module_from_spec(spec)
    # Prevent main() from running on import: tracemiku's main is gated on
    # `if __name__ == '__main__':` so importing under another name skips it.
    spec.loader.exec_module(mod)
    return mod


def test_tracemiku_imports_cleanly():
    """The CLI script must be importable as a module (no top-level side effects)."""
    mod = _load_tracemiku_module()
    assert hasattr(mod, "cmd_trace")
    assert hasattr(mod, "main")


# ---------------------------------------------------------------------------
# Bug 2 contract: agent_cmodule_v5.js armWith() supports --export.
# We cannot run JS here, so we lock the source-level invariants.
# ---------------------------------------------------------------------------
AGENT_V5 = pathlib.Path(__file__).resolve().parent.parent / "tracer" / "agent_cmodule_v5.js"


def test_agent_v5_resolves_export_name_not_null_pointer():
    """Bug 2 fix: armWith() must guard fnOffset==null and fall back to exportName."""
    src = AGENT_V5.read_text()

    # Pre-fix, the only line that used fnOffset was `m.base.add(STATE.fnOffset)`
    # with no null check. Post-fix, we have the explicit branch on STATE.exportName.
    assert "STATE.exportName" in src, \
        "agent v5 should reference STATE.exportName for --export resolution"
    assert "findExportByName" in src, \
        "agent v5 should call findExportByName to resolve --export"
    # The init() must initialize exportName so armWith can read it.
    assert "STATE.exportName = opts.exportName" in src, \
        "init() should propagate opts.exportName into STATE"


def test_agent_v5_does_not_blindly_add_null_offset():
    """Bug 2 root cause: `m.base.add(STATE.fnOffset)` with fnOffset==null crashed.
    Post-fix, that expression must be guarded by a null check."""
    src = AGENT_V5.read_text()
    # Find the exact crash line; it must be inside an `if (STATE.fnOffset !== null...` branch.
    # We check by ensuring the protective phrase appears before the dangerous expr.
    crash_line_idx = src.find("m.base.add(STATE.fnOffset)")
    assert crash_line_idx != -1, "expected fnOffset add expression to still exist somewhere"
    # The 200 chars *before* that expression must contain the null guard.
    guard_window = src[max(0, crash_line_idx - 200):crash_line_idx]
    assert "STATE.fnOffset !== null" in guard_window or "fnOffset != null" in guard_window, (
        "the m.base.add(STATE.fnOffset) call must be inside a fnOffset!=null branch"
    )


# ---------------------------------------------------------------------------
# Bug 1 + Bug 3 contracts: tracemiku's adb_pull_device_trace handles
#   (a) broken device gzip (raw cat fallback)
#   (b) shell-uid permission denial (su wrapping)
# We test the source-level shape since the function is closed over cmd_trace's
# scope. Behavioral testing would require mocking subprocess.Popen across
# many call sites; the source-level checks pin the fix in place.
# ---------------------------------------------------------------------------
TRACEMIKU_SRC = TRACEMIKU.read_text()


def test_pull_has_gzip_then_raw_cat_fallback():
    """Bug 1 fix: gzip exception must trigger raw cat fallback, not abort."""
    # Look at the adb_pull_device_trace function specifically.
    start = TRACEMIKU_SRC.find("def adb_pull_device_trace")
    assert start != -1, "adb_pull_device_trace function must exist"
    # Slice ~3 KB after the def (the function body).
    body = TRACEMIKU_SRC[start:start + 3500]
    assert "gzip -1 -c" in body, "should still try gzip first (fast path)"
    # The fallback "cat" command must exist.
    assert "cat " in body and "回退 raw cat" in body, (
        "must have raw-cat fallback when gzip fails"
    )
    # And the fallback must be inside a try/except, not a hard fail.
    assert "except" in body, "gzip path must catch exception, not propagate"


def test_pull_uses_su_when_shell_uid_lacks_perms():
    """Bug 3 fix: app cache files are owned by app uid; on KSU-rooted user
    builds, `adb shell` runs as shell uid and gets EACCES. Must wrap with su."""
    body = TRACEMIKU_SRC[
        TRACEMIKU_SRC.find("def adb_pull_device_trace"):
        TRACEMIKU_SRC.find("def adb_pull_device_trace") + 4000
    ]
    # The wrapper helper must be invoked.
    assert "_wrap_su" in body, (
        "adb_pull_device_trace must call _wrap_su(...) to handle KSU-rooted user builds"
    )
    # The wrapper itself must check root via `id`.
    assert '"adb", "shell", "id"' in TRACEMIKU_SRC, (
        "_detect_su_needed must probe 'adb shell id' to decide if su wrapping is needed"
    )
    assert "uid=0" in TRACEMIKU_SRC, (
        "_detect_su_needed must check for uid=0 in the id output"
    )


def test_pull_cleanup_also_runs_with_su():
    """The post-pull `rm -f` must also be su-wrapped, otherwise it silently
    fails on user builds and leaves the device cache full."""
    body = TRACEMIKU_SRC[
        TRACEMIKU_SRC.find("def adb_pull_device_trace"):
        TRACEMIKU_SRC.find("def adb_pull_device_trace") + 4000
    ]
    # Find the rm command and confirm it's wrapped.
    rm_idx = body.find("rm -f ")
    assert rm_idx != -1, "must rm device file after pull"
    # The 100 chars before rm should contain _wrap_su(
    pre = body[max(0, rm_idx - 200):rm_idx]
    assert "_wrap_su" in pre, "rm must be _wrap_su()'d, not raw"
