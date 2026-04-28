"""Choose a decompiler backend by availability + user preference.

Default order: binja > ghidra > none

  - binja: 启动 ~3s, ARM64 + HLIL 业界一流, API 干净, 商业 license 才能 headless
  - ghidra: Apache 2.0 免费, 但 JVM 启动慢 ~10s — 还是 stub, 等真要做时实现
  - none: 全 stub, viewer 退化到现有 trace-only 行为

ENV override: TRACEMIKU_DECOMP_BACKEND=ghidra (force one backend)
"""
from __future__ import annotations
import os, importlib, logging
from typing import Optional
from .backend import DecompilerBackend


log = logging.getLogger(__name__)
_DEFAULT_ORDER = ["binja", "ghidra", "none"]


def list_backends() -> list[tuple[str, bool, str]]:
    """Return [(name, available, reason)] for every known backend.
    available=True means the backend's deps import OK (does NOT mean a SO is open)."""
    out = []
    for name in _DEFAULT_ORDER:
        try:
            mod = importlib.import_module(f"viewer.decompiler.backends.{name}")
            cls = getattr(mod, "Backend")
            inst = cls()
            ok = inst.is_available()
            out.append((name, ok, "" if ok else getattr(inst, "_unavailable_reason", "deps missing")))
        except Exception as e:
            out.append((name, False, f"import error: {e}"))
    return out


def make_backend(prefer: str | None = None) -> DecompilerBackend:
    """Create the highest-priority available backend.
    prefer can be 'binja' | 'ghidra' | 'none' or None for auto."""
    if prefer is None:
        prefer = os.environ.get("TRACEMIKU_DECOMP_BACKEND")
    order = [prefer] + [b for b in _DEFAULT_ORDER if b != prefer] if prefer else _DEFAULT_ORDER
    last_err = None
    for name in order:
        if name is None: continue
        try:
            mod = importlib.import_module(f"viewer.decompiler.backends.{name}")
            cls = getattr(mod, "Backend")
            inst = cls()
            if inst.is_available():
                log.info("decompiler backend = %s", name)
                return inst
            else:
                log.info("backend %s unavailable: %s", name, getattr(inst, "_unavailable_reason", "?"))
        except Exception as e:
            last_err = e
            log.info("backend %s import error: %s", name, e)
    raise RuntimeError(f"no decompiler backend available; last error: {last_err}")
