from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any


@dataclass
class Session:
    so_path: str | None = None
    bv: Any = None
    bn: Any = None
    ready: bool = False
    error: str | None = None

    def open_so(self, path: str) -> dict[str, Any]:
        self.so_path = path
        try:
            import binaryninja  # type: ignore

            self.bn = binaryninja
            self.bv = binaryninja.load(path)
            self.ready = self.bv is not None
            return {
                "ok": self.ready,
                "ready": self.ready,
                "version": getattr(binaryninja, "__version__", ""),
                "fn_count": len(list(self.bv.functions)) if self.bv is not None else 0,
            }
        except Exception as exc:  # pragma: no cover - depends on local BN install
            self.ready = False
            self.error = str(exc)
            return {"ok": False, "ready": False, "error": self.error}

    def functions(self) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        fns = [
            {"start": int(fn.start), "name": str(fn.name)}
            for fn in self.bv.functions
        ]
        return {"ok": True, "ready": True, "functions": fns}

    def hlil_for(self, pc: int) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        fn = self._function_for_pc(pc)
        if fn is None:
            return {"ok": False, "ready": True, "error": f"no function contains 0x{pc:x}"}
        lines = []
        for insn in fn.hlil.instructions:
            addr = int(getattr(insn, "address", 0) or 0)
            lines.append({"pc": f"0x{addr:x}", "text": str(insn), "tokens": []})
        return {
            "ok": True,
            "ready": True,
            "fn": {"name": str(fn.name), "start": int(fn.start), "end": int(fn.highest_address)},
            "lines": lines,
            "vars": [],
        }

    def cfg_for(self, pc: int) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        fn = self._function_for_pc(pc)
        if fn is None:
            return {"ok": False, "ready": True, "error": f"no function contains 0x{pc:x}"}
        blocks = [{"id": i, "start": int(bb.start), "end": int(bb.end)} for i, bb in enumerate(fn.basic_blocks)]
        return {"ok": True, "ready": True, "blocks": blocks, "edges": [], "svg": ""}

    def _function_for_pc(self, pc: int) -> Any | None:
        fn = self.bv.get_function_at(pc)
        if fn is not None:
            return fn
        containing = list(self.bv.get_functions_containing(pc))
        return containing[0] if containing else None


def handle(session: Session, req: dict[str, Any]) -> dict[str, Any]:
    method = req.get("method")
    params = req.get("params") or {}
    if method == "open_so":
        return session.open_so(str(params.get("path") or ""))
    if method == "functions":
        return session.functions()
    if method == "hlil_for":
        return session.hlil_for(int(params.get("pc") or 0))
    if method == "cfg_for":
        return session.cfg_for(int(params.get("pc") or 0))
    return {"ok": False, "ready": session.ready, "error": f"unknown method {method!r}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--so", default="")
    args = parser.parse_args()
    session = Session()
    if args.so:
        session.open_so(args.so)
    for line in sys.stdin:
        try:
            req = json.loads(line)
            result = handle(session, req)
            resp = {"id": req.get("id"), "result": result}
        except Exception as exc:
            resp = {"id": None, "error": str(exc)}
        print(json.dumps(resp, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
