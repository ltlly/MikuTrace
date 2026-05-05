from __future__ import annotations

import argparse
import json
import re
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

    def asm_tokens(self, pcs: list[int]) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        out: dict[str, list[dict[str, Any]]] = {}
        seen: set[int] = set()
        for pc in pcs:
            if pc in seen:
                continue
            seen.add(pc)
            tokens = self._asm_tokens_at(pc)
            if tokens:
                out[f"0x{pc:x}"] = tokens
            if len(seen) >= 512:
                break
        return {"ok": True, "ready": True, "status": "ok", "tokens": out}

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

    def cfg_for(self, pc: int, mode: str = "asm", timeout: int | None = None) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        fn = self._function_for_pc(pc)
        if fn is None:
            return {"ok": False, "ready": True, "error": f"no function contains 0x{pc:x}"}
        blocks = [{"id": i, "start": int(bb.start), "end": int(bb.end)} for i, bb in enumerate(fn.basic_blocks)]
        return {"ok": True, "ready": True, "mode": mode, "timeout": timeout, "blocks": blocks, "edges": [], "svg": ""}

    def _function_for_pc(self, pc: int) -> Any | None:
        fn = self.bv.get_function_at(pc)
        if fn is not None:
            return fn
        containing = list(self.bv.get_functions_containing(pc))
        return containing[0] if containing else None

    def _asm_tokens_at(self, pc: int) -> list[dict[str, Any]]:
        fn = self._function_for_pc(pc)
        raw_tokens = None
        if fn is not None:
            raw_tokens = self._call_instruction_text(fn, pc)
        if raw_tokens is None:
            raw_tokens = self._call_instruction_text(self.bv, pc)
        if raw_tokens:
            return [self._token_to_wire(t) for t in raw_tokens if getattr(t, "text", "")]
        try:
            text = str(self.bv.get_disassembly(pc))
        except Exception:
            return []
        return self._fallback_asm_tokens(text)

    def _call_instruction_text(self, provider: Any, pc: int) -> Any | None:
        method = getattr(provider, "get_instruction_text", None)
        if method is None:
            return None
        try:
            result = method(pc)
        except TypeError:
            try:
                result = method(self.bv.arch, pc)
            except Exception:
                return None
        except Exception:
            return None
        if result is None:
            return None
        if hasattr(result, "tokens"):
            return list(result.tokens)
        if isinstance(result, tuple):
            for item in result:
                if hasattr(item, "tokens"):
                    return list(item.tokens)
                if isinstance(item, list):
                    return item
        if isinstance(result, list):
            return result
        return None

    def _token_to_wire(self, token: Any) -> dict[str, Any]:
        text = str(getattr(token, "text", "") or "")
        type_name = str(getattr(token, "type", "")).split(".")[-1]
        cls = _classify_token(type_name, text)
        addr = _token_addr(token, type_name)
        out: dict[str, Any] = {"t": text, "c": cls}
        if addr is not None:
            out["a"] = f"0x{addr:x}"
        return out

    def _fallback_asm_tokens(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        m = re.match(r"^(\s*)(\S+)(.*)$", text)
        if not m:
            return [{"t": text, "c": "txt"}]
        out: list[dict[str, Any]] = []
        if m.group(1):
            out.append({"t": m.group(1), "c": "txt"})
        out.append({"t": m.group(2), "c": "mnem"})
        rest = m.group(3)
        reg_re = re.compile(r"\b(?:x(?:[0-9]|1[0-9]|2[0-9]|3[01])|w(?:[0-9]|1[0-9]|2[0-9]|3[01])|sp|fp|lr|xzr|wzr|pc)\b", re.I)
        last = 0
        for rm in reg_re.finditer(rest):
            if rm.start() > last:
                out.append({"t": rest[last:rm.start()], "c": "txt"})
            out.append({"t": rm.group(0), "c": "reg"})
            last = rm.end()
        if last < len(rest):
            out.append({"t": rest[last:], "c": "txt"})
        return out


def handle(session: Session, req: dict[str, Any]) -> dict[str, Any]:
    method = req.get("method")
    params = req.get("params") or {}
    if method == "open_so":
        return session.open_so(str(params.get("path") or ""))
    if method == "functions":
        return session.functions()
    if method == "asm_tokens":
        raw_pcs = params.get("pcs") or []
        pcs: list[int] = []
        for pc in raw_pcs:
            try:
                pcs.append(int(pc))
            except Exception:
                continue
        return session.asm_tokens(pcs)
    if method == "hlil_for":
        return session.hlil_for(int(params.get("pc") or 0))
    if method == "cfg_for":
        timeout = params.get("timeout")
        return session.cfg_for(
            int(params.get("pc") or 0),
            mode=str(params.get("mode") or "asm"),
            timeout=int(timeout) if timeout is not None else None,
        )
    return {"ok": False, "ready": session.ready, "error": f"unknown method {method!r}"}


def _classify_token(type_name: str, text: str) -> str:
    name = type_name.lower()
    if "instruction" in name:
        return "mnem"
    if "register" in name:
        return "reg"
    if "codesymbol" in name or "imports" in name:
        return "fn"
    if "datasymbol" in name or "address" in name:
        return "data"
    if "possibleaddress" in name:
        return "hex"
    if "integer" in name or "float" in name:
        return "num"
    if "string" in name:
        return "str"
    if "localvariable" in name or "argumentname" in name:
        return "var"
    if "keyword" in name:
        return "key"
    if "typename" in name:
        return "type"
    if "field" in name:
        return "field"
    if "comment" in name:
        return "cmt"
    if "label" in name:
        return "label"
    if "operandseparator" in name:
        return "sep"
    if "brace" in name or "memoryoperand" in name:
        return "brace"
    if text.strip() in {"+", "-", "*", "/", "<<", ">>", "&", "|", "^", "=", "==", "!=", "<", ">"}:
        return "op"
    return "txt"


def _token_addr(token: Any, type_name: str) -> int | None:
    name = type_name.lower()
    if not any(s in name for s in ("symbol", "address", "integer")):
        return None
    for attr in ("address", "value"):
        value = getattr(token, attr, None)
        if isinstance(value, int) and value > 0:
            return value
    return None


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
