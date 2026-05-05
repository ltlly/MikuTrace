from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    so_path: str | None = None
    runtime_base: int | None = None
    image_base: int = 0
    image_end: int = 0
    bv: Any = None
    bn: Any = None
    ready: bool = False
    error: str | None = None
    created_functions: set[int] = field(default_factory=set)

    def open_so(self, path: str) -> dict[str, Any]:
        self.so_path = path
        try:
            import binaryninja  # type: ignore

            self.bn = binaryninja
            self.bv = binaryninja.load(path)
            self.ready = self.bv is not None
            if self.bv is not None:
                self.image_base, self.image_end = _image_bounds(self.bv)
            return {
                "ok": self.ready,
                "ready": self.ready,
                "version": getattr(binaryninja, "__version__", ""),
                "fn_count": len(list(self.bv.functions)) if self.bv is not None else 0,
                "runtime_base": _hex_or_none(self.runtime_base),
                "image_base": f"0x{self.image_base:x}",
            }
        except Exception as exc:  # pragma: no cover - depends on local BN install
            self.ready = False
            self.error = str(exc)
            return {"ok": False, "ready": False, "error": self.error}

    def functions(self) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        fns = [
            {"start": self._to_trace_addr(int(fn.start)), "name": str(fn.name)}
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

    def hlil_for(self, pc: int, fn_start: int | None = None) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        bn_pc = self._to_bn_addr(pc)
        fn = self._function_for_pc(bn_pc)
        created = False
        if fn is None:
            fn = self._create_function_for_pc(bn_pc, self._to_bn_addr(fn_start) if fn_start else None)
            created = fn is not None
        if fn is None:
            return {
                "ok": False,
                "ready": True,
                "error": f"no function contains trace 0x{pc:x} (bn 0x{bn_pc:x})",
                "created_function": False,
            }
        pseudo_lines = self._pseudo_hlil_lines(fn)
        hlil_lines = self._linear_hlil_lines(fn)
        if pseudo_lines:
            _copy_structured_indents(hlil_lines, pseudo_lines)
        lines = pseudo_lines or hlil_lines
        return {
            "ok": True,
            "ready": True,
            "fn": {
                "name": str(fn.name),
                "start": self._to_trace_addr(int(fn.start)),
                "end": self._to_trace_addr(int(fn.highest_address)),
            },
            "created_function": created,
            "lines": lines,
            "pseudo_lines": pseudo_lines,
            "hlil_lines": hlil_lines,
            "vars": [],
        }

    def cfg_for(
        self,
        pc: int,
        mode: str = "asm",
        timeout: int | None = None,
        fn_start: int | None = None,
    ) -> dict[str, Any]:
        if not self.ready or self.bv is None:
            return {"ok": False, "ready": False, "error": self.error or "BN not ready"}
        bn_pc = self._to_bn_addr(pc)
        fn = self._function_for_pc(bn_pc)
        created = False
        if fn is None:
            fn = self._create_function_for_pc(bn_pc, self._to_bn_addr(fn_start) if fn_start else None)
            created = fn is not None
        if fn is None:
            return {
                "ok": False,
                "ready": True,
                "error": f"no function contains trace 0x{pc:x} (bn 0x{bn_pc:x})",
                "created_function": False,
            }
        blocks = [
            {"id": i, "start": self._to_trace_addr(int(bb.start)), "end": self._to_trace_addr(int(bb.end))}
            for i, bb in enumerate(fn.basic_blocks)
        ]
        return {
            "ok": True,
            "ready": True,
            "mode": mode,
            "timeout": timeout,
            "created_function": created,
            "blocks": blocks,
            "edges": [],
            "svg": "",
        }

    def _function_for_pc(self, pc: int) -> Any | None:
        fn = self.bv.get_function_at(pc)
        if fn is not None:
            return fn
        containing = list(self.bv.get_functions_containing(pc))
        return containing[0] if containing else None

    def _create_function_for_pc(self, bn_pc: int, bn_fn_start: int | None = None) -> Any | None:
        candidates: list[int] = []
        if bn_fn_start is not None and self._addr_in_image(bn_fn_start):
            candidates.append(bn_fn_start)
        if self._addr_in_image(bn_pc) and bn_pc not in candidates:
            candidates.append(bn_pc)
        for start in candidates:
            fn = self._try_create_function(start, bn_pc)
            if fn is not None:
                return fn
        return None

    def _try_create_function(self, start: int, want_pc: int) -> Any | None:
        existing = self._function_for_pc(start)
        if existing is not None:
            return existing
        try:
            created = self.bv.create_user_function(start)
            self.created_functions.add(start)
        except Exception:
            created = None
        try:
            self.bv.update_analysis_and_wait()
        except Exception:
            pass
        fn = self._function_for_pc(want_pc)
        if fn is not None:
            return fn
        fn = self._function_for_pc(start)
        if fn is not None:
            return fn
        return created

    def _addr_in_image(self, addr: int) -> bool:
        if self.image_base and self.image_end:
            return self.image_base <= addr < self.image_end
        return addr > 0

    def _asm_tokens_at(self, pc: int) -> list[dict[str, Any]]:
        bn_pc = self._to_bn_addr(pc)
        fn = self._function_for_pc(bn_pc)
        raw_tokens = None
        if fn is not None:
            raw_tokens = self._call_instruction_text(fn, bn_pc)
        if raw_tokens is None:
            raw_tokens = self._call_instruction_text(self.bv, bn_pc)
        if raw_tokens:
            return [self._token_to_wire(t) for t in raw_tokens if getattr(t, "text", "")]
        try:
            text = str(self.bv.get_disassembly(bn_pc))
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
        addr = self._to_trace_addr(_token_addr(token, type_name))
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

    def _pseudo_hlil_lines(self, fn: Any) -> list[dict[str, Any]]:
        root = getattr(getattr(fn, "hlil", None), "root", None)
        if root is None:
            return []
        return self._lines_from_hlil(root, None)

    def _linear_hlil_lines(self, fn: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            instructions = list(fn.hlil.instructions)
        except Exception:
            instructions = []
        for insn in instructions:
            addr = int(getattr(insn, "address", 0) or 0)
            rendered = self._lines_from_hlil(insn, addr)
            if rendered:
                out.extend(rendered)
            else:
                text = str(insn)
                out.append(
                    {
                        "pc": f"0x{self._to_trace_addr(addr) or 0:x}",
                        "text": text,
                        "indent": _leading_indent(text),
                        "tokens": _fallback_code_tokens(text),
                    }
                )
        return out

    def _lines_from_hlil(self, instr: Any, fallback_addr: int | None) -> list[dict[str, Any]]:
        try:
            raw_lines = list(instr.lines)
        except Exception:
            try:
                raw_lines = list(instr.get_lines())
            except Exception:
                raw_lines = []
        return [self._line_to_wire(line, fallback_addr) for line in raw_lines]

    def _line_to_wire(self, line: Any, fallback_addr: int | None) -> dict[str, Any]:
        raw_addr = getattr(line, "address", None)
        if raw_addr in (None, 0):
            il_instr = getattr(line, "il_instruction", None)
            raw_addr = getattr(il_instr, "address", None)
        if raw_addr in (None, 0):
            raw_addr = fallback_addr
        trace_addr = self._to_trace_addr(int(raw_addr or 0)) or 0
        tokens = []
        for token in getattr(line, "tokens", []) or []:
            if _is_hidden_line_token(token):
                continue
            wire = self._token_to_wire(token)
            if wire["t"]:
                tokens.append(wire)
        text = "".join(token["t"] for token in tokens)
        indent = _leading_indent(text)
        if indent == 0:
            try:
                indent = int(getattr(line, "address_and_indentation_width", 0) or 0)
            except Exception:
                indent = 0
            if indent > 0 and text and not text[0].isspace():
                tokens.insert(0, {"t": " " * indent, "c": "indent"})
                text = (" " * indent) + text
        if not tokens:
            text = str(line)
            indent = _leading_indent(text)
            tokens = _fallback_code_tokens(text)
        return {
            "pc": f"0x{trace_addr:x}",
            "text": text,
            "indent": indent,
            "tokens": tokens,
        }

    def _to_bn_addr(self, pc: int) -> int:
        if self.runtime_base is None:
            return pc
        if pc < self.runtime_base:
            return pc
        return self.image_base + (pc - self.runtime_base)

    def _to_trace_addr(self, addr: int | None) -> int | None:
        if addr is None:
            return None
        if self.runtime_base is None:
            return addr
        if self.image_base <= addr < self.image_end:
            return self.runtime_base + (addr - self.image_base)
        return addr


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
        fn_start = params.get("fn_start")
        return session.hlil_for(
            int(params.get("pc") or 0),
            fn_start=int(fn_start) if fn_start is not None else None,
        )
    if method == "cfg_for":
        timeout = params.get("timeout")
        fn_start = params.get("fn_start")
        return session.cfg_for(
            int(params.get("pc") or 0),
            mode=str(params.get("mode") or "asm"),
            timeout=int(timeout) if timeout is not None else None,
            fn_start=int(fn_start) if fn_start is not None else None,
        )
    return {"ok": False, "ready": session.ready, "error": f"unknown method {method!r}"}


def _classify_token(type_name: str, text: str) -> str:
    name = type_name.lower()
    stripped = text.strip()
    if not stripped:
        return "indent" if "indent" in name else "txt"
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
    if "type" in name and "token" in name:
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
    if stripped in _CODE_KEYWORDS:
        return "key"
    if stripped in _CODE_TYPES:
        return "type"
    if _NUMBER_RE.match(stripped):
        return "num"
    if stripped.startswith('"') or stripped.startswith("'"):
        return "str"
    if stripped in {"(", ")", "[", "]", "{", "}"}:
        return "brace"
    if stripped in _CODE_OPERATORS:
        return "op"
    if _IDENT_RE.match(stripped):
        return "var"
    return "txt"


def _token_type_name(token: Any) -> str:
    return str(getattr(token, "type", "")).split(".")[-1]


def _token_addr(token: Any, type_name: str) -> int | None:
    name = type_name.lower()
    if not any(s in name for s in ("symbol", "address")):
        return None
    for attr in ("address", "value"):
        value = getattr(token, attr, None)
        if isinstance(value, int) and value > 0:
            return value
    return None


def _is_hidden_line_token(token: Any) -> bool:
    name = _token_type_name(token).lower()
    return "addressdisplay" in name or "addressseparator" in name


def _leading_indent(text: str) -> int:
    width = 0
    for ch in text:
        if ch == " ":
            width += 1
        elif ch == "\t":
            width += 4
        else:
            break
    return width


_CODE_KEYWORDS = {
    "break",
    "case",
    "continue",
    "default",
    "do",
    "else",
    "false",
    "for",
    "goto",
    "if",
    "return",
    "switch",
    "true",
    "while",
}

_CODE_TYPES = {
    "bool",
    "char",
    "const",
    "double",
    "float",
    "int",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "long",
    "short",
    "size_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "void",
}

_CODE_OPERATORS = {
    "!",
    "!=",
    "%",
    "&",
    "&&",
    "*",
    "*=",
    "+",
    "++",
    "+=",
    "-",
    "--",
    "-=",
    "->",
    "/",
    "/=",
    "<",
    "<<",
    "<=",
    "=",
    "==",
    ">",
    ">=",
    ">>",
    "^",
    "|",
    "|=",
    "||",
    "~",
}

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NUMBER_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)(?:[uUlL]*)$")
_CODE_TOKEN_RE = re.compile(
    r'(\s+|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|0x[0-9a-fA-F]+|\d+|'
    r'[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|<<|>>|&&|\|\||->|\+\+|--|[{}()\[\],;:.*&=<>+\-/|!~^%])'
)


def _fallback_code_tokens(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pos = 0
    for match in _CODE_TOKEN_RE.finditer(text):
        if match.start() > pos:
            out.append({"t": text[pos:match.start()], "c": "txt"})
        token = match.group(0)
        out.append({"t": token, "c": _classify_token("", token)})
        pos = match.end()
    if pos < len(text):
        out.append({"t": text[pos:], "c": "txt"})
    return out or [{"t": text, "c": "txt"}]


def _copy_structured_indents(
    linear_lines: list[dict[str, Any]],
    structured_lines: list[dict[str, Any]],
) -> None:
    indent_by_key: dict[tuple[str, str], int] = {}
    for line in structured_lines:
        key = (str(line.get("pc") or ""), str(line.get("text") or "").strip())
        indent = int(line.get("indent") or 0)
        if not key[0] or not key[1] or indent <= 0:
            continue
        old = indent_by_key.get(key)
        if old is None or indent > old:
            indent_by_key[key] = indent
    for line in linear_lines:
        text = str(line.get("text") or "")
        stripped = text.strip()
        if not stripped or int(line.get("indent") or 0) > 0:
            continue
        indent = indent_by_key.get((str(line.get("pc") or ""), stripped))
        if not indent:
            continue
        line["indent"] = indent
        line["text"] = (" " * indent) + stripped
        tokens = line.get("tokens")
        if isinstance(tokens, list):
            line["tokens"] = [{"t": " " * indent, "c": "indent"}, *tokens]
        else:
            line["tokens"] = _fallback_code_tokens(str(line["text"]))


def _image_bounds(bv: Any) -> tuple[int, int]:
    starts: list[int] = []
    ends: list[int] = []
    for attr in ("segments", "sections"):
        try:
            items = list(getattr(bv, attr))
        except Exception:
            items = []
        for item in items:
            start = getattr(item, "start", None)
            end = getattr(item, "end", None)
            if isinstance(start, int):
                starts.append(start)
            if isinstance(end, int):
                ends.append(end)
    if not starts:
        try:
            funcs = list(bv.functions)
        except Exception:
            funcs = []
        starts.extend(int(getattr(fn, "start", 0) or 0) for fn in funcs)
        ends.extend(int(getattr(fn, "highest_address", 0) or 0) for fn in funcs)
    start = min(starts) if starts else 0
    end = max(ends) if ends else start
    return start, max(end, start + 1)


def _parse_int(raw: str | int | None) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        return None


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--so", default="")
    parser.add_argument("--base", default="")
    args = parser.parse_args()
    session = Session(runtime_base=_parse_int(args.base))
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
