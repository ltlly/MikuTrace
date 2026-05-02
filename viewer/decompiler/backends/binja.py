"""Binary Ninja backend.

需要:
  - BN 装好 (本机 /home/ltlly/tools/binaryninja/python)
  - Commercial 或更高 license (Personal license 不允许 headless API 调用)

加载策略: 进程内长驻. open() 阻塞分析 (大 SO 数十秒冷启), 之后 hot-path
查询 ~5ms / 函数. close() 时显式 close BV, 不靠 GC.
"""
from __future__ import annotations
import os, sys, time, logging
from typing import Optional
from ..backend import (DecompilerBackend, Function, HlilLine, FieldHint, VarType,
                       Token, CfgBlock, CfgEdge)


# BN InstructionTextTokenType.name → 稳定 CSS class id (前端用 t-{cls}). 故意
# 缩短: 减少 wire 体积 + CSS 简单. 颜色定义在前端 styles.css.
_TOK_CLASS = {
    # 关键字 / 类型
    "KeywordToken": "key",
    "TypeNameToken": "type",
    # 标识符
    "RegisterToken": "reg",
    "LocalVariableToken": "var", "StackVariableToken": "var",
    "ArgumentNameToken": "var",
    # 字面量
    "IntegerToken": "num", "FloatingPointToken": "num",
    "AddressDisplayToken": "num", "PossibleAddressToken": "num",
    "CodeRelativeAddressToken": "num",
    "StringToken": "str", "CharacterConstantToken": "str",
    # 符号引用
    "CodeSymbolToken": "fn",
    "ImportToken": "fn", "ExternalSymbolToken": "fn", "IndirectImportToken": "fn",
    "DataSymbolToken": "data",
    "FieldNameToken": "field", "StructOffsetToken": "field",
    "EnumerationMemberToken": "field",
    # 注释 / 元
    "CommentToken": "cmt", "AnnotationToken": "cmt",
    # 运算/标点
    "OperationToken": "op",
    "OperandSeparatorToken": "sep",
    "BraceToken": "brace",
    "BeginMemoryOperandToken": "brace", "EndMemoryOperandToken": "brace",
    # ASM
    "InstructionToken": "mnem",
    "OpcodeToken": "opcode",
    # 排版
    "IndentationToken": "indent",
    "TextToken": "txt",
    # 地址前缀 / 折叠等 — 前端会用 CSS 折叠隐藏 (减视觉噪声)
    "AddressSeparatorToken": "meta",
    "CollapseStateIndicatorToken": "meta",
    "CollapsedInformationToken": "meta",
    # 跳转标签
    "GotoLabelToken": "label",
    "TagToken": "tag",
    # hexdump / 其它
    "HexDumpByteValueToken": "hex", "HexDumpSkippedByteToken": "hex",
    "HexDumpInvalidByteToken": "hex", "HexDumpTextToken": "hex",
}


def _bn_token(tk) -> Token:
    """BN InstructionTextToken → our Token dataclass."""
    cls = _TOK_CLASS.get(tk.type.name, "other")
    addr = 0
    if cls in ("fn", "data"):
        addr = getattr(tk, "value", 0) or 0
    return Token(text=tk.text, cls=cls, addr=addr)


log = logging.getLogger(__name__)
_BN_PYTHON_HINTS = [
    "/home/ltlly/tools/binaryninja/python",
    "/Applications/Binary Ninja.app/Contents/Resources/python",  # macOS
]


class Backend:
    name = "binja"
    _unavailable_reason = ""

    def __init__(self):
        self._bn = None
        self._bv = None
        self._base = 0
        self._fn_cache: dict[int, "Function"] = {}    # absolute PC -> our Function
        self._hlil_cache: dict[int, list[HlilLine]] = {}
        self._vars_cache: dict[int, list[VarType]] = {}
        # per-fn ASM-token map: fn.start (caller-coords) -> {pc: list[Token]}.
        # 第一次 query 某 fn 任一 PC 时, cfg_for 一次跑全 BB, 之后该 fn 的查询都 O(1).
        self._asm_tok_cache: dict[int, dict[int, list]] = {}
        # 每条 PC 是否已经尝试过 create_user_function — 防 cursor 反复打到同一坏 PC
        # 时无限期 update_analysis_and_wait 卡死后端线程.
        self._force_create_tried: set[int] = set()
        # 每个 fn.start (caller-coords) 是否已经尝试过 reanalyze — 防同函数反复触发.
        self._force_reanalyze_tried: set[int] = set()

    def is_available(self) -> bool:
        try:
            import binaryninja  # noqa: F401
            self._bn = binaryninja
            return True
        except ImportError:
            # try injecting common BN install paths
            for p in _BN_PYTHON_HINTS:
                if os.path.isdir(p) and p not in sys.path:
                    sys.path.insert(0, p)
                    try:
                        import binaryninja
                        self._bn = binaryninja
                        return True
                    except ImportError:
                        continue
            self._unavailable_reason = (
                "binaryninja python module not importable; "
                "ensure BN is installed and PYTHONPATH includes the BN python dir, "
                "or export it via binaryninja.scripting.install_api()")
            return False

    def open(self, so_path: str, base: int = 0) -> None:
        assert self._bn is not None, "call is_available() first"
        if self._bv is not None:
            self.close()
        t0 = time.time()
        # update_analysis=True does the full slow first pass
        bv = self._bn.load(so_path, update_analysis=True)
        if bv is None:
            raise RuntimeError(f"BN failed to load {so_path}")
        self._bv = bv
        self._base = int(base)        # 0 = SO-offset semantics, !=0 = absolute-pc semantics
        log.info("binja loaded %s in %.1fs (%d functions)", so_path,
                 time.time() - t0, len(list(bv.functions)))

    def close(self) -> None:
        if self._bv is not None:
            try: self._bv.file.close()
            except Exception: pass
            self._bv = None
        self._fn_cache.clear()
        self._hlil_cache.clear()
        self._vars_cache.clear()

    def loaded_base(self) -> int:
        return self._bv.start if self._bv is not None else 0

    def _to_bv_addr(self, pc: int) -> int:
        """Convert caller-supplied PC -> BN BinaryView address.
        - base == 0  : pc 是 SO 内部偏移; bv 加载到 bv.start, return bv.start + pc
        - base != 0  : pc 是绝对运行时地址; return pc - base + bv.start"""
        if self._base == 0:
            return self._bv.start + pc
        return pc - self._base + self._bv.start

    # ---- hot path queries ----
    def _from_bv_addr(self, bv_addr: int) -> int:
        """Inverse of _to_bv_addr: BV-internal -> caller-coordinate."""
        if self._base == 0:
            return bv_addr - self._bv.start          # offset within SO
        return bv_addr - self._bv.start + self._base  # absolute runtime PC

    def function_at(self, pc: int) -> Optional[Function]:
        if pc in self._fn_cache: return self._fn_cache[pc]
        if self._bv is None: return None
        ad = self._to_bv_addr(pc)
        bn_fn = self._bv.get_function_at(ad)
        if bn_fn is None:
            # try 'containing' for mid-function PCs
            fns = self._bv.get_functions_containing(ad)
            if fns:
                bn_fn = fns[0]
        if bn_fn is None and ad not in self._force_create_tried:
            # BN 完全不知道这个地址 — 但 trace 证明 PC 真在执行此处.
            # 当作 user fn 强制创建并阻塞等分析. 仅一次, 失败也不再重试 (防卡线程).
            self._force_create_tried.add(ad)
            log.info("function_at(%#x): no BN fn — force create_user_function from trace", ad)
            try:
                self._bv.create_user_function(ad)
                self._bv.update_analysis_and_wait()
                bn_fn = self._bv.get_function_at(ad)
                if bn_fn is None:
                    fns = self._bv.get_functions_containing(ad)
                    if fns: bn_fn = fns[0]
                if bn_fn is not None:
                    log.info("function_at(%#x): force-created %s", ad, bn_fn.name)
            except Exception as e:
                log.warning("create_user_function(%#x) failed: %s", ad, e)
        if bn_fn is None:
            # nothing covers pc — find nearest <= pc fn (混淆区/trampoline 旁边)
            # bv.get_previous_function_start_before is the official helper
            prev_start = None
            try:
                prev_start = self._bv.get_previous_function_start_before(ad)
            except Exception: pass
            if prev_start is not None and prev_start > 0:
                cand = self._bv.get_function_at(prev_start)
                # require pc within 4KB of fn end so we don't return a wildly far fn
                if cand is not None and ad - (cand.start + cand.total_bytes) <= 0x1000:
                    bn_fn = cand
        if bn_fn is None:
            return None
        f = Function(
            start=self._from_bv_addr(bn_fn.start),
            end=self._from_bv_addr(bn_fn.start + bn_fn.total_bytes),
            name=bn_fn.name,
            backend=self.name,
            raw=bn_fn,
        )
        self._fn_cache[pc] = f
        return f

    _HLIL_CODE_CLS = ("mnem","key","fn","var","field","type","label")

    def _pull_linear_view(self, bn_fn) -> list[HlilLine]:
        """Run BN LinearView for `bn_fn`, return HlilLine list with hex-dump
        lines filtered out. Empty result means BN didn't lift this fn to HLIL."""
        out: list[HlilLine] = []
        try:
            from binaryninja import LinearViewObject, LinearViewCursor, DisassemblySettings, DisassemblyOption
            s = DisassemblySettings()
            s.set_option(DisassemblyOption.WaitForIL, True)
            obj = LinearViewObject.language_representation(self._bv, s)
            cur = LinearViewCursor(obj)
            cur.seek_to_address(bn_fn.start)
            fn_end_bv = bn_fn.start + bn_fn.total_bytes
            seen_lines = 0
            MAX_LINES = 2000
            while seen_lines < MAX_LINES:
                batch = self._bv.get_next_linear_disassembly_lines(cur)
                if not batch: break
                for ln in batch:
                    addr = ln.contents.address
                    if addr >= fn_end_bv and out: break
                    text = str(ln.contents)
                    indent = len(text) - len(text.lstrip(' '))
                    pc_lo = self._from_bv_addr(addr)
                    toks = [_bn_token(t) for t in ln.contents.tokens]
                    for t in toks:
                        if t.addr: t.addr = self._from_bv_addr(t.addr)
                    out.append(HlilLine(text=text, pc_lo=pc_lo, pc_hi=pc_lo,
                                        indent=indent, tokens=toks))
                    seen_lines += 1
                else:
                    continue
                break
        except Exception as e:
            log.warning("LinearView for %s failed: %s", bn_fn.name, e)
        # OLLVM/未抬升函数 LinearView 会发 HexDump tokens — 去掉这些 hex 行
        return [ln for ln in out if not any(t.cls == "hex" for t in (ln.tokens or []))]

    def _has_code_lines(self, lines: list[HlilLine]) -> bool:
        return any(any(t.cls in self._HLIL_CODE_CLS for t in (ln.tokens or [])) for ln in lines)

    def hlil_for(self, fn: Function) -> list[HlilLine]:
        if fn.start in self._hlil_cache: return self._hlil_cache[fn.start]
        bn_fn = fn.raw
        if bn_fn is None: return []

        out = self._pull_linear_view(bn_fn)

        # 第一次拉空 / 全 hex — 是 BN 抬升失败 (大 fn / 混淆). 强制 reanalyze 一次再试.
        if not self._has_code_lines(out) and fn.start not in self._force_reanalyze_tried:
            self._force_reanalyze_tried.add(fn.start)
            log.info("hlil_for(%s): no code lines, forcing reanalyze", fn.name)
            try:
                if hasattr(bn_fn, "set_auto_analysis_skipped"):
                    bn_fn.set_auto_analysis_skipped(False)
                bn_fn.reanalyze()
                self._bv.update_analysis_and_wait()
                out = self._pull_linear_view(bn_fn)
                if self._has_code_lines(out):
                    log.info("hlil_for(%s): reanalyze produced %d code lines", fn.name, len(out))
            except Exception as e:
                log.warning("hlil_for(%s) reanalyze failed: %s", fn.name, e)

        # 仍然抬不出 → ASM 兜底, 让用户至少能看汇编 + 知情
        if not self._has_code_lines(out):
            log.warning("hlil_for(%s): still no HLIL after force-attempts, ASM fallback", fn.name)
            asm_lines: list[HlilLine] = []
            note_pc = self._from_bv_addr(bn_fn.start)
            asm_lines.append(HlilLine(
                text=f"// BN could not lift {fn.name} to HLIL even after reanalyze; showing disassembly",
                pc_lo=note_pc, pc_hi=note_pc, indent=0,
                tokens=[Token(f"// BN could not lift {fn.name} to HLIL even after reanalyze; showing disassembly", "cmt")],
            ))
            try:
                blocks, _edges = self.cfg_for(fn, mode="asm")
                for bb in blocks:
                    asm_lines.extend(bb.lines)
            except Exception as e:
                log.warning("hlil_for(%s) ASM fallback failed: %s", fn.name, e)
            out = asm_lines

        self._hlil_cache[fn.start] = out
        return out

    def vars_for(self, fn: Function) -> list[VarType]:
        if fn.start in self._vars_cache: return self._vars_cache[fn.start]
        bn_fn = fn.raw
        if bn_fn is None: return []
        out: list[VarType] = []
        # Parameters first (named arg1/arg2/...)
        try:
            for v in bn_fn.parameter_vars:
                out.append(VarType(name=v.name, type_name=str(v.type), storage=str(v.storage)))
        except Exception: pass
        # Then locals
        try:
            for v in bn_fn.vars:
                if v in (bn_fn.parameter_vars or []): continue
                out.append(VarType(name=v.name, type_name=str(v.type), storage=str(v.storage)))
        except Exception: pass
        self._vars_cache[fn.start] = out
        return out

    def field_at(self, pc: int, reg: str, offset: int) -> Optional[FieldHint]:
        """Find struct field semantic at (pc, reg, offset).

        Walks BN HLIL instructions at `pc`, looks for deref-field or
        struct-offset operands where the base register matches `reg` and
        the offset matches `offset`.
        """
        if self._bv is None: return None
        fn = self.function_at(pc)
        if fn is None: return None
        bn_fn = fn.raw
        if bn_fn is None: return None
        ad = self._to_bv_addr(pc)
        try:
            hlil = bn_fn.hlil
            if hlil is None: return None
            # Find HLIL instructions at this address
            for insn in hlil.instructions:
                if insn.address != ad: continue
                result = self._walk_hlil_for_field(insn, reg, offset)
                if result: return result
            # Also check HLIL instructions that span this address
            for insn in hlil.instructions:
                if insn.address <= ad < insn.address + 4:
                    result = self._walk_hlil_for_field(insn, reg, offset)
                    if result: return result
        except Exception as e:
            log.debug("field_at(%#x, %s, %#x) failed: %s", pc, reg, offset, e)
        return None

    def _walk_hlil_for_field(self, hlil_insn, reg: str, offset: int) -> Optional[FieldHint]:
        """Recursively walk an HLIL expression tree looking for struct field access."""
        try:
            from binaryninja import HighLevelILOperation as Op
        except ImportError:
            return None
        return self._search_expr(hlil_insn, reg, offset, depth=0)

    def _search_expr(self, expr, reg: str, offset: int, depth: int) -> Optional[FieldHint]:
        """Search an HLIL expression for (reg + offset) with struct field info."""
        if depth > 10: return None
        try:
            from binaryninja import HighLevelILOperation as Op
        except ImportError:
            return None
        try:
            op = expr.operation
            # HLIL_DEREF_FIELD: memory access with known struct field
            if op == Op.HLIL_DEREF_FIELD:
                src = expr.src
                if hasattr(src, 'offset') and src.offset == offset:
                    # Check if the source register matches
                    if self._expr_uses_reg(src, reg):
                        field_name = expr.constant_field.name if hasattr(expr, 'constant_field') and expr.constant_field else ""
                        type_name = str(expr.expr_type) if hasattr(expr, 'expr_type') and expr.expr_type else ""
                        return FieldHint(
                            struct=str(src.expr_type) if hasattr(src, 'expr_type') and src.expr_type else "",
                            field=field_name,
                            offset=offset,
                            type_name=type_name,
                        )
            # HLIL_STRUCT_FIELD: struct field access (not necessarily memory)
            if op == Op.HLIL_STRUCT_FIELD:
                if hasattr(expr, 'offset') and expr.offset == offset:
                    if self._expr_uses_reg(expr.src, reg):
                        return FieldHint(
                            struct=str(expr.expr_type) if hasattr(expr, 'expr_type') and expr.expr_type else "",
                            field=expr.constant_field.name if hasattr(expr, 'constant_field') and expr.constant_field else "",
                            offset=offset,
                            type_name=str(expr.expr_type) if hasattr(expr, 'expr_type') and expr.expr_type else "",
                        )
            # Recurse into operands
            for operand in expr.operands:
                if hasattr(operand, 'operation'):
                    result = self._search_expr(operand, reg, offset, depth + 1)
                    if result: return result
        except Exception:
            pass
        return None

    def _expr_uses_reg(self, expr, reg: str) -> bool:
        """Check if an HLIL expression references the given register."""
        try:
            from binaryninja import HighLevelILOperation as Op
            if expr.operation == Op.HLIL_REG:
                reg_info = expr.reg
                if hasattr(reg_info, 'name'):
                    return reg_info.name == reg
                # Try to get register name from index
                if hasattr(reg_info, 'index'):
                    arch = self._bv.arch
                    if arch:
                        reg_name = arch.get_reg_name(reg_info.index)
                        return reg_name == reg
        except Exception:
            pass
        return False

    def xrefs_to(self, addr: int) -> list[int]:
        if self._bv is None: return []
        ad = self._to_bv_addr(addr)
        try:
            return [self._from_bv_addr(r.address) for r in self._bv.get_code_refs(ad)]
        except Exception:
            return []

    # ---- CFG ----
    _EDGE_KIND_MAP = {
        "TrueBranch": "true", "FalseBranch": "false",
        "UnconditionalBranch": "uncond",
        "IndirectBranch": "indirect",
        "CallDestination": "call",
        "FunctionReturn": "ret",
        "SystemCall": "syscall",
        "ExceptionBranch": "exc",
        "UnresolvedBranch": "unres",
        "UserDefinedBranch": "user",
    }
    def _extract_cfg(self, bn_fn) -> tuple[list[CfgBlock], list[CfgEdge]]:
        blocks: list[CfgBlock] = []
        edges: list[CfgEdge] = []
        for bb in bn_fn.basic_blocks:
            cb = CfgBlock(
                start=self._from_bv_addr(bb.start),
                end=self._from_bv_addr(bb.end),
                lines=[],
            )
            for asm_ln in bb.get_disassembly_text():
                addr = asm_ln.address
                if addr < bb.start or addr >= bb.end: continue
                toks = [_bn_token(t) for t in asm_ln.tokens]
                for t in toks:
                    if t.addr: t.addr = self._from_bv_addr(t.addr)
                pc = self._from_bv_addr(addr)
                cb.lines.append(HlilLine(text=str(asm_ln), pc_lo=pc, pc_hi=pc,
                                         indent=0, tokens=toks))
            blocks.append(cb)
            for e in bb.outgoing_edges:
                edges.append(CfgEdge(
                    src=self._from_bv_addr(bb.start),
                    dst=self._from_bv_addr(e.target.start),
                    kind=self._EDGE_KIND_MAP.get(e.type.name, e.type.name.lower()),
                ))
        return blocks, edges

    def cfg_for(self, fn: Function, mode: str = "asm"):
        """BN BB-level CFG. mode='asm' uses ASM tokens (default; matches BN UI's
        'Disassembly' graph view); 'hlil' would need extra work to map HLIL
        stmt indexes back to EAs and is deferred."""
        bn_fn = fn.raw
        if bn_fn is None: return [], []
        blocks, edges = self._extract_cfg(bn_fn)
        # 若 basic_blocks 为空 (BN 没在该 fn 上完成分析), 强制 reanalyze 一次再试.
        # 与 hlil_for 共用 _force_reanalyze_tried, 同一 fn 同 BV-update 只触发一次.
        if not blocks and fn.start not in self._force_reanalyze_tried:
            self._force_reanalyze_tried.add(fn.start)
            log.info("cfg_for(%s): no basic_blocks, forcing reanalyze", fn.name)
            try:
                if hasattr(bn_fn, "set_auto_analysis_skipped"):
                    bn_fn.set_auto_analysis_skipped(False)
                bn_fn.reanalyze()
                self._bv.update_analysis_and_wait()
                blocks, edges = self._extract_cfg(bn_fn)
                # ASM token cache keyed by 相同 fn.start, 强制 reanalyze 后失效
                self._asm_tok_cache.pop(fn.start, None)
                if blocks:
                    log.info("cfg_for(%s): reanalyze produced %d BBs", fn.name, len(blocks))
            except Exception as e:
                log.warning("cfg_for(%s) reanalyze failed: %s", fn.name, e)
        return blocks, edges

    def asm_tokens_at(self, pc: int):
        """Return BN ASM tokens for the instruction at `pc`, or None if unknown.
        First query in a fn warms a per-fn dict via cfg_for; subsequent O(1)."""
        fn = self.function_at(pc)
        if fn is None: return None
        cache = self._asm_tok_cache.get(fn.start)
        if cache is None:
            blocks, _edges = self.cfg_for(fn, mode="asm")
            cache = {}
            for bb in blocks:
                for ln in bb.lines:
                    cache[ln.pc_lo] = ln.tokens
            self._asm_tok_cache[fn.start] = cache
        return cache.get(pc)
