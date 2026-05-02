"""Pass 8: HLIL tree → C-like markdown render.

把 pass 7 的 HlilStmt tree 输出成可读 C 风格代码. 这是机器算法的最终
输出, 不调 LLM. 跟 BN HLIL view 类似.

§7.0:
  ✓ 渲染算法跟 ABI/SDK 解耦
  ✓ 不识别的 HlilGoto / HlilBlock 直接输出原 LLIL roots
  ✓ 不假装识别 (LLIL_INTRINSIC 出 'intrinsic(svc, #0)')
"""
from __future__ import annotations
from .expr import (
    LlilExpr,
    LLIL_REG, LLIL_CONST, LLIL_CONST_PTR, LLIL_FLAG, LLIL_FLAG_COND,
    LLIL_LOAD, LLIL_STORE, LLIL_SET_REG, LLIL_SET_FLAG,
    LLIL_ADD, LLIL_SUB, LLIL_MUL, LLIL_NEG,
    LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_NOT,
    LLIL_LSL, LLIL_LSR, LLIL_ASR,
    LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT, LLIL_CMP_SLE,
    LLIL_CMP_SGE, LLIL_CMP_SGT, LLIL_CMP_ULT, LLIL_CMP_ULE,
    LLIL_CMP_UGE, LLIL_CMP_UGT,
    LLIL_GOTO, LLIL_JUMP, LLIL_IF,
    LLIL_CALL, LLIL_RET, LLIL_NOP,
    LLIL_INTRINSIC, ARITH_OPS, BITWISE_OPS, CMP_OPS,
)
from .ssa import SsaBlock
from .pass_restructure import (
    HlilSeq, HlilLoop, HlilIfElse, HlilBlock, HlilGoto, HlilRet,
)
from .pass_typelat import TypeEnv
from .pass_struct import StructShape


# 操作符号表 (BN-like)
_OP_SYM = {
    LLIL_ADD: "+", LLIL_SUB: "-", LLIL_MUL: "*",
    LLIL_AND: "&", LLIL_OR: "|", LLIL_XOR: "^",
    LLIL_LSL: "<<", LLIL_LSR: ">>", LLIL_ASR: ">>",
    LLIL_NEG: "-", LLIL_NOT: "~",
    LLIL_CMP_E: "==", LLIL_CMP_NE: "!=",
    LLIL_CMP_SLT: "<", LLIL_CMP_SLE: "<=",
    LLIL_CMP_SGE: ">=", LLIL_CMP_SGT: ">",
    LLIL_CMP_ULT: "<", LLIL_CMP_ULE: "<=",
    LLIL_CMP_UGE: ">=", LLIL_CMP_UGT: ">",
}


def expr_to_c(expr, types: TypeEnv = None,
              shapes: dict[tuple, StructShape] = None,
              tag=None,
              entry_versions: dict[str, int] = None) -> str:
    """递归 LlilExpr → C 表达式字符串."""
    if not isinstance(expr, LlilExpr):
        if isinstance(expr, int):
            return f"{expr:#x}" if abs(expr) >= 16 else str(expr)
        return str(expr)
    op = expr.op

    # leaf
    if op == LLIL_REG:
        return expr.operands[0]
    if op == LLIL_CONST:
        v = expr.operands[0]
        return f"{v:#x}" if abs(v) >= 16 else str(v)
    if op == LLIL_CONST_PTR:
        return f"{expr.operands[0]:#x}"
    if op == LLIL_FLAG:
        return f"flag.{expr.operands[0]}"
    if op == LLIL_FLAG_COND:
        return f"flag_cond({expr.operands[0]})"

    # mem ops — try field rewrite if struct shape known
    if op == LLIL_LOAD:
        addr = expr.operands[0]
        f = _try_field(addr, types, shapes, tag, entry_versions)
        if f:
            return f
        return f"*({_size_cast(expr.size)}*)({expr_to_c(addr, types, shapes, tag, entry_versions)})"
    if op == LLIL_STORE:
        addr = expr.operands[0]
        val = expr.operands[1]
        f = _try_field(addr, types, shapes, tag, entry_versions)
        rhs = expr_to_c(val, types, shapes, tag, entry_versions)
        if f:
            return f"{f} = {rhs}"
        cast = _size_cast(expr.size)
        return f"*({cast}*)({expr_to_c(addr, types, shapes, tag, entry_versions)}) = {rhs}"

    # binary arith / bit / cmp
    if op in ARITH_OPS or op in BITWISE_OPS or op in CMP_OPS:
        sym = _OP_SYM.get(op, op)
        if len(expr.operands) == 2:
            l = expr_to_c(expr.operands[0], types, shapes, tag, entry_versions)
            r = expr_to_c(expr.operands[1], types, shapes, tag, entry_versions)
            return f"({l} {sym} {r})"
        if len(expr.operands) == 1:
            return f"{sym}{expr_to_c(expr.operands[0], types, shapes, tag, entry_versions)}"

    if op == LLIL_CALL:
        target = expr_to_c(expr.operands[0], types, shapes, tag, entry_versions)
        return f"call({target})"

    if op == LLIL_INTRINSIC:
        m = expr.extra.get("mnem", "?")
        ostr = expr.extra.get("op_str", "")
        return f"intrinsic({m}, '{ostr}')"

    return f"<{op}>"


def _try_field(addr: LlilExpr,
               types: TypeEnv,
               shapes: dict[tuple, StructShape],
               tag,
               entry_versions: dict[str, int]) -> str:
    """addr expr 若是 (PTR-typed reg + offset) 且 struct shape 已知 → 'reg->fN'."""
    if not (types and shapes and tag):
        return ""
    from .pass_struct import _extract_base_disp
    br = _extract_base_disp(addr, tag, entry_versions or {})
    if br is None:
        return ""
    base, version, disp = br
    sh = shapes.get((base, version))
    if not sh:
        return ""
    fa = sh.fields.get(disp)
    if not fa:
        return ""
    return f"{base}->f{disp:#x}"


def _size_cast(size: int) -> str:
    if size == 1: return "uint8_t"
    if size == 2: return "uint16_t"
    if size == 4: return "uint32_t"
    if size == 8: return "uint64_t"
    return "uint64_t"


# ─────────── HLIL stmt → markdown ───────────

def render_hlil(stmt, types: TypeEnv = None,
                shapes: dict[tuple, StructShape] = None,
                indent: int = 0) -> list[str]:
    """递归 stmt → list of lines (markdown 安全, 包含 indent)."""
    pad = "    " * indent

    if isinstance(stmt, HlilSeq):
        out = []
        for s in stmt.stmts:
            out.extend(render_hlil(s, types, shapes, indent))
        return out

    if isinstance(stmt, HlilLoop):
        head = f"{pad}while (true) {{   // header={stmt.header_pc:#x}, iters={stmt.iters}"
        body_lines = render_hlil(stmt.body, types, shapes, indent + 1)
        return [head] + body_lines + [f"{pad}}}"]

    if isinstance(stmt, HlilIfElse):
        cond = expr_to_c(stmt.cond, types, shapes,
                         tag=None, entry_versions={})
        out = [f"{pad}if ({cond}) {{"]
        out.extend(render_hlil(stmt.then_b, types, shapes, indent + 1))
        if stmt.else_b is not None:
            out.append(f"{pad}}} else {{")
            out.extend(render_hlil(stmt.else_b, types, shapes, indent + 1))
        out.append(f"{pad}}}")
        return out

    if isinstance(stmt, HlilBlock):
        return _render_block(stmt.block, types, shapes, indent)

    if isinstance(stmt, HlilGoto):
        return [f"{pad}goto {stmt.target_pc:#x};"]

    if isinstance(stmt, HlilRet):
        return [f"{pad}return;"]

    return [f"{pad}/* unknown stmt {type(stmt).__name__} */"]


def _render_block(blk: SsaBlock, types: TypeEnv,
                  shapes: dict[tuple, StructShape],
                  indent: int) -> list[str]:
    pad = "    " * indent
    out: list[str] = [f"{pad}// block @ {blk.block_pc:#x}"]
    for root in blk.roots:
        if not isinstance(root, LlilExpr):
            continue
        line = _root_to_c(root, types, shapes, blk)
        if line:
            out.append(f"{pad}{line};")
    return out


def _root_to_c(root: LlilExpr,
               types: TypeEnv,
               shapes: dict[tuple, StructShape],
               blk: SsaBlock) -> str:
    """root expr → C statement (no semicolon, 调用方加)."""
    op = root.op
    if op == LLIL_SET_REG:
        rname = root.operands[0]
        val = root.operands[1]
        rhs = expr_to_c(val, types, shapes, tag=blk.tag,
                        entry_versions=blk.entry_versions)
        return f"{rname} = {rhs}"
    if op == LLIL_STORE:
        return expr_to_c(root, types, shapes, tag=blk.tag,
                         entry_versions=blk.entry_versions)
    if op == LLIL_SET_FLAG:
        fname = root.operands[0]
        rhs = expr_to_c(root.operands[1], types, shapes, tag=blk.tag,
                        entry_versions=blk.entry_versions)
        return f"flag.{fname} = {rhs}"
    if op == LLIL_GOTO:
        return f"goto {root.operands[0]:#x}"
    if op == LLIL_IF:
        # 通常 IF 在 restructure 阶段被吃掉, 残留 case 输出原始
        cond = expr_to_c(root.operands[0], types, shapes, tag=blk.tag,
                         entry_versions=blk.entry_versions)
        return f"if ({cond}) goto {root.operands[1]:#x} else goto {root.operands[2]:#x}"
    if op == LLIL_CALL:
        return expr_to_c(root, types, shapes, tag=blk.tag,
                         entry_versions=blk.entry_versions)
    if op == LLIL_RET:
        return "return"
    if op == LLIL_JUMP:
        target = expr_to_c(root.operands[0], types, shapes, tag=blk.tag,
                           entry_versions=blk.entry_versions)
        return f"goto *{target}  // indirect"
    if op == LLIL_NOP:
        return ""
    if op == LLIL_INTRINSIC:
        m = root.extra.get("mnem", "?")
        ostr = root.extra.get("op_str", "")
        return f"intrinsic({m}, '{ostr}')"
    return f"/* {op} */"
