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


def try_decode_string(addr: int, mem, t_idx: int = -1,
                      min_len: int = 4, max_len: int = 80) -> str | None:
    """从 memshadow 在 addr 处读 NUL-terminated ASCII. 返回 string 或 None.

    用于 trace 反编译显示 OLLVM 加密 string 解密后的真值 (BN 静态看不到).
    """
    if mem is None or not mem.built:
        return None
    chars: list[str] = []
    for i in range(max_len):
        b, _kind, _src = mem.byte_at(addr + i, t_idx)
        if b is None:
            return None
        if b == 0:
            break
        if not (32 <= b < 127):
            return None
        chars.append(chr(b))
    if len(chars) < min_len:
        return None
    return "".join(chars)


def collect_const_strings(blocks: dict, mem, t_idx: int = -1
                          ) -> dict[int, str]:
    """遍历所有 SsaBlock, 找 LLIL_CONST / LLIL_CONST_PTR, 查 memshadow 解
    string. 返回 dict[addr → string].
    """
    if mem is None or not mem.built:
        return {}
    out: dict[int, str] = {}
    seen_addrs: set[int] = set()
    for blk in blocks.values():
        for root in blk.roots:
            if not isinstance(root, LlilExpr):
                continue
            for n in root.walk():
                if n.op in ("LLIL_CONST", "LLIL_CONST_PTR"):
                    if not n.operands:
                        continue
                    v = n.operands[0]
                    if not isinstance(v, int):
                        continue
                    # 仅查典型 .rodata-ish 范围 (跳过 0/小整数避免 noise)
                    if v < 0x1000 or v in seen_addrs:
                        continue
                    seen_addrs.add(v)
                    s = try_decode_string(v, mem, t_idx)
                    if s is not None:
                        out[v] = s
    return out


def _try_local_var(addr: LlilExpr,
                   loc_names: dict | None) -> str:
    """addr 是 (sp+disp) 或 (fp+disp) → 返回 'var_<hex>' (BN HLIL var_NN 风格).

    loc_names: 共享 dict, 同 (base, disp) 重复使用同名. 第一次看到分配新 idx.
    None → 不重命名, 返回 "".
    """
    if loc_names is None or not isinstance(addr, LlilExpr):
        return ""
    base = ""
    disp = 0
    if addr.op == LLIL_REG and addr.operands[0] in ("sp", "fp"):
        base = addr.operands[0]
        disp = 0
    elif addr.op == "LLIL_ADD" and len(addr.operands) == 2:
        a, b = addr.operands
        if (isinstance(a, LlilExpr) and a.op == LLIL_REG
                and a.operands[0] in ("sp", "fp")
                and isinstance(b, LlilExpr) and b.op == "LLIL_CONST"):
            base = a.operands[0]
            disp = int(b.operands[0])
        elif (isinstance(a, LlilExpr) and a.op == "LLIL_CONST"
                and isinstance(b, LlilExpr) and b.op == LLIL_REG
                and b.operands[0] in ("sp", "fp")):
            base = b.operands[0]
            disp = int(a.operands[0])
    if not base:
        return ""
    # disp 可能负 (fp - 0x8). 用 hex(abs) + 符号
    sign = "" if disp >= 0 else "n"
    name = f"var_{base}_{sign}{abs(disp):x}"
    if (base, disp) not in loc_names:
        loc_names[(base, disp)] = name
    return loc_names[(base, disp)]


def expr_to_c(expr, types: TypeEnv = None,
              shapes: dict[tuple, StructShape] = None,
              tag=None,
              entry_versions: dict[str, int] = None,
              loc_names: dict | None = None,
              var_names: dict | None = None,
              const_strings: dict | None = None) -> str:
    """递归 LlilExpr → C 表达式字符串.

    loc_names: stack location 命名 (sp/fp + offset → var_*).
    var_names: (reg, version) → var name 映射 (来自 pass_var_unify), 替代 reg 名.
    const_strings: dict[addr → string] — memshadow 解出的 string, LLIL_CONST/
                   CONST_PTR 命中 addr 时显示 "string" 替代 0x...
    """
    if not isinstance(expr, LlilExpr):
        if isinstance(expr, int):
            return f"{expr:#x}" if abs(expr) >= 16 else str(expr)
        return str(expr)
    op = expr.op

    # leaf
    if op == LLIL_REG:
        rname = expr.operands[0]
        if var_names and tag is not None:
            v = tag.get(expr) if hasattr(tag, "get") else 0
            if v == 0:
                v = (entry_versions or {}).get(rname, 0)
            if (rname, v) in var_names:
                return var_names[(rname, v)]
        return rname
    if op == LLIL_CONST:
        v = expr.operands[0]
        # 看是否是 string 地址 (memshadow 解出的)
        if const_strings and v in const_strings:
            s = const_strings[v]
            esc = s.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{esc}"'
        return f"{v:#x}" if abs(v) >= 16 else str(v)
    if op == LLIL_CONST_PTR:
        v = expr.operands[0]
        if const_strings and v in const_strings:
            s = const_strings[v]
            esc = s.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{esc}"'
        return f"{v:#x}"
    if op == LLIL_FLAG:
        return f"flag.{expr.operands[0]}"
    if op == LLIL_FLAG_COND:
        return f"flag_cond({expr.operands[0]})"

    # mem ops — 优先 stack local var 命名 (sp/fp+disp); 然后 struct field;
    # 兜底 *(T*)(addr).
    if op == LLIL_LOAD:
        addr = expr.operands[0]
        v = _try_local_var(addr, loc_names)
        if v:
            return v
        f = _try_field(addr, types, shapes, tag, entry_versions)
        if f:
            return f
        return f"*({_size_cast(expr.size)}*)({expr_to_c(addr, types, shapes, tag, entry_versions, loc_names, var_names, const_strings)})"
    if op == LLIL_STORE:
        addr = expr.operands[0]
        val = expr.operands[1]
        rhs = expr_to_c(val, types, shapes, tag, entry_versions, loc_names, var_names, const_strings)
        v = _try_local_var(addr, loc_names)
        if v:
            return f"{v} = {rhs}"
        f = _try_field(addr, types, shapes, tag, entry_versions)
        if f:
            return f"{f} = {rhs}"
        cast = _size_cast(expr.size)
        return f"*({cast}*)({expr_to_c(addr, types, shapes, tag, entry_versions, loc_names, var_names, const_strings)}) = {rhs}"

    # binary arith / bit / cmp
    if op in ARITH_OPS or op in BITWISE_OPS or op in CMP_OPS:
        sym = _OP_SYM.get(op, op)
        if len(expr.operands) == 2:
            l = expr_to_c(expr.operands[0], types, shapes, tag, entry_versions, loc_names, var_names, const_strings)
            r = expr_to_c(expr.operands[1], types, shapes, tag, entry_versions, loc_names, var_names, const_strings)
            return f"({l} {sym} {r})"
        if len(expr.operands) == 1:
            return f"{sym}{expr_to_c(expr.operands[0], types, shapes, tag, entry_versions, loc_names, var_names, const_strings)}"

    if op == LLIL_CALL:
        target = expr_to_c(expr.operands[0], types, shapes, tag, entry_versions, loc_names, var_names, const_strings)
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
                indent: int = 0,
                loc_names: dict | None = None,
                exec_counts: dict | None = None,
                var_names: dict | None = None,
                const_strings: dict | None = None) -> list[str]:
    """递归 stmt → list of lines (markdown 安全, 包含 indent).

    loc_names: 跨整 fn 共享的 dict[(base, disp) → 'var_*']. None 时初始化空 dict.
    exec_counts: dict[block_pc → int] — trace 实测每块执行次数.
    var_names: (reg, version) → var name 映射 (来自 unify_vars). 替代 reg 名.
    """
    pad = "    " * indent
    if loc_names is None:
        loc_names = {}

    if isinstance(stmt, HlilSeq):
        out = []
        for s in stmt.stmts:
            out.extend(render_hlil(s, types, shapes, indent, loc_names, exec_counts, var_names, const_strings))
        return out

    if isinstance(stmt, HlilLoop):
        head = f"{pad}while (true) {{   // header={stmt.header_pc:#x}, iters={stmt.iters}"
        body_lines = render_hlil(stmt.body, types, shapes, indent + 1, loc_names, exec_counts, var_names, const_strings)
        return [head] + body_lines + [f"{pad}}}"]

    if isinstance(stmt, HlilIfElse):
        cond = expr_to_c(stmt.cond, types, shapes,
                         tag=None, entry_versions={},
                         loc_names=loc_names, var_names=var_names,
                         const_strings=const_strings)
        out = [f"{pad}if ({cond}) {{"]
        out.extend(render_hlil(stmt.then_b, types, shapes, indent + 1, loc_names, exec_counts, var_names, const_strings))
        if stmt.else_b is not None:
            out.append(f"{pad}}} else {{")
            out.extend(render_hlil(stmt.else_b, types, shapes, indent + 1, loc_names, exec_counts, var_names, const_strings))
        out.append(f"{pad}}}")
        return out

    if isinstance(stmt, HlilBlock):
        return _render_block(stmt.block, types, shapes, indent,
                              loc_names=loc_names,
                              exec_counts=exec_counts,
                              var_names=var_names,
                              const_strings=const_strings)

    if isinstance(stmt, HlilGoto):
        return [f"{pad}goto {stmt.target_pc:#x};"]

    if isinstance(stmt, HlilRet):
        return [f"{pad}return;"]

    return [f"{pad}/* unknown stmt {type(stmt).__name__} */"]


def _is_prologue_root(root: LlilExpr) -> bool:
    """识别 ARM64 prologue store: STORE([sp+N], xK) 或 SET_REG(sp, sp-N).

    Prologue/epilogue 是 boilerplate, BN HLIL 也隐藏. 折叠成单行注释.
    """
    if not isinstance(root, LlilExpr):
        return False
    # SET_REG(sp, sp ± const)  — 栈分配/释放
    if root.op == LLIL_SET_REG and root.operands[0] == "sp":
        v = root.operands[1]
        if isinstance(v, LlilExpr) and v.op in ("LLIL_ADD", "LLIL_SUB"):
            ops = v.operands
            if (len(ops) == 2 and isinstance(ops[0], LlilExpr)
                    and ops[0].op == "LLIL_REG"
                    and ops[0].operands[0] == "sp"
                    and isinstance(ops[1], LlilExpr)
                    and ops[1].op == "LLIL_CONST"):
                return True
    # SET_REG(fp, sp + const) — 设置 fp
    if root.op == LLIL_SET_REG and root.operands[0] == "fp":
        v = root.operands[1]
        if isinstance(v, LlilExpr) and v.op == "LLIL_ADD":
            ops = v.operands
            if (len(ops) == 2 and isinstance(ops[0], LlilExpr)
                    and ops[0].op == "LLIL_REG"
                    and ops[0].operands[0] == "sp"
                    and isinstance(ops[1], LlilExpr)
                    and ops[1].op == "LLIL_CONST"):
                return True
    # STORE([sp+N], xK) 其中 xK 是 callee-saved (x19-x30, fp, lr, x29)
    if root.op == LLIL_STORE and len(root.operands) == 2:
        addr, val = root.operands
        if not isinstance(val, LlilExpr) or val.op != "LLIL_REG":
            return False
        rname = val.operands[0]
        if rname not in (
            "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
            "x27", "x28", "x29", "x30", "fp", "lr",
        ):
            return False
        # addr 是 sp 或 sp + const
        if isinstance(addr, LlilExpr):
            if addr.op == "LLIL_REG" and addr.operands[0] == "sp":
                return True
            if addr.op == "LLIL_ADD":
                ops = addr.operands
                if (len(ops) == 2 and isinstance(ops[0], LlilExpr)
                        and ops[0].op == "LLIL_REG"
                        and ops[0].operands[0] == "sp"
                        and isinstance(ops[1], LlilExpr)
                        and ops[1].op == "LLIL_CONST"):
                    return True
    return False


def _render_block(blk: SsaBlock, types: TypeEnv,
                  shapes: dict[tuple, StructShape],
                  indent: int,
                  collapse_prologue: bool = True,
                  loc_names: dict | None = None,
                  exec_counts: dict | None = None,
                  var_names: dict | None = None,
                  const_strings: dict | None = None) -> list[str]:
    pad = "    " * indent
    head = f"// block @ {blk.block_pc:#x}"
    if exec_counts and blk.block_pc in exec_counts:
        head += f"  ×{exec_counts[blk.block_pc]}"
    out: list[str] = [f"{pad}{head}"]

    # 检测 prologue / epilogue 区段 — 连续 N 条 prologue-style root, 折叠成
    # 单行注释 (BN HLIL 类似行为).
    roots = list(blk.roots)
    if collapse_prologue:
        # 前缀: 连续 prologue stores
        prefix_n = 0
        for r in roots:
            if _is_prologue_root(r):
                prefix_n += 1
            else:
                break
        # 后缀: 反向找连续 prologue (epilogue)
        suffix_n = 0
        for r in reversed(roots):
            if _is_prologue_root(r):
                suffix_n += 1
            else:
                break
        # 至少 3 条才折叠 (避免单 stp 被误隐藏)
        if prefix_n >= 3:
            out.append(f"{pad}// prologue: save callee-saved + alloc stack ({prefix_n} ops)")
            roots = roots[prefix_n:]
        # 后缀只在 prefix 没全吃完时折叠
        if suffix_n >= 3 and len(roots) > 0:
            epilogue = roots[-suffix_n:]
            roots = roots[:-suffix_n]
        else:
            epilogue = []
    else:
        epilogue = []

    # 维护 cur_versions (block 内 reg 当前 SSA version), 在 LLIL_CALL 处
    # dump x0..x7 当前 version 用作 args (ARM64 ABI: args 在 x0..x7).
    cur_versions = dict(blk.entry_versions)
    for root in roots:
        if not isinstance(root, LlilExpr):
            continue
        line = _root_to_c(root, types, shapes, blk,
                          loc_names=loc_names, var_names=var_names,
                          cur_versions=cur_versions,
                          const_strings=const_strings)
        # 更新 cur_versions
        if root.op == LLIL_SET_REG:
            rname = root.operands[0]
            cur_versions[rname] = blk.tag.get(root)
        elif root.op == LLIL_CALL:
            # 跟 SSA call-kill 一致 — caller-saved version 同步 bump,
            # 这样 call 后的 reg 引用拿到正确的 (post-call) version.
            for r in ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                      "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                      "x16", "x17", "x18", "lr"):
                cur_versions[r] = cur_versions.get(r, 0) + 1
        if line:
            out.append(f"{pad}{line};")
    if epilogue:
        out.append(f"{pad}// epilogue: restore callee-saved ({len(epilogue)} ops)")
    return out


def _root_to_c(root: LlilExpr,
               types: TypeEnv,
               shapes: dict[tuple, StructShape],
               blk: SsaBlock,
               loc_names: dict | None = None,
               var_names: dict | None = None,
               cur_versions: dict | None = None,
               const_strings: dict | None = None) -> str:
    """root expr → C statement (no semicolon, 调用方加).

    cur_versions: 当前 SSA reg → version dict (block 内动态维护, 调用方更新).
                  LLIL_CALL 时 dump x0..x7 作 args (ARM64 ABI).
    """
    op = root.op
    if op == LLIL_SET_REG:
        rname = root.operands[0]
        val = root.operands[1]
        rhs = expr_to_c(val, types, shapes, tag=blk.tag,
                        entry_versions=blk.entry_versions,
                        loc_names=loc_names, var_names=var_names, const_strings=const_strings)
        # dst 也用 var_name
        dst_name = rname
        if var_names is not None:
            dv = blk.tag.get(root)
            if (rname, dv) in var_names:
                dst_name = var_names[(rname, dv)]
        return f"{dst_name} = {rhs}"
    if op == LLIL_STORE:
        return expr_to_c(root, types, shapes, tag=blk.tag,
                         entry_versions=blk.entry_versions,
                         loc_names=loc_names, var_names=var_names, const_strings=const_strings)
    if op == LLIL_SET_FLAG:
        fname = root.operands[0]
        rhs = expr_to_c(root.operands[1], types, shapes, tag=blk.tag,
                        entry_versions=blk.entry_versions,
                        loc_names=loc_names, var_names=var_names, const_strings=const_strings)
        return f"flag.{fname} = {rhs}"
    if op == LLIL_GOTO:
        return f"goto {root.operands[0]:#x}"
    if op == LLIL_IF:
        cond = expr_to_c(root.operands[0], types, shapes, tag=blk.tag,
                         entry_versions=blk.entry_versions,
                         loc_names=loc_names, var_names=var_names, const_strings=const_strings)
        return f"if ({cond}) goto {root.operands[1]:#x} else goto {root.operands[2]:#x}"
    if op == LLIL_CALL:
        target = expr_to_c(root.operands[0], types, shapes, tag=blk.tag,
                           entry_versions=blk.entry_versions,
                           loc_names=loc_names, var_names=var_names, const_strings=const_strings)
        # 检测 args: x0..x7 当前 version 在 var_names 里查名字
        args_str = ""
        if cur_versions is not None and var_names is not None:
            argv: list[str] = []
            for i, rname in enumerate(("x0", "x1", "x2", "x3",
                                        "x4", "x5", "x6", "x7")):
                v = cur_versions.get(rname, 0)
                name = var_names.get((rname, v), rname)
                # 跳过 callee-saved 默认 (它们不是 args, 但 x0-x7 都是
                # potential args). MVP 显示前 4 个 (主流 fn 大多 ≤4 args).
                argv.append(name)
                if i >= 3:
                    break
            args_str = ", ".join(argv)
        return f"call({target}, {args_str})" if args_str else f"call({target})"
    if op == LLIL_RET:
        # ARM64 AAPCS64: 返回值在 x0 (大值用 x0+x1 pair). 渲染 BN 风格
        # `return x0_vN` (cur_versions 已知). 没 var_names dict 时回退 'return'.
        if cur_versions is not None and var_names is not None:
            v = cur_versions.get("x0", 0)
            if (("x0", v) in var_names):
                return f"return {var_names[('x0', v)]}"
            # fallback: 显示原 reg + version
            return f"return x0_v{v}" if v > 0 else "return x0"
        return "return"
    if op == LLIL_JUMP:
        target = expr_to_c(root.operands[0], types, shapes, tag=blk.tag,
                           entry_versions=blk.entry_versions,
                           loc_names=loc_names, var_names=var_names, const_strings=const_strings)
        return f"goto *{target}  // indirect"
    if op == LLIL_NOP:
        return ""
    if op == LLIL_INTRINSIC:
        m = root.extra.get("mnem", "?")
        ostr = root.extra.get("op_str", "")
        return f"intrinsic({m}, '{ostr}')"
    return f"/* {op} */"
