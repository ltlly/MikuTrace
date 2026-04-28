"""Decompiler backend abstraction.

trace 里只有 PC + 寄存器 + raw inst。要把"运行时真值"叠到"静态语义"上,
需要一个反编译器后端提供:
  - 函数级 HLIL 伪代码 (pc -> source line)
  - struct 字段语义 (pc 处某 reg+offset 解读为 struct.field)
  - 静态 xref (trace 没走过的死路径)
  - 函数变量类型 (寄存器 -> 'JNIEnv*' / 'cmdId')

所有 backend 都是 in-process long-lived (启动时一次分析, 之后纯查询):
  - BN: import binaryninja -> BinaryView 常驻 (实际跑通)
  - Ghidra: pyghidra.start() -> JVM + Program 常驻 (stub, 占位)

调用者拿到 backend 实例后, 反复调用 function_at / hlil_for / ... 都是 ~ms 级.
冷启动 (open) 慢, 热路径快, 这是项目设计目标.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Optional


@dataclass
class Function:
    """A decompiler-resolved function. backend-agnostic."""
    start: int                      # absolute PC of fn entry
    end: int                        # exclusive
    name: str
    backend: str = ""               # 'binja' | 'ghidra' | 'none'
    raw: object = None              # backend-specific handle (for follow-up calls)


@dataclass
class Token:
    """A syntax-highlighted token. cls is a stable string identifier mapped to
    CSS class on the frontend (e.g. 'key', 'reg', 'var', 'num', 'str', 'fn',
    'data', 'cmt', 'op', 'brace', 'indent', 'mnem', 'field', 'txt')."""
    text: str
    cls: str
    addr: int = 0       # token's target address (for fn/data/code-symbol tokens), 0 if N/A


@dataclass
class HlilLine:
    """One line of pseudocode mapped back to a PC range.
    pc_lo == pc_hi means single instruction; otherwise spans a stmt.

    `text` is the joined plain text (fallback / search). `tokens` is the
    syntax-highlighted token stream (each with a CSS class)."""
    text: str
    pc_lo: int
    pc_hi: int
    indent: int = 0
    tokens: list[Token] = field(default_factory=list)


@dataclass
class CfgBlock:
    """One basic block in a function's CFG.

    `lines` is per-instruction text (ASM mode) or per-stmt text (HLIL mode), each
    with its own pc + tokens. The frontend renders block contents from these.
    """
    start: int           # absolute PC (caller's coordinate system)
    end: int             # exclusive
    lines: list[HlilLine] = field(default_factory=list)
    exec_count: int = 0  # filled by server (joined with trace)


@dataclass
class CfgEdge:
    src: int             # block start PC
    dst: int             # block start PC
    kind: str            # 'true' | 'false' | 'uncond' | 'indirect' | 'call' | 'fallthrough'
    seen_in_trace: bool = False   # filled by server


@dataclass
class FieldHint:
    """For memshadow overlay: at (base_reg, offset) we know it's struct.field.

    Example: trace shows 'ldr x9, [x8, 0x80]' at pc=0x...
             FieldHint(struct='pthread_mutex_t', field='__lock', offset=0x80)
    """
    struct: str
    field: str
    offset: int
    type_name: str = ""             # e.g. 'int32_t', 'JavaVM*'


@dataclass
class VarType:
    """A function variable / parameter with its inferred type."""
    name: str                       # 'cmdId', 'env', 'arg1' ...
    type_name: str                  # 'jint', 'JNIEnv*', 'int' ...
    storage: str = ""               # 'x0', 'x1', '[sp+0x10]' (where this var lives)


class DecompilerBackend(Protocol):
    """Protocol every backend implements. Methods MUST be cheap after open().

    Lifecycle:
      open(so_path, base) -> long blocking call (analysis), only once
      close()             -> release resources

    Hot-path queries (must be < 50ms after warmup, OK to fail-fast on cache miss):
      function_at(pc)
      hlil_for(fn)        -> list of HlilLine, fully covers the function
      vars_for(fn)        -> list of VarType
      field_at(pc, reg, offset) -> FieldHint | None
      xrefs_to(addr)      -> list[int]
    """
    name: str                       # backend identifier

    def is_available(self) -> bool:
        """True if this backend's deps are importable on this machine."""
        ...

    def open(self, so_path: str, base: int = 0) -> None:
        """Load + analyze. Slow (seconds-minutes). Called once.

        base semantics:
          base == 0        → 调用方将以 'SO 内部偏移' 调 function_at(0x57770).
                             backend 自动加上 BV 自己的 ELF preferred base.
          base != 0        → 调用方将以 '绝对运行时 PC' 调 function_at(0x6d52ed1770).
                             backend 用 (pc - base + bv.start) 做 rebase.
        """
        ...

    def close(self) -> None: ...

    def loaded_base(self) -> int:
        """The address inside this backend at which the SO is loaded.
        Useful for callers that want to convert offset <-> bv-absolute."""
        ...

    def function_at(self, pc: int) -> Optional[Function]: ...

    def hlil_for(self, fn: Function) -> list[HlilLine]: ...

    def vars_for(self, fn: Function) -> list[VarType]: ...

    def field_at(self, pc: int, reg: str, offset: int) -> Optional[FieldHint]: ...

    def xrefs_to(self, addr: int) -> list[int]: ...

    def cfg_for(self, fn: Function, mode: str = "asm") -> tuple[list["CfgBlock"], list["CfgEdge"]]:
        """Per-function CFG with tokenized line content.
        mode == 'asm'   → BB lines are individual instructions (token stream from BN ASM)
        mode == 'hlil'  → BB lines are HLIL stmts (token stream from BN HLIL)
        Returns (blocks, edges). blocks/edges use caller-coordinate PCs."""
        ...

    def asm_tokens_at(self, pc: int) -> Optional[list[Token]]:
        """Return tokenized ASM for the instruction at `pc`, or None if unknown.
        Backend should cache per-fn (cfg_for-grade lookup) so per-PC queries are O(1).
        Used by viewer to pull BN syntax-highlighted disasm into the trace stream
        without a per-PC subprocess hop."""
        ...
