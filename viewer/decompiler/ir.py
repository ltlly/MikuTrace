"""TraceIR — LLM-friendly skeleton 中间表示 (路线 B).

设计: docs/trace-decompiler-design.md §3.

核心思想: 静态骨架 (static block / fn structure, BN 给) + 动态计数注解
(执行次数 / 分支 taken-count / 寄存器样本) — 不 per-record 实例化.

层级:
    TopIR
    └─ FuncIR[]
       ├─ BlockIR[]
       ├─ LoopIR[]
       └─ CallIR[]

ID 稳定: F0/F1/... B0/B1/... L0/L1/...
LLM 反复引用同一 ID 可定位回 IR (markdown 锚点 + tool-use 检索).

MVP 范围 (本文件): 数据载体, 不做分析. 分析在 builder.py.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BlockIR:
    """One basic block. PC 是绝对运行时地址 (跟 trace 一致)."""
    id: str                              # 'B0', 'B1', ...
    pc: int                              # block start absolute PC
    end_pc: int                          # 末尾分支指令的 PC (含)
    insns: int                           # 指令条数
    exec_count: int                      # 该静态块在本 fn 内执行次数
    exits: list["EdgeIR"] = field(default_factory=list)
    # 首次执行时的关键 reg 快照. MVP 只放入参 x0..x3 + sp; 完整 sample 待 stage 2.
    samples: dict[str, int] = field(default_factory=dict)
    # asm 文本 (只首次完整, ref-block 不重复). MVP: 第一次出现该 PC 的 asm 多行.
    asm: str = ""
    # 若是 ref-block (重复块去重时用), 指向首次出现的 block id.
    ref: Optional[str] = None
    # P2-DEC3-A: 热度分级.
    # 'hot'  — top-K exec_count, 必含完整 asm
    # 'warm' — exec_count > 0 但非 top-K, 渲染 stub (PC + count + exits, 无 asm)
    # 'cold' — exec_count == 0 (静态可达但 trace 没走). MVP 永不出现 (cfg 只
    #          收 trace 命中过的 block); 留字段给未来 BN prior 注入静态块用.
    tier: str = "hot"


@dataclass
class EdgeIR:
    """One CFG edge."""
    dst: str                             # 目标 block id (可能跨 fn → 'F1.B0')
    kind: str                            # cond | uncond | call | call-return | indirect | fallthrough | ret
    taken_count: int = 0                 # 走过几次
    not_taken_count: int = 0             # 仅 cond 边记意义 (反向计数, 信息有用 — 0 = 永远走这边)


@dataclass
class LoopIR:
    """One loop (SCC of size>1 或 size=1 自环)."""
    id: str                              # 'L0', ...
    header: str                          # block id (loop header)
    body: list[str]                      # block id list
    iters: int                           # 实测迭代次数
    induction_var: Optional[dict] = None # {reg, init, delta, exit_cond} — stage 2 才填


@dataclass
class CallIR:
    """One bl/blr call event observed in trace."""
    idx: int                             # trace record idx
    src_block: str                       # 哪个 block 发起的
    callee_pc: int                       # 实际跳到的 PC
    callee_fn: Optional[str] = None      # 'F1' 若解析到, 否则 None
    callee_name: str = ""                # symbol 名 (BN/symbols.py)
    ret_idx: Optional[int] = None        # 配对的 ret idx, 没找到 = None
    ret_val_x0: Optional[int] = None     # ret 时 x0 (按 ARM64 ABI)


@dataclass
class FuncIR:
    """One function. MVP: 用 calltree 划分, 没 BN 时 name='?'."""
    id: str                              # 'F0', ...
    name: str                            # symbol 名, 没 BN 时 sub_<hex>
    pc_start: int                        # fn 入口 PC
    pc_end: int                          # 末尾 PC (max block end pc, 估值)
    entry_idx: int                       # trace idx 入
    exit_idx: int                        # trace idx 出 (含)
    truncated: bool = False              # 末尾是否截断 (无 ret)
    last_insn_is_ret: bool = False
    blocks: list[BlockIR] = field(default_factory=list)
    loops: list[LoopIR] = field(default_factory=list)
    calls: list[CallIR] = field(default_factory=list)
    # BN/Ghidra 静态 prior. MVP 留 None, stage 2 填.
    # 形如: {'signature': '...', 'hlil_excerpt': '...', 'inferred_types': {...}}
    static: Optional[dict] = None
    # 执行次数 (一个 fn 在 trace 里被调几次). 顶层 fn 通常 1, 子 fn 可能 >1.
    exec_count: int = 1


@dataclass
class TopIR:
    """Trace 顶层 IR — summary 级."""
    records: int                         # trace 总指令数
    truncated: bool                      # trace 末尾是否截断
    last_insn_is_ret: bool
    module_name: str = ""                # 主目标 SO
    module_base: int = 0
    module_size: int = 0
    cmd: Optional[int] = None            # 业务命令 (如 sgmain cmdId)
    method: str = ""
    fns: list[FuncIR] = field(default_factory=list)
    # 工具版本 / 生成时间, 给 LLM 看上下文.
    tracemiku_version: str = ""
    generated_at: str = ""               # ISO timestamp

    def fn(self, fn_id: str) -> Optional[FuncIR]:
        for f in self.fns:
            if f.id == fn_id: return f
        return None

    def summary(self) -> str:
        """一行一 fn 的简明 ASCII summary, 给 CLI / debug 用."""
        out = [f"trace: {self.records} records, module={self.module_name}"]
        for f in self.fns:
            out.append(f"  {f.id} {f.name:<24} blocks={len(f.blocks):<4} "
                       f"loops={len(f.loops):<3} calls={len(f.calls):<3} "
                       f"idx=[{f.entry_idx},{f.exit_idx}]")
        return "\n".join(out)
