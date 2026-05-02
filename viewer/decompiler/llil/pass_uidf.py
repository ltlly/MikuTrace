"""Pass 1.5 (insert between lift & SSA): UIDF — User-Informed DataFlow.

BN 的 UIDF (https://docs.binary.ninja/dev/uidf.html) 让用户提供 reg 在某
addr 处的真值, 注入 dataflow 引擎. 在我们 trace 反编译器里, **trace 自己
就是 user** — 每个静态 PC 在 trace 中实际命中的 reg 真值就是最强 UIDF.

§7.0:
  ✓ 来源 = trace 实测, 不假设 SDK / VM / 变种
  ✓ 处理 ObservedValues (single / range / many / unknown), 不强行
  ✓ 不识别的 op 不出 ObservedValues, 不假装

入口:
  collect_uidf(trace, ssa_blocks) → dict[(block_pc, root_idx) → ObservedValues]

后续 pass (constfold / typelat) 接受可选 uidf 参数, 优先用 trace 真值.

数据结构跟 BN's PossibleValueSet 类似:
  ObservedValues:
    n_hits        — 该静态 PC 在 trace 命中次数
    distinct_count — 不同值的数量
    first / last  — 第一次/最后一次实测值
    sample        — 前 K 个唯一值 (K=8, 给 LLM/人看)
    is_const()    — distinct_count == 1
    is_range()    — distinct > 1 但全部连续 (induction var 候选)

性能:
  对 fn 内每个 SET_REG root, walk trace 一次找命中位置抓 dst reg 值.
  numpy bitmask 加速 — 15M trace 单 fn 用 SET_REG 数 ~几千, 总耗时 < 1s.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import numpy as np
from .expr import LlilExpr, LLIL_SET_REG, LLIL_SET_FLAG, LLIL_CALL
from .ssa import SsaBlock


@dataclass
class ObservedValues:
    """A SSA def 的 trace 实测值集合."""
    pc: int                  # 写该 reg 的 ARM64 PC
    reg: str                 # dst reg name
    n_hits: int = 0
    distinct_count: int = 0
    first: Optional[int] = None
    last: Optional[int] = None
    sample: list = field(default_factory=list)   # 前 8 个唯一值

    def is_const(self) -> bool:
        return self.distinct_count == 1

    def const_value(self) -> Optional[int]:
        """if is_const() → 该唯一值, else None."""
        return self.first if self.is_const() else None

    def short(self) -> str:
        if self.is_const():
            return f"{self.reg}={self.first:#x} (×{self.n_hits})"
        s = ",".join(f"{v:#x}" for v in self.sample[:3])
        more = "+" if self.distinct_count > 3 else ""
        return f"{self.reg}∈{{{s}{more}}} (n={self.n_hits} d={self.distinct_count})"


def _collect_for_pc(trace, pc: int, reg_idx_or_special) -> tuple[int, list]:
    """走 trace 找所有 PC 命中, 取 dst reg 值. 返回 (n_hits, values list).

    reg_idx_or_special: int 索引 (x0..x30 = 0..30) or 'sp' / 'pc'.
    """
    pc_arr = trace.pc_array()
    mask = pc_arr == np.uint64(pc)
    if not mask.any():
        return (0, [])
    idxs = np.nonzero(mask)[0]
    n = len(idxs)
    # 最多取 5000 个 hit (统计够), 多余跳采样
    if n > 5000:
        step = n // 5000
        idxs = idxs[::step]
    vals: list = []
    if isinstance(reg_idx_or_special, str):
        for i in idxs:
            r = trace.record(int(i))
            v = r.reg(reg_idx_or_special)
            vals.append(int(v))
    else:
        # numpy 直接读 reg column. 但 record format 复杂, fallback 用 record.reg
        for i in idxs:
            r = trace.record(int(i))
            vals.append(int(r.regs[reg_idx_or_special]))
    return (n, vals)


def _norm_reg_to_query(reg: str):
    """ARM64 reg name → trace.record.reg() 接受的 key.
    x0..x28 → idx 0..28; fp/x29 → 29; lr/x30 → 30; sp → 'sp'."""
    if reg == "sp": return "sp"
    if reg in ("fp", "x29"): return 29
    if reg in ("lr", "x30"): return 30
    if reg.startswith("x") and reg[1:].isdigit():
        n = int(reg[1:])
        if 0 <= n <= 30:
            return n
    if reg.startswith("w") and reg[1:].isdigit():
        # w0..w30 共享 x0..x30 (低 32 位)
        n = int(reg[1:])
        if 0 <= n <= 30:
            return n
    return None


def collect_uidf(trace,
                 ssa_blocks: dict[int, SsaBlock],
                 max_blocks: int = 1000,
                 max_roots_per_block: int = 100,
                 ) -> dict[tuple, ObservedValues]:
    """走 trace 给每个 LLIL_SET_REG root 收 ObservedValues.

    Returns dict[(block_pc, root_idx) → ObservedValues].

    限制 max_blocks / max_roots_per_block 防极大 fn 上爆 (超出 fn 走默认行为).
    """
    out: dict[tuple, ObservedValues] = {}
    n_total = len(trace)
    if n_total == 0:
        return out
    block_count = 0
    for block_pc, blk in ssa_blocks.items():
        if block_count >= max_blocks:
            break
        block_count += 1
        for root_idx, root in enumerate(blk.roots):
            if root_idx >= max_roots_per_block:
                break
            if not isinstance(root, LlilExpr):
                continue
            if root.op == LLIL_SET_REG:
                reg_name = root.operands[0]
                _record_uidf_for_reg(trace, out, block_pc, root_idx,
                                     root.pc, reg_name)
            elif root.op == LLIL_CALL:
                # AAPCS64 return value 在 x0 (大值 x0+x1). trace 在 call 命中
                # 的下一条 record (== 被叫 fn 的入口 OR ret 后) 通常不直接是
                # caller PC + 4. 但如果 fn 完整返回 + 没插指令, record(idx_of_call+1)
                # 之后某点的 x0 就是 return. MVP: 用 next_pc=call.pc+4 PC 命中
                # 抓 x0 — 这是 return 后第一条 caller insn 的 record 值.
                _record_uidf_for_reg(trace, out, block_pc, root_idx,
                                     root.pc + 4, "x0", reg_alias="ret_x0")
    return out


def _record_uidf_for_reg(trace, out: dict, block_pc: int, root_idx: int,
                         pc: int, reg_name: str,
                         reg_alias: str | None = None,
                         use_same_idx: bool | None = None) -> None:
    """跑一次 ObservedValues 收集, 写入 out[(block_pc, root_idx)].

    pc: 静态 PC 用于 trace 命中匹配 (SET_REG 用 root.pc; CALL 用 root.pc+4
        — 即 call 后第一条 record 处 x0 = return value)
    reg_alias: 别名 (e.g. 'ret_x0' for call return), 用于 reg 字段标记来源.
    use_same_idx: None (auto: alias 含 'ret_' → True, 否则 False).
    """
    query = _norm_reg_to_query(reg_name)
    if query is None:
        return
    if use_same_idx is None:
        use_same_idx = bool(reg_alias and reg_alias.startswith("ret_"))
    n_hits, vals = _NextIdxRegQuery(trace, pc, query).run(use_same_idx=use_same_idx)
    if n_hits == 0:
        return
    mask = (1 << 64) - 1
    vals_masked = [v & mask for v in vals]
    unique = list(dict.fromkeys(vals_masked))
    ov = ObservedValues(
        pc=pc, reg=(reg_alias or reg_name),
        n_hits=n_hits,
        distinct_count=len(unique),
        first=vals_masked[0] if vals_masked else None,
        last=vals_masked[-1] if vals_masked else None,
        sample=unique[:8],
    )
    out[(block_pc, root_idx)] = ov


class _NextIdxRegQuery:
    """轻量 helper: 给 PC, 找所有命中 + 拿 i+1 的 reg 值 (= 写后值)."""

    def __init__(self, trace, pc: int, reg_query):
        self.t = trace
        self.pc = pc
        self.q = reg_query

    def run(self, use_same_idx: bool = False) -> tuple[int, list]:
        """use_same_idx=False (default): 取 record(i+1) — 即 PC 命中后的下条
        record, reg 是 SET_REG 写后值.
        use_same_idx=True: 取 record(i) — 即 PC 命中处, reg 是该指令执行 *前*
        的状态. 用于 CALL+4 PC 的场景 (record at PC+4 已是 call 返回后).
        """
        n = len(self.t)
        pc_arr = self.t.pc_array()
        mask = pc_arr == np.uint64(self.pc)
        if not mask.any():
            return (0, [])
        idxs = np.nonzero(mask)[0]
        n_hits = len(idxs)
        if n_hits > 5000:
            step = n_hits // 5000
            idxs = idxs[::step]
        vals: list = []
        for i in idxs:
            ni = int(i) if use_same_idx else int(i) + 1
            if ni >= n or ni < 0:
                continue
            r = self.t.record(ni)
            if isinstance(self.q, str):
                vals.append(int(r.reg(self.q)))
            else:
                vals.append(int(r.regs[self.q]))
        return (n_hits, vals)


# ─────────────────── apply UIDF to passes ───────────────────


def apply_uidf_to_constfold_env(uidf: dict[tuple, ObservedValues],
                                blk: SsaBlock,
                                env: dict[tuple, int]) -> None:
    """把 uidf 中 is_const 的 ObservedValues 注入 const env (constfold pass 用).

    env: dict[(reg, version) → int_value]. 修改 in-place.

    For each (block_pc=blk.block_pc, root_idx) in uidf:
      若 ObservedValues.is_const() → env[(reg, dst_version)] = const_value
    """
    bpc = blk.block_pc
    for i, root in enumerate(blk.roots):
        key = (bpc, i)
        if key not in uidf:
            continue
        ov = uidf[key]
        if not ov.is_const():
            continue
        if not isinstance(root, LlilExpr) or root.op != LLIL_SET_REG:
            continue
        reg_name = root.operands[0]
        dst_v = blk.tag.get(root)
        env[(reg_name, dst_v)] = ov.const_value()
