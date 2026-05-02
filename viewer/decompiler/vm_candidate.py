"""VM bytecode 候选区段检测 — DEC3-D, 严守 §7.0 普适性.

设计目标: 把"巨大 OLLVM-VM 函数 (1056 块)"问题转化为
"VM bytecode 是这串字节, 你 (LLM) 推编码反汇编它".

普适性自查 (§7.0):
  ✓ 复用 viewer/ollvmdet.py heuristic 评分, 不假设特定 VM (AVMP/Themida/VMP/etc.)
  ✓ bytecode reader 检测靠通用 pattern (self-update load 高频出现), 不假设位宽
  ✓ 输出 hex dump 喂 LLM, **不 disasm** (LLM 推编码; 已有 mimo PoC 实证可行)
  ✓ ollvmdet 没检测到 → 没 candidate, 不影响其他功能 (backward compat)
  ✓ 没写死任何 SO 名 / fn 偏移 / opcode 编码 / 寄存器名

算法 (粗粒度):
  1. ollvm_detect_vm(trace) 拿可疑 dispatcher fn (置信度 + reasons)
  2. 在每个候选 fn 内, 找"高频 self-update load" (ldrh/ldrb/ldr with `!`):
     这是经典 VM bytecode reader 模式 — 单指令读字节并自增 IP
  3. 拿那条指令所有命中处的 base register 值序列, 取 min/max → bytecode 地址范围
  4. memshadow.hex_dump(min_addr, t=last_idx, rows=16) → 喂 LLM 用的 hex 视图
  5. 输出 VmCandidate, 不解码

Caveats (诚实标注):
  - 任何 hot self-update load 都会触发, 真假阳由 confidence + reasons 区分
  - LLM 看 hex dump 可推编码, 但 trace 短 (单 cmd) 时可能数据不够
  - bytecode 地址范围估值粗 — 极端情况 base reg 包绕也按 min/max 取
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import numpy as np
from ..disasm import decode


@dataclass
class VmCandidate:
    """One VM dispatcher 候选区."""
    dispatcher_pc: int                   # ollvmdet 给的 dispatcher 锚点
    confidence: float                    # ollvmdet 评分
    reasons: list[str] = field(default_factory=list)
    # bytecode reader: 高频 self-update load 指令
    reader_pc: int = 0
    reader_inst: str = ""                # mnemonic + op_str 文本 (LLM 看)
    reader_hits: int = 0                 # 该 PC 在 trace 命中次数
    reader_base_reg: str = ""            # 解析出的 base register
    # bytecode 字节范围 (mem 范围, 不是 record idx)
    bytecode_addr: int = 0
    bytecode_len: int = 0
    # hex dump (memshadow 抓的实际字节)
    hex_dump: list[str] = field(default_factory=list)


def _find_self_update_loads(trace, fn_idx_lo: int, fn_idx_hi: int,
                            min_hits: int = 8,
                            max_step: int = 16) -> list[tuple[int, int, str, str]]:
    """在 [fn_idx_lo, fn_idx_hi] 区间内找高频 self-update load.

    Returns: list of (pc, hits, mnem_op_str, base_reg_name).
    self-update 判定:
      - mnemonic in {ldrh, ldrb, ldr}
      - op_str 含 '!' (pre/post-update)
      - **|step| ≤ max_step** — VM bytecode reader 步长应该是单 opcode 大小
        (典型 1-8 字节, 极少 16+). 步长 #0x40 之类是 struct field access,
        过滤掉 (重要 false-positive 防线, 真机实证有效).

    Caveat: 这是 heuristic, 不是绝对. 个别 VM 用大步长 reader (跳过校验/填充
    字节) 会被误过滤. 真要看可调 max_step.
    """
    pc_arr = trace.pc_array()
    sub_pcs = pc_arr[fn_idx_lo:fn_idx_hi + 1]
    unique, counts = np.unique(sub_pcs, return_counts=True)
    order = np.argsort(-counts)
    hits_seen: dict[int, tuple[int, str, str]] = {}
    for i in order[:200]:
        pc = int(unique[i])
        cnt = int(counts[i])
        if cnt < min_hits:
            continue
        local_mask = sub_pcs == np.uint64(pc)
        if not local_mask.any():
            continue
        local_idx = int(np.argmax(local_mask)) + fn_idx_lo
        d = decode(pc, trace.inst(local_idx))
        if d.mnemonic not in ("ldrh", "ldrb", "ldr"):
            continue
        if "!" not in d.op_str:
            continue
        if not d.mem_op:
            continue
        base_reg, _idx_reg, disp, _sz, _is_w, _src = d.mem_op[0]
        # 步长 sanity 过滤
        if abs(int(disp)) > max_step:
            continue
        hits_seen[pc] = (cnt, f"{d.mnemonic} {d.op_str}", base_reg or "")
    return sorted(
        [(pc, c, ms, br) for pc, (c, ms, br) in hits_seen.items()],
        key=lambda x: -x[1],
    )


def _bytecode_range(trace, reader_pc: int, base_reg: str,
                    fn_idx_lo: int, fn_idx_hi: int) -> tuple[int, int]:
    """从所有命中 reader_pc 的 record 上拿 base_reg 值, 返回 (min, max).

    Returns (0, 0) 若解析失败 (无命中或 reg 名错).
    """
    if not base_reg:
        return (0, 0)
    pc_arr = trace.pc_array()
    sub_pcs = pc_arr[fn_idx_lo:fn_idx_hi + 1]
    mask = sub_pcs == np.uint64(reader_pc)
    if not mask.any():
        return (0, 0)
    idxs = np.nonzero(mask)[0] + fn_idx_lo
    vals = []
    for i in idxs[:5000]:                # cap to 5K hits, 够估范围
        try:
            r = trace.record(int(i))
            v = r.reg(base_reg)
            if v:
                vals.append(int(v))
        except Exception:
            continue
    if not vals:
        return (0, 0)
    return (min(vals), max(vals))


def detect_vm_candidates(trace, cfg, mem=None,
                         confidence_threshold: float = 0.4) -> list[VmCandidate]:
    """主入口: 从 trace 检测 VM dispatcher 候选 + 抓 bytecode hex.

    Args:
        trace: loaded Trace
        cfg: built CFG
        mem: optional MemShadow (建过的). None 则不出 hex_dump (省时间).
        confidence_threshold: ollvmdet 阈值

    Returns: list[VmCandidate], 按 confidence 降序.
    """
    from ..ollvmdet import ollvm_detect_vm
    findings = ollvm_detect_vm(trace, conf_threshold=confidence_threshold)
    if not findings:
        return []

    out: list[VmCandidate] = []
    n = len(trace)
    for f in findings:
        dispatcher_pc = int(f.get("fn_pc"), 16) if isinstance(f.get("fn_pc"), str) \
                        else int(f.get("fn_pc") or 0)
        cand = VmCandidate(
            dispatcher_pc=dispatcher_pc,
            confidence=float(f.get("confidence") or 0.0),
            reasons=str(f.get("reason", "")).split(" + ") if f.get("reason") else [],
        )
        # bytecode reader: 在整 trace 范围扫 (ollvmdet 没给 fn 边界, 用全程)
        readers = _find_self_update_loads(trace, 0, n - 1, min_hits=8)
        if readers:
            pc, hits, ms, base = readers[0]      # 最热的那条
            cand.reader_pc = pc
            cand.reader_inst = ms
            cand.reader_hits = hits
            cand.reader_base_reg = base
            lo, hi = _bytecode_range(trace, pc, base, 0, n - 1)
            if lo and hi and hi > lo:
                cand.bytecode_addr = lo
                # cap bytecode_len: base reg max-min 在地址跨段间会爆炸
                # (e.g. 跨 mmap region). 真实 VM bytecode 通常 < 64KB.
                # 超 64KB 标 'spans multiple regions, length unreliable'.
                raw_len = hi - lo + 1
                cand.bytecode_len = raw_len
                if mem is not None and mem.built:
                    # hex dump 只取 256 字节 (16 行 × 16), 足够 LLM 看 pattern
                    rows = 16
                    cand.hex_dump = mem.hex_dump(lo, n - 1, rows=rows, cols=16)
        out.append(cand)
    out.sort(key=lambda c: -c.confidence)
    return out
