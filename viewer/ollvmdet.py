"""OLLVM VM dispatcher detection (heuristic, P1-D).

Looks for the classic obfuscation pattern:
  while (1) {
    op = bytecode[ip++];   ← ldrh wN, [base, #imm]!  (self-update)
    handler = table[op];   ← ldr xN, [tbl, idx, lsl #3]
    goto handler;          ← br xN  (indirect)
  }

Scoring:
  +0.4   indirect br/blr seen in trace
  +0.3   ldr [base, idx, lsl #3] preceded the indirect br
  +0.2   self-update load (ldrh w?, [.., #N]! style)
  +0.1   high-entry count function (>= min_entries iterations)

Output is "possibly OLLVM/VM" — heuristic, NOT proof. User decides.
NEVER decode VM bytecode (TODO 决定: P2-E 旧 OLLVM VM decode 不做).
"""
from __future__ import annotations
from collections import defaultdict
import numpy as np
from .disasm import decode


def ollvm_detect_vm(trace, min_entries: int = 10,
                     conf_threshold: float = 0.3) -> list[dict]:
    """Return list of {fn_pc, entry_count, confidence, reason, hint}.

    Walk trace once:
      - Count fn-entry visits (proxy: distinct PC at function start, here
        approximated as block-leader frequency)
      - For each indirect br at idx I, look back ≤ 4 insns for ldr ...lsl #3
        and ldrh self-update patterns
    """
    n = len(trace)
    if n < min_entries:
        return []
    pc_freq: dict[int, int] = defaultdict(int)
    indirect_total = 0
    table_load_total = 0
    self_update_total = 0
    indirect_pc_first: dict[int, int] = {}  # br PC → first idx seen

    for i in range(n):
        r = trace.record(i); d = decode(r.pc, r.inst)
        pc_freq[r.pc] += 1
        m = d.mnemonic
        if m in ("br", "blr"):
            indirect_total += 1
            indirect_pc_first.setdefault(r.pc, i)
            # look back 4 insns for table-load + self-update
            for j in range(max(0, i - 4), i):
                rj = trace.record(j); dj = decode(rj.pc, rj.inst)
                op_str = dj.op_str.lower()
                if "lsl #3" in op_str and dj.mnemonic == "ldr":
                    table_load_total += 1
                if "!" in op_str and dj.mnemonic in ("ldrh", "ldrb", "ldr"):
                    self_update_total += 1

    if indirect_total < min_entries:
        return []

    confidence = 0.4   # indirect br seen
    reasons = ["indirect br/blr"]
    if table_load_total >= min_entries // 2:
        confidence += 0.3
        reasons.append(f"ldr [..,lsl #3] table-load near br ({table_load_total}×)")
    if self_update_total >= min_entries // 2:
        confidence += 0.2
        reasons.append(f"self-update ldr[h/b]/[..,#N]! ({self_update_total}×)")
    if indirect_total >= min_entries * 5:
        confidence += 0.1
        reasons.append(f"high-frequency indirect ({indirect_total} hits)")

    if confidence < conf_threshold:
        return []

    # Pick first indirect PC as candidate dispatcher anchor (best guess).
    anchor_pc = min(indirect_pc_first.keys(), default=0,
                     key=lambda p: indirect_pc_first[p])
    return [{
        "fn_pc": hex(anchor_pc),
        "entry_count": indirect_total,
        "confidence": round(confidence, 2),
        "reason": " + ".join(reasons),
        "hint": "可能是 OLLVM VM dispatcher / jump-table 派发. "
                "反向追踪建议 skip 内部, 看 VM 调用边界数据流即可.",
    }]
