"""Build nested call tree from trace by walking bl/ret pairs.

Algorithm:
  - Init stack with root frame {fn:'?', enter_idx:0, children:[]}
  - For each idx i: decode insn at pc.
      - bl / blr  → push frame, link as child of current top
      - ret       → pop top, set exit_idx=i (if stack > 1)
  - At end: set exit_idx for any unclosed frames to last idx

Caveats (real-world OLLVM):
  - Indirect br x14 / br x16 are tail-calls or jump tables — NOT counted as
    call boundaries (no LR set).
  - Some functions tail-call via b instead of bl — undetectable here.
  - Frinet's full-fidelity tree needs FP-chain walking too; this is bl/ret
    based and matches what user expects on common code.
"""
from __future__ import annotations
from .trace import Trace
from .disasm import decode


def build_call_tree(trace: Trace, sym=None,
                    max_depth: int = 50) -> dict:
    """Returns root tree node {fn, enter_idx, exit_idx, children}.

    max_depth: cap nesting depth — extra calls are flattened into the deepest
    permitted frame's children rather than nested deeper. Prevents runaway
    HTML for OLLVM auto-recursive jumpouts.
    """
    if sym is None:
        from .symbols import build_from_trace
        sym = build_from_trace(trace)

    n = len(trace)
    root = {"fn": "?", "enter_idx": 0, "exit_idx": n - 1 if n else 0,
            "children": [], "depth": 0}
    stack = [root]

    for i in range(n):
        r = trace.record(i)
        d = decode(r.pc, r.inst)
        m = d.mnemonic
        if m in ("bl", "blr"):
            top = stack[-1]
            # Resolve callee name from operand at idx i+1's PC (the call target)
            target_pc = trace.pc(i + 1) if i + 1 < n else 0
            cf, _ = sym.lookup(target_pc) if target_pc else ("?", 0)
            new_depth = top["depth"] + 1
            if new_depth > max_depth:
                # cap reached — skip pushing. Mark top as having truncated
                # children so UI can show "...". Stack stays at max_depth so
                # subsequent rets pop normally.
                top["truncated_children"] = top.get("truncated_children", 0) + 1
                stack.append(top)  # push duplicate so next ret balances
                continue
            child = {
                "fn": cf if cf != "?" else None,
                "enter_idx": i, "exit_idx": i,
                "children": [], "depth": new_depth,
            }
            top["children"].append(child)
            stack.append(child)
        elif m == "ret":
            if len(stack) > 1:
                top = stack.pop()
                top["exit_idx"] = i

    # close any remaining open frames at last idx
    last = n - 1 if n else 0
    while len(stack) > 1:
        top = stack.pop()
        top["exit_idx"] = last
    root["exit_idx"] = last
    return root
