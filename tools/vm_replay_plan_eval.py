#!/usr/bin/env python3
"""Evaluate traceMiku vm-ops --replay-plan JSON.

This is intentionally trace-generic. It executes the compact
``python_with_values`` expressions emitted by ``tracemiku-cli vm-ops
--replay-plan`` and reports which effects were computed from prior state versus
which effects required observed trace values as a fallback.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

MASK64 = (1 << 64) - 1


@dataclass
class ReplayState:
    slots: dict[int, int] = field(default_factory=dict)
    mem: dict[int, int] = field(default_factory=dict)
    computed_effects: int = 0
    trusted_effects: int = 0
    skipped_effects: int = 0
    unresolved_reads: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)


def parse_int(text: str | None) -> int | None:
    if text is None:
        return None
    text = text.strip()
    if text == "" or text == "null":
        return None
    return int(text, 0)


def parse_value(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return parse_int(value)
    return None


def split_args(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:idx].strip())
            start = idx + 1
    args.append(text[start:].strip())
    return [arg for arg in args if arg]


def eval_expr(expr: str, state: ReplayState, effect: dict[str, Any]) -> int | None:
    expr = expr.strip()
    if expr == "null":
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", expr):
        return int(expr, 0)
    if match := re.fullmatch(r"slot\[(\d+)\]", expr):
        slot = int(match.group(1))
        if slot in state.slots:
            return state.slots[slot]
        record_unresolved(state, effect, f"slot[{slot}]")
        return None
    if match := re.fullmatch(r"low8\(slot\[(\d+)\]\)", expr):
        value = eval_expr(f"slot[{match.group(1)}]", state, effect)
        return None if value is None else value & 0xFF
    if match := re.fullmatch(r"byte_load\((0x[0-9a-fA-F]+|\d+)\)", expr):
        observed = parse_value(effect.get("value"))
        if observed is not None:
            return observed & 0xFF
        source = effect.get("source_byte_load") or {}
        return parse_value(source.get("value"))
    if match := re.fullmatch(r"(add|sub|and|orr|eor|lsl|lsr)\((.*)\)", expr):
        op = match.group(1)
        values = [eval_expr(arg, state, effect) for arg in split_args(match.group(2))]
        if any(value is None for value in values):
            return None
        nums = [value for value in values if value is not None]
        if op == "add":
            return sum(nums) & MASK64
        if op == "sub":
            head, *tail = nums
            for value in tail:
                head = (head - value) & MASK64
            return head
        if op == "and":
            head, *tail = nums
            for value in tail:
                head &= value
            return head & MASK64
        if op == "orr":
            out = 0
            for value in nums:
                out |= value
            return out & MASK64
        if op == "eor":
            out = 0
            for value in nums:
                out ^= value
            return out & MASK64
        if op == "lsl":
            return (nums[0] << nums[1]) & MASK64
        if op == "lsr":
            return (nums[0] & MASK64) >> nums[1]
    record_unresolved(state, effect, expr)
    return None


def record_unresolved(state: ReplayState, effect: dict[str, Any], expr: str) -> None:
    state.unresolved_reads.append(
        {
            "idx": effect.get("idx"),
            "python_with_values": effect.get("python_with_values"),
            "missing": expr,
        }
    )


def value_width_bytes(value: int, rhs: str) -> int:
    if rhs.startswith("low8("):
        return 1
    if value <= 0xFF:
        return 1
    if value <= 0xFFFF:
        return 2
    if value <= 0xFFFFFFFF:
        return 4
    return 8


def write_mem(state: ReplayState, addr: int, value: int, width: int) -> None:
    for offset in range(width):
        state.mem[addr + offset] = (value >> (offset * 8)) & 0xFF


def apply_effect(effect: dict[str, Any], state: ReplayState, trust_observed: bool) -> None:
    text = effect.get("python_with_values")
    if not isinstance(text, str) or "=" not in text:
        state.skipped_effects += 1
        return
    lhs, rhs = [part.strip() for part in text.split("=", 1)]
    computed = eval_expr(rhs, state, effect)
    observed = parse_value(effect.get("value"))
    if computed is None and trust_observed:
        computed = observed
        state.trusted_effects += 1
    elif computed is not None:
        state.computed_effects += 1
    else:
        state.skipped_effects += 1
        return
    if computed is None:
        state.skipped_effects += 1
        return
    if match := re.fullmatch(r"slot\[(\d+)\]", lhs):
        slot = int(match.group(1))
        state.slots[slot] = computed & MASK64
        state.writes.append(
            {
                "kind": "slot",
                "idx": effect.get("idx"),
                "slot": slot,
                "value": f"{computed & MASK64:#x}",
                "computed_from_rhs": observed == computed if observed is not None else None,
                "python_with_values": text,
            }
        )
        return
    if match := re.fullmatch(r"mem\[(0x[0-9a-fA-F]+|\d+|null)\]", lhs):
        addr = parse_int(match.group(1))
        if addr is None:
            state.skipped_effects += 1
            return
        width = parse_value(effect.get("store_width")) or value_width_bytes(computed, rhs)
        write_mem(state, addr, computed, width)
        state.writes.append(
            {
                "kind": "mem",
                "idx": effect.get("idx"),
                "addr": f"{addr:#x}",
                "value": f"{computed:#x}",
                "width": width,
                "python_with_values": text,
            }
        )
        return
    state.skipped_effects += 1


def replay_plan(plan: dict[str, Any], trust_observed: bool) -> ReplayState:
    state = ReplayState()
    for step in plan.get("replay_steps", []):
        for effect in step.get("effects", []):
            apply_effect(effect, state, trust_observed=trust_observed)
    return state


def dump_mem(state: ReplayState, spec: str) -> dict[str, Any]:
    addr_text, size_text = spec.split(":", 1)
    addr = int(addr_text, 0)
    size = int(size_text, 0)
    bytes_out = [state.mem.get(addr + offset) for offset in range(size)]
    return {
        "addr": f"{addr:#x}",
        "size": size,
        "complete": all(value is not None for value in bytes_out),
        "hex": "".join(f"{value:02x}" if value is not None else "??" for value in bytes_out),
        "missing_offsets": [
            offset for offset, value in enumerate(bytes_out) if value is None
        ],
    }


def summarize(plan: dict[str, Any], state: ReplayState, dump_specs: list[str]) -> dict[str, Any]:
    touched_slots = sorted(state.slots)
    return {
        "status": "ready",
        "source_status": plan.get("status"),
        "source_range": [plan.get("start"), plan.get("end")],
        "replay_step_count": plan.get("replay_step_count"),
        "effect_count": plan.get("effect_count"),
        "computed_effects": state.computed_effects,
        "trusted_effects": state.trusted_effects,
        "skipped_effects": state.skipped_effects,
        "unresolved_read_count": len(state.unresolved_reads),
        "unresolved_reads_preview": state.unresolved_reads[:20],
        "slot_count": len(state.slots),
        "touched_slots": touched_slots,
        "recent_writes": state.writes[-20:],
        "mem_dumps": [dump_mem(state, spec) for spec in dump_specs],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-mem", action="append", default=[], metavar="ADDR:SIZE")
    parser.add_argument(
        "--no-trust-observed",
        action="store_true",
        help="Do not fall back to observed trace values when operands are missing.",
    )
    args = parser.parse_args()
    plan = json.load(sys.stdin)
    state = replay_plan(plan, trust_observed=not args.no_trust_observed)
    json.dump(summarize(plan, state, args.dump_mem), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
