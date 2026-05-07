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
    trusted_writes: list[dict[str, Any]] = field(default_factory=list)
    seed_suggestions: dict[int, dict[str, Any]] = field(default_factory=dict)
    seeded_slots: dict[int, int] = field(default_factory=dict)


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


def formula_rhs_operands(effect: dict[str, Any]) -> list[int]:
    formula = effect.get("formula") or {}
    expression = formula.get("expression")
    if not isinstance(expression, str) or "=" not in expression:
        return []
    rhs = expression.split("=", 1)[1]
    return [int(value, 0) for value in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", rhs)]


def seed_suggestions(effect: dict[str, Any], text: str) -> list[dict[str, Any]]:
    if "=" not in text:
        return []
    _lhs, rhs = [part.strip() for part in text.split("=", 1)]
    match = re.fullmatch(r"(add|sub|and|orr|eor|lsl|lsr)\((.*)\)", rhs)
    if match is None:
        return []
    args = split_args(match.group(2))
    operands = formula_rhs_operands(effect)
    if not operands:
        return []
    suggestions: list[dict[str, Any]] = []
    operand_idx = 0
    for arg in args:
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", arg):
            operand_idx += 1
            continue
        slot_match = re.fullmatch(r"slot\[(\d+)\]", arg)
        if slot_match is None:
            operand_idx += 1
            continue
        if operand_idx >= len(operands):
            continue
        suggestions.append(
            {
                "slot": int(slot_match.group(1)),
                "value": f"{operands[operand_idx]:#x}",
                "source": effect.get("pseudocode") or effect.get("python_with_values"),
            }
        )
        operand_idx += 1
    return suggestions


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
    slot_match = re.fullmatch(r"slot\[(\d+)\]", lhs)
    mem_match = re.fullmatch(r"mem\[(0x[0-9a-fA-F]+|\d+|null)\]", lhs)
    if slot_match is None and mem_match is None:
        state.skipped_effects += 1
        return
    computed = eval_expr(rhs, state, effect)
    observed = parse_value(effect.get("value"))
    if computed is None and trust_observed:
        computed = observed
        if computed is not None:
            state.trusted_effects += 1
            suggestions = seed_suggestions(effect, text)
            for suggestion in suggestions:
                slot = int(suggestion["slot"])
                state.seed_suggestions.setdefault(slot, suggestion)
            state.trusted_writes.append(
                {
                    "idx": effect.get("idx"),
                    "value": f"{computed:#x}",
                    "python_with_values": text,
                    "seed_suggestions": suggestions,
                }
            )
    elif computed is not None:
        state.computed_effects += 1
    else:
        state.skipped_effects += 1
        return
    if computed is None:
        state.skipped_effects += 1
        return
    if slot_match is not None:
        slot = int(slot_match.group(1))
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
    if mem_match is not None:
        addr = parse_int(mem_match.group(1))
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


def parse_seed_slot(spec: str) -> tuple[int, int]:
    slot_text, value_text = spec.split("=", 1)
    return int(slot_text, 0), int(value_text, 0)


def parse_seed_slots(seed_slots: list[str]) -> dict[int, int]:
    seeds = {}
    for spec in seed_slots:
        slot, value = parse_seed_slot(spec)
        seeds[slot] = value & MASK64
    return seeds


def seed_specs_from_map(seeds: dict[int, int]) -> list[str]:
    return [f"{slot}={value:#x}" for slot, value in sorted(seeds.items())]


def formatted_slots(seeds: dict[int, int]) -> dict[str, str]:
    return {str(slot): f"{value:#x}" for slot, value in sorted(seeds.items())}


def replay_plan(
    plan: dict[str, Any], trust_observed: bool, seed_slots: list[str]
) -> ReplayState:
    state = ReplayState()
    for slot, value in parse_seed_slots(seed_slots).items():
        state.slots[slot] = value & MASK64
        state.seeded_slots[slot] = value & MASK64
    for step in plan.get("replay_steps", []):
        for effect in step.get("effects", []):
            apply_effect(effect, state, trust_observed=trust_observed)
    return state


def replay_python_expr(expr: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"\bslot\[(\d+)\]", r"slots[\1]", expr)
    helpers = {
        "add": "vm_add",
        "sub": "vm_sub",
        "and": "vm_and",
        "orr": "vm_orr",
        "eor": "vm_eor",
        "lsl": "vm_lsl",
        "lsr": "vm_lsr",
        "low8": "vm_low8",
    }

    def replace_helper(match: re.Match[str]) -> str:
        return f"{helpers.get(match.group(1), match.group(1))}("

    return re.sub(
        r"\b(add|sub|and|orr|eor|lsl|lsr|low8|byte_load)\(",
        replace_helper,
        expr,
    )


def python_int_dict(items: dict[int, int], *, hex_keys: bool = False) -> str:
    if not items:
        return "{}"
    entries = ", ".join(
        f"{slot:#x}: {value:#x}" if hex_keys else f"{slot}: {value:#x}"
        for slot, value in sorted(items.items())
    )
    return "{" + entries + "}"


def python_int_list(items: list[int]) -> str:
    return "[" + ", ".join(str(item) for item in items) + "]"


def suggestion_seed_slots(suggestions: dict[int, dict[str, Any]]) -> dict[int, int]:
    out = {}
    for slot, suggestion in sorted(suggestions.items()):
        value = parse_value(suggestion.get("value"))
        if value is not None:
            out[slot] = value & MASK64
    return out


def replay_plan_observed_byte_loads(plan: dict[str, Any]) -> dict[int, int]:
    out = {}
    for step in plan.get("replay_steps", []):
        for effect in step.get("effects", []):
            text = effect.get("python_with_values")
            if not isinstance(text, str):
                continue
            match = re.search(r"byte_load\((0x[0-9a-fA-F]+|\d+)\)", text)
            if match is None:
                continue
            addr = parse_int(match.group(1))
            value = parse_value(effect.get("value"))
            if value is None:
                value = parse_value((effect.get("source_byte_load") or {}).get("value"))
            if addr is not None and value is not None:
                out[addr] = value & 0xFF
    return out


def generate_python_replay(
    plan: dict[str, Any],
    seed_slots: list[str] | None = None,
    suggestions: dict[int, dict[str, Any]] | None = None,
    effective_seed_slots: dict[int, int] | None = None,
    redundant_seed_slots: list[int] | None = None,
) -> str:
    user_seeds = parse_seed_slots(seed_slots or [])
    suggested_seeds = suggestion_seed_slots(suggestions or {})
    effective_seeds = effective_seed_slots if effective_seed_slots is not None else suggested_seeds
    redundant_seeds = redundant_seed_slots or []
    observed_byte_loads = replay_plan_observed_byte_loads(plan)
    lines = [
        "# Generated from traceMiku vm-ops --replay-plan.",
        "# This is a generic trace replay skeleton, not a target-specific algorithm.",
        "# SUGGESTED_SEED_SLOTS are formula-derived from observed trace values.",
        "# EFFECTIVE_SEED_SLOTS are the minimized subset used by default.",
        "# OBSERVED_BYTE_LOADS are also trace-derived defaults.",
        "# Prove or replace both before treating this as a portable algorithm.",
        "MASK64 = (1 << 64) - 1",
        f"USER_SEED_SLOTS = {python_int_dict(user_seeds)}",
        f"SUGGESTED_SEED_SLOTS = {python_int_dict(suggested_seeds)}",
        f"EFFECTIVE_SEED_SLOTS = {python_int_dict(effective_seeds)}",
        f"REDUNDANT_SEED_SLOTS = {python_int_list(redundant_seeds)}",
        f"OBSERVED_BYTE_LOADS = {python_int_dict(observed_byte_loads, hex_keys=True)}",
        "",
        "def vm_add(*values): return sum(values) & MASK64",
        "def vm_sub(head, *tail):",
        "    for value in tail:",
        "        head = (head - value) & MASK64",
        "    return head",
        "def vm_and(head, *tail):",
        "    for value in tail:",
        "        head &= value",
        "    return head & MASK64",
        "def vm_orr(*values):",
        "    out = 0",
        "    for value in values:",
        "        out |= value",
        "    return out & MASK64",
        "def vm_eor(*values):",
        "    out = 0",
        "    for value in values:",
        "        out ^= value",
        "    return out & MASK64",
        "def vm_lsl(value, shift): return (value << shift) & MASK64",
        "def vm_lsr(value, shift): return (value & MASK64) >> shift",
        "def vm_low8(value): return value & 0xff",
        "",
        "def store_le(mem, addr, value, width=None):",
        "    if width is None:",
        "        width = 1 if value <= 0xff else 2 if value <= 0xffff else 4 if value <= 0xffffffff else 8",
        "    for offset in range(width):",
        "        mem[addr + offset] = (value >> (offset * 8)) & 0xff",
        "",
        "def replay(seed_slots=None, byte_loads=None, use_effective_seeds=True):",
        "    merged_seed_slots = dict(USER_SEED_SLOTS)",
        "    if use_effective_seeds:",
        "        merged_seed_slots.update(EFFECTIVE_SEED_SLOTS)",
        "    if seed_slots is not None:",
        "        merged_seed_slots.update(seed_slots)",
        "    slots = {int(k): int(v) & MASK64 for k, v in merged_seed_slots.items()}",
        "    merged_byte_loads = dict(OBSERVED_BYTE_LOADS)",
        "    if byte_loads is not None:",
        "        merged_byte_loads.update(byte_loads)",
        "    byte_loads = {int(k): int(v) & 0xff for k, v in merged_byte_loads.items()}",
        "    mem = {}",
        "    def byte_load(addr):",
        "        return byte_loads[addr]",
    ]
    for step_idx, step in enumerate(plan.get("replay_steps", [])):
        lines.append(f"    # replay step {step_idx}")
        for effect in step.get("effects", []):
            text = effect.get("python_with_values")
            if not isinstance(text, str) or "=" not in text:
                continue
            lhs, rhs = [part.strip() for part in text.split("=", 1)]
            expr = replay_python_expr(rhs)
            lines.append(f"    # trace #{effect.get('idx')}: {text}")
            if slot_match := re.fullmatch(r"slot\[(\d+)\]", lhs):
                lines.append(f"    slots[{int(slot_match.group(1))}] = ({expr}) & MASK64")
                continue
            if mem_match := re.fullmatch(r"mem\[(0x[0-9a-fA-F]+|\d+|null)\]", lhs):
                addr = parse_int(mem_match.group(1))
                if addr is None:
                    lines.append("    # skipped unresolved memory address")
                    continue
                width = parse_value(effect.get("store_width"))
                width_arg = "None" if width is None else str(width)
                lines.append(f"    store_le(mem, {addr:#x}, {expr}, {width_arg})")
                continue
            lines.append("    # skipped unsupported effect lhs")
    lines.append('    return {"slots": slots, "mem": mem}')
    lines.append("")
    return "\n".join(lines)


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
        "seed_suggestions": [
            state.seed_suggestions[slot] for slot in sorted(state.seed_suggestions)
        ],
        "trusted_writes_preview": state.trusted_writes[:20],
        "slot_count": len(state.slots),
        "seeded_slots": {
            str(slot): f"{value:#x}" for slot, value in sorted(state.seeded_slots.items())
        },
        "touched_slots": touched_slots,
        "recent_writes": state.writes[-20:],
        "mem_dumps": [dump_mem(state, spec) for spec in dump_specs],
    }


def auto_seeded_replay_summary(
    plan: dict[str, Any], seed_slots: list[str], dump_specs: list[str]
) -> dict[str, Any]:
    trusted_pass = replay_plan(plan, trust_observed=True, seed_slots=seed_slots)
    user_seeds = parse_seed_slots(seed_slots)
    seeds = dict(user_seeds)
    applied = []
    for slot, suggestion in sorted(trusted_pass.seed_suggestions.items()):
        if slot in seeds:
            continue
        value = parse_value(suggestion.get("value"))
        if value is None:
            continue
        seeds[slot] = value & MASK64
        applied.append(suggestion)
    replay = replay_plan(
        plan, trust_observed=False, seed_slots=seed_specs_from_map(seeds)
    )
    minimized_seeds = minimize_auto_seed_slots(plan, user_seeds, seeds, replay)
    minimized_replay = replay_plan(
        plan, trust_observed=False, seed_slots=seed_specs_from_map(minimized_seeds)
    )
    return {
        "status": "ready",
        "caution": (
            "Seed suggestions are derived from observed fallback formulas. "
            "Use this to remove mechanical fallback noise, then prove each "
            "seed with lineage before treating the replay as portable."
        ),
        "applied_seed_suggestions": applied,
        "effective_seed_slots": formatted_slots(minimized_seeds),
        "redundant_seed_slots": [
            slot for slot in sorted(seeds) if slot not in minimized_seeds
        ],
        "summary": summarize(plan, replay, dump_specs),
        "minimized_summary": summarize(plan, minimized_replay, dump_specs),
    }


def replay_equivalent(candidate: ReplayState, reference: ReplayState) -> bool:
    return (
        candidate.trusted_effects == 0
        and not candidate.unresolved_reads
        and candidate.slots == reference.slots
        and candidate.mem == reference.mem
    )


def minimize_auto_seed_slots(
    plan: dict[str, Any],
    user_seeds: dict[int, int],
    seeds: dict[int, int],
    reference: ReplayState,
) -> dict[int, int]:
    minimized = dict(seeds)
    for slot in sorted(seeds):
        if slot in user_seeds:
            continue
        candidate = dict(minimized)
        candidate.pop(slot, None)
        replay = replay_plan(
            plan, trust_observed=False, seed_slots=seed_specs_from_map(candidate)
        )
        if replay_equivalent(replay, reference):
            minimized = candidate
    return minimized


def seed_lineage_commands(
    plan: dict[str, Any],
    suggestions: dict[int, dict[str, Any]],
    call_dir: str | None,
    slot_base: str | None,
    before_idx: int | None,
    depth: int,
    lookback: int,
) -> list[dict[str, Any]]:
    base = parse_int(slot_base) if slot_base else parse_value(plan.get("vm_state_base"))
    if base is None:
        return []
    trace_dir = call_dir or "<call_dir>"
    idx = before_idx if before_idx is not None else int(plan.get("start") or 0)
    out = []
    for slot, suggestion in sorted(suggestions.items()):
        addr = base + slot * 8
        out.append(
            {
                "slot": slot,
                "suggested_value": suggestion.get("value"),
                "addr": f"{addr:#x}",
                "command": (
                    "tracemiku-cli byte-lineage "
                    f"{trace_dir} --addr {addr:#x} --before-idx {idx} "
                    f"--depth {depth} --lookback {lookback} --compact"
                ),
                "caution": "This proves the suggested initial slot value, not the whole replay.",
            }
        )
    return out


def filter_suggestions_for_effective_seeds(
    suggestions: dict[int, dict[str, Any]],
    effective_seed_slots: dict[str, str],
    user_seed_slots: list[str],
) -> dict[int, dict[str, Any]]:
    user_slots = set(parse_seed_slots(user_seed_slots))
    effective_slots = {int(slot, 0) for slot in effective_seed_slots}
    return {
        slot: suggestion
        for slot, suggestion in suggestions.items()
        if slot in effective_slots and slot not in user_slots
    }


def emitted_replay_seed_sets(
    plan: dict[str, Any], seed_slots: list[str]
) -> dict[str, Any]:
    trusted_pass = replay_plan(plan, trust_observed=True, seed_slots=seed_slots)
    user_seeds = parse_seed_slots(seed_slots)
    suggested_seeds = dict(user_seeds)
    for slot, suggestion in sorted(trusted_pass.seed_suggestions.items()):
        if slot in suggested_seeds:
            continue
        value = parse_value(suggestion.get("value"))
        if value is not None:
            suggested_seeds[slot] = value & MASK64
    reference_replay = replay_plan(
        plan, trust_observed=False, seed_slots=seed_specs_from_map(suggested_seeds)
    )
    minimized_seeds = minimize_auto_seed_slots(
        plan, user_seeds, suggested_seeds, reference_replay
    )
    effective_auto_seeds = {
        slot: value for slot, value in minimized_seeds.items() if slot not in user_seeds
    }
    redundant_auto_seeds = [
        slot
        for slot in sorted(suggested_seeds)
        if slot not in minimized_seeds and slot not in user_seeds
    ]
    return {
        "trusted_pass": trusted_pass,
        "user_seeds": user_seeds,
        "suggested_seeds": suggested_seeds,
        "minimized_seeds": minimized_seeds,
        "effective_auto_seeds": effective_auto_seeds,
        "redundant_auto_seeds": redundant_auto_seeds,
    }


def verify_generated_python_replay(
    plan: dict[str, Any], seed_slots: list[str]
) -> dict[str, Any]:
    seed_sets = emitted_replay_seed_sets(plan, seed_slots)
    generated = generate_python_replay(
        plan,
        seed_slots,
        seed_sets["trusted_pass"].seed_suggestions,
        seed_sets["effective_auto_seeds"],
        seed_sets["redundant_auto_seeds"],
    )
    namespace: dict[str, Any] = {}
    exec(generated, namespace)
    generated_result = namespace["replay"]()
    expected = replay_plan(
        plan,
        trust_observed=False,
        seed_slots=seed_specs_from_map(seed_sets["minimized_seeds"]),
    )
    slots_match = generated_result["slots"] == expected.slots
    mem_match = generated_result["mem"] == expected.mem
    ok = slots_match and mem_match
    return {
        "status": "ok" if ok else "mismatch",
        "slots_match": slots_match,
        "mem_match": mem_match,
        "generated_line_count": len(generated.splitlines()),
        "user_seed_slots": formatted_slots(seed_sets["user_seeds"]),
        "effective_auto_seed_slots": formatted_slots(seed_sets["effective_auto_seeds"]),
        "redundant_auto_seed_slots": seed_sets["redundant_auto_seeds"],
        "expected_slot_count": len(expected.slots),
        "expected_mem_byte_count": len(expected.mem),
        "generated_slot_count": len(generated_result["slots"]),
        "generated_mem_byte_count": len(generated_result["mem"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-mem", action="append", default=[], metavar="ADDR:SIZE")
    parser.add_argument(
        "--seed-slot",
        action="append",
        default=[],
        metavar="SLOT=VALUE",
        help="Seed an initial VM slot value before replay, e.g. --seed-slot 0=0.",
    )
    parser.add_argument(
        "--no-trust-observed",
        action="store_true",
        help="Do not fall back to observed trace values when operands are missing.",
    )
    parser.add_argument(
        "--emit-python",
        action="store_true",
        help="Emit a standalone Python replay skeleton instead of executing the plan.",
    )
    parser.add_argument(
        "--verify-emitted-python",
        action="store_true",
        help=(
            "Generate the Python replay skeleton, execute it in-memory, and "
            "verify that replay() matches the internal no-trust evaluator."
        ),
    )
    parser.add_argument(
        "--auto-seed-suggestions",
        action="store_true",
        help=(
            "Run a trusted first pass, apply formula-derived seed_suggestions, "
            "then report a second no-trust replay. Suggestions still require "
            "independent lineage proof."
        ),
    )
    parser.add_argument(
        "--seed-lineage-call-dir",
        help="Call directory to use when emitting seed lineage command strings.",
    )
    parser.add_argument(
        "--seed-lineage-base",
        help=(
            "VM slot memory base for command hints; slot address is base + slot*8. "
            "Defaults to replay-plan vm_state_base when available."
        ),
    )
    parser.add_argument(
        "--seed-lineage-before-idx",
        type=int,
        help="Trace index for seed lineage command hints. Defaults to replay plan start.",
    )
    parser.add_argument("--seed-lineage-depth", type=int, default=80)
    parser.add_argument("--seed-lineage-lookback", type=int, default=5_000_000)
    args = parser.parse_args()
    plan = json.load(sys.stdin)
    if args.verify_emitted_python:
        summary = verify_generated_python_replay(plan, args.seed_slot)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["status"] == "ok" else 1
    if args.emit_python:
        seed_sets = emitted_replay_seed_sets(plan, args.seed_slot)
        sys.stdout.write(
            generate_python_replay(
                plan,
                args.seed_slot,
                seed_sets["trusted_pass"].seed_suggestions,
                seed_sets["effective_auto_seeds"],
                seed_sets["redundant_auto_seeds"],
            )
        )
        return 0
    state = replay_plan(
        plan, trust_observed=not args.no_trust_observed, seed_slots=args.seed_slot
    )
    summary = summarize(plan, state, args.dump_mem)
    if args.auto_seed_suggestions:
        summary["auto_seeded_replay"] = auto_seeded_replay_summary(
            plan, args.seed_slot, args.dump_mem
        )
        effective_suggestions = filter_suggestions_for_effective_seeds(
            state.seed_suggestions,
            summary["auto_seeded_replay"].get("effective_seed_slots", {}),
            args.seed_slot,
        )
        effective_commands = seed_lineage_commands(
            plan,
            effective_suggestions,
            args.seed_lineage_call_dir,
            args.seed_lineage_base,
            args.seed_lineage_before_idx,
            args.seed_lineage_depth,
            args.seed_lineage_lookback,
        )
        if effective_commands:
            summary["auto_seeded_replay"][
                "effective_seed_lineage_commands"
            ] = effective_commands
    commands = seed_lineage_commands(
        plan,
        state.seed_suggestions,
        args.seed_lineage_call_dir,
        args.seed_lineage_base,
        args.seed_lineage_before_idx,
        args.seed_lineage_depth,
        args.seed_lineage_lookback,
    )
    if commands:
        summary["seed_lineage_commands"] = commands
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
