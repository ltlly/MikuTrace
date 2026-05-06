"""Partial x-sign reconstruction simulator from confirmed trace evidence.

This is intentionally not the full x-sign algorithm yet. It captures only the
pieces that have been proven from local libsgmainso traces:

- final x-sign text is valid Base64, but the variable tail after the fixed
  12-character prefix is also an unaligned Base64 slice;
- one upstream VM state chain is seeded by libc time();
- that chain uses state = state * 0x5851f42d4c957f2d + 1 mod 2^64;
- two output byte paths fold 64-bit states with (x + x / 0xff) & 0xff;
- Base64 group "piYQ" is built from the aligned tail scratch bytes
  0x0a, 0x62, and 0x61.

Run:
    uv run python examples/libsgmainso/xsign_partial_sim.py
"""

from __future__ import annotations

import base64
import datetime as dt
import json


MASK64 = (1 << 64) - 1
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
LCG_MULT = 0x5851F42D4C957F2D
LCG_INC = 1
FIXED_PREFIX_CHARS = 12
TAIL_ALIGNMENT_PREFIX = "AA"

CALL_001_XSIGN = (
    "azYBCM007xAApiYQXVKLkaXxoOr2BiYWKai5MLGI6T9yCUYPHSKV0zba5j/4Jbr6D0UvFBHd3FllrCJShVQSWn+qcIYmFY3mFgYmFi"
)

TRACE_TIME_RET = 0x69F5B3CB
TRACE_LCG_STATES = [
    0x9A7BE8B46D894FB0,
    0x7988B092011B51F1,
    0x4B1654CDFCB8F65E,
    0xC4FCFFE67B71F087,
    0x5036F3354BED40BC,
    0x52C36263893DA50D,
    0xDD1841BEA148764A,
    0x99BD5D21D7D8103,
]

TRACE_FOLDS = [
    {
        "name": "scratch_0x62",
        "input": 0x74FFAFCA73,
        "expected": 0x62,
    },
    {
        "name": "scratch_0x61",
        "input": 0x74BEABE59C,
        "expected": 0x61,
    },
]

TRACE_SMALL_AFFINE = {
    "previous_state": 0xC87,
    "multiplier": 0x3,
    "delta": 0x13,
    "expected_state": 0x25A8,
}


def b64decode_unpadded(raw: str) -> bytes:
    return base64.b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))


def b64encode_unpadded(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def lcg_next(state: int) -> int:
    return (state * LCG_MULT + LCG_INC) & MASK64


def lcg_sequence(seed: int, count: int) -> list[int]:
    out = []
    state = seed
    for _ in range(count):
        state = lcg_next(state)
        out.append(state)
    return out


def mod255_low_byte(value: int) -> int:
    return (value + value // 0xFF) & 0xFF


def affine_mod64(previous_state: int, multiplier: int, delta: int) -> int:
    return (previous_state * multiplier + delta) & MASK64


def base64_i0(byte0: int) -> int:
    return (byte0 >> 2) & 0x3F


def base64_i1(byte0: int, byte1: int) -> int:
    return ((byte0 & 0x03) << 4) | (byte1 >> 4)


def base64_i2(byte1: int, byte2: int) -> int:
    return ((byte1 & 0x0F) << 2) | (byte2 >> 6)


def base64_i3(byte2: int) -> int:
    return byte2 & 0x3F


def main() -> None:
    payload = b64decode_unpadded(CALL_001_XSIGN)
    tail_chars = CALL_001_XSIGN[FIXED_PREFIX_CHARS:]
    aligned_tail = b64decode_unpadded(TAIL_ALIGNMENT_PREFIX + tail_chars)
    semantic_tail = aligned_tail[1:]
    reencoded_tail = b64encode_unpadded(aligned_tail)
    lcg_states = lcg_sequence(TRACE_TIME_RET, len(TRACE_LCG_STATES))
    folds = [
        {
            "name": item["name"],
            "input": f"{item['input']:#x}",
            "computed": f"{mod255_low_byte(item['input']):#x}",
            "expected_trace_byte": f"{item['expected']:#x}",
            "matches_trace": mod255_low_byte(item["input"]) == item["expected"],
        }
        for item in TRACE_FOLDS
    ]
    small_affine_state = affine_mod64(
        TRACE_SMALL_AFFINE["previous_state"],
        TRACE_SMALL_AFFINE["multiplier"],
        TRACE_SMALL_AFFINE["delta"],
    )

    # Trace-proven first variable group: the x-sign tail starts at Base64
    # character offset 2 of the aligned scratch stream.
    group = CALL_001_XSIGN[12:16]
    decoded_group = b64decode_unpadded(group)
    index_p_from_payload = base64_i0(decoded_group[0])
    scratch0, scratch1, scratch2, scratch3 = semantic_tail[:4]
    index_p_from_trace_scratch = base64_i2(scratch0, scratch1)
    indices_from_payload = [
        base64_i0(decoded_group[0]),
        base64_i1(decoded_group[0], decoded_group[1]),
        base64_i2(decoded_group[1], decoded_group[2]),
        base64_i3(decoded_group[2]),
    ]
    indices_from_trace_scratch = [
        base64_i2(scratch0, scratch1),
        base64_i3(scratch1),
        base64_i0(scratch2),
        base64_i1(scratch2, scratch3),
    ]

    report = {
        "status": "partial",
        "xsign_len": len(CALL_001_XSIGN),
        "payload_len": len(payload),
        "payload_prefix_hex": payload[:16].hex(),
        "tail_alignment": {
            "fixed_prefix_chars": FIXED_PREFIX_CHARS,
            "variable_tail_chars": len(tail_chars),
            "synthetic_prefix": TAIL_ALIGNMENT_PREFIX,
            "aligned_tail_len": len(aligned_tail),
            "aligned_tail_prefix_hex": aligned_tail[:16].hex(),
            "semantic_tail_prefix_hex": semantic_tail[:16].hex(),
            "reencoded_tail_prefix": reencoded_tail[:18],
            "tail_reencodes_xsign_tail_from_char_2": reencoded_tail[2:] == tail_chars,
            "note": "The first aligned byte is synthetic; semantic tracing starts at aligned_tail[1].",
        },
        "time_seed": {
            "hex": f"{TRACE_TIME_RET:#x}",
            "unix": TRACE_TIME_RET,
            "local_iso": dt.datetime.fromtimestamp(TRACE_TIME_RET).isoformat(),
        },
        "lcg": {
            "multiplier": f"{LCG_MULT:#x}",
            "increment": LCG_INC,
            "matches_trace": lcg_states == TRACE_LCG_STATES,
            "states_hex": [f"{value:#x}" for value in lcg_states],
        },
        "small_affine": {
            "previous_state": f"{TRACE_SMALL_AFFINE['previous_state']:#x}",
            "multiplier": f"{TRACE_SMALL_AFFINE['multiplier']:#x}",
            "delta": f"{TRACE_SMALL_AFFINE['delta']:#x}",
            "computed": f"{small_affine_state:#x}",
            "expected_state": f"{TRACE_SMALL_AFFINE['expected_state']:#x}",
            "matches_trace": small_affine_state == TRACE_SMALL_AFFINE["expected_state"],
        },
        "mod255_low_byte": folds,
        "base64_group_3": {
            "chars": group,
            "decoded_hex": decoded_group.hex(),
            "aligned_tail_bytes_hex": bytes([scratch0, scratch1, scratch2, scratch3]).hex(),
            "aligned_tail_formula": "chars == base64(aligned_tail)[2:6]",
            "tail_group_matches": reencoded_tail[2:6] == group,
            "indices_from_payload": [f"{value:#x}" for value in indices_from_payload],
            "indices_from_trace_scratch": [f"{value:#x}" for value in indices_from_trace_scratch],
            "payload_i0": f"{index_p_from_payload:#x}",
            "trace_scratch_i0": f"{index_p_from_trace_scratch:#x}",
            "char_from_trace_index": BASE64_ALPHABET[index_p_from_trace_scratch],
            "matches_trace": indices_from_payload == indices_from_trace_scratch,
        },
        "complete_algorithm": False,
        "missing": [
            "full semantic tail construction after the synthetic alignment byte",
            "meaning of the fixed 12-character prefix / 9 decoded bytes",
            "all VM bytecode templates feeding Base64 indexes",
            "role of the LCG/time state in every payload byte",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
