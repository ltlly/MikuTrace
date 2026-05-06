"""Partial x-sign reconstruction simulator from confirmed trace evidence.

This is intentionally not the full x-sign algorithm yet. It captures only the
pieces that have been proven from local libsgmainso traces:

- final x-sign text is standard Base64 over a 76-byte payload;
- one upstream VM state chain is seeded by libc time();
- that chain uses state = state * 0x5851f42d4c957f2d + 1 mod 2^64;
- one output byte path folds a 64-bit state with (x + x / 0xff) & 0xff;
- Base64 index 'p' in group "piYQ" is built from bytes 0x0a and 0x62.

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


def b64decode_unpadded(raw: str) -> bytes:
    return base64.b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))


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
    lcg_states = lcg_sequence(TRACE_TIME_RET, len(TRACE_LCG_STATES))
    fold_input = 0x74FFAFCA73
    folded_byte = mod255_low_byte(fold_input)

    # Trace-proven first variable group: "piYQ" decodes to a6 26 10.
    group = CALL_001_XSIGN[12:16]
    decoded_group = b64decode_unpadded(group)
    index_p_from_payload = base64_i0(decoded_group[0])
    index_p_from_trace_scratch = ((0x0A << 2) & 0x3F) | (0x62 >> 6)

    report = {
        "status": "partial",
        "xsign_len": len(CALL_001_XSIGN),
        "payload_len": len(payload),
        "payload_prefix_hex": payload[:16].hex(),
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
        "mod255_low_byte": {
            "input": f"{fold_input:#x}",
            "computed": f"{folded_byte:#x}",
            "expected_trace_byte": "0x62",
            "matches_trace": folded_byte == 0x62,
        },
        "base64_group_3": {
            "chars": group,
            "decoded_hex": decoded_group.hex(),
            "payload_i0": f"{index_p_from_payload:#x}",
            "trace_scratch_i0": f"{index_p_from_trace_scratch:#x}",
            "char_from_trace_index": BASE64_ALPHABET[index_p_from_trace_scratch],
            "matches_trace": index_p_from_payload == index_p_from_trace_scratch == BASE64_ALPHABET.index("p"),
        },
        "complete_algorithm": False,
        "missing": [
            "full 76-byte payload construction",
            "all VM bytecode templates feeding Base64 indexes",
            "role of the LCG/time state in every payload byte",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
