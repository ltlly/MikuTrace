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
- the full 68-byte semantic tail for call_001 has a complete byte-writer map
  before the final output buffer overwrite;
- the repeated semantic tail range tail[65:68] == tail[13:16] is a structural
  repeat across samples, but call_001 trace evidence shows the tail copy
  candidate is re-encoded from VM scratch bytes, not yet proven as a direct
  string memcpy.

Run:
    uv run python examples/libsgmainso/xsign_partial_sim.py
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import urllib.parse


MASK64 = (1 << 64) - 1
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
LCG_MULT = 0x5851F42D4C957F2D
LCG_INC = 1
FIXED_PREFIX_CHARS = 12
TAIL_ALIGNMENT_PREFIX = "AA"

CALL_001_XSIGN = (
    "azYBCM007xAApiYQXVKLkaXxoOr2BiYWKai5MLGI6T9yCUYPHSKV0zba5j/4Jbr6D0UvFBHd3FllrCJShVQSWn+qcIYmFY3mFgYmFi"
)

SAMPLE_XSIGNS = {
    "diff_run1_truncated_call_006": "azYBCM007xAAq6ob9x25o0UaJH1qe6obpaU1PT2FZTL+BMoCkS8Z3rrXajJ0KDb3g0ijGZ3QUFTpoa5fCVmeV/On/IuqGA8bmguqG6",
    "diff_run1_call_001": CALL_001_XSIGN,
    "diff_run1_call_003": "azYBCM007xAAo0uUzOxwDBWNAUjLo0uTRC3UtdwNhLofjCuKcKf4Vltfi7qVoNd/YsBCkXxYsdwIKU/X6NF/3xIvHQNLkOGDe4NLk0",
    "diff_run1_call_004": "azYBCM007xAAobVDBd/tCgTJ7jwFAbVBuv8qZyLfemjhXtVYjnUGhKWNdWhrcimtnBK8Q4KKTw72+7EFFgOBDez949G1QhKhhVG1Qb",
    "diff_run1_call_005": "azYBCM007xAAqVxW9B0aoS9pUvJ8CVxZU+fDf8vHk3AIRjxAZ23vnEyVnHCCasC1dQpVW2uSphYf41gd/xtoFQXlCslcWvZpbHlcWV",
    "jni_only_call_001": "azYBCM007xAApHrmlCyZkzRvMUHKxHrkdVrlwu16tc0u%2Bxr9QdDJIWoous2k1%2BYIU7dz5k0vgKs5Xn6g2aZOqCNYLHR660L0SsR65H",
}

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

CALL_001_SEMANTIC_TAIL_HEX = (
    "0a626105d528b91a5f1a0eaf606261629a8b930b188e93f7209460"
    "f1d2295d336dae63ff825bafa0f452f1411dddc5965ac22528554125"
    "a7faa708626158de6160626162"
)

TRACE_TAIL_WRITER_MAP = {
    "scratch_addr": "0x74b68bcc1d",
    "size": 68,
    "idx_hi": 14739000,
    "matched": 228,
    "returned": 228,
    "truncated": False,
    "writer_runs": 32,
    "semantic_kind_counts": {
        "add_small_delta": 2,
        "bitwise_or_merge": 13,
        "mod255_low_byte": 7,
        "shift_right": 12,
        "ubfx": 12,
        "xor_identity": 6,
    },
    "classes": [
        {
            "range": "0..6",
            "bytes_hex": "0a626105d528b9",
            "note": "single-byte stores; offsets 1 and 2 already fold through mod255",
        },
        {
            "range": "7..54",
            "note": "packed 32-bit stores; short chains classify as OR merge plus ubfx/shift_right byte extraction",
        },
        {
            "range": "3..6 deeper selected chains",
            "note": "selected long chains expose add_known_constant(md5_iv_a), add32_mix, 32-bit shift_left, and identity masks",
        },
        {
            "range": "59..60,65..67",
            "bytes_hex": "6261626162",
            "note": "mod255_low_byte with xor_identity normalization; includes repeated suffix 62 61 62",
        },
    ],
}

TRACE_CRYPTO_EVIDENCE = {
    "status": "candidate_component",
    "note": "MD5/SHA1 IV constants are loaded in the same VM bytecode window, but final digest linkage is not proven yet.",
    "iv_hits": [
        {
            "name": "MD5_A/SHA1_H0",
            "value": "0x67452301",
            "addr": "0x74fbf3ae98",
            "first_idx": 14590463,
        },
        {
            "name": "MD5_B/SHA1_H1",
            "value": "0xefcdab89",
            "addr": "0x74fbf3aeb8",
            "first_idx": 14590471,
        },
        {
            "name": "MD5_C/SHA1_H2",
            "value": "0x98badcfe",
            "addr": "0x74fbf3aef8",
            "first_idx": 14590500,
        },
        {
            "name": "MD5_D/SHA1_H3",
            "value": "0x10325476",
            "addr": "0x74fbf3af18",
            "first_idx": 14590508,
        },
    ],
    "packed_vm_values": [
        "0xefcdab8967452301",
        "0x1032547698badcfe",
    ],
    "hash_finalize_md5_candidates": [
        {
            "addr": "0x74b68bc770",
            "enter_idx": 13749400,
            "exit_idx": 13749442,
            "size": 16,
        },
        {
            "addr": "0x74b68bc780",
            "enter_idx": 13749456,
            "exit_idx": 13749466,
            "size": 16,
        },
        {
            "addr": "0x74b68bca08",
            "enter_idx": 13750906,
            "exit_idx": 13750912,
            "size": 16,
        },
    ],
}

TRACE_TAIL_REPEAT_EVIDENCE = [
    {
        "semantic_offset": 65,
        "byte": 0x62,
        "scratch_addr": "0x74b68bcc5e",
        "xor_identity_idx": 14712345,
        "mod255_input": 0x74FFAFCA73,
    },
    {
        "semantic_offset": 66,
        "byte": 0x61,
        "scratch_addr": "0x74b68bcc5f",
        "xor_identity_idx": 14712478,
        "mod255_input": 0x74BEABE59C,
    },
    {
        "semantic_offset": 67,
        "byte": 0x62,
        "scratch_addr": "0x74b68bcc60",
        "xor_identity_idx": 14712611,
        "mod255_input": 0x74FFAFCA73,
    },
]


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


def aligned_tail(xsign: str) -> bytes:
    xsign = urllib.parse.unquote(xsign)
    tail_chars = xsign[FIXED_PREFIX_CHARS:]
    return b64decode_unpadded(TAIL_ALIGNMENT_PREFIX + tail_chars)


def semantic_tail(xsign: str) -> bytes:
    return aligned_tail(xsign)[1:]


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
    tail_chars = urllib.parse.unquote(CALL_001_XSIGN)[FIXED_PREFIX_CHARS:]
    aligned = aligned_tail(CALL_001_XSIGN)
    semantic = aligned[1:]
    sample_tails = {name: semantic_tail(xsign) for name, xsign in SAMPLE_XSIGNS.items()}
    reencoded_tail = b64encode_unpadded(aligned)
    expected_semantic = bytes.fromhex(CALL_001_SEMANTIC_TAIL_HEX)
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
    scratch0, scratch1, scratch2, scratch3 = semantic[:4]
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
            "aligned_tail_len": len(aligned),
            "aligned_tail_prefix_hex": aligned[:16].hex(),
            "semantic_tail_prefix_hex": semantic[:16].hex(),
            "semantic_tail_hex": semantic.hex(),
            "semantic_tail_matches_writer_map": semantic == expected_semantic,
            "reencoded_tail_prefix": reencoded_tail[:18],
            "tail_reencodes_xsign_tail_from_char_2": reencoded_tail[2:] == tail_chars,
            "note": "The first aligned byte is synthetic; semantic tracing starts at aligned_tail[1].",
        },
        "semantic_tail_writer_map": {
            **TRACE_TAIL_WRITER_MAP,
            "bytes_hex": CALL_001_SEMANTIC_TAIL_HEX,
            "complete": TRACE_TAIL_WRITER_MAP["matched"] == TRACE_TAIL_WRITER_MAP["returned"]
            and not TRACE_TAIL_WRITER_MAP["truncated"]
            and semantic == expected_semantic,
            "trace_command": (
                "tracemiku-cli byte-writer-map <call_dir> --addr 0x74b68bcc1d "
                "--size 68 --idx-hi 14739000 --max 300 --vm-chain-steps 10 "
                "--vm-chain-runs 34 --vm-chain-follow-frontier"
            ),
        },
        "crypto_evidence": TRACE_CRYPTO_EVIDENCE,
        "multi_sample_tail_structure": {
            "samples": len(sample_tails),
            "tail_lengths": sorted({len(tail) for tail in sample_tails.values()}),
            "stable_tail_offsets": [
                offset
                for offset in range(min(len(tail) for tail in sample_tails.values()))
                if len({tail[offset] for tail in sample_tails.values()}) == 1
            ],
            "tail0_value": f"{next(iter(sample_tails.values()))[0]:#x}",
            "repeat_13_16_to_65_68_all": all(tail[13:16] == tail[65:68] for tail in sample_tails.values()),
            "repeat_examples": {
                name: {
                    "tail_13_16": tail[13:16].hex(),
                    "tail_65_68": tail[65:68].hex(),
                }
                for name, tail in sample_tails.items()
            },
            "trace_note": "Repeated bytes are equality evidence only; call_001 currently shows re-encoding through VM scratch/Base64, not direct string memcpy.",
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
        "tail_repeat_trace_evidence": [
            {
                **item,
                "byte": f"{item['byte']:#x}",
                "mod255_input": f"{item['mod255_input']:#x}",
                "mod255_computed": f"{mod255_low_byte(item['mod255_input']):#x}",
                "matches_trace": mod255_low_byte(item["mod255_input"]) == item["byte"],
                "frontier_semantic": "xor_identity feeds the non-zero operand before the mod255 fold",
            }
            for item in TRACE_TAIL_REPEAT_EVIDENCE
        ],
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
