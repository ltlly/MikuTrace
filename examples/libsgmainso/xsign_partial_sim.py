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
- byte-level backward chains must keep the writer's little-endian
  source_byte_offset as byte_lane when crossing multi-byte loads;
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
        "xor_identity": 5,
        "xor_mix": 24,
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
            "note": (
                "lane-aware selected long chains expose XOR byte mixing such as "
                "tail[4] 0xd5 = 0xb4 ^ 0x61 plus add_known_constant(md5_iv_a), "
                "add32_mix, and 32-bit shift/extract operations"
            ),
        },
        {
            "range": "59..60,65..67",
            "bytes_hex": "6261626162",
            "note": "mod255_low_byte with xor_identity normalization; includes repeated suffix 62 61 62",
        },
    ],
}

TRACE_MULTI_SAMPLE_WRITER_MAPS = {
    "status": "stable_auto_anchor",
    "samples": 5,
    "all_complete": True,
    "semantic_len": 68,
    "writer_runs": 32,
    "command": (
        "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
        "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-writer-map --summary"
    ),
    "calls": [
        {
            "name": "_truncated_call_006",
            "idx_hi": 7083756,
            "matched_writes": 189,
        },
        {
            "name": "call_001",
            "idx_hi": 14747885,
            "matched_writes": 228,
        },
        {
            "name": "call_003",
            "idx_hi": 7007945,
            "matched_writes": 179,
        },
        {
            "name": "call_004",
            "idx_hi": 6988275,
            "matched_writes": 179,
        },
        {
            "name": "call_005",
            "idx_hi": 7029973,
            "matched_writes": 179,
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
            "name": "SHA1_H3/MD5_D",
            "value": "0x10325476",
            "addr": "0x74fbf3af18",
            "first_idx": 14590508,
        },
        {
            "name": "SHA1_H4",
            "value": "0xc3d2e1f0",
            "addr": "0x74fbf3af58",
            "first_idx": 14590537,
        },
    ],
    "packed_vm_values": [
        "0xefcdab8967452301",
        "0x1032547698badcfe",
        "0xc3d2e1f0",
    ],
    "hash_finalize_map_summary": {
        "command": (
            "tracemiku-cli hash-finalize-detect <call_dir> --limit 50 --window 500 "
            "--min-size 16 --map-bytes --map-candidates 10 --target-bytes <semantic_tail_hex>"
        ),
        "inspected": 10,
        "zero_candidates": 7,
        "nonzero_candidates": 3,
        "target_hit_candidates": 0,
        "interpretation": (
            "No inspected finalize candidate bytes occur inside the 68-byte semantic tail; "
            "continue anchoring backward analysis at the final tail byte-writer map."
        ),
    },
    "hash_finalize_md5_candidates": [
        {
            "addr": "0x74b68bc770",
            "enter_idx": 13749400,
            "exit_idx": 13749442,
            "size": 16,
            "byte_writer_map": "all_zero",
        },
        {
            "addr": "0x74b68bc780",
            "enter_idx": 13749456,
            "exit_idx": 13749466,
            "size": 16,
            "byte_writer_map": "all_zero",
        },
        {
            "addr": "0x74b68bca08",
            "enter_idx": 13750906,
            "exit_idx": 13750912,
            "size": 16,
            "byte_writer_map": "all_zero",
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

TRACE_TAIL_XOR_EQUATIONS = [
    {
        "semantic_offset": 3,
        "lhs": 0x67,
        "rhs": 0x62,
        "expected": 0x05,
        "source": "lane-aware vm-backchain step 4",
    },
    {
        "semantic_offset": 4,
        "lhs": 0xB4,
        "rhs": 0x61,
        "expected": 0xD5,
        "source": "lane-aware vm-backchain step 4",
    },
    {
        "semantic_offset": 5,
        "lhs": 0x4A,
        "rhs": 0x62,
        "expected": 0x28,
        "source": "lane-aware vm-backchain step 4",
    },
    {
        "semantic_offset": 6,
        "lhs": 0xD8,
        "rhs": 0x61,
        "expected": 0xB9,
        "source": "lane-aware vm-backchain step 4",
    },
]

TRACE_MULTI_SAMPLE_XOR_WORDS = {
    "diff_run1_truncated_call_006": {
        "state_word_le": 0x3B61D005,
        "source": "lane-aware byte_equations lhs bytes 05 d0 61 3b",
    },
    "diff_run1_call_001": {
        "state_word_le": 0xD84AB467,
        "source": "lane-aware byte_equations lhs bytes 67 b4 4a d8",
    },
    "diff_run1_call_003": {
        "state_word_le": 0xB9F37778,
        "source": "lane-aware byte_equations lhs bytes 78 77 f3 b9",
    },
    "diff_run1_call_004": {
        "state_word_le": 0x84E5092B,
        "source": "lane-aware byte_equations lhs bytes 2b 09 e5 84",
    },
    "diff_run1_call_005": {
        "state_word_le": 0x6F4484FA,
        "source": "lane-aware byte_equations lhs bytes fa 84 44 6f",
    },
}

TRACE_MULTI_SAMPLE_MASK_FOLDS = {
    "diff_run1_truncated_call_006": {
        "tail1_input": 0x750A2E58B4,
        "tail2_input": 0x75294D862F,
    },
    "diff_run1_call_001": {
        "tail1_input": 0x74FFAFCA73,
        "tail2_input": 0x74BEABE59C,
    },
    "diff_run1_call_003": {
        "tail1_input": 0x753D0189F6,
        "tail2_input": 0x757A6F4E0C,
    },
    "diff_run1_call_004": {
        "tail1_input": 0x7502282E4D,
        "tail2_input": 0x74D57E8EFC,
    },
    "diff_run1_call_005": {
        "tail1_input": 0x75A8D92776,
        "tail2_input": 0x75011196A7,
    },
}

TRACE_CALL_001_STATE_WORD_SOURCE = {
    "state_buffer_addr": "0x74b68bb6a8",
    "state_word_loaded_idx": 14678409,
    "state_word_loaded_value": 0x67B44AD8,
    "state_word_writer_idx": 14678167,
    "state_word_writer_asm": "str w1, [x19, x6]",
    "state_word_writer_src_value": 0x267B44AD8,
    "state_add_idx": 14678154,
    "state_add_asm": "add x13, x8, x12",
    "state_add_lhs": 0x1B57FEB14,
    "state_add_rhs": 0xB2345FC4,
    "previous_state_writer_idx": 14635558,
    "previous_state_word": 0xB2345FC4,
    "round_accumulator": 0xB57FEB14,
    "state_updates": [
        {
            "formula_idx": 14678154,
            "store_idx": 14678167,
            "store_addr": "0x74b68bb6a8",
            "lhs": 0x1B57FEB14,
            "rhs": 0xB2345FC4,
            "result": 0x267B44AD8,
        },
        {
            "formula_idx": 14678176,
            "store_idx": 14678188,
            "store_addr": "0x74b68bb6ac",
            "lhs": 0x561D4E18,
            "rhs": 0x22212A57,
            "result": 0x783E786F,
        },
        {
            "formula_idx": 14678197,
            "store_idx": 14678209,
            "store_addr": "0x74b68bb6b0",
            "lhs": 0x2E657DF9,
            "rhs": 0x9F97230B,
            "result": 0xCDFCA104,
        },
        {
            "formula_idx": 14678218,
            "store_idx": 14678230,
            "store_addr": "0x74b68bb6b4",
            "lhs": 0x9397F163,
            "rhs": 0xB87FE8D3,
            "result": 0x14C17DA36,
        },
        {
            "formula_idx": 14678239,
            "store_idx": 14678255,
            "store_addr": "0x74b68bb6b8",
            "lhs": 0x059D465C,
            "rhs": 0x69C3F988,
            "result": 0x6F613FE4,
        },
    ],
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


def xor_mix(lhs: int, rhs: int) -> int:
    return (lhs ^ rhs) & 0xFF


def word32_le_bytes(value: int) -> bytes:
    return int(value & 0xFFFFFFFF).to_bytes(4, "little")


def bswap32(value: int) -> int:
    return int.from_bytes(int(value & 0xFFFFFFFF).to_bytes(4, "big"), "little")


def xor_word_tail_bytes(state_word: int, mask_a: int, mask_b: int) -> bytes:
    state = word32_le_bytes(state_word)
    return bytes(
        [
            xor_mix(state[0], mask_a),
            xor_mix(state[1], mask_b),
            xor_mix(state[2], mask_a),
            xor_mix(state[3], mask_b),
        ]
    )


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
    xor_equations = [
        {
            **item,
            "lhs": f"{item['lhs']:#x}",
            "rhs": f"{item['rhs']:#x}",
            "computed": f"{xor_mix(item['lhs'], item['rhs']):#x}",
            "expected": f"{item['expected']:#x}",
            "matches_trace": xor_mix(item["lhs"], item["rhs"]) == item["expected"],
        }
        for item in TRACE_TAIL_XOR_EQUATIONS
    ]
    xor_reconstructed = bytearray(semantic[:7])
    for item in TRACE_TAIL_XOR_EQUATIONS:
        xor_reconstructed[item["semantic_offset"]] = xor_mix(item["lhs"], item["rhs"])
    xor_word_samples = {}
    for name, item in TRACE_MULTI_SAMPLE_XOR_WORDS.items():
        tail = sample_tails[name]
        computed = xor_word_tail_bytes(item["state_word_le"], tail[1], tail[2])
        xor_word_samples[name] = {
            "state_word_le": f"{item['state_word_le']:#x}",
            "state_bytes_le": word32_le_bytes(item["state_word_le"]).hex(),
            "mask_bytes_from_tail_1_2": tail[1:3].hex(),
            "computed_tail_3_7": computed.hex(),
            "expected_tail_3_7": tail[3:7].hex(),
            "matches_trace": computed == tail[3:7],
            "source": item["source"],
        }
    mask_fold_samples = {}
    for name, item in TRACE_MULTI_SAMPLE_MASK_FOLDS.items():
        tail = sample_tails[name]
        computed_tail1 = mod255_low_byte(item["tail1_input"])
        computed_tail2 = mod255_low_byte(item["tail2_input"])
        mask_fold_samples[name] = {
            "tail1_input": f"{item['tail1_input']:#x}",
            "tail1_computed": f"{computed_tail1:#x}",
            "tail1_expected": f"{tail[1]:#x}",
            "tail1_matches": computed_tail1 == tail[1],
            "tail2_input": f"{item['tail2_input']:#x}",
            "tail2_computed": f"{computed_tail2:#x}",
            "tail2_expected": f"{tail[2]:#x}",
            "tail2_matches": computed_tail2 == tail[2],
        }
    state_source = TRACE_CALL_001_STATE_WORD_SOURCE
    state_source_add_low32 = (state_source["state_add_lhs"] + state_source["state_add_rhs"]) & 0xFFFFFFFF
    state_source_loaded = state_source["state_word_loaded_value"] & 0xFFFFFFFF
    state_source_word_le = bswap32(state_source_loaded)
    state_updates = [
        {
            **item,
            "lhs": f"{item['lhs']:#x}",
            "lhs_low32": f"{item['lhs'] & 0xFFFFFFFF:#x}",
            "rhs": f"{item['rhs']:#x}",
            "rhs_low32": f"{item['rhs'] & 0xFFFFFFFF:#x}",
            "result": f"{item['result']:#x}",
            "result_low32": f"{item['result'] & 0xFFFFFFFF:#x}",
            "computed_low32": f"{(item['lhs'] + item['rhs']) & 0xFFFFFFFF:#x}",
            "matches_result_low32": ((item["lhs"] + item["rhs"]) & 0xFFFFFFFF)
            == (item["result"] & 0xFFFFFFFF),
        }
        for item in state_source["state_updates"]
    ]
    state_words_be = [item["result"] & 0xFFFFFFFF for item in state_source["state_updates"]]
    state_digest_be = b"".join(value.to_bytes(4, "big") for value in state_words_be)

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
            "auto_trace_command": (
                "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
                "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-writer-map "
                "--semantic-writer-map-vm-chain-steps 4 --semantic-writer-map-vm-chain-runs 3 "
                "--semantic-writer-map-vm-chain-follow-frontier --summary"
            ),
            "auto_trace_result": {
                "semantic_addr": "0x74b68bcc1d",
                "idx_hi": 14747885,
                "idx_hi_source": "first_final_output_writer",
                "writer_runs": 32,
                "expanded_chain_semantics": {
                    "mod255_low_byte": 2,
                },
            },
        },
        "multi_sample_writer_maps": TRACE_MULTI_SAMPLE_WRITER_MAPS,
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
        "tail_xor_equations": {
            "status": "partial_trace_equations",
            "equations": xor_equations,
            "reconstructed_offsets": [item["semantic_offset"] for item in TRACE_TAIL_XOR_EQUATIONS],
            "reconstructed_prefix_0_7_hex": bytes(xor_reconstructed).hex(),
            "matches_semantic_prefix_0_7": bytes(xor_reconstructed) == semantic[:7],
            "multi_sample_word_template": {
                "formula": "tail[3:7] = word32_le(state_word) ^ [tail[1], tail[2], tail[1], tail[2]]",
                "samples": xor_word_samples,
                "all_match": all(item["matches_trace"] for item in xor_word_samples.values()),
            },
            "call_001_state_word_source": {
                "status": "trace_proven_one_sample",
                "state_buffer_addr": state_source["state_buffer_addr"],
                "sha1_like_state_words_be": [f"{value:#x}" for value in state_words_be],
                "sha1_like_state_digest_be_hex": state_digest_be.hex(),
                "all_state_updates_match_low32": all(item["matches_result_low32"] for item in state_updates),
                "state_updates": state_updates,
                "loaded_idx": state_source["state_word_loaded_idx"],
                "loaded_word_be": f"{state_source_loaded:#x}",
                "template_state_word_le": f"{state_source_word_le:#x}",
                "matches_template_state_word": state_source_word_le
                == TRACE_MULTI_SAMPLE_XOR_WORDS["diff_run1_call_001"]["state_word_le"],
                "writer_idx": state_source["state_word_writer_idx"],
                "writer_asm": state_source["state_word_writer_asm"],
                "writer_src_value": f"{state_source['state_word_writer_src_value']:#x}",
                "writer_low32": f"{state_source['state_word_writer_src_value'] & 0xFFFFFFFF:#x}",
                "state_add": {
                    "idx": state_source["state_add_idx"],
                    "asm": state_source["state_add_asm"],
                    "lhs": f"{state_source['state_add_lhs']:#x}",
                    "lhs_low32": f"{state_source['state_add_lhs'] & 0xFFFFFFFF:#x}",
                    "rhs": f"{state_source['state_add_rhs']:#x}",
                    "rhs_low32": f"{state_source['state_add_rhs'] & 0xFFFFFFFF:#x}",
                    "computed_low32": f"{state_source_add_low32:#x}",
                    "matches_loaded_word": state_source_add_low32 == state_source_loaded,
                },
                "interpretation": (
                    "tail[3:7] uses the big-endian byte order of a 32-bit state "
                    "word loaded from the hash/state buffer; the tail template "
                    "stores those bytes as word32_le(bswap32(state_word_be))."
                ),
            },
            "multi_sample_mask_folds": {
                "formula": "tail[1], tail[2] = (input + input // 0xff) & 0xff",
                "samples": mask_fold_samples,
                "all_match": all(
                    item["tail1_matches"] and item["tail2_matches"]
                    for item in mask_fold_samples.values()
                ),
            },
            "upstream_lane_note": (
                "Offsets 4..6 require byte-lane-aware OR/shift/extract tracking; "
                "otherwise the chain can drift into neighboring packed-word bytes."
            ),
        },
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
            "full semantic tail construction after the currently proven XOR/mod255 fragments",
            "meaning of the fixed 12-character prefix / 9 decoded bytes",
            "all VM bytecode templates feeding Base64 indexes",
            "role of the LCG/time state in every payload byte",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
