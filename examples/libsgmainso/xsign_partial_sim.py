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
- one VM byte-load boundary now explains slot[18] = byte[0x753ddd7fdc]
  (0x7a), but the producing helper call is not lifted yet.

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
BOUNDARY_STAT_LAUNCH2_XSIGN = (
    "azYBCM007xAAqErog5popN6eEiM6+EroRVbVzt12hcEc4eryggz5IyuqOsGVBI4Oc1UoT9ABO3oZUk6s6ap+pBNUHHhK7M04evhK6E"
)

SAMPLE_XSIGNS = {
    "diff_run1_truncated_call_006": "azYBCM007xAAq6ob9x25o0UaJH1qe6obpaU1PT2FZTL+BMoCkS8Z3rrXajJ0KDb3g0ijGZ3QUFTpoa5fCVmeV/On/IuqGA8bmguqG6",
    "diff_run1_call_001": CALL_001_XSIGN,
    "diff_run1_call_003": "azYBCM007xAAo0uUzOxwDBWNAUjLo0uTRC3UtdwNhLofjCuKcKf4Vltfi7qVoNd/YsBCkXxYsdwIKU/X6NF/3xIvHQNLkOGDe4NLk0",
    "diff_run1_call_004": "azYBCM007xAAobVDBd/tCgTJ7jwFAbVBuv8qZyLfemjhXtVYjnUGhKWNdWhrcimtnBK8Q4KKTw72+7EFFgOBDez949G1QhKhhVG1Qb",
    "diff_run1_call_005": "azYBCM007xAAqVxW9B0aoS9pUvJ8CVxZU+fDf8vHk3AIRjxAZ23vnEyVnHCCasC1dQpVW2uSphYf41gd/xtoFQXlCslcWvZpbHlcWV",
    "jni_only_call_001": "azYBCM007xAApHrmlCyZkzRvMUHKxHrkdVrlwu16tc0u%2Bxr9QdDJIWoous2k1%2BYIU7dz5k0vgKs5Xn6g2aZOqCNYLHR660L0SsR65H",
    "boundary_stat_launch2_call_001": BOUNDARY_STAT_LAUNCH2_XSIGN,
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

CALL001_STAT_MTIM_TV_SEC = 0x69F2E9FB
CALL001_MIDDLE_LHS_MIXED_SUFFIX_HEX = (
    "79ecf29541f60193b34b3c510ccc029de339cec2953090237cbfa4f43b"
    "a0444a342344c59bc569"
)

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
        "add_small_delta": 6,
        "bitwise_or_merge": 16,
        "mod255_low_byte": 7,
        "shift_right": 13,
        "ubfx": 13,
        "xor_identity": 6,
        "xor_mix": 23,
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

TRACE_FIXED_PREFIX_WRITER_MAP = {
    "status": "trace_observed_string_prefix",
    "raw_prefix": "azYBCM007xAA",
    "raw_prefix_hex": "617a5942434d303037784141",
    "whole_base64_decoded_hex": "6b360108cd34ef1000",
    "decoded_prefix_direct_trace_hits": 0,
    "raw_prefix_hits": [
        {"addr": "0x74b68bcc1c", "first_idx": 14755491},
        {"addr": "0x756649a2d0", "first_idx": 14761618},
        {"addr": "0x756649f510", "first_idx": 14818316},
        {"addr": "0x756649fb35", "first_idx": 14803456},
    ],
    "copy_buffer_writer_runs": [
        {
            "range": [0, 4],
            "ascii": "azYB",
            "src_value": "0x42597a61",
            "writer_idx": 14755538,
        },
        {
            "range": [4, 8],
            "ascii": "CM00",
            "src_value": "0x30304d43",
            "writer_idx": 14755552,
        },
        {
            "range": [8, 12],
            "ascii": "7xAA",
            "src_value": "0x41417837",
            "writer_idx": 14755558,
        },
    ],
    "interpretation": (
        "The stable prefix is observed as raw Base64 text written/copied in "
        "three little-endian word stores. The decoded nine-byte prefix is not "
        "observed directly in trace memory, so the simulator should treat the "
        "raw 12-character prefix as the current evidence boundary."
    ),
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
        "source_word_be": 0x05D0613B,
        "state_add_idx": 7014025,
        "state_add_lhs": 0x27DA05E37,
        "state_add_rhs": 0x88300304,
        "state_add_result": 0x305D0613B,
    },
    "diff_run1_call_001": {
        "state_word_le": 0xD84AB467,
        "source": "lane-aware byte_equations lhs bytes 67 b4 4a d8",
        "source_word_be": 0x67B44AD8,
        "state_add_idx": 14678154,
        "state_add_lhs": 0x1B57FEB14,
        "state_add_rhs": 0xB2345FC4,
        "state_add_result": 0x267B44AD8,
    },
    "diff_run1_call_003": {
        "state_word_le": 0xB9F37778,
        "source": "lane-aware byte_equations lhs bytes 78 77 f3 b9",
        "source_word_be": 0x7877F3B9,
        "state_add_idx": 6938214,
        "state_add_lhs": 0x17E6740B3,
        "state_add_rhs": 0xFA10B306,
        "state_add_result": 0x27877F3B9,
    },
    "diff_run1_call_004": {
        "state_word_le": 0x84E5092B,
        "source": "lane-aware byte_equations lhs bytes 2b 09 e5 84",
        "source_word_be": 0x2B09E584,
        "state_add_idx": 6918544,
        "state_add_lhs": 0x20D8147DD,
        "state_add_rhs": 0x1D889DA7,
        "state_add_result": 0x22B09E584,
    },
    "diff_run1_call_005": {
        "state_word_le": 0x6F4484FA,
        "source": "lane-aware byte_equations lhs bytes fa 84 44 6f",
        "source_word_be": 0xFA84446F,
        "state_add_idx": 6960242,
        "state_add_lhs": 0x2B018C817,
        "state_add_rhs": 0x4A6B7C58,
        "state_add_result": 0x2FA84446F,
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

TRACE_CALL_001_BYTE_LANE_STATE_SOURCE = {
    "command": (
        "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
        "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-offset 7 "
        "--semantic-count 32 --semantic-writer-map --semantic-writer-map-vm-chain-bytes "
        "--semantic-writer-map-vm-chain-steps 55 --semantic-writer-map-vm-chain-runs 32 "
        "--semantic-writer-map-vm-chain-follow-frontier --summary"
    ),
    "vm_chain_seed_mode": "bytes",
    "byte_equation_count": 32,
    "selected_semantic_offset": 7,
    "local_semantic_range": [0, 4],
    "lhs_word_le": 0x6F783E78,
    "source_word": 0x783E786F,
    "source_word_match": "bswap_lhs_word_le",
    "word_extract_idx": 14678516,
    "word_extract_asm": "lsr w14, w13, w11",
    "state_add_idx": 14678176,
    "state_add_asm": "add x13, x8, x12",
    "state_add_lhs": 0x561D4E18,
    "state_add_rhs": 0x22212A57,
    "state_add_result": 0x783E786F,
}

TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY = {
    "command": (
        "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
        "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-offset 0 "
        "--semantic-count 68 --semantic-writer-map --semantic-writer-map-vm-chain-bytes "
        "--semantic-writer-map-vm-chain-steps 16 --semantic-writer-map-vm-chain-runs 68 "
        "--semantic-writer-map-vm-chain-follow-frontier --summary"
    ),
    "byte_equation_count": 68,
    "requested_range": [0, 68],
    "requested_coverage_status": "complete_in_requested_range",
    "covered_range": [0, 68],
    "kind_counts": {
        "byte_lane_extract": 1,
        "mod255_low_byte": 10,
        "xor_mix": 57,
    },
    "byte_lane_equations": [
        {
            "offset": 0,
            "source_value": 0x0A000142,
            "source_byte_offset": 3,
            "result": 0x0A,
            "expression": "result == byte_lane_le(source_value, source_byte_offset)",
        }
    ],
    "input_summary": {
        "byte_lane_sources": [
            {
                "source_value": 0x0A000142,
                "offsets": [0],
                "source_byte_offsets": [3],
                "result_hex": "0a",
            }
        ],
        "mod255_inputs": [
            {
                "input": 0x74BEABE59C,
                "output_byte": 0x61,
                "quotient": 0x7533DFC5,
                "offsets": [2, 14, 60, 66],
            },
            {
                "input": 0x74FFAFCA73,
                "output_byte": 0x62,
                "quotient": 0x757524EF,
                "offsets": [1, 13, 15, 59, 65, 67],
            },
        ],
        "xor_lhs_offsets": (
            list(range(3, 13))
            + list(range(16, 59))
            + list(range(61, 65))
        ),
    },
    "xor_rhs_pattern": {
        "kind": "offset_parity_mask",
        "even_byte": 0x61,
        "odd_byte": 0x62,
        "matched_offsets": 57,
    },
    "xor_lhs_runs": [
        {
            "range": [3, 13],
            "lhs_hex": "67b44ad8783e786fcd01",
            "rhs_hex": "62616261626162616261",
            "result_hex": "05d528b91a5f1a0eaf60",
        },
        {
            "range": [16, 59],
            "lhs_hex": (
                "fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237c"
                "bfa4f43ba0444a342344c59bc569"
            ),
            "rhs_hex": (
                "616261626162616261626162616261626162616261626162616261626162"
                "61626162616261626162616261"
            ),
            "result_hex": (
                "9a8b930b188e93f7209460f1d2295d336dae63ff825bafa0f452f1"
                "411dddc5965ac22528554125a7faa708"
            ),
        },
        {
            "range": [61, 65],
            "lhs_hex": "3abf0301",
            "rhs_hex": "62616261",
            "result_hex": "58de6160",
        },
    ],
    "unexplained_offsets": [],
}

TRACE_MOD255_INPUT_LCG_CHAIN = {
    "status": "trace_proven_one_sample",
    "command": (
        "tracemiku-cli vm-backchain <call_dir> --idx 13946345 --reg x13 "
        "--steps 45 --follow-frontier --summary"
    ),
    "semantic_offset": 1,
    "mod255_input": 0x74FFAFCA73,
    "output_byte": 0x62,
    "chain_head": [
        "0x74ffafca73 = 0x74ffafbdec + 0xc87",
        "0x74ffafbdec = 0x69adbccc | 0x74b68bb9a4",
        "0x69adbccc = (0xd35b7999 >> 1) & 0xffffffff",
        "0xd35b7999 = low32(0x099bd5d2 + 0xc9bfa3c7)",
        "0x099bd5d2 = 0x99bd5d21d7d8103 >> 0x20",
    ],
    "lcg_multiplier": LCG_MULT,
    "lcg_increment": LCG_INC,
    "lcg_states_seen": [
        0x99BD5D21D7D8103,
        0xDD1841BEA148764A,
        0x52C36263893DA50D,
        0x5036F3354BED40BC,
        0xC4FCFFE67B71F087,
        0x4B1654CDFCB8F65E,
        0x7988B092011B51F1,
        0x9A7BE8B46D894FB0,
    ],
}

TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN = {
    "status": "trace_proven_one_sample",
    "command": (
        "tracemiku-cli vm-backchain <call_dir> --idx 13946997 --reg x13 "
        "--steps 45 --follow-frontier --summary"
    ),
    "semantic_offset": 2,
    "mod255_input": 0x74BEABE59C,
    "output_byte": 0x61,
    "chain_head": [
        "0x74beabe59c uses vm frontier value 0x25a8",
        "0x25a8 = 0x2595 + 0x13",
        "0x2595 = 0xc87 * 0x3",
    ],
    "small_affine": TRACE_SMALL_AFFINE,
}

TRACE_BYTE_LANE_STATIC_SOURCE = {
    "status": "trace_proven_one_sample",
    "command": (
        "tracemiku-cli vm-backchain <call_dir> --idx 13781975 --reg x1 "
        "--steps 10 --follow-frontier --summary"
    ),
    "semantic_offset": 0,
    "source_value": 0x0A000142,
    "load_idx": 13720346,
    "load_asm": "ldr w16, [x8, x20]",
    "addr": "0x74fbf2dc7c",
    "observed_bytes_hex": "4201000a",
    "interpretation": "static_memory_load_constant",
}

TRACE_BASE64_PAYLOAD_PREFIX_FORMULAS = {
    "command": (
        "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
        "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-offset 0 "
        "--semantic-count 8 --index-tree-depth 8 --index-tree-max-nodes 180 "
        "--lookback 500000 --summary"
    ),
    "semantic_range": [0, 8],
    "semantic_hex": "0a626105d528b91a",
    "rows": [
        {
            "semantic_offset": 0,
            "value_hex": "0a",
            "base64_formula": "((i1 & 0x0f) << 4) | (i2 >> 2)",
            "index_formulas": ["0x0 = 0x0a >> 0x4", "0x29 = 0x28 | 0x1"],
        },
        {
            "semantic_offset": 1,
            "value_hex": "62",
            "base64_formula": "((i2 & 0x03) << 6) | i3",
            "index_formulas": ["0x29 = 0x28 | 0x1", "0x22 = 0x62 & 0x3f"],
        },
        {
            "semantic_offset": 2,
            "value_hex": "61",
            "base64_formula": "(i0 << 2) | (i1 >> 4)",
            "index_formulas": ["0x18 = 0x61 >> 0x2", "0x10 = 0x610 & 0x30"],
        },
        {
            "semantic_offset": 3,
            "value_hex": "05",
            "base64_formula": "((i1 & 0x0f) << 4) | (i2 >> 2)",
            "index_formulas": ["0x10 = 0x610 & 0x30", "0x17 = 0x14 | 0x3"],
        },
        {
            "semantic_offset": 4,
            "value_hex": "d5",
            "base64_formula": "((i2 & 0x03) << 6) | i3",
            "index_formulas": ["0x17 = 0x14 | 0x3", "0x15 = 0xd5 & 0x3f"],
        },
        {
            "semantic_offset": 5,
            "value_hex": "28",
            "base64_formula": "(i0 << 2) | (i1 >> 4)",
            "index_formulas": ["0x0a = 0x28 >> 0x2", "0x0b = 0xb9 >> 0x4"],
        },
        {
            "semantic_offset": 6,
            "value_hex": "b9",
            "base64_formula": "((i1 & 0x0f) << 4) | (i2 >> 2)",
            "index_formulas": ["0x0b = 0xb9 >> 0x4", "0x24 = 0x2e4 & 0x3c"],
        },
        {
            "semantic_offset": 7,
            "value_hex": "1a",
            "base64_formula": "((i2 & 0x03) << 6) | i3",
            "index_formulas": ["0x24 = 0x2e4 & 0x3c", "0x1a = 0x1a & 0x3f"],
        },
    ],
    "interpretation": (
        "These rows prove the late Base64 index layer for semantic tail bytes "
        "0..7. They are still bit slicing over scratch bytes, not yet proof "
        "that those scratch bytes are final business inputs."
    ),
}

TRACE_MULTI_SAMPLE_XOR_LHS_MIDDLE_RUN = {
    "semantic_range": [16, 59],
    "size": 43,
    "samples": {
        "diff_run1_call_001": (
            "fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237c"
            "bfa4f43ba0444a342344c59bc569"
        ),
        "diff_run1_call_003": (
            "fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237c"
            "bfa4f43ba0444a342344c59bc569"
        ),
        "diff_run1_call_004": (
            "fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237c"
            "bfa4f43ba0444a342344c59bc569"
        ),
        "diff_run1_call_005": (
            "fbe9f26979ecf24141f60193b34b3c510ccc029de339cec2953090237c"
            "bfa4f43ba0444a342344c59bc569"
        ),
    },
    "interpretation": (
        "The large middle XOR lhs stream is nearly stable across diff samples; "
        "prioritize fixed table/salt/VM literal provenance before treating it "
        "as ASLR-derived pointer noise."
    ),
    "call_001_first_word_source": {
        "lhs_bytes_hex": "fbe9f269",
        "lhs_word_le": 0x69F2E9FB,
        "memory_hits": [
            {"addr": "0x74b68bbe03", "first_idx": 14691056},
            {"addr": "0x74b68bc00c", "first_idx": 14700861},
            {"addr": "0x74fbf31b48", "first_idx": 14089060},
        ],
        "earliest_writer_idx": 13980743,
        "earliest_writer_asm": "str w1, [x19, x6]",
        "earliest_writer_addr": "0x74fbf31b48",
        "earliest_writer_src_value": 0x69F2E9FB,
        "boundary": {
            "status": "observed_read_without_matching_traced_write",
            "load_idx": 13980730,
            "load_asm": "ldr x8, [x1, x5]",
            "load_addr": "0x74b68bd108",
            "observed_bytes_hex": "fbe9f26900000000",
            "external_candidate": {
                "call_idx": 13980120,
                "call_asm": "blr x22",
                "target": "libc.so+0xa0f5c",
                "target_symbol": "stat@@LIBC",
                "path_reg": "x0",
                "path_addr": "0x753dcfeac0",
                "path_string": "/",
                "arg_reg": "x1",
                "arg_base": "0x74b68bd0b0",
                "field_offset": "0x58",
                "android_aarch64_struct_stat_field": "st_mtim.tv_sec",
                "field_value": 0x69F2E9FB,
                "field_value_hex": "0x69f2e9fb",
                "field_value_local_iso": "2026-04-30T13:34:51+08:00",
            },
            "stale_writer_idx": 13979551,
            "stale_writer_asm": "str x6, [x19, x20]",
            "stale_writer_src_value": 0x0,
            "touching_addr_with_bytes": {
                "addr": "0x74b68bd108",
                "cursor": 13980730,
                "before": [{"idx": 13979551, "kind": "w", "byte": 0x00}],
                "after": [{"idx": 13980730, "kind": "r", "byte": 0xFB}],
            },
            "interpretation": (
                "The chain reaches an observed memory value that is not explained "
                "by the latest traced write; stop here instead of following the "
                "stale zero write."
            ),
        },
    },
}

TRACE_XOR_WORD_SOURCE_COVERAGE = {
    "command": (
        "tracemiku-cli output-map <call_dir> --key x-sign --base64-tail-start 12 "
        "--base64-tail-align-prefix AA --base64-tail-drop 1 --semantic-offset 0 "
        "--semantic-count 68 --semantic-writer-map "
        "--semantic-writer-map-vm-chain-bytes --semantic-writer-map-vm-chain-steps 90 "
        "--semantic-writer-map-vm-chain-runs 68 --semantic-writer-map-vm-chain-follow-frontier "
        "--summary"
    ),
    "coverage_status": "complete",
    "semantic_byte_equation_coverage": {
        "coverage_status": "complete_in_requested_range",
        "requested_range": [0, 68],
        "covered_count": 68,
        "missing_offsets": [],
        "kind_counts": {
            "byte_lane_extract": 2,
            "mod255_low_byte": 10,
            "xor_mix": 56,
        },
        "note": (
            "Offset 44 is not an xor byte. Its selected byte is 0x00 and is "
            "explained as byte_lane_le(0xb71300fd, 1). Earlier output-map "
            "summaries picked the first recognized xor_mix in that chain, "
            "which described neighboring result 0xfd and produced a false "
            "xor-word template."
        ),
    },
    "template_count": 13,
    "source_count": 13,
    "missing_count": 0,
    "source_status_counts": {
        "state_update_found": 2,
        "word_source_only": 11,
    },
    "interpretation": (
        "Every word-sized XOR lhs chunk has a trace source candidate. This is "
        "source coverage, not portable formula coverage: most middle/tail chunks "
        "still need their word_source_only upstream classified as static table, "
        "external metadata, or a wider-trace boundary. Full semantic-byte "
        "coverage is 68/68, but offsets 0 and 44 are byte-lane extracts rather "
        "than xor formulas."
    ),
}

TRACE_BOUNDARY_STAT_LAUNCH2_SEM16_LINEAGE = {
    "command": (
        "tracemiku-cli byte-lineage <call_dir> --addr 0x74974cc16d "
        "--before-idx 8319800 --depth 80 --lookback 5000000 --summary"
    ),
    "semantic_offset": 16,
    "status": "observed_read_without_matching_traced_write",
    "stop_step": 41,
    "load_addr": "0x74974cc648",
    "observed_bytes_hex": "fbe9f26900000000",
    "latest_traced_write": {
        "idx": 7571629,
        "asm": "str x6, [x19, x20]",
        "src_value": "0x0",
    },
    "top_gap_candidate": {
        "idx": 7572198,
        "target_module": "libc.so",
        "target_offset": "0xa0f5c",
        "arg_offsets": [
            {"reg": "x1", "offset": "0x58"},
            {"reg": "x6", "offset": "0x44"},
        ],
    },
    "interpretation": (
        "The first boundary-stat semantic lhs word now stops at the observed "
        "memory boundary instead of following a stale zero write or pointer "
        "frontier. Model this as an external file-metadata input unless a "
        "future hook proves a narrower producer."
    ),
}

TRACE_CALL001_SCRATCH_TABLE_WRITER_CHAIN_SUMMARY = {
    "command": (
        "tracemiku-cli byte-writer-map <call_dir> --addr 0x74b68bbe00 "
        "--size 52 --idx-hi 14695600 --max 300 --vm-chain-steps 120 "
        "--vm-chain-runs 16 --vm-chain-lookback 4000000 "
        "--vm-chain-follow-frontier --summary"
    ),
    "scratch_addr_range": "0x74b68bbe00..0x74b68bbe34",
    "writer_run_count": 16,
    "aggregate_pattern_counts": {
        "memory_boundary_read": 4,
        "static_memory_load_constant": 10,
    },
    "cli_vm_source_ranges": [
        {
            "offsets_inclusive": [0, 7],
            "bytes_hex": "000000fbe9f26979",
            "source_class": "memory_boundary_read",
            "boundary_addr": "0x74b68bd108",
            "boundary_value": "0x69f2e9fb",
        },
        {
            "offsets_inclusive": [8, 11],
            "bytes_hex": "ecf29541",
            "source_class": "static_memory_load_constant",
            "static_memory_load_count": 10,
            "first_static_addr": "0x74fbf29208",
            "first_static_value": "0x90bf1d91",
        },
        {
            "offsets_inclusive": [12, 35],
            "bytes_hex": (
                "f60193b34b3c510ccc029de339cec2953090237cbfa4f43b"
            ),
            "source_class": "traced_formula_only",
            "writer_idxs": [
                14164504,
                14164611,
                14164665,
                14164720,
                14164763,
                14164870,
            ],
        },
        {
            "offsets_inclusive": [36, 43],
            "bytes_hex": "a0444a342344c59b",
            "source_class": "memory_boundary_read",
            "boundary_values": ["0x362e3031", "0x30312e30"],
        },
        {
            "offsets_inclusive": [44, 47],
            "bytes_hex": "c5690000",
            "source_class": "traced_formula_only",
        },
        {
            "offsets_inclusive": [48, 51],
            "bytes_hex": "3abf0301",
            "source_class": "unclassified",
        },
    ],
    "vm_ip_stop_probe": {
        "command": (
            "tracemiku-cli vm-ops <call_dir> --start 10613140 --count 120 "
            "--summary --effects-only --max-ops 20"
        ),
        "bytecode_read_count": 44,
        "control_effect_count": 1,
        "op_template_count": 12,
        "first_control": {
            "idx": 10613174,
            "pseudocode": "0x75ebae5970 = 0x75ebae58e0 + 0x9",
            "bytecode_read_idx": 10613173,
            "bytecode_offset": "0x8",
            "bytecode_value": "0x9",
            "template_signature": "bc[0x8:8] effects[control:formula:add]",
            "template_skeleton": "vm_ip = add(vm_ip, bc_0x8_u64)",
            "template_skeleton_with_roles": "vm_ip = add(vm_ip, bc_0x8_u64)",
            "template_operand_roles": {
                "bc_0x8_u64": [{"role": "control_operand", "count": 1}],
            },
        },
        "interpretation": (
            "Formula-only byte-writer chains that stop at x21 can be continued "
            "as VM operation windows. The compact effects-only view now keeps "
            "bytecode reads, control effects, joined op_effects, grouped "
            "op_templates, and shape-only template_skeletons at top level."
        ),
    },
    "wide_vm_template_probe": {
        "command": (
            "tracemiku-cli vm-ops <call_dir> --start 10613140 --end 10620150 "
            "--summary --effects-only --max-ops 400"
        ),
        "op_template_count": 34,
        "top_template": {
            "count": 49,
            "signature": "bc[0x3:1,0x5:1,0x8:4,0x10:2] effects[slot_write:formula:ubfx]",
            "operand_offsets": ["0x3", "0x5", "0x8", "0x10"],
            "template_operands": [
                "bc_0x3_u8",
                "bc_0x5_u8",
                "bc_0x8_u32",
                "bc_0x10_u16",
            ],
            "template_operand_roles": {
                "bc_0x3_u8": [
                    {"role": "src_slot", "count": 49},
                    {"role": "dst_slot", "count": 32},
                ],
                "bc_0x5_u8": [
                    {"role": "dst_slot", "count": 49},
                    {"role": "src_slot", "count": 32},
                ],
                "bc_0x8_u32": [{"role": "bytecode_operand", "count": 49}],
                "bc_0x10_u16": [{"role": "bytecode_operand", "count": 49}],
            },
            "template_skeleton": (
                "slot[dst] = ubfx(slot_srcs, bc_0x3_u8, bc_0x5_u8, "
                "bc_0x8_u32, bc_0x10_u16)"
            ),
            "template_skeleton_with_roles": (
                "slot[bc_0x5_u8] = ubfx(slot[bc_0x3_u8], "
                "bc_0x8_u32, bc_0x10_u16)"
            ),
            "effect_shape": {
                "kind": "slot_write",
                "formula_op": "ubfx",
                "input_slots": [{"value": 19, "count": 44}, {"value": 20, "count": 5}],
                "output_slots": [{"value": 19, "count": 27}, {"value": 20, "count": 22}],
            },
        },
        "interpretation": (
            "The formula-only VM ladder window has repeated opcode shapes. "
            "The highest-frequency template is a bytecode-operand-driven UBFX "
            "slot write and is now directly visible without scanning raw ops. "
            "Template effect_shapes expose input/output slot roles for lifting, "
            "template_operands.roles adds aggregate parameter-role hints, and "
            "template_skeletons provide shape-only plus role-bound Python "
            "starting points."
        ),
    },
    "scratch_writer_template_probe": {
        "command": (
            "tracemiku-cli vm-ops <call_dir> --start 14164280 --end 14165320 "
            "--summary --effects-only --max-ops 200"
        ),
        "source_requested": 1040,
        "source_returned": 1040,
        "source_maybe_truncated": False,
        "op_template_count": 24,
        "effect_count": 110,
        "memory_store_effect_count": 16,
        "control_effect_count": 5,
        "top_templates": [
            {
                "count": 14,
                "signature": (
                    "bc[0x2:1,0x6:1,0x8:8,0x10:2] "
                    "effects[slot_write:formula:add]"
                ),
                "template_skeleton_with_roles": (
                    "slot[bc_0x2_u8] = add(slot[bc_0x6_u8], "
                    "bc_0x8_u64, bc_0x10_u16)"
                ),
                "sample": "slot[25] = 0x74b68bcc2c = 0x74b68bcc1c + 0x10",
            },
            {
                "count": 12,
                "signature": (
                    "bc[0x2:1,0x5:1,0x8:8,0x10:2] "
                    "effects[memory_store:literal:none]"
                ),
                "template_skeleton_with_roles": "mem[addr] = slot[bc_0x5_u8]",
                "sample": "mem[0x74b68bbe04] = 0x7969f2e9",
            },
            {
                "count": 9,
                "signature": (
                    "bc[0x3:1,0x4:1,0x5:1,0x10:2] "
                    "effects[slot_write:formula:orr]"
                ),
                "template_skeleton_with_roles": (
                    "slot[bc_0x3_u8] = orr(slot[bc_0x3_u8], "
                    "slot[bc_0x4_u8], slot[bc_0x5_u8], bc_0x10_u16)"
                ),
                "sample": "slot[2] = 0x7969f2e9 = 0x79000000 | 0x69f2e9",
            },
        ],
        "python_with_values_samples": [
            "slot[25] = add(slot[25], 0x10)",
            "slot[4] = lsl(slot[3], 0x18)",
            "slot[2] = orr(slot[4], slot[2])",
        ],
        "interpretation": (
            "The scratch lhs writer window now has directly liftable VM opcode "
            "templates. The remaining work is validating each role-bound "
            "skeleton against per-op samples and implementing the portable "
            "Python opcodes, not merely finding the upstream VM bytecode."
        ),
    },
    "interpretation": (
        "The scratch lhs table is generated by mixed VM writer chains. The "
        "first two runs consume stat('/').st_mtim.tv_sec, the 8..12 run "
        "still reaches no-writer-in-window table reads, the 12..36 runs "
        "continue to earlier VM-generated ladder values, and later runs "
        "consume an external-looking text buffer."
    ),
    "lookback_note": (
        "The default 1.8M-row lookback misclassified 0x7599191020+ reads as "
        "static. With a 4M lookback, those reads reach earlier traced writers "
        "around #11430997. Only the 0x74fbf29xxx table reads remain "
        "no-writer-in-window in this probe."
    ),
    "runs": [
        {
            "scratch_offset": [0, 4],
            "bytes_hex": "000000fb",
            "writer_idx": 14164352,
            "source_class": "stat_mtim_boundary_shift",
            "boundary_addr": "0x74b68bd108",
            "boundary_bytes_hex": "fbe9f26900000000",
        },
        {
            "scratch_offset": [4, 8],
            "bytes_hex": "e9f26979",
            "writer_idx": 14164406,
            "source_class": "stat_mtim_boundary_shift_plus_static_byte",
            "boundary_addr": "0x74b68bd108",
            "boundary_bytes_hex": "fbe9f26900000000",
        },
        {
            "scratch_offset": [8, 12],
            "bytes_hex": "ecf29541",
            "writer_idx": 14164461,
            "source_class": "no_writer_window_table_xor_ladder",
            "static_load_count": 10,
            "first_static_addr": "0x74fbf29208",
            "first_static_value": "0x90bf1d91",
            "note": (
                "The writer combines a shifted previous ladder word with a "
                "high byte from the next ladder word; this is not a direct "
                "copy from a static table."
            ),
        },
        {
            "scratch_offset": [12, 36],
            "bytes_hex": (
                "f60193b34b3c510ccc029de339cec2953090237cbfa4f43b"
            ),
            "writer_idxs": [
                14164504,
                14164611,
                14164665,
                14164720,
                14164763,
                14164870,
            ],
            "source_class": "vm_generated_ladder_from_earlier_table",
            "intermediate_table_addr": "0x7599191020",
            "intermediate_table_writer_idxs": [
                11430997,
                11431100,
                11431203,
                11431306,
                11431409,
                11431512,
            ],
            "intermediate_values_hex": [
                "0xd37f54b4",
                "0x36fb2fcf",
                "0x496352c0",
                "0x97dccb2b",
                "0x7a1e7739",
                "0xa9b01e26",
            ],
        },
        {
            "scratch_offset": [36, 44],
            "bytes_hex": "a0444a342344c59b",
            "writer_idxs": [14164924, 14164979],
            "source_class": "external_text_boundary_ladder",
            "boundary_reads": [
                {
                    "addr": "0x756649a2d0",
                    "bytes_hex": "31302e36",
                    "ascii": "10.6",
                },
                {
                    "addr": "0x756649a2d4",
                    "bytes_hex": "302e3130",
                    "ascii": "0.10",
                },
            ],
        },
        {
            "scratch_offset": [44, 52],
            "bytes_hex": "c56900003abf0301",
            "writer_idxs": [14165022, 14165215, 14165225, 14165246, 14165276],
            "source_class": "literal_or_short_ladder_tail",
        },
    ],
}

TRACE_CALL001_VM_BYTE_LOAD_BOUNDARIES = [
    {
        "status": "x_umt_trace_boundary_one_sample",
        "command": (
            "tracemiku-cli vm-ops <call_dir> --start 10616026 --count 15 "
            "--max-ops 1 --summary"
        ),
        "effect": "slot[18] = byte[0x753ddd7fdc] (0x7a)",
        "byte_load_sequence": [
            {"idx": 10613257, "addr": "0x753ddd7fd0", "value": "0x51", "ascii": "Q"},
            {"idx": 10613454, "addr": "0x753ddd7fd1", "value": "0x66", "ascii": "f"},
            {"idx": 10613695, "addr": "0x753ddd7fd2", "value": "0x59", "ascii": "Y"},
            {"idx": 10613892, "addr": "0x753ddd7fd3", "value": "0x42", "ascii": "B"},
            {"idx": 10614172, "addr": "0x753ddd7fd4", "value": "0x6b", "ascii": "k"},
            {"idx": 10614413, "addr": "0x753ddd7fd5", "value": "0x37", "ascii": "7"},
            {"idx": 10614686, "addr": "0x753ddd7fd6", "value": "0x4e", "ascii": "N"},
            {"idx": 10614883, "addr": "0x753ddd7fd7", "value": "0x4c", "ascii": "L"},
            {"idx": 10615163, "addr": "0x753ddd7fd8", "value": "0x50", "ascii": "P"},
            {"idx": 10615360, "addr": "0x753ddd7fd9", "value": "0x46", "ascii": "F"},
            {"idx": 10615557, "addr": "0x753ddd7fda", "value": "0x45", "ascii": "E"},
            {"idx": 10615754, "addr": "0x753ddd7fdb", "value": "0x4d", "ascii": "M"},
            {"idx": 10616034, "addr": "0x753ddd7fdc", "value": "0x7a", "ascii": "z"},
        ],
        "observed_stream_ascii": "QfYBk7NLPFEMz",
        "jni_output_pair": {
            "key": "x-umt",
            "key_idx": 15322406,
            "value": "QfYBk7NLPFEMzAKd4znOwpUwkCN8v6T0",
            "value_idx": 15322467,
            "note": "This boundary is not the final x-sign value; x-sign is emitted at #15322907.",
        },
        "wide_window_probe": {
            "command": (
                "tracemiku-cli vm-ops <call_dir> --start 10613240 "
                "--end 10616100 --summary --effects-only --max-ops 500"
            ),
            "source_requested": 2860,
            "source_returned": 2860,
            "source_chunks": 4,
            "chunk_size": 900,
            "source_maybe_truncated": False,
            "byte_load_effect_count": 13,
            "legacy_single_request": {
                "command_suffix": "--chunk-size 0",
                "source_returned": 1000,
                "source_maybe_truncated": True,
                "byte_load_effect_count": 5,
            },
        },
        "consumer_idx": 10616034,
        "consumer_asm": "ldrb w3, [x4, x20]",
        "buffer_addr": "0x753ddd7fd0",
        "byte_offset": 12,
        "byte_addr": "0x753ddd7fdc",
        "byte_value": "0x7a",
        "ascii": "z",
        "buffer_preview_ascii": "QfYBk7NLPEMz",
        "upstream_status": "observed_read_without_matching_traced_write",
        "latest_traced_writer": {
            "idx": 10591494,
            "asm": "str w16, [x2,x5]",
            "byte_value": "0x00",
        },
        "gap_call_candidates": [
            {
                "idx": 10612864,
                "target": "libsgmainso+0x163928",
                "score": 10,
                "score_adjustment_trace_write": -50,
                "callee_trace_status": "traced_callee_no_target_write",
                "span": {
                    "base_reg": "x3",
                    "base": "0x753ddd7fd0",
                    "len_reg": "x2",
                    "len": "0x19",
                    "offset": "0xc",
                },
            },
            {
                "idx": 10612910,
                "target": "libsgmainso+0x163944",
                "score": -30,
                "score_adjustment_trace_write": -50,
                "callee_trace_status": "traced_callee_no_target_write",
            },
        ],
        "later_buffer_reuse_probe": {
            "status": "cleared_and_reused_later_not_producer",
            "idx_range": [11454800, 11455200],
            "commands": [
                (
                    "tracemiku-cli byte-writer-map <call_dir> "
                    "--addr 0x753ddd7fd0 --size 16 --idx-lo 11454800 "
                    "--idx-hi 11455200 --max 100 --summary"
                ),
                (
                    "tracemiku-cli mem-dump <call_dir> --addr 0x753ddd7fd0 "
                    "--count 32 --cursor 11455200 --summary"
                ),
                (
                    "tracemiku-cli vm-ops <call_dir> --start 11454800 "
                    "--end 11455200 --summary --effects-only --max-ops 120"
                ),
            ],
            "writer_runs": [
                {
                    "range": [0, 4],
                    "writer_idx": 11455075,
                    "asm": "str w1, [x19, x6]",
                    "src_value": "0x0",
                },
                {
                    "range": [4, 8],
                    "writer_idx": 11455119,
                    "asm": "str w11, [x8, x4]",
                    "src_value": "0x0",
                },
                {
                    "range": [8, 12],
                    "writer_idx": 11455125,
                    "asm": "str w2, [x5, x16]",
                    "src_value": "0x0",
                },
                {
                    "range": [12, 16],
                    "writer_idx": 11455168,
                    "asm": "str w11, [x8, x4]",
                    "src_value": "0x0",
                },
            ],
            "mem_dump_at_11455200_hex": (
                "00000000000000000000000000000000"
                "00000000000000000000000076365430"
            ),
            "memory_effects": [
                "mem[0x753ddd7fd0] = low8(slot[0])",
                "mem[0x753ddd7fd1] = low8(slot[25])",
                "mem[0x753ddd7fd2] = low8(slot[25])",
                "mem[0x753ddd7fd3] = low8(slot[25])",
                "mem[0x753ddd7fd0] = 0x0",
                "mem[0x753ddd7fd4] = 0x0",
                "mem[0x753ddd7fd8] = 0x0",
                "mem[0x753ddd7fdc] = 0x0",
            ],
            "interpretation": (
                "A later VM window clears/reuses the same buffer. It is not "
                "evidence that the earlier observed QfYBk7NLPFEMz stream was "
                "generated by traced code."
            ),
        },
        "interpretation": (
            "The byte consumed by the VM is observed in memory, but the latest "
            "traced writer does not match it. Gap-call candidates cover the "
            "buffer by argument span but their traced callees do not write the "
            "target range, so treat this as a trace coverage or preexisting "
            "buffer boundary, not as a static byte or proven helper output."
        ),
    }
]

TRACE_CALL001_WORD_SOURCE_CLASSES = [
    {
        "semantic_range": [3, 7],
        "source_status": "state_update_found",
        "source_word": "0x67b44ad8",
        "class": "sha1_like_state_word",
        "state_update_idx": 14678154,
    },
    {
        "semantic_range": [7, 11],
        "source_status": "state_update_found",
        "source_word": "0x783e786f",
        "class": "sha1_like_state_word",
        "state_update_idx": 14678176,
    },
    {
        "semantic_range": [16, 52],
        "source_status": "word_source_only",
        "class": "vm_scratch_lhs_table",
        "scratch_addr_range": "0x74b68bbe00..0x74b68bbe34",
        "scratch_bytes_hex": (
            "000000fbe9f26979ecf29541f60193b34b3c510ccc029de339cec295"
            "3090237cbfa4f43ba0444a342344c59bc56900003abf0301"
        ),
        "writer_map_status": {
            "matched_writes": 23,
            "writer_runs": 16,
            "truncated": False,
        },
        "representative_writer_sources": [
            {
                "writer_idx": 14164352,
                "writer_bytes_hex": "000000fb",
                "source_class": "stat_mtim_shift",
                "source_value": "0x69f2e9fb",
                "formula": "(stat('/').st_mtim.tv_sec << 24) & 0xffffffff",
            },
            {
                "writer_idx": 14164406,
                "writer_bytes_hex": "e9f26979",
                "source_class": "stat_mtim_shift_plus_static_byte",
                "formula": "(stat('/').st_mtim.tv_sec >> 8) | (static_xor_ladder_low_byte << 24)",
                "stat_component": "0x0069f2e9",
                "static_component": "0x79000000",
            },
            {
                "writer_idx": 14164461,
                "writer_bytes_hex": "ecf29541",
                "source_class": "no_writer_window_table_xor_ladder",
                "first_static_load": {
                    "addr": "0x74fbf29208",
                    "value": "0x90bf1d91",
                    "caution": "no writer found in the tested lookback window",
                },
                "formula_shape": (
                    "writer_word = (previous_ladder_word >> 8) | "
                    "((next_ladder_word & 0xff) << 24)"
                ),
            },
        ],
        "note": (
            "Backchains for these chunks repeatedly hit overlapping 32-bit loads "
            "from a traced VM scratch table. The first chunk also has a "
            "stat.st_mtim.tv_sec boundary candidate recorded separately; the table "
            "writer formulas still need to be lifted into portable inputs."
        ),
    },
    {
        "semantic_range": [52, 56],
        "source_status": "word_source_only",
        "class": "memory_boundary_read_text",
        "addr": "0x756649a2d4",
        "bytes_hex": "302e3130",
        "ascii": "0.10",
        "container_addr": "0x756649a2d0",
        "container_c_string": "10.60.10^^",
        "container_offset": 4,
        "load_idx": 14082315,
        "last_write_idx": 14062790,
        "interpretation": (
            "Observed bytes do not match the latest traced write. The current "
            "MemShadow cursor shows this as a substring of the external-looking "
            "text buffer '10.60.10^^'."
        ),
    },
    {
        "semantic_range": [61, 65],
        "source_status": "word_source_only",
        "class": "vm_scratch_lhs_table_tail",
        "addr": "0x74b68bbe30",
        "bytes_hex": "3abf0301",
        "writer_idxs": [14165215, 14165225, 14165246, 14165276],
    },
]

CALL001_XOR_LHS_RUNS = [
    {
        "range": [3, 13],
        "lhs_hex": "67b44ad8783e786fcd01",
    },
    {
        "range": [16, 59],
        "source": "stat_mtim_le_plus_mixed_suffix",
    },
    {
        "range": [61, 65],
        "lhs_hex": "3abf0301",
    },
]

CALL001_MOD255_MASK_OFFSETS = [1, 2, 13, 14, 15, 59, 60, 65, 66, 67]


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


def mask_bits(value: int, bits: int) -> int:
    return value & ((1 << bits) - 1)


def vm_add(lhs: int, rhs: int, bits: int = 64) -> int:
    return mask_bits(lhs + rhs, bits)


def vm_and(lhs: int, rhs: int, bits: int = 64) -> int:
    return mask_bits(lhs & rhs, bits)


def vm_orr(lhs: int, rhs: int, bits: int = 64) -> int:
    return mask_bits(lhs | rhs, bits)


def vm_lsl(value: int, shift: int, bits: int = 64) -> int:
    return mask_bits(value << shift, bits)


def vm_lsr(value: int, shift: int, bits: int = 64) -> int:
    return mask_bits(value, bits) >> shift


def vm_ubfx(value: int, lsb: int, width: int) -> int:
    return (value >> lsb) & ((1 << width) - 1)


def vm_store_le(memory: dict[int, int], addr: int, value: int, width: int) -> None:
    for offset in range(width):
        memory[addr + offset] = (value >> (offset * 8)) & 0xFF


def validate_scratch_vm_opcode_samples() -> dict:
    memory: dict[int, int] = {}
    samples = [
        {
            "expr": "slot[25] = add(slot[25], 0x10)",
            "computed": vm_add(0x74B68BCC1C, 0x10),
            "expected": 0x74B68BCC2C,
        },
        {
            "expr": "slot[2] = and(slot[2], 0x9)",
            "computed": vm_and(0x1, 0x9, 32),
            "expected": 0x1,
        },
        {
            "expr": "slot[2] = lsr(slot[2], 0x8)",
            "computed": vm_lsr(0x1, 0x8, 32),
            "expected": 0x0,
        },
        {
            "expr": "slot[4] = lsl(slot[3], 0x18)",
            "computed": vm_lsl(0x69F2E9FB, 0x18, 32),
            "expected": 0xFB000000,
        },
        {
            "expr": "slot[2] = orr(slot[4], slot[2])",
            "computed": vm_orr(0xFB000000, 0x0, 32),
            "expected": 0xFB000000,
        },
        {
            "expr": "slot[20] = ubfx(slot[19], 0x0, 0x20)",
            "computed": vm_ubfx(0x10, 0, 0x20),
            "expected": 0x10,
        },
    ]
    vm_store_le(memory, 0x74B68BBE04, 0x7969F2E9, 4)
    store_sample = {
        "expr": "mem[0x74b68bbe04] = slot[5]",
        "computed_hex": bytes(memory[0x74B68BBE04 + i] for i in range(4)).hex(),
        "expected_hex": "e9f26979",
    }
    return {
        "status": "partial_opcode_semantics_validated",
        "samples": [
            {
                "expr": item["expr"],
                "computed": f"{item['computed']:#x}",
                "expected": f"{item['expected']:#x}",
                "matches": item["computed"] == item["expected"],
            }
            for item in samples
        ],
        "store_sample": {
            **store_sample,
            "matches": store_sample["computed_hex"] == store_sample["expected_hex"],
        },
        "all_match": all(item["computed"] == item["expected"] for item in samples)
        and store_sample["computed_hex"] == store_sample["expected_hex"],
    }


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


def xor_lhs_run_result(run: dict) -> bytes:
    lhs = bytes.fromhex(run["lhs_hex"])
    rhs = bytes.fromhex(run["rhs_hex"])
    return bytes(xor_mix(a, b) for a, b in zip(lhs, rhs))


def call001_lhs_run_bytes(run: dict) -> bytes:
    if "lhs_hex" in run:
        return bytes.fromhex(run["lhs_hex"])
    if run.get("source") == "stat_mtim_le_plus_mixed_suffix":
        return word32_le_bytes(CALL001_STAT_MTIM_TV_SEC) + bytes.fromhex(
            CALL001_MIDDLE_LHS_MIXED_SUFFIX_HEX
        )
    raise ValueError(f"unsupported lhs run source: {run}")


def trace_mask_byte_for_semantic_offset(offset: int) -> int:
    if offset % 2 == 0:
        return mod255_low_byte(0x74BEABE59C)
    return mod255_low_byte(0x74FFAFCA73)


def reconstruct_call001_semantic_tail_from_trace_formulas() -> bytes:
    out = bytearray(68)
    out[0] = (0x0A000142 >> 24) & 0xFF
    for offset in CALL001_MOD255_MASK_OFFSETS:
        out[offset] = trace_mask_byte_for_semantic_offset(offset)
    for run in CALL001_XOR_LHS_RUNS:
        start, end = run["range"]
        lhs = call001_lhs_run_bytes(run)
        if len(lhs) != end - start:
            raise ValueError(f"bad lhs length for range {run['range']}")
        for idx, lhs_byte in enumerate(lhs, start=start):
            out[idx] = xor_mix(lhs_byte, trace_mask_byte_for_semantic_offset(idx))
    return bytes(out)


def bytewise_variations(hex_by_sample: dict[str, str]) -> list[dict]:
    byte_by_sample = {name: bytes.fromhex(raw) for name, raw in hex_by_sample.items()}
    lengths = {len(raw) for raw in byte_by_sample.values()}
    if len(lengths) != 1:
        return [
            {
                "status": "length_mismatch",
                "lengths": {name: len(raw) for name, raw in byte_by_sample.items()},
            }
        ]
    length = next(iter(lengths))
    out = []
    for offset in range(length):
        values = {raw[offset] for raw in byte_by_sample.values()}
        if len(values) <= 1:
            continue
        out.append(
            {
                "offset": offset,
                "values": {name: f"{raw[offset]:02x}" for name, raw in byte_by_sample.items()},
            }
        )
    return out


def xor_lhs_word_chunks(raw_hex: str, semantic_start: int) -> list[dict]:
    data = bytes.fromhex(raw_hex)
    chunks = []
    for offset in range(0, len(data), 4):
        chunk = data[offset : offset + 4]
        row = {
            "semantic_range": [semantic_start + offset, semantic_start + offset + len(chunk)],
            "size": len(chunk),
            "lhs_hex": chunk.hex(),
        }
        if len(chunk) == 4:
            row["kind"] = "word32"
            row["lhs_word_le"] = f"{int.from_bytes(chunk, 'little'):#010x}"
        else:
            row["kind"] = "tail_bytes"
        chunks.append(row)
    return chunks


def aligned_tail(xsign: str) -> bytes:
    xsign = urllib.parse.unquote(xsign)
    tail_chars = xsign[FIXED_PREFIX_CHARS:]
    return b64decode_unpadded(TAIL_ALIGNMENT_PREFIX + tail_chars)


def semantic_tail(xsign: str) -> bytes:
    return aligned_tail(xsign)[1:]


def xsign_from_semantic_tail(raw_prefix: str, tail: bytes) -> str:
    return raw_prefix + b64encode_unpadded(b"\x00" + tail)[2:]


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
    reconstructed_call001 = xsign_from_semantic_tail(
        urllib.parse.unquote(CALL_001_XSIGN)[:FIXED_PREFIX_CHARS],
        semantic,
    )
    multi_sample_reencoded = {
        name: xsign_from_semantic_tail(
            urllib.parse.unquote(xsign)[:FIXED_PREFIX_CHARS],
            sample_tails[name],
        )
        for name, xsign in SAMPLE_XSIGNS.items()
    }
    expected_semantic = bytes.fromhex(CALL_001_SEMANTIC_TAIL_HEX)
    formula_semantic = reconstruct_call001_semantic_tail_from_trace_formulas()
    formula_xsign = xsign_from_semantic_tail(
        urllib.parse.unquote(CALL_001_XSIGN)[:FIXED_PREFIX_CHARS],
        formula_semantic,
    )
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
        state_add_low32 = (item["state_add_lhs"] + item["state_add_rhs"]) & 0xFFFFFFFF
        xor_word_samples[name] = {
            "state_word_le": f"{item['state_word_le']:#x}",
            "state_bytes_le": word32_le_bytes(item["state_word_le"]).hex(),
            "source_word_be": f"{item['source_word_be']:#x}",
            "bswap32_source_matches_state_word": bswap32(item["source_word_be"]) == item["state_word_le"],
            "state_add_idx": item["state_add_idx"],
            "state_add_lhs": f"{item['state_add_lhs']:#x}",
            "state_add_rhs": f"{item['state_add_rhs']:#x}",
            "state_add_result": f"{item['state_add_result']:#x}",
            "state_add_result_low32": f"{item['state_add_result'] & 0xFFFFFFFF:#x}",
            "state_add_computed_low32": f"{state_add_low32:#x}",
            "state_add_matches_source_word": state_add_low32 == item["source_word_be"],
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
    byte_lane_source = TRACE_CALL_001_BYTE_LANE_STATE_SOURCE
    byte_lane_source_low32 = (
        byte_lane_source["state_add_lhs"] + byte_lane_source["state_add_rhs"]
    ) & 0xFFFFFFFF
    xor_lhs_runs = TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["xor_lhs_runs"]
    xor_lhs_runs_match_tail = all(
        xor_lhs_run_result(run) == semantic[run["range"][0] : run["range"][1]]
        and xor_lhs_run_result(run).hex() == run["result_hex"]
        for run in xor_lhs_runs
    )
    middle_lhs = TRACE_MULTI_SAMPLE_XOR_LHS_MIDDLE_RUN
    middle_lhs_variations = bytewise_variations(middle_lhs["samples"])
    middle_lhs_chunks_by_sample = {
        name: xor_lhs_word_chunks(raw, middle_lhs["semantic_range"][0])
        for name, raw in middle_lhs["samples"].items()
    }
    middle_lhs_call001_chunks = middle_lhs_chunks_by_sample["diff_run1_call_001"]
    middle_lhs_word_chunk_variations = [
        {
            "chunk": chunk_idx,
            "semantic_range": middle_lhs_call001_chunks[chunk_idx]["semantic_range"],
            "values": {
                name: chunks[chunk_idx]["lhs_hex"]
                for name, chunks in middle_lhs_chunks_by_sample.items()
            },
        }
        for chunk_idx in range(len(middle_lhs_call001_chunks))
        if len({chunks[chunk_idx]["lhs_hex"] for chunks in middle_lhs_chunks_by_sample.values()})
        > 1
    ]
    scratch_vm_opcode_validation = validate_scratch_vm_opcode_samples()

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
            "reconstructed_call_001_xsign_matches": reconstructed_call001
            == urllib.parse.unquote(CALL_001_XSIGN),
            "multi_sample_reencode_all_match": all(
                multi_sample_reencoded[name] == urllib.parse.unquote(xsign)
                for name, xsign in SAMPLE_XSIGNS.items()
            ),
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
                "--size 68 --idx-hi 14739000 --max 300 --vm-chain-steps 12 "
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
        "fixed_prefix_writer_map": TRACE_FIXED_PREFIX_WRITER_MAP,
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
            "call_001_formula_reconstruction": {
                "status": "complete_from_trace_formula_inputs",
                "semantic_tail_hex": formula_semantic.hex(),
                "semantic_tail_matches_trace": formula_semantic == expected_semantic,
                "xsign_matches_trace": formula_xsign == urllib.parse.unquote(CALL_001_XSIGN),
                "formula_classes": [
                    "byte_lane_extract",
                    "mod255_low_byte",
                    "stat('/').st_mtim.tv_sec little-endian bytes",
                    "xor_lhs_run ^ parity_mask",
                ],
                "formula_inputs": {
                    "stat_mtim_tv_sec": f"{CALL001_STAT_MTIM_TV_SEC:#x}",
                    "middle_lhs_mixed_suffix_hex": CALL001_MIDDLE_LHS_MIXED_SUFFIX_HEX,
                },
                "note": (
                    "This reconstructs the observed call_001 output from traced "
                    "formula inputs. It is not yet a portable x-sign algorithm "
                    "because several lhs runs are still trace constants or "
                    "external-data boundaries."
                ),
            },
            "equations": xor_equations,
            "reconstructed_offsets": [item["semantic_offset"] for item in TRACE_TAIL_XOR_EQUATIONS],
            "reconstructed_prefix_0_7_hex": bytes(xor_reconstructed).hex(),
            "matches_semantic_prefix_0_7": bytes(xor_reconstructed) == semantic[:7],
            "base64_payload_prefix_formulas": {
                **TRACE_BASE64_PAYLOAD_PREFIX_FORMULAS,
                "matches_semantic_tail_prefix": bytes.fromhex(
                    TRACE_BASE64_PAYLOAD_PREFIX_FORMULAS["semantic_hex"]
                )
                == semantic[:8],
            },
            "multi_sample_word_template": {
                "formula": "tail[3:7] = word32_le(state_word) ^ [tail[1], tail[2], tail[1], tail[2]]",
                "samples": xor_word_samples,
                "all_match": all(item["matches_trace"] for item in xor_word_samples.values()),
                "all_state_adds_match": all(
                    item["bswap32_source_matches_state_word"] and item["state_add_matches_source_word"]
                    for item in xor_word_samples.values()
                ),
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
            "call_001_byte_lane_state_source": {
                "status": "trace_proven_one_sample",
                "command": byte_lane_source["command"],
                "vm_chain_seed_mode": byte_lane_source["vm_chain_seed_mode"],
                "byte_equation_count": byte_lane_source["byte_equation_count"],
                "selected_semantic_offset": byte_lane_source["selected_semantic_offset"],
                "local_semantic_range": byte_lane_source["local_semantic_range"],
                "lhs_word_le": f"{byte_lane_source['lhs_word_le']:#x}",
                "source_word": f"{byte_lane_source['source_word']:#x}",
                "source_word_match": byte_lane_source["source_word_match"],
                "word_extract": {
                    "idx": byte_lane_source["word_extract_idx"],
                    "asm": byte_lane_source["word_extract_asm"],
                },
                "state_add": {
                    "idx": byte_lane_source["state_add_idx"],
                    "asm": byte_lane_source["state_add_asm"],
                    "lhs": f"{byte_lane_source['state_add_lhs']:#x}",
                    "rhs": f"{byte_lane_source['state_add_rhs']:#x}",
                    "computed_low32": f"{byte_lane_source_low32:#x}",
                    "matches_source_word": byte_lane_source_low32
                    == byte_lane_source["source_word"],
                },
                "matches_state_digest_word_1": byte_lane_source["source_word"] == state_words_be[1],
            },
            "call_001_full_byte_equation_summary": {
                "status": "trace_proven_one_sample",
                "command": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["command"],
                "byte_equation_count": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                    "byte_equation_count"
                ],
                "requested_range": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                    "requested_range"
                ],
                "requested_coverage_status": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                    "requested_coverage_status"
                ],
                "covered_range": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["covered_range"],
                "kind_counts": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["kind_counts"],
                "byte_lane_equations": [
                    {
                        "offset": item["offset"],
                        "source_value": f"{item['source_value']:#x}",
                        "source_byte_offset": item["source_byte_offset"],
                        "result": f"{item['result']:#x}",
                        "expression": item["expression"],
                    }
                    for item in TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                        "byte_lane_equations"
                    ]
                ],
                "input_summary": {
                    "byte_lane_sources": [
                        {
                            "source_value": f"{item['source_value']:#x}",
                            "offsets": item["offsets"],
                            "source_byte_offsets": item["source_byte_offsets"],
                            "result_hex": item["result_hex"],
                        }
                        for item in TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                            "input_summary"
                        ]["byte_lane_sources"]
                    ],
                    "mod255_inputs": [
                        {
                            "input": f"{item['input']:#x}",
                            "output_byte": f"{item['output_byte']:#x}",
                            "quotient": f"{item['quotient']:#x}",
                            "offsets": item["offsets"],
                        }
                        for item in TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                            "input_summary"
                        ]["mod255_inputs"]
                    ],
                    "xor_lhs_offsets": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                        "input_summary"
                    ]["xor_lhs_offsets"],
                },
                "xor_rhs_pattern": {
                    "kind": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["xor_rhs_pattern"][
                        "kind"
                    ],
                    "even_byte": f"{TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY['xor_rhs_pattern']['even_byte']:#x}",
                    "odd_byte": f"{TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY['xor_rhs_pattern']['odd_byte']:#x}",
                    "matched_offsets": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                        "xor_rhs_pattern"
                    ]["matched_offsets"],
                    "formula": "tail[i] xor rhs is 0x61 for even semantic offsets and 0x62 for odd offsets",
                },
                "xor_lhs_runs": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY["xor_lhs_runs"],
                "xor_lhs_runs_match_tail": xor_lhs_runs_match_tail,
                "unexplained_offsets": TRACE_CALL_001_FULL_BYTE_EQUATION_SUMMARY[
                    "unexplained_offsets"
                ],
                "next_problem": (
                    "Trace the lhs_i stream for the 57 XOR bytes back to the "
                    "VM/hash state; the final x-sign tail itself is no longer opaque."
                ),
            },
            "call_001_mod255_input_lcg_chain": {
                "status": TRACE_MOD255_INPUT_LCG_CHAIN["status"],
                "command": TRACE_MOD255_INPUT_LCG_CHAIN["command"],
                "semantic_offset": TRACE_MOD255_INPUT_LCG_CHAIN["semantic_offset"],
                "mod255_input": f"{TRACE_MOD255_INPUT_LCG_CHAIN['mod255_input']:#x}",
                "output_byte": f"{TRACE_MOD255_INPUT_LCG_CHAIN['output_byte']:#x}",
                "chain_head": TRACE_MOD255_INPUT_LCG_CHAIN["chain_head"],
                "lcg_multiplier": f"{TRACE_MOD255_INPUT_LCG_CHAIN['lcg_multiplier']:#x}",
                "lcg_increment": TRACE_MOD255_INPUT_LCG_CHAIN["lcg_increment"],
                "lcg_states_seen": [
                    f"{state:#x}"
                    for state in TRACE_MOD255_INPUT_LCG_CHAIN["lcg_states_seen"]
                ],
            },
            "call_001_mod255_input_small_affine_chain": {
                "status": TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN["status"],
                "command": TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN["command"],
                "semantic_offset": TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN[
                    "semantic_offset"
                ],
                "mod255_input": f"{TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN['mod255_input']:#x}",
                "output_byte": f"{TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN['output_byte']:#x}",
                "chain_head": TRACE_MOD255_INPUT_SMALL_AFFINE_CHAIN["chain_head"],
                "small_affine": {
                    "previous_state": f"{TRACE_SMALL_AFFINE['previous_state']:#x}",
                    "multiplier": f"{TRACE_SMALL_AFFINE['multiplier']:#x}",
                    "delta": f"{TRACE_SMALL_AFFINE['delta']:#x}",
                    "expected_state": f"{TRACE_SMALL_AFFINE['expected_state']:#x}",
                },
            },
            "call_001_byte_lane_static_source": {
                "status": TRACE_BYTE_LANE_STATIC_SOURCE["status"],
                "command": TRACE_BYTE_LANE_STATIC_SOURCE["command"],
                "semantic_offset": TRACE_BYTE_LANE_STATIC_SOURCE["semantic_offset"],
                "source_value": f"{TRACE_BYTE_LANE_STATIC_SOURCE['source_value']:#x}",
                "load_idx": TRACE_BYTE_LANE_STATIC_SOURCE["load_idx"],
                "load_asm": TRACE_BYTE_LANE_STATIC_SOURCE["load_asm"],
                "addr": TRACE_BYTE_LANE_STATIC_SOURCE["addr"],
                "observed_bytes_hex": TRACE_BYTE_LANE_STATIC_SOURCE[
                    "observed_bytes_hex"
                ],
                "interpretation": TRACE_BYTE_LANE_STATIC_SOURCE["interpretation"],
            },
            "multi_sample_xor_lhs_middle_run": {
                "status": "trace_observed_four_diff_samples",
                "semantic_range": middle_lhs["semantic_range"],
                "size": middle_lhs["size"],
                "samples": middle_lhs["samples"],
                "variation_count": len(middle_lhs_variations),
                "variations": middle_lhs_variations,
                "stable_byte_count": middle_lhs["size"] - len(middle_lhs_variations),
                "word_chunks_call_001": middle_lhs_call001_chunks,
                "word_chunk_variations": middle_lhs_word_chunk_variations,
                "call_001_first_word_source": {
                    **middle_lhs["call_001_first_word_source"],
                    "lhs_word_le": f"{middle_lhs['call_001_first_word_source']['lhs_word_le']:#x}",
                    "earliest_writer_src_value": (
                        f"{middle_lhs['call_001_first_word_source']['earliest_writer_src_value']:#x}"
                    ),
                    "boundary": {
                        **middle_lhs["call_001_first_word_source"]["boundary"],
                        "stale_writer_src_value": (
                            f"{middle_lhs['call_001_first_word_source']['boundary']['stale_writer_src_value']:#x}"
                        ),
                    },
                },
                "interpretation": middle_lhs["interpretation"],
            },
            "xor_word_source_coverage": TRACE_XOR_WORD_SOURCE_COVERAGE,
            "boundary_stat_launch2_sem16_lineage": TRACE_BOUNDARY_STAT_LAUNCH2_SEM16_LINEAGE,
            "scratch_table_writer_chain_summary": TRACE_CALL001_SCRATCH_TABLE_WRITER_CHAIN_SUMMARY,
            "scratch_vm_opcode_validation": scratch_vm_opcode_validation,
            "vm_byte_load_boundaries": TRACE_CALL001_VM_BYTE_LOAD_BOUNDARIES,
            "call_001_word_source_classes": TRACE_CALL001_WORD_SOURCE_CLASSES,
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
            (
                "portable formulas or external inputs for the word_source_only "
                "XOR lhs chunks"
            ),
            (
                "semantic meaning of the fixed 12-character raw prefix; trace "
                "now proves it as raw text, not as directly observed decoded bytes"
            ),
            (
                "validated Python VM opcode implementations for the scratch "
                "table and semantic tail byte sources"
            ),
            "role of the LCG/time state in every payload byte",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
