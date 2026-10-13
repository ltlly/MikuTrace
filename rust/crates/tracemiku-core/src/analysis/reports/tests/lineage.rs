use super::*;

#[test]
fn pairs_vm_state_update_formula_with_following_store() {
    let ops = vec![
        serde_json::json!({
            "idx_start": 14678147,
            "alu_formulas": [
                {
                    "idx": 14678154,
                    "asm": "add x13, x8, x12",
                    "semantic": {
                        "kind": "add32_mix",
                        "result": "0x267b44ad8",
                        "result_low32": "0x67b44ad8"
                    }
                }
            ],
            "memory_stores": []
        }),
        serde_json::json!({
            "idx_start": 14678158,
            "alu_formulas": [],
            "memory_stores": [
                {
                    "idx": 14678167,
                    "asm": "str w1, [x19, x6]",
                    "mem_addr": "0x74b68bb6a8",
                    "store_src": [
                        {"reg": "w1", "value": "0x267b44ad8"}
                    ]
                }
            ]
        }),
    ];
    let updates = vm_ops_state_updates(&ops);
    let first = updates.as_array().unwrap().first().unwrap();
    assert_eq!(first["formula_idx"], serde_json::json!(14678154));
    assert_eq!(first["store_idx"], serde_json::json!(14678167));
    assert_eq!(first["store_addr"], serde_json::json!("0x74b68bb6a8"));
    assert_eq!(
        first["semantic"]["result_low32"],
        serde_json::json!("0x67b44ad8")
    );
}

#[test]
fn recognizes_affine_mod64_state_steps() {
    let chain = vec![
        serde_json::json!({
            "step": 0,
            "local_def": {
                "formula": {
                    "semantic": {
                        "kind": "add_small_delta",
                        "input": "0x52c36263893da50c",
                        "delta": "0x1",
                        "result": "0x52c36263893da50d"
                    }
                }
            }
        }),
        serde_json::json!({
            "step": 1,
            "local_def": {
                "formula": {
                    "semantic": {
                        "kind": "mul_mod64",
                        "lhs": "0x5036f3354bed40bc",
                        "rhs": "0x5851f42d4c957f2d",
                        "result": "0x52c36263893da50c",
                        "rhs_odd": true
                    }
                }
            }
        }),
    ];
    let patterns = recognized_backchain_patterns(&chain);
    assert_eq!(patterns.len(), 1);
    assert_eq!(
        patterns[0]["kind"],
        serde_json::json!("affine_mod64_state_step")
    );
    assert_eq!(
        patterns[0]["previous_state"],
        serde_json::json!("0x5036f3354bed40bc")
    );
    assert_eq!(
        patterns[0]["multiplier"],
        serde_json::json!("0x5851f42d4c957f2d")
    );
    assert_eq!(
        patterns[0]["multiplier_inverse"],
        serde_json::json!("0xc097ef87329e28a5")
    );
    assert_eq!(patterns[0]["delta"], serde_json::json!("0x1"));
    let summary = recognized_backchain_pattern_summary(&patterns);
    assert_eq!(
        summary["affine_mod64_recurrences"][0]["count"],
        serde_json::json!(1)
    );
    assert_eq!(
        summary["affine_mod64_recurrences"][0]["multiplier"],
        serde_json::json!("0x5851f42d4c957f2d")
    );
    assert_eq!(
        summary["affine_mod64_recurrences"][0]["transitions"][0]["state"],
        serde_json::json!("0x52c36263893da50d")
    );
}

#[test]
fn computes_odd_inverse_mod_2_64() {
    let multiplier = 0x5851f42d4c957f2d_u64;
    let inverse = odd_u64_inverse(multiplier).unwrap();
    assert_eq!(inverse, 0xc097ef87329e28a5);
    assert_eq!(multiplier.wrapping_mul(inverse), 1);
    assert!(odd_u64_inverse(2).is_none());
}

#[test]
fn summarizes_vm_backchain_stop_reason() {
    let chain = vec![serde_json::json!({
        "step": 12,
        "idx": 10616024,
        "reg": "x21",
        "value": "0x75ebae5d80",
        "target": {
            "asm": "ldr x13, [x21, #8]",
            "class": "bytecode-read"
        },
        "upstream": {
            "status": "no_local_def",
            "searched_context": 120
        },
        "decision": {
            "kind": "stop",
            "reason": "no_upstream_next_or_frontier"
        }
    })];
    let stop = vm_backchain_stop_summary(&chain);
    assert_eq!(stop["idx"], serde_json::json!(10616024));
    assert_eq!(
        stop["decision"]["reason"],
        serde_json::json!("no_upstream_next_or_frontier")
    );
    assert_eq!(stop["target"]["class"], serde_json::json!("bytecode-read"));
}

#[test]
fn summarizes_vm_op_slot_write_effects() {
    let op = serde_json::json!({
        "vm_slot_reads": [
            {"slot": 18, "value": "0x7a"}
        ],
        "vm_slot_writes": [
            {"idx": 10616058, "slot": 19, "value": "0x39"}
        ],
        "memory_stores": [],
        "alu_formulas": [
            {
                "idx": 10616056,
                "asm": "add x2, x0, x1",
                "expression": "0x39 = 0x7a + 0xffffffffffffffbf",
                "semantic": {
                    "kind": "add_small_delta",
                    "result": "0x39"
                }
            }
        ]
    });
    let effects = vm_op_effect_summaries(&op, &std::collections::HashSet::new(), None);
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0]["kind"], serde_json::json!("slot_write"));
    assert_eq!(
        effects[0]["pseudocode"],
        serde_json::json!("slot[19] = 0x39 = 0x7a + 0xffffffffffffffbf")
    );
    assert_eq!(
        effects[0]["formula"]["semantic"]["kind"],
        serde_json::json!("add_small_delta")
    );
}

#[test]
fn summarizes_vm_op_formula_effect_python_values() {
    let op = serde_json::json!({
        "vm_slot_reads": [
            {"slot": 19, "value": "0x10"}
        ],
        "vm_slot_writes": [
            {"idx": 10613292, "slot": 20, "value": "0x10"}
        ],
        "small_byte_loads": [],
        "memory_stores": [],
        "alu_formulas": [
            {
                "idx": 10613289,
                "asm": "ubfx x3, x1, #0, #0x20",
                "expression": "0x10 = ubfx(0x10, 0x0, 0x20)",
                "op": "ubfx",
                "operands": [{"reg": "x1", "value": "0x10"}],
                "semantic": {
                    "kind": "ubfx",
                    "input": "0x10",
                    "lsb": "0x0",
                    "width": "0x20",
                    "result": "0x10"
                },
                "value": "0x10"
            }
        ]
    });
    let effects = vm_op_effect_summaries(&op, &std::collections::HashSet::new(), None);
    assert_eq!(
        effects[0]["python_with_values"],
        serde_json::json!("slot[20] = ubfx(slot[19], 0x0, 0x20)")
    );
}

#[test]
fn summarizes_vm_op_byte_load_effects() {
    let op = serde_json::json!({
        "vm_slot_reads": [
            {"slot": 24, "value": "0x753ddd7fd0"},
            {"slot": 25, "value": "0xc"}
        ],
        "vm_slot_writes": [
            {"idx": 10616037, "slot": 18, "value": "0x7a"}
        ],
        "small_byte_loads": [
            {"idx": 10616034, "mem_addr": "0x753ddd7fdc", "value": "0x7a"}
        ],
        "memory_stores": [],
        "alu_formulas": []
    });
    let effects = vm_op_effect_summaries(&op, &std::collections::HashSet::new(), None);
    assert_eq!(
        effects[0]["pseudocode"],
        serde_json::json!("slot[18] = byte[0x753ddd7fdc] (0x7a)")
    );
    assert_eq!(
        effects[0]["python_with_values"],
        serde_json::json!("slot[18] = byte_load(0x753ddd7fdc)")
    );
    assert_eq!(
        effects[0]["source_byte_load"]["idx"],
        serde_json::json!(10616034)
    );
}
