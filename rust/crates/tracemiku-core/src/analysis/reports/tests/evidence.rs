use super::lineage_batch::byte_lineage_batch_frontier_groups;
use super::*;

#[test]
fn byte_lineage_compact_summary_reports_pointer_transitions() {
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 4,
        "steps_returned": 1,
        "stop_reason": {"kind": "depth_limit"},
        "steps": [
            {
                "step": 0,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 200, "reg": "x16"},
                "backstep": {
                    "idx": 200,
                    "source_reg": "x16",
                    "source_value": "0x74b68bd4c0",
                    "target": {"idx": 200, "asm": "str x16, [x25]", "class": "vm-reg-store"},
                    "local_def": {
                        "idx": 199,
                        "asm": "add x16, x11, x2",
                        "class": "alu",
                        "formula": {
                            "op": "add",
                            "expression": "0x74b68bd4c0 = 0x74b68bd6d0 + 0xfffffffffffffdf0",
                            "operands": [
                                {"reg": "x11", "value": "0x74b68bd6d0"},
                                {"reg": "x2", "value": "0xfffffffffffffdf0"}
                            ]
                        }
                    },
                    "upstream": {"status": "not_memory_backed"}
                },
                "decision": {"kind": "frontier_auto"},
                "next": {"idx": 199, "reg": "x11"}
            }
        ]
    });
    let compact = byte_lineage_compact_summary(&lineage);
    assert_eq!(
        compact["pointer_transitions"][0]["expression"],
        serde_json::json!("0x74b68bd4c0 = 0x74b68bd6d0 + 0xfffffffffffffdf0")
    );
    assert_eq!(
        compact["pointer_transitions"][0]["pointer_base"],
        serde_json::json!("0x74b68bd6d0")
    );
    assert_eq!(
        compact["pointer_transitions"][0]["delta"],
        serde_json::json!("0xfffffffffffffdf0")
    );
}

#[test]
fn byte_lineage_compact_summary_reports_repeated_values() {
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 2,
        "steps_returned": 2,
        "stop_reason": {
            "kind": "cycle",
            "seed": {"kind": "reg_at", "idx": 190, "reg": "x1"}
        },
        "steps": [
            {
                "step": 0,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 200, "reg": "x8"},
                "backstep": {
                    "idx": 200,
                    "source_reg": "x8",
                    "source_value": "0x74b68bb9a0",
                    "target": {"idx": 200, "asm": "str x8, [x25]", "class": "vm-reg-store"},
                    "local_def": {
                        "idx": 199,
                        "asm": "orr x8, x0, x1",
                        "class": "alu",
                        "formula": {
                            "op": "orr",
                            "expression": "0x74b68bb9a0 = 0x0 | 0x74b68bb9a0"
                        }
                    },
                    "upstream": {"status": "not_memory_backed"}
                },
                "decision": {"kind": "frontier_auto"},
                "next": {"idx": 190, "reg": "x1"}
            },
            {
                "step": 1,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 190, "reg": "x1"},
                "backstep": {
                    "idx": 190,
                    "source_reg": "x1",
                    "source_value": "0x74b68bb9a0",
                    "target": {"idx": 190, "asm": "str x1, [x25]", "class": "vm-reg-store"},
                    "local_def": {
                        "idx": 189,
                        "asm": "ldr x1, [x25, #0xa0]",
                        "class": "vm-reg-load",
                        "vm_slot": {"slot_bytes": 8, "slot": 20}
                    },
                    "upstream": {"status": "ready", "addr": "0x7744599548"}
                },
                "decision": {"kind": "upstream_next"},
                "next": {"idx": 180, "reg": "x1"}
            }
        ]
    });
    let compact = byte_lineage_compact_summary(&lineage);
    assert_eq!(
        compact["repeated_values"][0]["value"],
        serde_json::json!("0x74b68bb9a0")
    );
    assert_eq!(compact["terminal"]["kind"], serde_json::json!("cycle"));
    assert_eq!(compact["terminal"]["seed"]["reg"], serde_json::json!("x1"));
    assert!(compact["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action.as_str().unwrap_or("").contains("repeated_values")));
}

#[test]
fn byte_lineage_compact_summary_reports_stable_pointer_loop() {
    let steps = (0..12)
        .map(|step| {
            serde_json::json!({
                "step": step,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 200 - step, "reg": "x9"},
                "backstep": {
                    "idx": 200 - step,
                    "source_reg": "x9",
                    "source_value": "0x74b68bd4c0",
                    "target": {"idx": 200 - step, "asm": "mov x9, x10", "class": "alu"},
                    "local_def": {
                        "idx": 199 - step,
                        "asm": "orr x9, xzr, x10",
                        "class": "alu",
                        "formula": {
                            "op": "orr",
                            "expression": "0x74b68bd4c0 = 0x0 | 0x74b68bd4c0"
                        }
                    },
                    "upstream": {"status": "not_memory_backed"}
                },
                "decision": {"kind": "frontier_auto"},
                "next": {"idx": 199 - step, "reg": "x10"}
            })
        })
        .collect::<Vec<_>>();
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 12,
        "steps_returned": 12,
        "stop_reason": {"kind": "depth_limit"},
        "steps": steps
    });
    let compact = byte_lineage_compact_summary(&lineage);
    assert_eq!(
        compact["stable_pointer_loop"]["kind"],
        serde_json::json!("stable_pointer_loop")
    );
    assert_eq!(
        compact["stable_pointer_loop"]["value"],
        serde_json::json!("0x74b68bd4c0")
    );
    assert_eq!(
        compact["stable_pointer_loop"]["count"],
        serde_json::json!(12)
    );
    assert!(compact["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action
            .as_str()
            .unwrap_or("")
            .contains("stable_pointer_loop")));
}

#[test]
fn byte_lineage_batch_groups_stable_pointer_loops() {
    let results = serde_json::json!([
        {
            "offset": 0,
            "addr": "0x4000",
            "lineage": {
                "status": "ready",
                "steps_returned": 80,
                "terminal": {"kind": "depth_limit"},
                "stable_pointer_loop": {
                    "kind": "stable_pointer_loop",
                    "value": "0x74b68bd4c0",
                    "count": 45
                },
                "repeated_values": [
                    {"value": "0x74b68bd4c0", "count": 45}
                ]
            }
        },
        {
            "offset": 1,
            "addr": "0x4001",
            "lineage": {
                "status": "ready",
                "steps_returned": 80,
                "terminal": {"kind": "depth_limit"},
                "stable_pointer_loop": {
                    "kind": "stable_pointer_loop",
                    "value": "0x74b68bd4c0",
                    "count": 40
                },
                "repeated_values": [
                    {"value": "0x74b68bd4c0", "count": 40}
                ]
            }
        }
    ]);
    let groups = byte_lineage_batch_frontier_groups(results.as_array().unwrap());
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["decision"], serde_json::json!("depth_limit"));
    assert_eq!(
        groups[0]["stable_pointer_loops"][0]["value"],
        serde_json::json!("0x74b68bd4c0")
    );
    assert_eq!(
        groups[0]["stable_pointer_loops"][0]["byte_count"],
        serde_json::json!(2)
    );
    assert_eq!(
        groups[0]["stable_pointer_loops"][0]["total_count"],
        serde_json::json!(85)
    );
    assert!(groups[0]["next_action"]
        .as_str()
        .unwrap_or("")
        .contains("stable pointer"));
}

#[test]
fn byte_lineage_compact_summary_keeps_call_return() {
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 4,
        "steps_returned": 1,
        "stop_reason": {
            "kind": "terminal",
            "decision": {
                "kind": "stop",
                "upstream_status": "call_return_boundary"
            }
        },
        "steps": [
            {
                "step": 0,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 201, "reg": "x0"},
                "backstep": {
                    "idx": 201,
                    "source_reg": "x0",
                    "source_value": "0x7599191120",
                    "target": {"idx": 201, "asm": "mov x23, x0", "class": "alu"},
                    "local_def": {
                        "idx": 200,
                        "asm": "blr x22",
                        "class": "call-return",
                        "call_return": {
                            "call_idx": 200,
                            "asm": "blr x22",
                            "target_reg": "x22",
                            "target_value": "0x787beb9718",
                            "return_reg": "x0",
                            "return_value": "0x7599191120",
                            "intervening_rows": 2,
                            "args": [{"reg": "x0", "value": "0x12"}]
                        }
                    },
                    "upstream": {"status": "call_return_boundary"}
                },
                "decision": {
                    "kind": "stop",
                    "upstream_status": "call_return_boundary"
                },
                "next": null
            }
        ]
    });
    let compact = byte_lineage_compact_summary(&lineage);
    assert_eq!(
        compact["path"][0]["local_def"]["call_return"]["target_value"],
        serde_json::json!("0x787beb9718")
    );
    assert_eq!(
        compact["path"][0]["local_def"]["call_return"]["intervening_rows"],
        serde_json::json!(2)
    );
    assert!(compact["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action.as_str().unwrap_or("").contains("callee")));
}

#[test]
fn lineage_uses_byte_lane_when_following_shift_frontier() {
    let backstep = serde_json::json!({
        "local_def": {
            "idx": 14165576,
            "asm": "lsr x13, x17, x5",
            "class": "alu",
            "def": {
                "reg": "x13",
                "src": [
                    {"reg": "x17", "value": "0x74b68bbdff"},
                    {"reg": "x5", "value": "0x10"}
                ],
                "value_after": "0x74b68b"
            }
        },
        "upstream": {
            "status": "not_memory_backed"
        },
        "frontier": [
            {
                "idx": 14165576,
                "reason": "local_def_source_reg",
                "reg": "x17",
                "value": "0x74b68bbdff"
            },
            {
                "idx": 14165576,
                "reason": "local_def_source_reg",
                "reg": "x5",
                "value": "0x10"
            }
        ]
    });
    let (seed, decision) = lineage_next_from_backstep(
        &backstep,
        Some(0),
        &VmProfile::new(
            "x9".to_string(),
            "x10".to_string(),
            "x11".to_string(),
            8.try_into().unwrap(),
            "x12".to_string(),
        )
        .unwrap(),
    );
    let seed = seed.unwrap().to_json();
    assert_eq!(decision["kind"], serde_json::json!("frontier_auto"));
    assert_eq!(seed["reg"], serde_json::json!("x17"));
    assert_eq!(seed["byte_lane"], serde_json::json!(2));
}

#[test]
fn finds_hex_byte_offsets_on_byte_boundaries() {
    assert_eq!(
        find_hex_byte_offsets("aa 62:61_62 bb 62 61 62", "626162"),
        vec![1, 5]
    );
    assert!(find_hex_byte_offsets("0626162", "626162").is_empty());
    assert!(find_hex_byte_offsets("626162", "00").is_empty());
}

#[test]
fn resolves_proc_maps_addresses() {
    let maps = "\
787beb8000-787bf61000 r-xp 0005b000 07:128 126231 /apex/com.android.runtime/lib64/bionic/libc.so\n";
    let hit = resolve_addr_in_maps_text(maps, 0x787bf034e8).unwrap();
    assert_eq!(hit["status"], serde_json::json!("hit"));
    assert_eq!(hit["map_offset"], serde_json::json!("0x4b4e8"));
    assert_eq!(hit["file_offset"], serde_json::json!("0xa64e8"));
    assert_eq!(
        hit["path"],
        serde_json::json!("/apex/com.android.runtime/lib64/bionic/libc.so")
    );
    assert!(resolve_addr_in_maps_text(maps, 0x7601b72790).is_none());
}

#[test]
fn resolves_nm_symbols_by_nearest_preceding_offset() {
    let target = parse_nm_symbol_line("0000000000001200 0000000000000038 T target_func@@LIB")
        .expect("parse symbol");
    assert_eq!(target.addr, 0x1200);
    assert_eq!(target.size, Some(0x38));
    assert_eq!(target.name, "target_func@@LIB");

    let symbols = vec![
        ElfSymbol {
            addr: 0x1000,
            size: Some(0x20),
            kind: "T".to_string(),
            name: "helper_func@@LIB".to_string(),
        },
        target,
    ];
    let hit = resolve_elf_symbol_json(&symbols, 0x1204).unwrap();
    assert_eq!(hit["status"], serde_json::json!("nearest"));
    assert_eq!(hit["symbol_addr"], serde_json::json!("0x1200"));
    assert_eq!(hit["delta"], serde_json::json!("0x4"));
    assert_eq!(hit["name"], serde_json::json!("target_func@@LIB"));
    assert_eq!(hit["base_name"], serde_json::json!("target_func"));
    assert_eq!(hit["in_symbol_range"], serde_json::json!(true));
}

#[test]
fn base64_decoder_accepts_unpadded_output() {
    let decoded = base64_decoded_bytes("SGVsbG8sIHdvcmxkIQ").unwrap();
    assert_eq!(decoded, b"Hello, world!");
}

#[test]
fn parse_addr_str_is_hex_default() {
    use super::{parse_addr_str, parse_u64_str};
    // address-typed args: bare token is HEX (disassembler convention)
    assert_eq!(parse_addr_str("0x10"), Some(16));
    assert_eq!(parse_addr_str("10"), Some(16)); // hex, NOT decimal
    assert_eq!(parse_addr_str("7fc108c568"), Some(0x7fc108c568));
    assert_eq!(parse_addr_str("d16"), Some(16)); // explicit decimal escape
    assert_eq!(parse_addr_str("zz"), None);
    // size/count args keep decimal-default via parse_u64_str
    assert_eq!(parse_u64_str("256"), Some(256));
    assert_eq!(parse_u64_str("0x100"), Some(256));
}
