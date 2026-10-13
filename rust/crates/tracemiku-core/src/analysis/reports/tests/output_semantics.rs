use super::vm_replay::{
    vm_ops_compact_replay_summary, vm_ops_effects_only_summary, vm_ops_replay_plan_summary,
};
use super::*;

#[test]
fn vm_ops_effects_only_summary_lifts_effects_to_top_level() {
    let output = serde_json::json!({
        "status": "ready",
        "start": 10616026,
        "end": 10616041,
        "source_requested": 15,
        "source_returned": 15,
        "source_maybe_truncated": false,
        "vm_rows": 15,
        "vm_state_base": "0x77445994a0",
        "vm_profile": {
            "ip_reg": "x9",
            "state_reg": "x10",
            "dispatch_reg": "x11",
            "infra_regs": ["x9", "x10", "x11", "x12", "sp", "fp", "lr"]
        },
        "ops_returned": 1,
        "truncated": false,
        "ops": [
            {
                "idx_start": 10616026,
                "idx_end": 10616041,
                "bytecode_reads": [
                    {
                        "idx": 10616029,
                        "offset": "0x5",
                        "width": 1,
                        "bytes_le_hex": "12",
                        "value": "0x12"
                    },
                    {
                        "idx": 10616030,
                        "offset": "0x8",
                        "width": 4,
                        "bytes_le_hex": "12000000",
                        "value": "0x12"
                    }
                ],
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
                "memory_stores": [
                    {
                        "idx": 10616038,
                        "class": "mem-store",
                        "mem_addr": "0x753ddd7fd0",
                        "store_src": [{"reg": "x1", "value": "0xab"}]
                    }
                ],
                "alu_formulas": []
            },
            {
                "idx_start": 10616041,
                "idx_end": 10616045,
                "bytecode_reads": [
                    {
                        "idx": 10616042,
                        "offset": "0x8",
                        "width": 8,
                        "bytes_le_hex": "0900000000000000",
                        "value": "0x9"
                    }
                ],
                "vm_slot_reads": [],
                "vm_slot_writes": [],
                "small_byte_loads": [],
                "memory_stores": [],
                "alu_formulas": [
                    {
                        "idx": 10616043,
                        "asm": "add x9, x9, x6, lsl #4",
                        "expression": "0x200 = 0x100 + 0x9",
                        "op": "add"
                    }
                ]
            }
        ]
    });
    let summary = vm_ops_effects_only_summary(&output);
    assert!(summary.get("ops").is_none());
    assert_eq!(summary["effect_count"], serde_json::json!(3));
    assert_eq!(summary["source_maybe_truncated"], serde_json::json!(false));
    assert_eq!(summary["vm_state_base"], serde_json::json!("0x77445994a0"));
    assert_eq!(summary["byte_load_effect_count"], serde_json::json!(1));
    assert_eq!(summary["memory_store_effect_count"], serde_json::json!(1));
    assert_eq!(summary["control_effect_count"], serde_json::json!(1));
    assert_eq!(summary["bytecode_read_count"], serde_json::json!(3));
    assert_eq!(summary["op_template_count"], serde_json::json!(2));
    assert_eq!(
        summary["effects"][0]["pseudocode"],
        serde_json::json!("slot[18] = byte[0x753ddd7fdc] (0x7a)")
    );
    assert_eq!(
        summary["effects"][0]["python_with_values"],
        serde_json::json!("slot[18] = byte_load(0x753ddd7fdc)")
    );
    assert_eq!(
        summary["effects"][0]["op_idx_start"],
        serde_json::json!(10616026)
    );
    assert_eq!(
        summary["byte_load_effects"][0]["source_byte_load"]["idx"],
        serde_json::json!(10616034)
    );
    assert_eq!(
        summary["memory_store_effects"][0]["pseudocode"],
        serde_json::json!("mem[0x753ddd7fd0] = 0xab")
    );
    assert_eq!(
        summary["memory_store_effects"][0]["python_with_values"],
        serde_json::json!("mem[0x753ddd7fd0] = 0xab")
    );
    assert_eq!(
        summary["bytecode_reads"][2]["value"],
        serde_json::json!("0x9")
    );
    assert_eq!(
        summary["bytecode_reads"][2]["name"],
        serde_json::json!("bc_0x8_u64")
    );
    assert_eq!(
        summary["control_effects"][0]["idx"],
        serde_json::json!(10616043)
    );
    assert_eq!(
        summary["control_effects"][0]["python_with_values"],
        serde_json::json!("0x200 = 0x100 + 0x9")
    );
    assert_eq!(summary["op_effects"].as_array().unwrap().len(), 2);
    assert_eq!(
        summary["op_effects"][1]["bytecode_reads"][0]["value"],
        serde_json::json!("0x9")
    );
    assert_eq!(
        summary["op_effects"][1]["bytecode_reads"][0]["name"],
        serde_json::json!("bc_0x8_u64")
    );
    assert_eq!(
        summary["op_effects"][1]["effects"][0]["kind"],
        serde_json::json!("control")
    );
    let templates = summary["op_templates"].as_array().unwrap();
    let byte_load_template = templates
        .iter()
        .find(|template| {
            template
                .get("signature")
                .and_then(|v| v.as_str())
                .is_some_and(|signature| signature.contains("slot_write:byte_load:none"))
        })
        .unwrap();
    let byte_load_operands = byte_load_template["template_operands"].as_array().unwrap();
    let byte_load_dst_operand = byte_load_operands
        .iter()
        .find(|operand| operand["name"] == serde_json::json!("bc_0x5_u8"))
        .unwrap();
    assert_eq!(
        byte_load_dst_operand["roles"][0],
        serde_json::json!({"role": "dst_slot", "count": 1})
    );
    assert_eq!(
        byte_load_operands
            .iter()
            .find(|operand| operand["name"] == serde_json::json!("bc_0x8_u32"))
            .unwrap()["name"],
        serde_json::json!("bc_0x8_u32")
    );
    assert!(byte_load_template["template_skeletons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|skeleton| {
            skeleton["python"] == serde_json::json!("slot[dst] = byte_load(addr_expr)")
                && skeleton["python_with_roles"]
                    == serde_json::json!("slot[bc_0x5_u8] = byte_load(addr_expr)")
                && skeleton["binding"] == serde_json::json!("shape_only")
        }));
    let control_template = templates
        .iter()
        .find(|template| {
            template
                .get("signature")
                .and_then(|v| v.as_str())
                .is_some_and(|signature| signature.contains("control:formula:add"))
        })
        .unwrap();
    assert_eq!(
        control_template["bytecode_operands"][0]["values"][0]["value"],
        serde_json::json!("0x9")
    );
    assert_eq!(
        control_template["template_operands"][0]["name"],
        serde_json::json!("bc_0x8_u64")
    );
    assert_eq!(
        control_template["template_operands"][0]["roles"][0],
        serde_json::json!({"role": "control_operand", "count": 1})
    );
    assert_eq!(
        control_template["template_skeletons"][0]["python"],
        serde_json::json!("vm_ip = add(vm_ip, bc_0x8_u64)")
    );
    assert_eq!(
        control_template["template_skeletons"][0]["python_with_roles"],
        serde_json::json!("vm_ip = add(vm_ip, bc_0x8_u64)")
    );
    assert_eq!(
        control_template["template_skeletons"][0]["role_binding"]["control_operands"][0],
        serde_json::json!("bc_0x8_u64")
    );
    assert_eq!(
        control_template["effect_shapes"][0]["formula_op"],
        serde_json::json!("add")
    );
    assert_eq!(
        control_template["effect_shapes"][0]["pseudocode_samples"][0],
        serde_json::json!("0x200 = 0x100 + 0x9")
    );

    let compact = vm_ops_compact_replay_summary(&output);
    assert!(compact.get("effects").is_none());
    assert!(compact.get("op_effects").is_none());
    assert!(compact.get("op_templates").is_none());
    assert_eq!(compact["effect_count"], serde_json::json!(3));
    assert_eq!(compact["vm_state_base"], serde_json::json!("0x77445994a0"));
    assert_eq!(compact["compact_template_count"], serde_json::json!(2));
    let compact_templates = compact["compact_templates"].as_array().unwrap();
    let compact_byte_load = compact_templates
        .iter()
        .find(|template| {
            template["signature"]
                .as_str()
                .is_some_and(|signature| signature.contains("slot_write:byte_load:none"))
        })
        .unwrap();
    assert!(compact_byte_load["skeletons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|skeleton| {
            skeleton["python_with_roles"]
                == serde_json::json!("slot[bc_0x5_u8] = byte_load(addr_expr)")
        }));
    assert!(compact_byte_load["effect_shapes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|shape| shape["samples"].as_array().into_iter().flatten())
        .any(|sample| sample == &serde_json::json!("slot[18] = byte[0x753ddd7fdc] (0x7a)")));

    let replay_plan = vm_ops_replay_plan_summary(&output);
    assert!(replay_plan.get("effects").is_none());
    assert!(replay_plan.get("op_effects").is_none());
    assert_eq!(replay_plan["replay_step_count"], serde_json::json!(2));
    assert_eq!(
        replay_plan["vm_state_base"],
        serde_json::json!("0x77445994a0")
    );
    assert_eq!(
        replay_plan["replay_steps"][0]["effects"][0]["python_with_values"],
        serde_json::json!("slot[18] = byte_load(0x753ddd7fdc)")
    );
    assert_eq!(
        replay_plan["replay_steps"][0]["effects"][0]["source_byte_load"]["mem_addr"],
        serde_json::json!("0x753ddd7fdc")
    );
    assert_eq!(
        replay_plan["replay_steps"][1]["effects"][0]["formula"]["op"],
        serde_json::json!("add")
    );
    let replay_memory_store = replay_plan["replay_steps"][0]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|effect| effect["kind"] == serde_json::json!("memory_store"))
        .unwrap();
    assert_eq!(replay_memory_store["store_width"], serde_json::json!(8));
}

#[test]
fn recognizes_static_memory_load_constants() {
    let chain = vec![serde_json::json!({
        "step": 7,
        "idx": 13720349,
        "value": "0xa000142",
        "local_def": {
            "idx": 13720346,
            "asm": "ldr w16, [x8, x20]",
            "class": "mem-load"
        },
        "upstream": {
            "status": "not_found",
            "addr": "0x74fbf2dc7c",
            "idx_lo": 13520349,
            "idx_hi": 13720349,
            "returned": 0,
            "maybe_truncated": false,
            "observed_bytes_hex": "4201000a"
        }
    })];
    let patterns = recognized_backchain_patterns(&chain);
    assert_eq!(patterns.len(), 1);
    assert_eq!(
        patterns[0]["kind"],
        serde_json::json!("static_memory_load_constant")
    );
    assert_eq!(patterns[0]["bytes_hex"], serde_json::json!("4201000a"));
    assert_eq!(
        patterns[0]["source_boundary"],
        serde_json::json!("lookback_window")
    );
    assert_eq!(patterns[0]["maybe_truncated"], serde_json::json!(false));
    assert_eq!(
        patterns[0]["expression"],
        serde_json::json!(
            "value loaded from memory with no writer found in current lookback window"
        )
    );
    let summary = recognized_backchain_pattern_summary(&patterns);
    assert_eq!(
        summary["static_memory_loads"][0]["value"],
        serde_json::json!("0xa000142")
    );
}

#[test]
fn recognizes_memory_boundary_reads() {
    let chain = vec![serde_json::json!({
        "step": 16,
        "idx": 14082318,
        "value": "0x30312e30",
        "local_def": {
            "idx": 14082318,
            "asm": "ldr w19, [x14, x13]",
            "class": "mem-load"
        },
        "upstream": {
            "status": "observed_read_without_matching_traced_write",
            "addr": "0x756649a2d4",
            "observed_bytes_hex": "302e3130",
            "observed_mismatches": [{"offset": 0, "observed": 0x30, "last_write": 0x30}],
            "last_write": {
                "idx": 14062790,
                "asm": "str x0, [x19]",
                "src_value": "0x756649a730"
            }
        }
    })];
    let patterns = recognized_backchain_patterns(&chain);
    assert_eq!(patterns.len(), 1);
    assert_eq!(
        patterns[0]["kind"],
        serde_json::json!("memory_boundary_read")
    );
    assert_eq!(patterns[0]["bytes_hex"], serde_json::json!("302e3130"));
    let summary = recognized_backchain_pattern_summary(&patterns);
    assert_eq!(
        summary["memory_boundary_reads"][0]["addr"],
        serde_json::json!("0x756649a2d4")
    );
}

#[test]
fn expands_byte_writer_map_from_little_endian_writes() {
    let response = serde_json::json!({
        "idx_range": [100, 300],
        "matched": 3,
        "returned": 3,
        "truncated": false,
        "writes": [
            {
                "idx": 110,
                "pc": "0x1000",
                "rel": "0x0",
                "func": "sub_old",
                "asm": "strb w0, [x1]",
                "dst_addr": "0x2001",
                "size": 1,
                "src_reg": "x0",
                "src_value": "0xaa",
                "byte0": 170
            },
            {
                "idx": 120,
                "pc": "0x1004",
                "rel": "0x4",
                "func": "sub_pack",
                "asm": "str w16, [x2]",
                "dst_addr": "0x2000",
                "size": 4,
                "src_reg": "x16",
                "src_value": "0x616260af",
                "byte0": 175
            },
            {
                "idx": 130,
                "pc": "0x1008",
                "rel": "0x8",
                "func": "sub_tail",
                "asm": "strb w19, [x8, x14]",
                "dst_addr": "0x2004",
                "size": 1,
                "src_reg": "x19",
                "src_value": "0x62",
                "byte0": 98
            }
        ]
    });
    let out = byte_writer_map_output(0x2000, 5, &response);
    assert_eq!(out["status"], serde_json::json!("ready"));
    assert_eq!(out["bytes_hex"], serde_json::json!("af60626162"));
    assert_eq!(out["bytes"][1]["byte_hex"], serde_json::json!("60"));
    assert_eq!(out["bytes"][1]["source_byte_offset"], serde_json::json!(1));
    assert_eq!(
        out["writer_runs"][0]["bytes_hex"],
        serde_json::json!("af606261")
    );
    assert_eq!(
        out["writer_runs"][0]["writer"]["idx"],
        serde_json::json!(120)
    );
    assert_eq!(
        out["writer_runs"][0]["source_byte_offsets"],
        serde_json::json!([0, 1, 2, 3])
    );
    assert_eq!(
        out["writer_runs"][0]["source_byte_offset"],
        serde_json::Value::Null
    );
    assert_eq!(out["writer_runs"][1]["bytes_hex"], serde_json::json!("62"));
    assert_eq!(byte_lane_from_writer_map_entry(&out["bytes"][2]), Some(2));
    let summary = byte_writer_map_summary(&out);
    assert_eq!(summary["byte_count"], serde_json::json!(5));
    assert_eq!(summary["ready_byte_count"], serde_json::json!(5));
    assert_eq!(summary["writer_run_count"], serde_json::json!(2));
    assert_eq!(
        summary["writer_runs"][0]["writer"]["asm"],
        serde_json::json!("str w16, [x2]")
    );
    assert!(summary.get("bytes").is_none());
}

#[test]
fn summarizes_mem_dump_as_c_string() {
    let response = serde_json::json!({
        "status": "ready",
        "addr": "0x1000",
        "count": 4,
        "cursor": 10,
        "bytes": [
            {"addr": "0x1000", "byte": 47, "kind": "r", "src_idx": 1},
            {"addr": "0x1001", "byte": 0, "kind": "r", "src_idx": 1},
            {"addr": "0x1002", "byte": null, "kind": "missing", "src_idx": null},
            {"addr": "0x1003", "byte": 65, "kind": "r", "src_idx": 2}
        ]
    });
    let summary = mem_dump_summary(&response, true);
    assert_eq!(summary["bytes_hex"], serde_json::json!("2f00..41"));
    assert_eq!(summary["ascii"], serde_json::json!("/..A"));
    assert_eq!(summary["c_string"], serde_json::json!("/"));
    assert_eq!(summary["c_string_terminated"], serde_json::json!(true));
    assert_eq!(summary["nul_offset"], serde_json::json!(1));
}

#[test]
fn summarizes_mem_dump_known_little_endian_words() {
    let response = serde_json::json!({
        "status": "ready",
        "addr": "0x1ffc",
        "count": 16,
        "cursor": 20,
        "bytes": [
            {"addr": "0x1ffc", "byte": 170},
            {"addr": "0x1ffd", "byte": 187},
            {"addr": "0x1ffe", "byte": 204},
            {"addr": "0x1fff", "byte": 221},
            {"addr": "0x2000", "byte": 1},
            {"addr": "0x2001", "byte": 2},
            {"addr": "0x2002", "byte": 3},
            {"addr": "0x2003", "byte": 4},
            {"addr": "0x2004", "byte": 5},
            {"addr": "0x2005", "byte": 6},
            {"addr": "0x2006", "byte": 7},
            {"addr": "0x2007", "byte": 8},
            {"addr": "0x2008", "byte": null},
            {"addr": "0x2009", "byte": 10},
            {"addr": "0x200a", "byte": 11},
            {"addr": "0x200b", "byte": 12}
        ]
    });
    let summary = mem_dump_summary(&response, false);
    assert_eq!(
        summary["words_le64"],
        serde_json::json!([
            {
                "offset": 4,
                "addr": "0x2000",
                "width": 8,
                "value": "0x807060504030201",
                "bytes_hex": "0102030405060708"
            }
        ])
    );
}

#[test]
fn extracts_source_byte_for_byte_addresses_inside_word_write() {
    let write = serde_json::json!({
        "dst_addr": "0x3000",
        "size": 4,
        "src_value": "0xd528b905"
    });
    assert_eq!(source_byte_for_write_at(&write, 0x3000), Some(0x05));
    assert_eq!(source_byte_for_write_at(&write, 0x3001), Some(0xb9));
    assert_eq!(source_byte_for_write_at(&write, 0x3002), Some(0x28));
    assert_eq!(source_byte_for_write_at(&write, 0x3003), Some(0xd5));
    assert_eq!(source_byte_for_write_at(&write, 0x3004), None);
    assert_eq!(source_byte_offset_for_write_at(&write, 0x3000), Some(0));
    assert_eq!(source_byte_offset_for_write_at(&write, 0x3003), Some(3));
    assert_eq!(source_byte_offset_for_write_at(&write, 0x3004), None);
}

#[test]
fn chooses_matching_byte_lane_from_deduped_upstream_writers() {
    let write = serde_json::json!({
        "idx": 120,
        "pc": "0x1004",
        "rel": "0x4",
        "func": "sub_pack",
        "asm": "str w16, [x2]",
        "dst_addr": "0x4000",
        "size": 4,
        "src_reg": "x16",
        "src_value": "0xd528b905",
        "byte0": 5
    });
    let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[write]);
    let step = serde_json::json!({
        "upstream": {
            "byte_nexts": dedupe_byte_nexts(&byte_writers)
        }
    });
    let lane0 = choose_laned_upstream_next(&step, 0).unwrap();
    assert_eq!(lane0["selected_byte_lane"], serde_json::json!(0));
    assert_eq!(lane0["source_byte_offset"], serde_json::json!(0));
    assert_eq!(lane0["addr"], serde_json::json!("0x4000"));

    let lane3 = choose_laned_upstream_next(&step, 3).unwrap();
    assert_eq!(lane3["selected_byte_lane"], serde_json::json!(3));
    assert_eq!(lane3["source_byte_offset"], serde_json::json!(3));
    assert_eq!(lane3["addr"], serde_json::json!("0x4003"));
}

#[test]
fn chooses_loaded_byte_offset_when_writer_source_lane_differs() {
    let lane0_write = serde_json::json!({
        "idx": 120,
        "pc": "0x1004",
        "rel": "0x4",
        "func": "sub_pack",
        "asm": "strb w1, [x2]",
        "dst_addr": "0x4000",
        "size": 1,
        "src_reg": "x1",
        "src_value": "0x11",
        "byte0": 0x11
    });
    let lane3_write = serde_json::json!({
        "idx": 123,
        "pc": "0x1010",
        "rel": "0x10",
        "func": "sub_pack",
        "asm": "strb w2, [x2, #3]",
        "dst_addr": "0x4003",
        "size": 1,
        "src_reg": "x2",
        "src_value": "0x22",
        "byte0": 0x22
    });
    let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[lane0_write, lane3_write]);
    let step = serde_json::json!({
        "upstream": {
            "byte_nexts": dedupe_byte_nexts(&byte_writers)
        }
    });
    let lane3 = choose_laned_upstream_next(&step, 3).unwrap();
    assert_eq!(lane3["idx"], serde_json::json!(123));
    assert_eq!(lane3["addr"], serde_json::json!("0x4003"));
    assert_eq!(lane3["selected_byte_lane"], serde_json::json!(3));
    assert_eq!(lane3["source_byte_offset"], serde_json::json!(0));
}

#[test]
fn infers_zero_extended_low_byte_upstream_next() {
    let step = serde_json::json!({
        "source_value": "0x1",
        "upstream": {
            "observed_bytes_hex": "01000000",
            "next": {
                "idx": 123,
                "reg": "x19",
                "src_value": "0x0"
            },
            "byte_nexts": [
                {
                    "addr": "0x4000",
                    "idx": 120,
                    "offset": 0,
                    "offsets": [0],
                    "reason": "memory_load_byte",
                    "reg": "x20",
                    "source_byte_offset": 0,
                    "source_byte_offsets": [0],
                    "src_value": "0x1"
                },
                {
                    "addr": "0x4003",
                    "idx": 123,
                    "offset": 3,
                    "offsets": [3],
                    "reason": "memory_load_byte",
                    "reg": "x19",
                    "source_byte_offset": 0,
                    "source_byte_offsets": [0],
                    "src_value": "0x0"
                }
            ]
        }
    });
    let next = choose_zero_extended_low_byte_upstream_next(&step).unwrap();
    assert_eq!(next["idx"], serde_json::json!(120));
    assert_eq!(next["reg"], serde_json::json!("x20"));
    assert_eq!(next["addr"], serde_json::json!("0x4000"));
    assert_eq!(next["selected_byte_lane"], serde_json::json!(0));
    assert_eq!(next["source_byte_offset"], serde_json::json!(0));
}

#[test]
fn detects_observed_load_bytes_that_do_not_match_traced_writers() {
    let stale_zero_write = serde_json::json!({
        "idx": 120,
        "pc": "0x1004",
        "rel": "0x4",
        "func": "sub_stale",
        "asm": "str x6, [x19, x20]",
        "dst_addr": "0x4000",
        "size": 8,
        "src_reg": "x6",
        "src_value": "0x0",
        "byte0": 0
    });
    let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[stale_zero_write]);
    let observed = 0x4433_2211u64.to_le_bytes();
    let mismatches = observed_byte_writer_mismatches(0x4000, &observed[..4], &byte_writers);
    assert_eq!(mismatches.len(), 4);
    assert_eq!(mismatches[0]["observed_byte"], serde_json::json!("11"));
    assert_eq!(mismatches[0]["writer_byte"], serde_json::json!("00"));
    assert_eq!(mismatches[0]["writer_idx"], serde_json::json!(120));
}

#[test]
fn lineage_prefers_matching_byte_lane_from_upstream_writers() {
    let write = serde_json::json!({
        "idx": 120,
        "pc": "0x1004",
        "rel": "0x4",
        "func": "sub_pack",
        "asm": "str w16, [x2]",
        "dst_addr": "0x4000",
        "size": 4,
        "src_reg": "x16",
        "src_value": "0xd528b905",
        "byte0": 5
    });
    let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[write]);
    let backstep = serde_json::json!({
        "upstream": {
            "next": {
                "idx": 120,
                "reg": "x16",
                "src_value": "0xd528b905"
            },
            "byte_nexts": dedupe_byte_nexts(&byte_writers)
        }
    });
    let (seed, decision) = lineage_next_from_backstep(
        &backstep,
        Some(2),
        &VmProfile::new(
            "x9".to_string(),
            "x10".to_string(),
            "x11".to_string(),
            "x12".to_string(),
        ),
    );
    let seed = seed.unwrap().to_json();
    assert_eq!(decision["kind"], serde_json::json!("upstream_byte_lane"));
    assert_eq!(seed["idx"], serde_json::json!(120));
    assert_eq!(seed["reg"], serde_json::json!("x16"));
    assert_eq!(seed["byte_lane"], serde_json::json!(2));
    assert_eq!(decision["next"]["addr"], serde_json::json!("0x4002"));
}

#[test]
fn lineage_stops_at_observed_memory_boundary_before_frontier() {
    let backstep = serde_json::json!({
        "local_def": {
            "idx": 7572808,
            "asm": "ldr x8, [x1, x5]",
            "class": "mem-load",
            "def": {
                "reg": "x8",
                "src": [
                    {"reg": "x1", "value": "0x74974cca00"},
                    {"reg": "x5", "value": "0xfffffffffffffc48"}
                ],
                "value_after": "0x69f2e9fb"
            }
        },
        "upstream": {
            "status": "observed_read_without_matching_traced_write",
            "addr": "0x74974cc648",
            "addr_hi": "0x74974cc650",
            "observed_bytes_hex": "fbe9f26900000000",
            "observed_mismatches": [
                {
                    "addr": "0x74974cc648",
                    "observed_byte": "fb",
                    "writer_byte": "00",
                    "writer_idx": 7571629
                }
            ],
            "last_write": {
                "idx": 7571629,
                "asm": "str x6, [x19, x20]",
                "src_value": "0x0"
            },
            "gap_call_candidates": {
                "candidate_count_total": 1,
                "candidates": [
                    {
                        "idx": 7572198,
                        "asm": "blr x22",
                        "target_module": {"name": "libc.so"}
                    }
                ]
            }
        },
        "frontier": [
            {
                "idx": 7572808,
                "reason": "local_def_source_reg",
                "reg": "x1",
                "value": "0x74974cca00"
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
            "x12".to_string(),
        ),
    );
    assert!(seed.is_none());
    assert_eq!(
        decision["kind"],
        serde_json::json!("observed_read_without_matching_traced_write")
    );
    assert_eq!(
        decision["upstream"]["observed_bytes_hex"],
        serde_json::json!("fbe9f26900000000")
    );
    assert_eq!(
        decision["upstream"]["gap_call_candidates"]["candidate_count_total"],
        serde_json::json!(1)
    );
}

#[test]
fn lineage_stops_at_missing_memory_writer_before_frontier() {
    let backstep = serde_json::json!({
        "local_def": {
            "idx": 14009402,
            "asm": "ldr x8, [x8]",
            "class": "mem-load",
            "def": {
                "reg": "x8",
                "src": [{"reg": "x8", "value": "0x74fbf7e650"}],
                "value_after": "0x74fbe99650"
            }
        },
        "upstream": {
            "status": "not_found",
            "addr": "0x74fbf7e650",
            "addr_hi": "0x74fbf7e658",
            "idx_lo": 9009402,
            "idx_hi": 14009402,
            "observed_bytes_hex": "5096e9fb74000000",
            "returned": 0,
            "maybe_truncated": false
        },
        "frontier": [
            {
                "idx": 14009402,
                "reason": "local_def_source_reg",
                "reg": "x8",
                "value": "0x74fbf7e650"
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
            "x12".to_string(),
        ),
    );
    assert!(seed.is_none());
    assert_eq!(
        decision["kind"],
        serde_json::json!("memory_not_found_boundary")
    );
    assert_eq!(decision["upstream_status"], serde_json::json!("not_found"));
    assert_eq!(
        decision["upstream"]["observed_bytes_hex"],
        serde_json::json!("5096e9fb74000000")
    );
}

#[test]
fn byte_lineage_summary_promotes_memory_boundaries() {
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 8,
        "steps_returned": 1,
        "stop_reason": {
            "kind": "terminal",
            "decision": {
                "kind": "observed_read_without_matching_traced_write"
            }
        },
        "steps": [
            {
                "step": 0,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 200, "reg": "x8"},
                "backstep": {
                    "idx": 200,
                    "source_reg": "x8",
                    "source_value": "0x69f2e9fb",
                    "target": {"idx": 200, "asm": "str x8, [x25]", "class": "vm-reg-store"},
                    "local_def": {"idx": 199, "asm": "ldr x8, [x1]", "class": "mem-load"},
                    "upstream": {
                        "status": "observed_read_without_matching_traced_write",
                        "addr": "0x4000",
                        "addr_hi": "0x4008",
                        "observed_bytes_hex": "fbe9f26900000000",
                        "observed_mismatches": [
                            {"addr": "0x4000", "observed_byte": "fb", "writer_byte": "00"}
                        ],
                        "last_write": {"idx": 120, "asm": "str x6, [x19]", "src_value": "0x0"}
                    }
                },
                "decision": {
                    "kind": "observed_read_without_matching_traced_write",
                    "upstream": {
                        "addr": "0x4000",
                        "addr_hi": "0x4008",
                        "observed_bytes_hex": "fbe9f26900000000"
                    }
                },
                "next": null
            }
        ]
    });
    let summary = byte_lineage_summary(&lineage);
    assert_eq!(summary["memory_boundaries"].as_array().unwrap().len(), 1);
    assert_eq!(
        summary["memory_boundaries"][0]["upstream"]["observed_bytes_hex"],
        serde_json::json!("fbe9f26900000000")
    );
    assert_eq!(
        summary["memory_boundaries"][0]["value"],
        serde_json::json!("0x69f2e9fb")
    );
}

#[test]
fn byte_lineage_compact_summary_omits_full_chain() {
    let lineage = serde_json::json!({
        "status": "ready",
        "start": {"addr": "0x4000", "before_idx": 200},
        "depth_requested": 8,
        "steps_returned": 1,
        "stop_reason": {
            "kind": "terminal",
            "decision": {
                "kind": "observed_read_without_matching_traced_write"
            }
        },
        "steps": [
            {
                "step": 0,
                "kind": "reg_source",
                "seed": {"kind": "reg_at", "idx": 200, "reg": "x8"},
                "backstep": {
                    "idx": 200,
                    "source_reg": "x8",
                    "source_value": "0x69f2e9fb",
                    "target": {"idx": 200, "asm": "str x8, [x25]", "class": "vm-reg-store"},
                    "local_def": {
                        "idx": 199,
                        "asm": "eor x8, x9, x10",
                        "class": "alu",
                        "formula": {
                            "op": "eor",
                            "expression": "0x69f2e9fb = 0x1 ^ 0x69f2e9fa",
                            "semantic": {"kind": "xor_mix"},
                            "operands": [
                                {"reg": "x9", "value": "0x1"},
                                {"reg": "x10", "value": "0x69f2e9fa"}
                            ]
                        }
                    },
                    "upstream": {
                        "status": "observed_read_without_matching_traced_write",
                        "addr": "0x4000",
                        "observed_bytes_hex": "fbe9f26900000000",
                        "maybe_truncated": false,
                        "last_write": {"idx": 120, "asm": "str x6, [x19]", "src_value": "0x0"},
                        "gap_call_candidates": {"candidate_count_total": 2}
                    }
                },
                "decision": {
                    "kind": "observed_read_without_matching_traced_write",
                    "upstream": {"addr": "0x4000"}
                },
                "next": null
            }
        ]
    });
    let compact = byte_lineage_compact_summary(&lineage);
    assert!(compact.get("chain").is_none());
    assert_eq!(compact["path"].as_array().unwrap().len(), 1);
    assert_eq!(
        compact["path"][0]["local_def"]["formula"]["semantic_kind"],
        serde_json::json!("xor_mix")
    );
    assert_eq!(
        compact["path"][0]["local_def"]["formula"]["operands"][0]["reg"],
        serde_json::json!("x9")
    );
    assert_eq!(
        compact["memory_boundaries"][0]["observed_bytes_hex"],
        serde_json::json!("fbe9f26900000000")
    );
    assert_eq!(
        compact["memory_boundaries"][0]["gap_call_count_total"],
        serde_json::json!(2)
    );
    assert_eq!(
        compact["memory_boundaries"][0]["mem_dump_command"],
        serde_json::json!(
            "./tracemiku mem-dump <call_dir> --addr 0x4000 --count 8 --cursor 200 --summary"
        )
    );
    assert!(compact["next_actions"].as_array().unwrap().len() >= 2);
}

#[test]
fn compact_lineage_formula_labels_pointer_add_operands() {
    let formula = serde_json::json!({
        "op": "add",
        "expression": "0x74b68bcc1c = 0x74b68bb9a0 + 0x127c",
        "semantic": {"kind": "add_small_delta"},
        "operands": [
            {"reg": "x13", "value": "0x74b68bb9a0"},
            {"reg": "x14", "value": "0x127c"}
        ]
    });
    let compact = compact_lineage_formula(Some(&formula));
    assert_eq!(
        compact["operands"][0]["role"],
        serde_json::json!("pointer_base")
    );
    assert_eq!(compact["operands"][1]["role"], serde_json::json!("delta"));

    let formula = serde_json::json!({
        "op": "add",
        "expression": "0x74b68bb9a0 = 0xffffffffffffe4e0 + 0x74b68bd4c0",
        "operands": [
            {"reg": "x7", "value": "0xffffffffffffe4e0"},
            {"reg": "x8", "value": "0x74b68bd4c0"}
        ]
    });
    let compact = compact_lineage_formula(Some(&formula));
    assert_eq!(compact["operands"][0]["role"], serde_json::json!("delta"));
    assert_eq!(
        compact["operands"][1]["role"],
        serde_json::json!("pointer_base")
    );

    let formula = serde_json::json!({
        "op": "add",
        "expression": "0x74b68bedc0 = 0x74b687edc0 + 0x40000",
        "operands": [
            {"reg": "x0", "value": "0x74b687edc0"},
            {"reg": "x20", "value": "0x40000"}
        ]
    });
    let compact = compact_lineage_formula(Some(&formula));
    assert_eq!(
        compact["operands"][0]["role"],
        serde_json::json!("pointer_base")
    );
    assert_eq!(compact["operands"][1]["role"], serde_json::json!("delta"));

    let formula = serde_json::json!({
        "op": "add",
        "expression": "0x74fbf636e0 = 0x74fbf635f0 + (0xf << 0x4)",
        "operands": [
            {"reg": "x21", "value": "0x74fbf635f0"},
            {
                "reg": "x3",
                "value": "0xf",
                "shift": "lsl",
                "shift_amount": "0x4",
                "effective_value": "0xf0"
            }
        ]
    });
    let compact = compact_lineage_formula(Some(&formula));
    assert_eq!(
        compact["operands"][0]["role"],
        serde_json::json!("pointer_base")
    );
    assert_eq!(compact["operands"][1]["role"], serde_json::json!("delta"));
    assert_eq!(
        compact["operands"][1]["effective_value"],
        serde_json::json!("0xf0")
    );
}
