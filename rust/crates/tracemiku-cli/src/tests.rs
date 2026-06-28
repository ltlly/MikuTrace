//! Unit tests for tracemiku-cli, extracted from main.rs to keep the
//! command file navigable. `super::{...}` resolves to the crate root
//! (main.rs items) exactly as when this was an inline module.

use super::{
    adjust_self_def_formula_next, alu_expression_from_asm, base64_decoded_bytes,
    byte_lane_from_writer_map_entry, byte_lineage_batch_frontier_groups,
    byte_lineage_compact_summary, byte_lineage_summary, byte_writer_map_output,
    byte_writer_map_summary, byte_writer_vm_source_ranges, byte_writers_from_range_writes,
    call_return_def_from_previous_call, choose_frontier_next, choose_frontier_next_for_lane,
    choose_laned_upstream_next, choose_zero_extended_low_byte_upstream_next, classify_vm_asm,
    compact_gap_call_candidates, compact_lineage_formula, dedupe_byte_nexts, def_entries_from_asm,
    def_source_contains_reg, def_source_regs_from_asm, enrich_gap_call_candidate_trace_writes,
    find_hex_byte_offsets, gap_call_candidate_from_record, lineage_next_from_backstep,
    mem_addr_from_asm, mem_dump_summary, memory_access_width, merge_missing_meta_field,
    observed_byte_writer_mismatches, odd_u64_inverse, output_map_summary,
    output_semantic_byte_equation, output_semantic_byte_equation_input_summary,
    output_semantic_byte_equation_summary, output_semantic_byte_equation_summary_with_context,
    output_semantic_xor_word_degenerate_templates, output_semantic_xor_word_run_templates,
    output_semantic_xor_word_state_source_summary, output_semantic_xor_word_state_sources,
    output_semantic_xor_word_templates, parse_nm_symbol_line, recognize_alu_semantic,
    recognized_backchain_pattern_summary, recognized_backchain_patterns, record_reg_u64,
    register_value_key, resolve_addr_in_maps_text, resolve_elf_symbol_json,
    source_byte_for_write_at, source_byte_offset_for_write_at, store_source_regs_from_asm,
    store_touch_for_addr, syscall_return_def_from_previous_svc, vm_backchain_stop_summary,
    vm_op_effect_summaries, vm_ops_compact_replay_summary, vm_ops_effects_only_summary,
    vm_ops_replay_plan_summary, vm_ops_state_updates, vm_slot_access_summaries, vm_slot_from_asm,
    ElfSymbol, VmProfile,
};

#[test]
fn parses_store_source_registers() {
    assert_eq!(store_source_regs_from_asm("str w1, [x19, x6]"), vec!["w1"]);
    assert_eq!(
        store_source_regs_from_asm("stp x9, x10, [x11, #0x10]"),
        vec!["x9", "x10"]
    );
    assert_eq!(
        store_source_regs_from_asm("stxp w0, x1, x2, [x3]"),
        vec!["x1", "x2"]
    );
    assert_eq!(store_source_regs_from_asm("stxr w0, x1, [x2]"), vec!["x1"]);
    assert!(store_source_regs_from_asm("ldr x0, [x1]").is_empty());
}

#[test]
fn register_value_key_matches_canonical_frame_aliases() {
    assert_eq!(register_value_key("x29"), "fp");
    assert_eq!(register_value_key("w29"), "fp");
    assert_eq!(register_value_key("x30"), "lr");
    assert_eq!(register_value_key("w30"), "lr");
    assert_eq!(register_value_key("wsp"), "sp");
    assert_eq!(register_value_key("w8"), "x8");
}

#[test]
fn detects_self_def_source_registers() {
    let self_def = serde_json::json!({
        "reg": "x0",
        "src": [{"reg": "x0", "value": "0x7b3a"}]
    });
    assert!(def_source_contains_reg(&self_def, "x0"));
    assert!(def_source_contains_reg(&self_def, "w0"));

    let copy_def = serde_json::json!({
        "reg": "x2",
        "src": [{"reg": "x3", "value": "0x7b3a"}]
    });
    assert!(!def_source_contains_reg(&copy_def, "x2"));
}

#[test]
fn mem_addr_from_asm_uses_stack_and_frame_aliases() {
    let record = serde_json::json!({
        "regs": {
            "sp": "0x7000",
            "fp": "0x7100",
            "x1": "0x20",
        }
    });
    assert_eq!(
        mem_addr_from_asm("ldr x8, [sp, #0x10]", &record),
        Some(0x7010)
    );
    assert_eq!(
        mem_addr_from_asm("ldr x8, [x29, #0x18]", &record),
        Some(0x7118)
    );
    assert_eq!(
        mem_addr_from_asm("ldur x3, [x29, #-0x18]", &record),
        Some(0x70e8)
    );
    assert_eq!(record_reg_u64(&record, "x29"), Some(0x7100));
}

#[test]
fn merge_missing_meta_field_keeps_call_specific_values() {
    let mut meta = serde_json::json!({
        "callIdx": 1,
        "modules": []
    });
    let parent = serde_json::json!({
        "module": {"name": "libtarget.so", "base": "0x1000", "size": 0x2000},
        "modules": [{"name": "libc.so", "base": "0x7000", "size": 0x1000}],
        "callIdx": 99
    });
    merge_missing_meta_field(&mut meta, &parent, "module");
    merge_missing_meta_field(&mut meta, &parent, "modules");
    merge_missing_meta_field(&mut meta, &parent, "callIdx");
    assert_eq!(meta["module"]["name"], serde_json::json!("libtarget.so"));
    assert_eq!(meta["modules"].as_array().unwrap().len(), 1);
    assert_eq!(meta["callIdx"], serde_json::json!(1));
}

#[test]
fn classifies_vm_records_and_scaled_slots() {
    let profile = VmProfile::default_profile();
    let record = serde_json::json!({
        "regs": {
            "x25": "0x1000",
            "x19": "0x19",
            "x1": "0xe0",
        }
    });
    assert_eq!(
        classify_vm_asm("ldr x4, [x25, x19, lsl #3]", &profile),
        "vm-reg-load"
    );
    assert_eq!(
        classify_vm_asm("ldur x3, [x29, #-0x18]", &profile),
        "mem-load"
    );
    assert_eq!(classify_vm_asm("svc #0", &profile), "syscall");
    assert_eq!(
        classify_vm_asm("ldp x9, x10, [x25, #0xc0]", &profile),
        "vm-reg-load"
    );
    assert_eq!(
        classify_vm_asm("stp x9, x10, [x25, #0xc0]", &profile),
        "vm-reg-store"
    );
    assert_eq!(
        mem_addr_from_asm("ldr x4, [x25, x19, lsl #3]", &record),
        Some(0x10c8)
    );
    let slot = vm_slot_from_asm("ldr x4, [x25, x19, lsl #3]", &record, &profile).unwrap();
    assert_eq!(slot["slot"], serde_json::json!(25));
    assert_eq!(
        mem_addr_from_asm("str x3, [x25, x1]", &record),
        Some(0x10e0)
    );
    let slot = vm_slot_from_asm("str x3, [x25, x1]", &record, &profile).unwrap();
    assert_eq!(slot["slot"], serde_json::json!(28));
    let slot = vm_slot_from_asm("stp x9, x10, [x25, #0xc0]", &record, &profile).unwrap();
    assert_eq!(slot["slot"], serde_json::json!(24));
    assert_eq!(slot["offset"], serde_json::json!("0xc0"));
}

#[test]
fn vm_slot_access_expands_pair_state_stores() {
    let row = serde_json::json!({
        "idx": 14017046,
        "class": "vm-reg-store",
        "asm": "stp x9, x10, [x25, #0x40]",
        "vm_slot": {"slot": 8, "index_reg": null, "index_value": null},
        "mem_addr": "0x77445994e0",
        "store_src": [
            {"reg": "x9", "value": "0x90d2d669"},
            {"reg": "x10", "value": "0x0"}
        ]
    });
    let writes = vm_slot_access_summaries(&row);
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0]["slot"], serde_json::json!(8));
    assert_eq!(writes[0]["mem_addr"], serde_json::json!("0x77445994e0"));
    assert_eq!(writes[0]["reg"], serde_json::json!("x9"));
    assert_eq!(writes[1]["slot"], serde_json::json!(9));
    assert_eq!(writes[1]["mem_addr"], serde_json::json!("0x77445994e8"));
    assert_eq!(writes[1]["reg"], serde_json::json!("x10"));
}

#[test]
fn vm_profile_allows_non_default_role_registers() {
    let profile = VmProfile::new(
        "x9".to_string(),
        "x20".to_string(),
        "x22".to_string(),
        "x26".to_string(),
    );
    let record = serde_json::json!({
        "regs": {
            "x20": "0x4000",
            "x3": "0x5",
        }
    });
    assert_eq!(
        classify_vm_asm("ldrb w1, [x9, #0x4]", &profile),
        "bytecode-read"
    );
    assert_eq!(
        classify_vm_asm("ldr x1, [x22, x8, lsl #3]", &profile),
        "dispatch-table-load"
    );
    assert_eq!(
        classify_vm_asm("ldr x4, [x20, x3, lsl #3]", &profile),
        "vm-reg-load"
    );
    let slot = vm_slot_from_asm("ldr x4, [x20, x3, lsl #3]", &record, &profile).unwrap();
    assert_eq!(slot["slot"], serde_json::json!(5));
    assert!(profile.is_infrastructure_reg("x26"));
}

#[test]
fn estimates_memory_access_widths() {
    assert_eq!(memory_access_width("ldrb w1, [x0, x4]"), 1);
    assert_eq!(memory_access_width("ldrh w5, [x21, #0x10]!"), 2);
    assert_eq!(memory_access_width("ldr w16, [x8, x20]"), 4);
    assert_eq!(memory_access_width("ldrsw x4, [x21, #0x18]"), 4);
    assert_eq!(memory_access_width("ldr x4, [x25, x19, lsl #3]"), 8);
    assert_eq!(memory_access_width("ldp x9, x10, [x25, #0xc0]"), 8);
}

#[test]
fn detects_external_gap_call_candidates() {
    let meta = serde_json::json!({
        "module": {"name": "libtarget.so", "base": "0x1000", "end": "0x2000"},
        "modules": [
            {"name": "libtarget.so", "base": "0x1000", "end": "0x2000"},
            {"name": "libc.so", "base": "0x7000", "end": "0x9000"}
        ]
    });
    let record = serde_json::json!({
        "idx": 42,
        "pc": "0x1500",
        "func": "sub_500",
        "asm": "blr x22",
        "regs": {
            "x0": "0x5000",
            "x1": "0x6000",
            "x2": "0x8",
            "x3": "0x0",
            "x4": "0x0",
            "x5": "0x0",
            "x6": "0x0",
            "x7": "0x0",
            "x22": "0x8120"
        }
    });
    let primary = super::primary_module_bounds(&meta);
    let candidate =
        gap_call_candidate_from_record(&record, &meta, primary.as_ref(), 0x6058).unwrap();
    assert_eq!(candidate["external_to_primary"], serde_json::json!(true));
    assert_eq!(
        candidate.pointer("/target_module/name"),
        Some(&serde_json::json!("libc.so"))
    );
    assert_eq!(
        candidate.pointer("/arg_offsets/0/reg"),
        Some(&serde_json::json!("x1"))
    );
    assert_eq!(
        candidate.pointer("/arg_offsets/0/offset"),
        Some(&serde_json::json!("0x58"))
    );

    let compact = compact_gap_call_candidates(Some(&serde_json::json!({
        "status": "ready",
        "scan_idx_lo": 40,
        "scan_idx_hi": 50,
        "candidate_count_total": 1,
        "truncated_by_record_cap": false,
        "candidates": [candidate]
    })));
    assert_eq!(
        compact.pointer("/candidates/0/target_module/offset"),
        Some(&serde_json::json!("0x1120"))
    );
}

#[test]
fn enriches_internal_gap_call_without_target_write_as_weak() {
    let mut candidate = serde_json::json!({
        "idx": 10,
        "pc": "0x1500",
        "asm": "bl #0x1600",
        "external_to_primary": false,
        "score": 60,
    });
    let records = vec![
        serde_json::json!({"idx": 10, "pc": "0x1500", "asm": "bl #0x1600", "regs": {}}),
        serde_json::json!({"idx": 11, "pc": "0x1600", "asm": "stp x29, x30, [sp, #-0x20]!", "regs": {"sp": "0x7000"}}),
        serde_json::json!({"idx": 12, "pc": "0x1604", "asm": "ret", "regs": {}}),
        serde_json::json!({"idx": 13, "pc": "0x1504", "asm": "mov x0, x0", "regs": {}}),
    ];
    enrich_gap_call_candidate_trace_writes(&mut candidate, &records, 0x6058);
    assert_eq!(
        candidate["callee_trace"]["status"],
        serde_json::json!("traced_callee_no_target_write")
    );
    assert_eq!(
        candidate["score_adjustment_trace_write"],
        serde_json::json!(-50)
    );
    assert_eq!(candidate["score"], serde_json::json!(10));
    let compact = compact_gap_call_candidates(Some(&serde_json::json!({
        "status": "ready",
        "candidates": [candidate],
    })));
    assert_eq!(
        compact["candidates"][0]["callee_trace"]["status"],
        serde_json::json!("traced_callee_no_target_write")
    );
}

#[test]
fn enriches_internal_gap_call_with_target_write() {
    let mut candidate = serde_json::json!({
        "idx": 10,
        "pc": "0x1500",
        "asm": "bl #0x1600",
        "external_to_primary": false,
        "score": 20,
    });
    let records = vec![
        serde_json::json!({"idx": 10, "pc": "0x1500", "asm": "bl #0x1600", "regs": {"x3": "0x6050"}}),
        serde_json::json!({"idx": 11, "pc": "0x1600", "asm": "strb w1, [x3, #8]", "regs": {"x1": "0x51", "x3": "0x6050"}}),
        serde_json::json!({"idx": 12, "pc": "0x1604", "asm": "ret", "regs": {}}),
        serde_json::json!({"idx": 13, "pc": "0x1504", "asm": "mov x0, x0", "regs": {}}),
    ];
    enrich_gap_call_candidate_trace_writes(&mut candidate, &records, 0x6058);
    assert_eq!(
        candidate["callee_trace"]["status"],
        serde_json::json!("traced_callee_target_write")
    );
    assert_eq!(
        candidate["score_adjustment_trace_write"],
        serde_json::json!(80)
    );
    assert_eq!(candidate["score"], serde_json::json!(100));
    assert_eq!(
        candidate["callee_trace"]["target_writes"][0]["idx"],
        serde_json::json!(11)
    );

    let touch = store_touch_for_addr(&records[1], 0x6058).unwrap();
    assert_eq!(touch["width"], serde_json::json!(1));
    assert_eq!(touch["offset"], serde_json::json!(0));
}

#[test]
fn parses_definition_source_registers() {
    assert_eq!(
        def_source_regs_from_asm("and x20, x19, x4"),
        vec!["x19", "x4"]
    );
    assert_eq!(
        def_source_regs_from_asm("ldrb w1, [x0, x4]"),
        vec!["x0", "x4"]
    );
    assert_eq!(
        def_source_regs_from_asm("ldp x9, x10, [x25, #0xc0]"),
        vec!["x25"]
    );
    assert_eq!(def_source_regs_from_asm("lsl x5, x3, #3"), vec!["x3"]);
    assert!(def_entries_from_asm("cbz x0, #0x1234", &serde_json::json!({}), None, None).is_empty());
    assert!(
        def_entries_from_asm("tbnz w8, #0, #0x1234", &serde_json::json!({}), None, None).is_empty()
    );
}

#[test]
fn call_return_boundary_scans_past_non_def_uses() {
    let rows = vec![
        serde_json::json!({"idx": 10, "asm": "bl #0x7601bcbd60"}),
        serde_json::json!({"idx": 11, "asm": "br x17"}),
        serde_json::json!({"idx": 12, "asm": "cbz x0, #0x7601bb6240"}),
        serde_json::json!({"idx": 13, "asm": "cmp w8, #2"}),
        serde_json::json!({"idx": 14, "asm": "add x8, x0, x20"}),
    ];
    let records = vec![
        serde_json::json!({"idx": 10, "regs": {"x0": "0x40000", "x1": "0x1000"}}),
        serde_json::json!({"idx": 11, "regs": {"x0": "0x74b687edc0"}}),
        serde_json::json!({"idx": 12, "regs": {"x0": "0x74b687edc0"}}),
        serde_json::json!({"idx": 13, "regs": {"x0": "0x74b687edc0"}}),
        serde_json::json!({"idx": 14, "regs": {"x0": "0x74b687edc0"}}),
    ];
    let row = call_return_def_from_previous_call(&rows, &records, 4, "x0", &records[4]).unwrap();
    assert_eq!(row["class"], serde_json::json!("call-return"));
    assert_eq!(row["call_return"]["call_idx"], serde_json::json!(10));
    assert_eq!(
        row["call_return"]["target_value"],
        serde_json::json!("0x7601bcbd60")
    );
    assert_eq!(row["call_return"]["intervening_rows"], serde_json::json!(3));
    assert_eq!(row["def"]["value_after"], serde_json::json!("0x74b687edc0"));
}

#[test]
fn syscall_return_boundary_scans_past_non_def_uses() {
    let rows = vec![
        serde_json::json!({"idx": 10, "asm": "svc #0"}),
        serde_json::json!({"idx": 11, "asm": "cmn x0, #1, lsl #12"}),
        serde_json::json!({"idx": 12, "asm": "cneg x0, x0, hi"}),
    ];
    let records = vec![
        serde_json::json!({"idx": 10, "regs": {"x0": "0x0", "x8": "0xac"}}),
        serde_json::json!({"idx": 11, "regs": {"x0": "0x7b3a", "x8": "0xac"}}),
        serde_json::json!({"idx": 12, "regs": {"x0": "0x7b3a", "x8": "0xac"}}),
    ];
    let row = syscall_return_def_from_previous_svc(&rows, &records, 2, "x0", &records[2]).unwrap();
    assert_eq!(row["class"], serde_json::json!("syscall-return"));
    assert_eq!(row["syscall_return"]["svc_idx"], serde_json::json!(10));
    assert_eq!(
        row["syscall_return"]["syscall_number"],
        serde_json::json!("0xac")
    );
    assert_eq!(
        row["syscall_return"]["return_value"],
        serde_json::json!("0x7b3a")
    );
    assert_eq!(row["def"]["value_after"], serde_json::json!("0x7b3a"));
}

#[test]
fn expands_pair_load_defs() {
    let rec = serde_json::json!({
        "regs": {
            "x25": "0x1000"
        }
    });
    let next = serde_json::json!({
        "regs": {
            "x9": "0x1111",
            "x10": "0x2222"
        }
    });
    let defs = def_entries_from_asm("ldp x9, x10, [x25, #0xc0]", &rec, Some(&next), Some(0x10c0));
    assert_eq!(defs.len(), 2);
    assert_eq!(defs[0]["reg"], serde_json::json!("x9"));
    assert_eq!(defs[0]["value_after"], serde_json::json!("0x1111"));
    assert_eq!(defs[0]["mem_addr"], serde_json::json!("0x10c0"));
    assert_eq!(defs[1]["reg"], serde_json::json!("x10"));
    assert_eq!(defs[1]["value_after"], serde_json::json!("0x2222"));
    assert_eq!(defs[1]["mem_addr"], serde_json::json!("0x10c8"));
}

#[test]
fn renders_alu_value_formulas() {
    assert_eq!(
        alu_expression_from_asm(
            "orr x4, x14, x17",
            "0x29",
            &["0x28".to_string(), "0x1".to_string()],
        ),
        Some("0x29 = 0x28 | 0x1".to_string())
    );
    assert_eq!(
        alu_expression_from_asm("lsl w16, w2, #2", "0x28", &["0xa".to_string()]),
        Some("0x28 = 0xa << 0x2".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "and x8, x8, #0xfffffffffffffff0",
            "0x74b68bd6d0",
            &["0x74b68bd6df".to_string()],
        ),
        Some("0x74b68bd6d0 = 0x74b68bd6df & 0xfffffffffffffff0".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "sub x8, x8, #0x71",
            "0x74b68bd6df",
            &["0x74b68bd750".to_string()],
        ),
        Some("0x74b68bd6df = 0x74b68bd750 - 0x71".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "add x21, x21, x3, lsl #4",
            "0x74fbf636e0",
            &["0x74fbf635f0".to_string(), "0xf".to_string()],
        ),
        Some("0x74fbf636e0 = 0x74fbf635f0 + (0xf << 0x4)".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "lsr w4, w20, w1",
            "0x1",
            &["0x62".to_string(), "0x6".to_string()],
        ),
        Some("0x1 = 0x62 >> 0x6".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "udiv x14, x13, x12",
            "0x757524ef",
            &["0x74ffafca73".to_string(), "0xff".to_string()],
        ),
        Some("0x757524ef = 0x74ffafca73 / 0xff".to_string())
    );
    assert_eq!(
        alu_expression_from_asm(
            "mul x3, x6, x4",
            "0xdd1841bea1487649",
            &[
                "0x52c36263893da50d".to_string(),
                "0x5851f42d4c957f2d".to_string()
            ],
        ),
        Some("0xdd1841bea1487649 = (0x52c36263893da50d * 0x5851f42d4c957f2d) mod 2^64".to_string())
    );
    let semantic = recognize_alu_semantic(
        "add x15, x13, x14",
        "0x757524ef62",
        &["0x74ffafca73".to_string(), "0x757524ef".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("mod255_low_byte"));
    assert_eq!(semantic["output_byte"], serde_json::json!("0x62"));
    assert!(recognize_alu_semantic(
        "add x5, x3, x4",
        "0x3",
        &["0x3".to_string(), "0x0".to_string()],
    )
    .is_none());
    let semantic = recognize_alu_semantic(
        "add x5, x3, x4",
        "0x99bd5d21d7d8103",
        &["0x99bd5d21d7d8102".to_string(), "0x1".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("add_small_delta"));
    assert_eq!(semantic["input"], serde_json::json!("0x99bd5d21d7d8102"));
    let semantic = recognize_alu_semantic(
        "add x21, x21, x3, lsl #4",
        "0x74fbf636e0",
        &["0x74fbf635f0".to_string(), "0xf".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("add_small_delta"));
    assert_eq!(semantic["delta"], serde_json::json!("0xf0"));
    let semantic = recognize_alu_semantic(
        "mul x3, x6, x4",
        "0xdd1841bea1487649",
        &[
            "0x52c36263893da50d".to_string(),
            "0x5851f42d4c957f2d".to_string(),
        ],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("mul_mod64"));
    assert_eq!(semantic["rhs_odd"], serde_json::json!(true));
    let semantic = recognize_alu_semantic(
        "and x19, x17, x13",
        "0x28",
        &["0x28".to_string(), "0x3c".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("bitmask_extract"));
    assert_eq!(semantic["mask"], serde_json::json!("0x3c"));
    assert_eq!(semantic["low_bit"], serde_json::json!(2));
    assert_eq!(semantic["width"], serde_json::json!(4));
    let semantic = recognize_alu_semantic(
        "orr x4, x14, x17",
        "0x29",
        &["0x28".to_string(), "0x1".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("bitwise_or_merge"));
    let semantic = recognize_alu_semantic(
        "lsr w4, w20, w1",
        "0x1",
        &["0x62".to_string(), "0x6".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("shift_right"));
    assert_eq!(semantic["input"], serde_json::json!("0x62"));
    let semantic = recognize_alu_semantic("lsl w16, w2, #2", "0x28", &["0xa".to_string()]).unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("shift_left"));
    assert_eq!(semantic["shift"], serde_json::json!("0x2"));
    let semantic = recognize_alu_semantic(
        "lsl w16, w1, w11",
        "0x78000000",
        &["0x6f783e78".to_string(), "0x18".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("shift_left"));
    assert_eq!(semantic["width"], serde_json::json!(32));
    let semantic = recognize_alu_semantic(
        "eor x16, x20, x5",
        "0x62",
        &["0x0".to_string(), "0x62".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("xor_identity"));
    assert_eq!(semantic["input"], serde_json::json!("0x62"));
    let semantic = recognize_alu_semantic(
        "eor x16, x20, x5",
        "0x5",
        &["0x67".to_string(), "0x62".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("xor_mix"));
    assert_eq!(semantic["lhs"], serde_json::json!("0x67"));
    let semantic = recognize_alu_semantic(
        "orr x5, x1, x2",
        "0x561d4e18",
        &["0x0".to_string(), "0x561d4e18".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("or_identity"));
    assert_eq!(semantic["input"], serde_json::json!("0x561d4e18"));
    let semantic = recognize_alu_semantic(
        "and x8, x11, x15",
        "0x561d4e18",
        &["0x561d4e18".to_string(), "0x561d4e1b".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("and_identity"));
    let semantic =
        recognize_alu_semantic("and x2, x16, #0xffffffff", "0x1a", &["0x1a".to_string()]).unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("and_identity"));
    assert_eq!(semantic["mask"], serde_json::json!("0xffffffff"));
    let semantic = recognize_alu_semantic(
        "and x8, x8, #0xfffffffffffffff0",
        "0x74b68bd6d0",
        &["0x74b68bd6df".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("align_down_mask"));
    assert_eq!(semantic["input"], serde_json::json!("0x74b68bd6df"));
    assert_eq!(semantic["alignment"], serde_json::json!("0x10"));
    let semantic = recognize_alu_semantic(
        "sub x8, x8, #0x71",
        "0x74b68bd6df",
        &["0x74b68bd750".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("sub_small_delta"));
    assert_eq!(semantic["input"], serde_json::json!("0x74b68bd750"));
    assert_eq!(semantic["delta"], serde_json::json!("0x71"));
    let semantic = recognize_alu_semantic(
        "add x13, x8, x12",
        "0x1b2345fc4",
        &["0x14aef3cc3".to_string(), "0x67452301".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("add_known_constant"));
    assert_eq!(semantic["constant_name"], serde_json::json!("md5_iv_a"));
    let semantic = recognize_alu_semantic(
        "add x13, x8, x12",
        "0x783e786f",
        &["0x561d4e18".to_string(), "0x22212a57".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("add32_mix"));
    let semantic = recognize_alu_semantic(
        "add x13, x8, x12",
        "0x267b44ad8",
        &["0x1b57feb14".to_string(), "0xb2345fc4".to_string()],
    )
    .unwrap();
    assert_eq!(semantic["kind"], serde_json::json!("add32_mix"));
    assert_eq!(semantic["result_low32"], serde_json::json!("0x67b44ad8"));
}

#[test]
fn formula_next_for_self_def_starts_before_current_write() {
    let step = serde_json::json!({
        "local_def": {
            "idx": 13545196_u64,
            "def": {"reg": "x8"}
        }
    });
    let operand = serde_json::json!({
        "reg": "x8",
        "value": "0x74b68bd6df"
    });
    let next = serde_json::json!({
        "idx": 13545196_u64,
        "reg": "x8"
    });
    let adjusted = adjust_self_def_formula_next(&step, &operand, next);
    assert_eq!(adjusted["idx"], serde_json::json!(13545195_u64));
    assert_eq!(
        adjusted["reason"],
        serde_json::json!("self_def_input_before_idx")
    );
}

#[test]
fn frontier_auto_prefers_small_non_infrastructure_registers() {
    let step = serde_json::json!({
        "frontier": [
            {"idx": 10, "reg": "x25", "value": "0x70000000"},
            {"idx": 10, "reg": "x4", "value": "0x74fbf29990"},
            {"idx": 10, "reg": "x20", "value": "0x18"}
        ]
    });
    let next = choose_frontier_next(&step).unwrap();
    assert_eq!(next["idx"], serde_json::json!(10));
    assert_eq!(next["reg"], serde_json::json!("x20"));
    assert_eq!(next["src_value"], serde_json::json!("0x18"));

    let infra_only = serde_json::json!({
        "frontier": [
            {"idx": 20, "reg": "x23", "value": "0x69f5b3cb"}
        ]
    });
    let next = choose_frontier_next(&infra_only).unwrap();
    assert_eq!(next["idx"], serde_json::json!(20));
    assert_eq!(next["reg"], serde_json::json!("x23"));
    assert_eq!(next["src_value"], serde_json::json!("0x69f5b3cb"));

    let call_return = serde_json::json!({
        "local_def": {
            "class": "call-return"
        },
        "frontier": [
            {"idx": 30, "reg": "x0", "value": "0x0"}
        ]
    });
    assert!(choose_frontier_next(&call_return).is_none());

    let syscall_return = serde_json::json!({
        "local_def": {
            "class": "syscall-return"
        },
        "frontier": [
            {"idx": 40, "reg": "x0", "value": "0x7b3a"}
        ]
    });
    assert!(choose_frontier_next(&syscall_return).is_none());

    let bytecode_read = serde_json::json!({
        "local_def": {
            "class": "bytecode-read"
        },
        "frontier": [
            {"idx": 50, "reg": "x21", "value": "0x74fbf74c70"}
        ]
    });
    assert!(choose_frontier_next(&bytecode_read).is_none());
}

#[test]
fn frontier_auto_prefers_semantic_alu_inputs() {
    let udiv = serde_json::json!({
        "local_def": {
            "asm": "udiv x1, x19, x6",
            "class": "alu",
            "def": {
                "reg": "x1",
                "src": [
                    {"reg": "x19", "value": "0x74ffafca73"},
                    {"reg": "x6", "value": "0xff"}
                ],
                "value_after": "0x757524ef"
            }
        },
        "frontier": [
            {"idx": 20, "reg": "x19", "value": "0x74ffafca73"},
            {"idx": 20, "reg": "x6", "value": "0xff"}
        ]
    });
    let next = choose_frontier_next(&udiv).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x19"));
    assert_eq!(next["src_value"], serde_json::json!("0x74ffafca73"));

    let folded = serde_json::json!({
        "local_def": {
            "asm": "add x15, x13, x14",
            "class": "alu",
            "def": {
                "reg": "x15",
                "src": [
                    {"reg": "x13", "value": "0x74ffafca73"},
                    {"reg": "x14", "value": "0x757524ef"}
                ],
                "value_after": "0x757524ef62"
            }
        },
        "frontier": [
            {"idx": 30, "reg": "x13", "value": "0x74ffafca73"},
            {"idx": 30, "reg": "x14", "value": "0x757524ef"}
        ]
    });
    let next = choose_frontier_next(&folded).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x13"));
    assert_eq!(next["src_value"], serde_json::json!("0x74ffafca73"));

    let shift = serde_json::json!({
        "local_def": {
            "asm": "lsr w0, w13, w4",
            "class": "alu",
            "def": {
                "reg": "w0",
                "src": [
                    {"reg": "w13", "value": "0x69adbccc"},
                    {"reg": "w4", "value": "0x0"}
                ],
                "value_after": "0x69adbccc"
            }
        },
        "frontier": [
            {"idx": 40, "reg": "w13", "value": "0x69adbccc"},
            {"idx": 40, "reg": "w4", "value": "0x0"}
        ]
    });
    let next = choose_frontier_next(&shift).unwrap();
    assert_eq!(next["reg"], serde_json::json!("w13"));
    assert_eq!(next["src_value"], serde_json::json!("0x69adbccc"));

    let add_delta = serde_json::json!({
        "local_def": {
            "asm": "add x5, x3, x4",
            "class": "alu",
            "def": {
                "reg": "x5",
                "src": [
                    {"reg": "x3", "value": "0x99bd5d21d7d8102"},
                    {"reg": "x4", "value": "0x1"}
                ],
                "value_after": "0x99bd5d21d7d8103"
            }
        },
        "frontier": [
            {"idx": 50, "reg": "x3", "value": "0x99bd5d21d7d8102"},
            {"idx": 50, "reg": "x4", "value": "0x1"}
        ]
    });
    let next = choose_frontier_next(&add_delta).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x3"));
    assert_eq!(next["src_value"], serde_json::json!("0x99bd5d21d7d8102"));

    let mul_small = serde_json::json!({
        "local_def": {
            "asm": "mul x12, x2, x15",
            "class": "alu",
            "def": {
                "reg": "x12",
                "src": [
                    {"reg": "x2", "value": "0xc87"},
                    {"reg": "x15", "value": "0x3"}
                ],
                "value_after": "0x2595"
            }
        },
        "frontier": [
            {"idx": 60, "reg": "x2", "value": "0xc87"},
            {"idx": 60, "reg": "x15", "value": "0x3"}
        ]
    });
    let next = choose_frontier_next(&mul_small).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x2"));
    assert_eq!(next["src_value"], serde_json::json!("0xc87"));

    let add_identity = serde_json::json!({
        "local_def": {
            "asm": "add x13, x8, x12",
            "class": "alu",
            "def": {
                "reg": "x13",
                "src": [
                    {"reg": "x8", "value": "0xc87"},
                    {"reg": "x12", "value": "0x0"}
                ],
                "value_after": "0xc87"
            }
        },
        "frontier": [
            {"idx": 70, "reg": "x8", "value": "0xc87"},
            {"idx": 70, "reg": "x12", "value": "0x0"}
        ]
    });
    let next = choose_frontier_next(&add_identity).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x8"));
    assert_eq!(next["src_value"], serde_json::json!("0xc87"));

    let eor_identity = serde_json::json!({
        "local_def": {
            "asm": "eor x16, x20, x5",
            "class": "alu",
            "def": {
                "reg": "x16",
                "src": [
                    {"reg": "x20", "value": "0x0"},
                    {"reg": "x5", "value": "0x62"}
                ],
                "value_after": "0x62"
            }
        },
        "frontier": [
            {"idx": 80, "reg": "x20", "value": "0x0"},
            {"idx": 80, "reg": "x5", "value": "0x62"}
        ]
    });
    let next = choose_frontier_next(&eor_identity).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x5"));
    assert_eq!(next["src_value"], serde_json::json!("0x62"));

    let align_self_def = serde_json::json!({
        "local_def": {
            "idx": 13545196_u64,
            "asm": "and x8, x8, #0xfffffffffffffff0",
            "class": "alu",
            "def": {
                "reg": "x8",
                "src": [
                    {"reg": "x8", "value": "0x74b68bd6df"}
                ],
                "value_after": "0x74b68bd6d0"
            }
        },
        "frontier": [
            {"idx": 13545196_u64, "reg": "x8", "value": "0x74b68bd6df"}
        ]
    });
    let next = choose_frontier_next(&align_self_def).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x8"));
    assert_eq!(next["idx"], serde_json::json!(13545195_u64));
    assert_eq!(
        next["reason"],
        serde_json::json!("self_def_input_before_idx")
    );

    let sub_self_def = serde_json::json!({
        "local_def": {
            "idx": 13545195_u64,
            "asm": "sub x8, x8, #0x71",
            "class": "alu",
            "def": {
                "reg": "x8",
                "src": [
                    {"reg": "x8", "value": "0x74b68bd750"}
                ],
                "value_after": "0x74b68bd6df"
            }
        },
        "frontier": [
            {"idx": 13545195_u64, "reg": "x8", "value": "0x74b68bd750"}
        ]
    });
    let next = choose_frontier_next(&sub_self_def).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x8"));
    assert_eq!(next["idx"], serde_json::json!(13545194_u64));
    assert_eq!(
        next["reason"],
        serde_json::json!("self_def_input_before_idx")
    );

    let pointer_add = serde_json::json!({
        "local_def": {
            "idx": 7375_u64,
            "asm": "add x8, x0, x20",
            "class": "alu",
            "def": {
                "reg": "x8",
                "src": [
                    {"reg": "x0", "value": "0x74b687edc0"},
                    {"reg": "x20", "value": "0x40000"}
                ],
                "value_after": "0x74b68bedc0"
            }
        },
        "frontier": [
            {"idx": 7375_u64, "reg": "x0", "value": "0x74b687edc0"},
            {"idx": 7361_u64, "reg": "x20", "value": "0x40000"}
        ]
    });
    let next = choose_frontier_next(&pointer_add).unwrap();
    assert_eq!(next["reg"], serde_json::json!("x0"));
    assert_eq!(next["src_value"], serde_json::json!("0x74b687edc0"));
}

#[test]
fn frontier_auto_uses_byte_lane_for_or_merge_and_shifts() {
    let profile = VmProfile::default_profile();
    let or_merge = serde_json::json!({
        "local_def": {
            "asm": "orr x4, x14, x17",
            "class": "alu",
            "def": {
                "reg": "x4",
                "src": [
                    {"reg": "x14", "value": "0x78000000"},
                    {"reg": "x17", "value": "0xd84ab4"}
                ],
                "value_after": "0x78d84ab4"
            }
        },
        "frontier": [
            {"idx": 90, "reg": "x14", "value": "0x78000000"},
            {"idx": 90, "reg": "x17", "value": "0xd84ab4"}
        ]
    });
    let lane1 = choose_frontier_next_for_lane(&or_merge, Some(1), &profile).unwrap();
    assert_eq!(lane1["reg"], serde_json::json!("x17"));
    assert_eq!(lane1["src_value"], serde_json::json!("0xd84ab4"));
    assert_eq!(lane1["source_byte_offset"], serde_json::json!(1));

    let lane3 = choose_frontier_next_for_lane(&or_merge, Some(3), &profile).unwrap();
    assert_eq!(lane3["reg"], serde_json::json!("x14"));
    assert_eq!(lane3["src_value"], serde_json::json!("0x78000000"));
    assert_eq!(lane3["source_byte_offset"], serde_json::json!(3));

    let shift_left = serde_json::json!({
        "local_def": {
            "asm": "lsl w16, w1, w11",
            "class": "alu",
            "def": {
                "reg": "w16",
                "src": [
                    {"reg": "w1", "value": "0x6f783e78"},
                    {"reg": "w11", "value": "0x18"}
                ],
                "value_after": "0x78000000"
            }
        },
        "frontier": [
            {"idx": 91, "reg": "w1", "value": "0x6f783e78"},
            {"idx": 91, "reg": "w11", "value": "0x18"}
        ]
    });
    let shifted = choose_frontier_next_for_lane(&shift_left, Some(3), &profile).unwrap();
    assert_eq!(shifted["reg"], serde_json::json!("w1"));
    assert_eq!(shifted["source_byte_offset"], serde_json::json!(0));

    let and_mask = serde_json::json!({
        "local_def": {
            "asm": "and x17, x15, x16",
            "class": "alu",
            "def": {
                "reg": "x17",
                "src": [
                    {"reg": "x15", "value": "0x6a654f6935bf"},
                    {"reg": "x16", "value": "0x7fffffff"}
                ],
                "value_after": "0x4f6935bf"
            }
        },
        "frontier": [
            {"idx": 92, "reg": "x15", "value": "0x6a654f6935bf"},
            {"idx": 92, "reg": "x16", "value": "0x7fffffff"}
        ]
    });
    let masked = choose_frontier_next_for_lane(&and_mask, Some(0), &profile).unwrap();
    assert_eq!(masked["reg"], serde_json::json!("x15"));
    assert_eq!(masked["source_byte_offset"], serde_json::json!(0));
}

#[test]
fn extracts_compact_byte_equations_from_semantic_chains() {
    let item = serde_json::json!({
        "start_offset": 4,
        "bytes_hex": "d5",
        "chain": {
            "recognized_semantics": [
                {
                    "step": 4,
                    "idx": 14704232,
                    "asm": "eor x16, x20, x5",
                    "semantic": {
                        "kind": "xor_mix",
                        "lhs": "0xb4",
                        "rhs": "0x61",
                        "result": "0xd5"
                    }
                }
            ]
        }
    });
    let equation = output_semantic_byte_equation(&item).unwrap();
    assert_eq!(equation["offset"], serde_json::json!(4));
    assert_eq!(equation["kind"], serde_json::json!("xor_mix"));
    assert_eq!(equation["idx"], serde_json::json!(14704232));
    assert_eq!(
        equation["expression"],
        serde_json::json!("result == (lhs ^ rhs) & 0xff")
    );
    assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
}

#[test]
fn extracts_byte_lane_equation_from_word_load_chain() {
    let item = serde_json::json!({
        "start_offset": 0,
        "bytes_hex": "0a",
        "chain": {
            "recognized_semantics": [],
            "chain": [
                {
                    "step": 5,
                    "idx": 13781975,
                    "local_def": {
                        "asm": "ldrb w1, [x0, x4]"
                    },
                    "next": {
                        "reason": "memory_load_byte",
                        "source_byte_offset": 3,
                        "src_value": "0xa000142"
                    }
                }
            ]
        }
    });
    let equation = output_semantic_byte_equation(&item).unwrap();
    assert_eq!(equation["offset"], serde_json::json!(0));
    assert_eq!(equation["kind"], serde_json::json!("byte_lane_extract"));
    assert_eq!(equation["source_value"], serde_json::json!("0xa000142"));
    assert_eq!(equation["source_byte_offset"], serde_json::json!(3));
    assert_eq!(equation["result"], serde_json::json!("0xa"));
    assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
}

#[test]
fn extracts_mod255_byte_equation_with_trace_idx() {
    let item = serde_json::json!({
        "start_offset": 1,
        "bytes_hex": "62",
        "chain": {
            "recognized_semantics": [
                {
                    "step": 3,
                    "idx": 14712345,
                    "asm": "add x15, x13, x14",
                    "semantic": {
                        "kind": "mod255_low_byte",
                        "input": "0x74ffafca73",
                        "quotient": "0x757524ef",
                        "output_byte": "0x62"
                    }
                }
            ]
        }
    });
    let equation = output_semantic_byte_equation(&item).unwrap();
    assert_eq!(equation["offset"], serde_json::json!(1));
    assert_eq!(equation["kind"], serde_json::json!("mod255_low_byte"));
    assert_eq!(equation["idx"], serde_json::json!(14712345));
    assert_eq!(equation["result"], serde_json::json!("0x62"));
    assert_eq!(
        equation["expression"],
        serde_json::json!("result == (input + floor(input / 0xff)) & 0xff")
    );
    assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
}

#[test]
fn falls_back_to_writer_byte_lane_when_first_semantic_mismatches() {
    let item = serde_json::json!({
        "start_offset": 44,
        "bytes_hex": "00",
        "source_byte_offset": 1,
        "seed": {
            "idx": 8320257,
            "asm": "str w16, [x2, x5]",
            "src_value": "0xb71300fd",
            "byte_lane": 1
        },
        "chain": {
            "recognized_semantics": [
                {
                    "step": 9,
                    "idx": 8301779,
                    "asm": "eor x16, x20, x5",
                    "semantic": {
                        "kind": "xor_mix",
                        "lhs": "0x79",
                        "rhs": "0x84",
                        "result": "0xfd"
                    }
                }
            ]
        }
    });

    let equation = output_semantic_byte_equation(&item).unwrap();
    assert_eq!(
        equation["kind"],
        serde_json::json!("writer_byte_lane_extract")
    );
    assert_eq!(equation["source_value"], serde_json::json!("0xb71300fd"));
    assert_eq!(equation["source_byte_offset"], serde_json::json!(1));
    assert_eq!(equation["result"], serde_json::json!("0x0"));
    assert_eq!(
        equation["rejected_semantic"]["kind"],
        serde_json::json!("xor_mix")
    );
    assert_eq!(
        equation["rejected_semantic"]["matches_first_byte"],
        serde_json::json!(false)
    );
}

#[test]
fn summarizes_xor_word_templates_from_byte_equations() {
    let equations = serde_json::json!([
        {
            "offset": 1,
            "kind": "mod255_low_byte",
            "output_byte": "0x62",
            "result": "0x62"
        },
        {
            "offset": 2,
            "kind": "mod255_low_byte",
            "output_byte": "0x61",
            "result": "0x61"
        },
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0x67",
            "rhs": "0x62",
            "result": "0x05"
        },
        {
            "offset": 4,
            "kind": "xor_mix",
            "lhs": "0xb4",
            "rhs": "0x61",
            "result": "0xd5"
        },
        {
            "offset": 5,
            "kind": "xor_mix",
            "lhs": "0x4a",
            "rhs": "0x62",
            "result": "0x28"
        },
        {
            "offset": 6,
            "kind": "xor_mix",
            "lhs": "0xd8",
            "rhs": "0x61",
            "result": "0xb9"
        }
    ]);
    let templates = output_semantic_xor_word_templates(&equations);
    let first = templates.as_array().unwrap().first().unwrap();
    assert_eq!(first["semantic_range"], serde_json::json!([3, 7]));
    assert_eq!(first["lhs_word_le"], serde_json::json!("0xd84ab467"));
    assert_eq!(
        first["rhs_pattern"]["kind"],
        serde_json::json!("alternating_two_byte_mask")
    );
    assert_eq!(
        first["rhs_pattern"]["source_offsets"],
        serde_json::json!([1, 2])
    );
    assert_eq!(first["result_bytes_hex"], serde_json::json!("05d528b9"));

    let summary = output_semantic_byte_equation_summary(&equations);
    let chunk = summary["xor_lhs_word_chunks"][0].clone();
    assert_eq!(chunk["kind"], serde_json::json!("word32"));
    assert_eq!(chunk["run_range"], serde_json::json!([3, 7]));
    assert_eq!(chunk["run_chunk"], serde_json::json!(0));
    assert_eq!(chunk["semantic_range"], serde_json::json!([3, 7]));
    assert_eq!(chunk["lhs_word_le"], serde_json::json!("0xd84ab467"));

    let run_templates = output_semantic_xor_word_run_templates(&equations);
    assert_eq!(run_templates.as_array().unwrap().len(), 1);
    assert_eq!(run_templates[0]["run_range"], serde_json::json!([3, 7]));
    assert_eq!(
        run_templates[0]["lhs_word_le"],
        serde_json::json!("0xd84ab467")
    );
}

#[test]
fn summarizes_selected_semantic_slice_coverage_with_local_offsets() {
    let equations = serde_json::json!([
        {
            "offset": 0,
            "kind": "xor_mix",
            "lhs": "0x78",
            "rhs": "0x62",
            "result": "0x1a"
        },
        {
            "offset": 1,
            "kind": "xor_mix",
            "lhs": "0x3e",
            "rhs": "0x61",
            "result": "0x5f"
        },
        {
            "offset": 2,
            "kind": "xor_mix",
            "lhs": "0x78",
            "rhs": "0x62",
            "result": "0x1a"
        },
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0x6f",
            "rhs": "0x61",
            "result": "0x0e"
        }
    ]);
    let context = serde_json::json!({
        "mode": "selected_output_buffer_pre_encoding",
        "semantic_offset": 7,
        "semantic_count": 4
    });

    let summary = output_semantic_byte_equation_summary_with_context(&equations, Some(&context));
    assert_eq!(summary["requested_range"], serde_json::json!([0, 4]));
    assert_eq!(
        summary["requested_offset_basis"],
        serde_json::json!("selected_slice_local")
    );
    assert_eq!(summary["semantic_global_range"], serde_json::json!([7, 11]));
    assert_eq!(
        summary["covered_count_in_requested_range"],
        serde_json::json!(4)
    );
    assert_eq!(
        summary["requested_coverage_status"],
        serde_json::json!("complete_in_requested_range")
    );
    assert_eq!(
        summary["xor_lhs_word_chunks"][0]["semantic_range"],
        serde_json::json!([0, 4])
    );
}

#[test]
fn summarizes_degenerate_xor_word_zero_lanes() {
    let equations = serde_json::json!([
        {
            "offset": 0,
            "kind": "xor_mix",
            "lhs": "0x87",
            "rhs": "0x95",
            "result": "0x12"
        },
        {
            "offset": 1,
            "kind": "xor_mix",
            "lhs": "0x33",
            "rhs": "0xc5",
            "result": "0xf6"
        },
        {
            "offset": 2,
            "kind": "mod255_low_byte",
            "output_byte": "0x95",
            "result": "0x95"
        },
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0xea",
            "rhs": "0xc5",
            "result": "0x2f"
        }
    ]);

    let templates = output_semantic_xor_word_degenerate_templates(&equations);
    let first = templates.as_array().unwrap().first().unwrap();
    assert_eq!(first["kind"], serde_json::json!("word32_zero_lane"));
    assert_eq!(first["semantic_range"], serde_json::json!([0, 4]));
    assert_eq!(first["lhs_bytes_hex"], serde_json::json!("873300ea"));
    assert_eq!(first["rhs_bytes_hex"], serde_json::json!("95c595c5"));
    assert_eq!(first["result_bytes_hex"], serde_json::json!("12f6952f"));
    assert_eq!(first["zero_lhs_offsets"], serde_json::json!([2]));

    let full_templates = output_semantic_xor_word_templates(&equations);
    assert!(full_templates.as_array().unwrap().is_empty());
}

#[test]
fn excludes_mismatched_byte_equations_from_compact_summaries() {
    let equations = serde_json::json!([
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0x67",
            "rhs": "0x62",
            "result": "0x05",
            "matches_first_byte": true
        },
        {
            "offset": 4,
            "kind": "xor_mix",
            "lhs": "0xb4",
            "rhs": "0x61",
            "result": "0xd5",
            "bytes_hex": "00",
            "matches_first_byte": false
        },
        {
            "offset": 5,
            "kind": "xor_mix",
            "lhs": "0x4a",
            "rhs": "0x62",
            "result": "0x28",
            "matches_first_byte": true
        },
        {
            "offset": 6,
            "kind": "xor_mix",
            "lhs": "0xd8",
            "rhs": "0x61",
            "result": "0xb9",
            "matches_first_byte": true
        }
    ]);

    let summary = output_semantic_byte_equation_summary(&equations);
    assert_eq!(summary["count"], serde_json::json!(3));
    assert_eq!(
        summary["missing_offsets_in_covered_range"],
        serde_json::json!([4])
    );
    assert_eq!(summary["xor_lhs_word_chunks"].as_array().unwrap().len(), 2);
    assert!(summary["xor_lhs_word_chunks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|chunk| chunk["kind"] != serde_json::json!("word32")));

    let templates = output_semantic_xor_word_run_templates(&equations);
    assert!(templates.as_array().unwrap().is_empty());
}

#[test]
fn summarizes_byte_equation_parity_masks() {
    let equations = serde_json::json!([
        {
            "offset": 1,
            "kind": "mod255_low_byte",
            "output_byte": "0x62",
            "result": "0x62"
        },
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0x67",
            "rhs": "0x62",
            "result": "0x05"
        },
        {
            "offset": 4,
            "kind": "xor_mix",
            "lhs": "0xb4",
            "rhs": "0x61",
            "result": "0xd5"
        }
    ]);
    let summary = output_semantic_byte_equation_summary(&equations);
    assert_eq!(summary["count"], serde_json::json!(3));
    assert_eq!(
        summary["missing_offsets_in_covered_range"],
        serde_json::json!([2])
    );
    assert_eq!(
        summary["xor_rhs_pattern"]["kind"],
        serde_json::json!("offset_parity_mask")
    );
    assert_eq!(
        summary["xor_rhs_pattern"]["odd_byte"],
        serde_json::json!("0x62")
    );
    assert_eq!(
        summary["xor_rhs_pattern"]["even_byte"],
        serde_json::json!("0x61")
    );
    assert_eq!(
        summary["xor_lhs_runs"][0]["range"],
        serde_json::json!([3, 5])
    );
    assert_eq!(
        summary["xor_lhs_runs"][0]["lhs_hex"],
        serde_json::json!("67b4")
    );
    assert_eq!(
        summary["xor_lhs_runs"][0]["result_hex"],
        serde_json::json!("05d5")
    );
    assert_eq!(
        summary["xor_lhs_run_chunks"],
        summary["xor_lhs_word_chunks"]
    );
}

#[test]
fn summarizes_semantic_byte_equation_inputs() {
    let equations = serde_json::json!([
        {
            "offset": 0,
            "kind": "byte_lane_extract",
            "bytes_hex": "0a",
            "source_value": "0xa000142",
            "source_byte_offset": 3,
            "result": "0xa"
        },
        {
            "offset": 1,
            "kind": "mod255_low_byte",
            "input": "0x74ffafca73",
            "output_byte": "0x62",
            "quotient": "0x757524ef"
        },
        {
            "offset": 13,
            "kind": "mod255_low_byte",
            "input": "0x74ffafca73",
            "output_byte": "0x62",
            "quotient": "0x757524ef"
        },
        {
            "offset": 3,
            "kind": "xor_mix",
            "lhs": "0x67",
            "rhs": "0x62",
            "result": "0x05"
        }
    ]);
    let summary = output_semantic_byte_equation_input_summary(&equations);
    assert_eq!(
        summary["byte_lane_sources"][0]["source_value"],
        serde_json::json!("0xa000142")
    );
    assert_eq!(
        summary["byte_lane_sources"][0]["source_byte_offsets"],
        serde_json::json!([3])
    );
    assert_eq!(
        summary["byte_lane_sources"][0]["result_hex"],
        serde_json::json!("0a")
    );
    assert_eq!(
        summary["mod255_inputs"][0]["offsets"],
        serde_json::json!([1, 13])
    );
    assert_eq!(summary["xor_lhs_offsets"], serde_json::json!([3]));
}

#[test]
fn output_map_summary_exposes_top_level_semantic_byte_summary() {
    let output = serde_json::json!({
        "status": "ready",
        "strategy": "output_base64_group_map",
        "semantic_writer_map": {
            "status": "ready",
            "semantic_context": {
                "semantic_offset": 3,
                "semantic_count": 2
            },
            "vm_chain_summary": {
                "chain_count": 1
            },
            "vm_chains": [
                {
                    "start_offset": 3,
                    "bytes_hex": "05",
                    "chain": {
                        "recognized_semantics": [
                            {
                                "step": 1,
                                "asm": "eor w0, w1, w2",
                                "semantic": {
                                    "kind": "xor_mix",
                                    "lhs": "0x67",
                                    "rhs": "0x62",
                                    "result": "0x05"
                                }
                            }
                        ]
                    }
                }
            ]
        },
        "groups": []
    });
    let summary = output_map_summary(&output);
    assert_eq!(
        summary["semantic_byte_equation_summary"],
        summary["semantic_writer_map"]["byte_equation_summary"]
    );
    assert_eq!(
        summary["semantic_byte_input_summary"],
        summary["semantic_writer_map"]["byte_equation_input_summary"]
    );
    assert_eq!(summary["semantic_byte_equation_summary"]["count"], 1);
    assert_eq!(
        summary["semantic_byte_equation_summary"]["requested_range"],
        serde_json::json!([3, 5])
    );
    assert_eq!(
        summary["semantic_byte_equation_summary"]["missing_offsets_in_requested_range"],
        serde_json::json!([4])
    );
    assert_eq!(
        summary["semantic_byte_equation_summary"]["requested_coverage_status"],
        serde_json::json!("partial_in_requested_range")
    );
    assert_eq!(
        summary["semantic_vm_chain_summary"]["chain_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        summary["semantic_writer_map"]["xor_word_template_count"],
        serde_json::json!(0)
    );
}

#[test]
fn byte_writer_summary_groups_vm_source_ranges() {
    let chains = serde_json::json!([
        {
            "start_offset": 0,
            "end_offset": 3,
            "bytes_hex": "000000fb",
            "ascii": "....",
            "writer_idx": 10,
            "recognized_pattern_summary": {
                "memory_boundary_reads": [
                    {
                        "idx": 90,
                        "step": 12,
                        "addr": "0x4000",
                        "bytes_hex": "fbe9f26900000000",
                        "value": "0x69f2e9fb",
                        "asm": "ldr x8, [x1]",
                        "last_write": {
                            "idx": 80,
                            "asm": "str x6, [x19]",
                            "dst_addr": "0x4000",
                            "src_reg": "x6",
                            "src_value": "0x0"
                        },
                        "observed_mismatches": [
                            {"offset": 0}, {"offset": 1}, {"offset": 2}, {"offset": 3}
                        ]
                    }
                ],
                "static_memory_loads": []
            },
            "recognized_semantics": [
                {"semantic": {"kind": "shift_left"}}
            ]
        },
        {
            "start_offset": 4,
            "end_offset": 7,
            "bytes_hex": "e9f26979",
            "ascii": "..iy",
            "writer_idx": 11,
            "recognized_pattern_summary": {
                "memory_boundary_reads": [
                    {
                        "idx": 90,
                        "step": 12,
                        "addr": "0x4000",
                        "bytes_hex": "fbe9f26900000000",
                        "value": "0x69f2e9fb",
                        "asm": "ldr x8, [x1]",
                        "last_write": {
                            "idx": 80,
                            "asm": "str x6, [x19]",
                            "dst_addr": "0x4000",
                            "src_reg": "x6",
                            "src_value": "0x0"
                        },
                        "observed_mismatches": [
                            {"offset": 0}, {"offset": 1}, {"offset": 2}, {"offset": 3}
                        ]
                    }
                ],
                "static_memory_loads": []
            },
            "recognized_semantics": [
                {"semantic": {"kind": "shift_right"}},
                {"semantic": {"kind": "bitwise_or_merge"}}
            ],
            "stop": {
                "step": 30,
                "idx": 60,
                "reg": "x8",
                "value": "0x1234",
                "decision": {"kind": "stop", "reason": "no_next"},
                "local_def": {
                    "idx": 60,
                    "asm": "ret",
                    "class": "branch"
                }
            }
        },
        {
            "start_offset": 8,
            "end_offset": 11,
            "bytes_hex": "ecf29541",
            "ascii": "...A",
            "writer_idx": 12,
            "recognized_pattern_summary": {
                "memory_boundary_reads": [],
                "static_memory_loads": [
                    {
                        "idx": 70,
                        "step": 20,
                        "addr": "0x5000",
                        "bytes_hex": "911dbf9000000000",
                        "value": "0x90bf1d91",
                        "asm": "ldr x5, [x16, x1]",
                        "idx_lo": 50,
                        "idx_hi": 70,
                        "source_boundary": "lookback_window",
                        "caution": "increase lookback"
                    }
                ]
            },
            "recognized_semantics": [
                {"semantic": {"kind": "xor_mix"}}
            ]
        }
    ]);
    let ranges = byte_writer_vm_source_ranges(chains.as_array().unwrap());
    assert_eq!(ranges.len(), 2);
    assert_eq!(
        ranges[0]["source_class"],
        serde_json::json!("memory_boundary_read")
    );
    assert_eq!(ranges[0]["start_offset"], serde_json::json!(0));
    assert_eq!(ranges[0]["end_offset"], serde_json::json!(7));
    assert_eq!(ranges[0]["writer_idxs"], serde_json::json!([10, 11]));
    assert_eq!(
        ranges[0]["memory_boundary_reads"][0]["observed_mismatch_count"],
        serde_json::json!(4)
    );
    assert_eq!(ranges[0]["stops"][0]["idx"], serde_json::json!(60));
    assert_eq!(
        ranges[1]["source_class"],
        serde_json::json!("static_memory_load_constant")
    );
    assert_eq!(
        ranges[1]["static_memory_loads"][0]["addr"],
        serde_json::json!("0x5000")
    );
}

#[test]
fn summarizes_xor_word_state_sources_from_vm_chain() {
    let templates = serde_json::json!([
        {
            "semantic_range": [3, 7],
            "lhs_word_le": "0xd84ab467"
        }
    ]);
    let value = serde_json::json!({
        "vm_chains": [
            {
                "start_offset": 3,
                "chain": {
                    "recognized_semantics": [
                        {
                            "step": 3,
                            "idx": 14678410,
                            "asm": "lsr w12, w7, w3",
                            "semantic": {
                                "kind": "shift_right",
                                "input": "0x1ab928d5",
                                "result": "0x1a",
                                "shift": "0x18"
                            }
                        },
                        {
                            "step": 15,
                            "idx": 14678420,
                            "asm": "lsr w0, w13, w4",
                            "semantic": {
                                "kind": "shift_right",
                                "input": "0x67b44ad8",
                                "result": "0x67",
                                "shift": "0x18"
                            }
                        },
                        {
                            "step": 19,
                            "idx": 14678154,
                            "asm": "add x13, x8, x12",
                            "semantic": {
                                "kind": "add32_mix",
                                "result": "0x267b44ad8",
                                "result_low32": "0x67b44ad8"
                            }
                        }
                    ]
                }
            }
        ]
    });
    let sources = output_semantic_xor_word_state_sources(&value, &templates);
    let first = sources.as_array().unwrap().first().unwrap();
    assert_eq!(
        first["source_status"],
        serde_json::json!("state_update_found")
    );
    assert_eq!(first["source_word_be"], serde_json::json!("0x67b44ad8"));
    assert_eq!(first["state_update"]["idx"], serde_json::json!(14678154));
}

#[test]
fn summarizes_xor_word_state_source_coverage() {
    let templates = serde_json::json!([
        {"semantic_range": [0, 4], "lhs_word_le": "0x6f783e78"},
        {"semantic_range": [4, 8], "lhs_word_le": "0xb9f37778"}
    ]);
    let sources = serde_json::json!([
        {
            "semantic_range": [0, 4],
            "source_word_be": "0x783e786f",
            "source_status": "state_update_found"
        }
    ]);
    let summary = output_semantic_xor_word_state_source_summary(&templates, &sources);
    assert_eq!(summary["template_count"], serde_json::json!(2));
    assert_eq!(summary["source_count"], serde_json::json!(1));
    assert_eq!(summary["missing_count"], serde_json::json!(1));
    assert_eq!(summary["coverage_status"], serde_json::json!("partial"));
    assert_eq!(
        summary["source_status_counts"],
        serde_json::json!([{"status": "state_update_found", "count": 1}])
    );
    assert_eq!(
        summary["source_status_ranges"][0],
        serde_json::json!({
            "status": "state_update_found",
            "ranges": [
                {
                    "semantic_range": [0, 4],
                    "lhs_word_le": null,
                    "source_word": null
                }
            ]
        })
    );
    assert_eq!(
        summary["missing_templates"][0]["semantic_range"],
        serde_json::json!([4, 8])
    );
}

#[test]
fn keeps_xor_word_sources_without_state_update() {
    let templates = serde_json::json!([
        {
            "semantic_range": [0, 4],
            "lhs_word_le": "0x69f2e9fb"
        }
    ]);
    let value = serde_json::json!({
        "vm_chains": [
            {
                "start_offset": 0,
                "chain": {
                    "recognized_semantics": [
                        {
                            "step": 15,
                            "idx": 14695079,
                            "asm": "orr x3, x19, x8",
                            "semantic": {
                                "kind": "bitwise_or_merge",
                                "lhs": "0x69000000",
                                "rhs": "0xf2e9fb",
                                "result": "0x69f2e9fb"
                            }
                        }
                    ]
                }
            }
        ]
    });
    let sources = output_semantic_xor_word_state_sources(&value, &templates);
    let first = sources.as_array().unwrap().first().unwrap();
    assert_eq!(
        first["source_status"],
        serde_json::json!("word_source_only")
    );
    assert_eq!(first["source_word"], serde_json::json!("0x69f2e9fb"));
    assert_eq!(first["state_update"], serde_json::Value::Null);
}

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
    let effects = vm_op_effect_summaries(&op);
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
    let effects = vm_op_effect_summaries(&op);
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
    let effects = vm_op_effect_summaries(&op);
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
                        "asm": "add x21, x21, x6, lsl #4",
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
    let (seed, decision) = lineage_next_from_backstep(&backstep, Some(2));
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
    let (seed, decision) = lineage_next_from_backstep(&backstep, Some(0));
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
    let (seed, decision) = lineage_next_from_backstep(&backstep, Some(0));
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
            "tracemiku-cli mem-dump <call_dir> --addr 0x4000 --count 8 --cursor 200 --summary"
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
                        "vm_slot": {"slot": 20}
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
    let (seed, decision) = lineage_next_from_backstep(&backstep, Some(0));
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
fn taint_params_include_scan_limit_when_set() {
    let params = super::taint_params(
        12,
        "x9".to_string(),
        Some(500),
        true,
        true,
        false,
        Some(50_000),
    );
    let map: std::collections::HashMap<&str, String> = params.into_iter().collect();
    assert_eq!(map.get("start").unwrap(), "12");
    assert_eq!(map.get("reg").unwrap(), "x9");
    assert_eq!(map.get("max_count").unwrap(), "500");
    assert_eq!(map.get("through_mem").unwrap(), "true");
    assert_eq!(map.get("data_only").unwrap(), "true");
    assert_eq!(map.get("cross_fn_call").unwrap(), "false");
    assert_eq!(map.get("scan_limit").unwrap(), "50000");
}

#[test]
fn taint_params_omit_scan_limit_when_none() {
    let params = super::taint_params(0, "x0".to_string(), None, false, false, false, None);
    let map: std::collections::HashMap<&str, String> = params.into_iter().collect();
    assert!(!map.contains_key("scan_limit"));
    assert!(!map.contains_key("max_count"));
    assert_eq!(map.get("through_mem").unwrap(), "false");
}

#[test]
fn route_path_encodes_query_params() {
    let qp = vec![
        ("limit", "5000".to_string()),
        ("idxs", "1234,5678".to_string()),
        ("mode", "intersection".to_string()),
    ];
    let url = super::route_path("/api/bfs-slice", &qp);
    assert!(url.starts_with("/api/bfs-slice?"));
    assert!(url.contains("limit=5000"));
    assert!(url.contains("idxs=1234%2C5678"));
    assert!(url.contains("mode=intersection"));
}
