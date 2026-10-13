use super::*;

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
    let profile = VmProfile::new(
        "x9".to_string(),
        "x25".to_string(),
        "x22".to_string(),
        "x26".to_string(),
    );
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
            {"idx": 10, "reg": "x12", "value": "0x70000000"},
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
            {"idx": 20, "reg": "x11", "value": "0x69f5b3cb"}
        ]
    });
    let next = choose_frontier_next(&infra_only).unwrap();
    assert_eq!(next["idx"], serde_json::json!(20));
    assert_eq!(next["reg"], serde_json::json!("x11"));
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
    let profile = VmProfile::new(
        "x9".to_string(),
        "x10".to_string(),
        "x11".to_string(),
        "x12".to_string(),
    );
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
