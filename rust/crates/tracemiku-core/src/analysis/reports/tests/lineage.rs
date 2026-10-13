use super::*;

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
