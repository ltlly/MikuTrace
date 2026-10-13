use super::*;

pub(super) fn vm_backchain_summary(backchain: &serde_json::Value) -> serde_json::Value {
    let chain = backchain
        .get("chain")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_backchain_summary_step)
        .collect::<Vec<_>>();
    let stop = vm_backchain_stop_summary(&chain);
    let recognized_semantics = chain
        .iter()
        .filter_map(|step| {
            step.pointer("/local_def/formula/semantic")
                .cloned()
                .map(|semantic| {
                    serde_json::json!({
                        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                        "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                        "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": semantic,
                    })
                })
        })
        .collect::<Vec<_>>();
    let recognized_patterns = recognized_backchain_patterns(&chain);
    let recognized_pattern_summary = recognized_backchain_pattern_summary(&recognized_patterns);
    serde_json::json!({
        "status": backchain.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": backchain.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "follow_frontier": backchain.get("follow_frontier").cloned().unwrap_or(serde_json::Value::Null),
        "steps_requested": backchain.get("steps_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": backchain.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop": stop,
        "recognized_semantics": recognized_semantics,
        "recognized_patterns": recognized_patterns,
        "recognized_pattern_summary": recognized_pattern_summary,
        "chain": chain,
    })
}

pub(super) fn vm_backchain_stop_summary(chain: &[serde_json::Value]) -> serde_json::Value {
    let Some(last) = chain.last() else {
        return serde_json::Value::Null;
    };
    let decision = last
        .get("decision")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if decision.get("kind").and_then(|v| v.as_str()) != Some("stop") {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "step": last.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "idx": last.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": last.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": last.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "target": last.get("target").cloned().unwrap_or(serde_json::Value::Null),
        "local_def": last.get("local_def").cloned().unwrap_or(serde_json::Value::Null),
        "upstream": last.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
        "decision": decision,
    })
}

#[derive(Debug, Default)]
pub(super) struct AffinePatternGroup {
    pub(super) multiplier: String,
    pub(super) delta: String,
    pub(super) multiplier_inverse: serde_json::Value,
    pub(super) multiplier_odd: serde_json::Value,
    pub(super) transitions: Vec<serde_json::Value>,
}

pub(super) fn recognized_backchain_pattern_summary(
    patterns: &[serde_json::Value],
) -> serde_json::Value {
    let mut affine = BTreeMap::<String, AffinePatternGroup>::new();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    let mut static_memory_loads = Vec::new();
    let mut memory_boundary_reads = Vec::new();
    for pattern in patterns {
        let Some(kind) = pattern.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };
        *kind_counts.entry(kind.to_string()).or_insert(0) += 1;
        if kind == "static_memory_load_constant" {
            static_memory_loads.push(pattern.clone());
            continue;
        }
        if kind == "memory_boundary_read" {
            memory_boundary_reads.push(pattern.clone());
            continue;
        }
        if kind != "affine_mod64_state_step" {
            continue;
        }
        let Some(multiplier) = pattern.get("multiplier").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(delta) = pattern.get("delta").and_then(|v| v.as_str()) else {
            continue;
        };
        let key = format!("{multiplier}|{delta}");
        let group = affine.entry(key).or_insert_with(|| AffinePatternGroup {
            multiplier: multiplier.to_string(),
            delta: delta.to_string(),
            multiplier_inverse: pattern
                .get("multiplier_inverse")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            multiplier_odd: pattern
                .get("multiplier_odd")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            ..AffinePatternGroup::default()
        });
        group.transitions.push(serde_json::json!({
            "add_step": pattern.get("add_step").cloned().unwrap_or(serde_json::Value::Null),
            "mul_step": pattern.get("mul_step").cloned().unwrap_or(serde_json::Value::Null),
            "previous_state": pattern.get("previous_state").cloned().unwrap_or(serde_json::Value::Null),
            "state": pattern.get("state").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    serde_json::json!({
        "kind_counts": kind_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "affine_mod64_recurrences": affine
            .into_values()
            .map(|group| serde_json::json!({
                "kind": "affine_mod64_recurrence",
                "count": group.transitions.len(),
                "multiplier": group.multiplier,
                "delta": group.delta,
                "multiplier_inverse": group.multiplier_inverse,
                "multiplier_odd": group.multiplier_odd,
                "expression": "state == (previous_state * multiplier + delta) mod 2^64",
                "transitions": group.transitions,
            }))
            .collect::<Vec<_>>(),
        "static_memory_loads": static_memory_loads,
        "memory_boundary_reads": memory_boundary_reads,
    })
}

pub(super) fn recognized_backchain_patterns(chain: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut patterns = Vec::new();
    for (idx, step) in chain.iter().enumerate() {
        if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("mem-load")
            && step.pointer("/upstream/status").and_then(|v| v.as_str()) == Some("not_found")
        {
            if let Some(bytes_hex) = step
                .pointer("/upstream/observed_bytes_hex")
                .and_then(|v| v.as_str())
            {
                patterns.push(serde_json::json!({
                    "kind": "static_memory_load_constant",
                    "step": step.get("step").cloned().unwrap_or_else(|| serde_json::json!(idx)),
                    "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": step.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "bytes_hex": bytes_hex,
                    "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    "upstream_status": step.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_lo": step.pointer("/upstream/idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_hi": step.pointer("/upstream/idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "returned": step.pointer("/upstream/returned").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": step.pointer("/upstream/maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                    "source_boundary": if step.pointer("/upstream/idx_lo").and_then(|v| v.as_u64()).unwrap_or(0) > 0 {
                        "lookback_window"
                    } else {
                        "trace_start"
                    },
                    "expression": "value loaded from memory with no writer found in current lookback window",
                    "caution": "Increase --lookback before treating this as a true static/pre-trace constant",
                }));
            }
        }
        if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("mem-load")
            && step.pointer("/upstream/status").and_then(|v| v.as_str())
                == Some("observed_read_without_matching_traced_write")
        {
            if let Some(bytes_hex) = step
                .pointer("/upstream/observed_bytes_hex")
                .and_then(|v| v.as_str())
            {
                patterns.push(serde_json::json!({
                    "kind": "memory_boundary_read",
                    "step": step.get("step").cloned().unwrap_or_else(|| serde_json::json!(idx)),
                    "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": step.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "bytes_hex": bytes_hex,
                    "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write": step.pointer("/upstream/last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_mismatches": step
                        .pointer("/upstream/observed_mismatches")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([])),
                    "expression": "value loaded from memory but latest traced write does not explain observed bytes",
                }));
            }
        }
        let semantic = step.pointer("/local_def/formula/semantic");
        if semantic
            .and_then(|v| v.get("kind"))
            .and_then(|v| v.as_str())
            != Some("add_small_delta")
        {
            continue;
        }
        let Some(add_semantic) = semantic else {
            continue;
        };
        let Some(add_input) = add_semantic.get("input").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(mul_step) = chain.iter().skip(idx + 1).find(|candidate| {
            let semantic = candidate.pointer("/local_def/formula/semantic");
            semantic
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
                == Some("mul_mod64")
                && semantic
                    .and_then(|v| v.get("result"))
                    .and_then(|v| v.as_str())
                    == Some(add_input)
        }) else {
            continue;
        };
        let Some(mul_semantic) = mul_step.pointer("/local_def/formula/semantic") else {
            continue;
        };
        let multiplier_inverse = mul_semantic
            .get("rhs")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .and_then(odd_u64_inverse)
            .map(|value| serde_json::Value::String(format!("{value:#x}")))
            .unwrap_or(serde_json::Value::Null);
        patterns.push(serde_json::json!({
            "kind": "affine_mod64_state_step",
            "add_step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "mul_step": mul_step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "state": add_semantic.get("result").cloned().unwrap_or(serde_json::Value::Null),
            "previous_state": mul_semantic.get("lhs").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier": mul_semantic.get("rhs").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier_inverse": multiplier_inverse,
            "delta": add_semantic.get("delta").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier_odd": mul_semantic.get("rhs_odd").cloned().unwrap_or(serde_json::Value::Null),
            "expression": "state == (previous_state * multiplier + delta) mod 2^64",
        }));
    }
    patterns
}

pub(super) fn odd_u64_inverse(value: u64) -> Option<u64> {
    if value & 1 == 0 {
        return None;
    }
    let mut inverse = value;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(inverse)));
    }
    Some(inverse)
}

pub(super) fn compact_backchain_summary_step(step: &serde_json::Value) -> serde_json::Value {
    let compact = step
        .get("backstep")
        .map(compact_lineage_backstep)
        .unwrap_or(serde_json::Value::Null);
    let lineage_step = serde_json::json!({
        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "byte_lane": step.get("byte_lane").cloned().unwrap_or(serde_json::Value::Null),
        "kind": "reg_source",
        "backstep": compact,
        "decision": step.get("decision").cloned().unwrap_or(serde_json::Value::Null),
        "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
    });
    compact_lineage_summary_step(&lineage_step)
}

pub(super) fn compact_lineage_summary_step(step: &serde_json::Value) -> serde_json::Value {
    match step.get("kind").and_then(|v| v.as_str()) {
        Some("last_write") => {
            let write = step.get("write").unwrap_or(&serde_json::Value::Null);
            serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "seed": step.get("seed").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "last_write",
                "source_byte_offset": step.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
                "addr": write.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": write.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "func": write.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": write.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "src_reg": write.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        Some("reg_source") => {
            let backstep = step.get("backstep").unwrap_or(&serde_json::Value::Null);
            let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
            serde_json::json!({
                    "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "seed": step.get("seed").cloned().unwrap_or(serde_json::Value::Null),
                    "byte_lane": step.get("byte_lane").cloned().unwrap_or(serde_json::Value::Null),
                    "kind": "reg_source",
                    "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
                    "value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
                    "target": compact_lineage_row_for_summary(backstep.get("target")),
                    "local_def": compact_lineage_row_for_summary(backstep.get("local_def")),
                    "upstream": {
                        "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
                "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "idx_lo": upstream.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                "idx_hi": upstream.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                "returned": upstream.get("returned").cloned().unwrap_or(serde_json::Value::Null),
                "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
                "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
                "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                "last_write": compact_lineage_last_write(upstream.get("last_write")),
                "byte_nexts": compact_lineage_byte_nexts(upstream.get("byte_nexts")),
                "gap_call_candidates": compact_gap_call_candidates(upstream.get("gap_call_candidates")),
            },
                    "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "decision": step.get("decision").cloned().unwrap_or(serde_json::Value::Null),
                    "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
                })
        }
        _ => step.clone(),
    }
}

pub(super) fn compact_lineage_row_for_summary(
    row: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(row) = row else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "def": row.get("def").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "vm_slot": row.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
        "formula": row.get("formula").cloned().unwrap_or(serde_json::Value::Null),
        "call_return": row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_return": row.get("syscall_return").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn compact_gap_call_candidates(value: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(value) = value else {
        return serde_json::Value::Null;
    };
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let candidates = value
        .get("candidates")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .take(8)
        .map(|candidate| {
            serde_json::json!({
                "idx": candidate.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": candidate.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "target_addr": candidate.get("target_addr").cloned().unwrap_or(serde_json::Value::Null),
                "target_module": candidate.get("target_module").cloned().unwrap_or(serde_json::Value::Null),
                "external_to_primary": candidate.get("external_to_primary").cloned().unwrap_or(serde_json::Value::Null),
                "arg_offsets": candidate.get("arg_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
                "span_matches": candidate.get("span_matches").cloned().unwrap_or_else(|| serde_json::json!([])),
                "near_regs": candidate.get("near_regs").cloned().unwrap_or_else(|| serde_json::json!([])),
                "score": candidate.get("score").cloned().unwrap_or(serde_json::Value::Null),
                "score_adjustment_trace_write": candidate.get("score_adjustment_trace_write").cloned().unwrap_or(serde_json::Value::Null),
                "callee_trace": candidate.get("callee_trace").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "scan_idx_lo": value.get("scan_idx_lo").cloned().unwrap_or(serde_json::Value::Null),
        "scan_idx_hi": value.get("scan_idx_hi").cloned().unwrap_or(serde_json::Value::Null),
        "candidate_count_total": value.get("candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
        "truncated_by_record_cap": value.get("truncated_by_record_cap").cloned().unwrap_or(serde_json::Value::Null),
        "candidates": candidates,
    })
}

pub(super) fn compact_lineage_last_write(write: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(write) = write else {
        return serde_json::Value::Null;
    };
    if write.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "idx": write.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "func": write.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": write.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "dst_addr": write.get("dst_addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": write.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "src_reg": write.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
        "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn compact_lineage_byte_nexts(nexts: Option<&serde_json::Value>) -> serde_json::Value {
    let rows = nexts
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|next| {
            let offsets = next
                .get("offsets")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .take(8)
                        .cloned()
                        .collect::<Vec<serde_json::Value>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "idx": next.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": next.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": next.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "addr": next.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "offset": next.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "offsets": offsets,
                "source_byte_offset": next.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
                "source_byte_offsets": next.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
                "reason": next.get("reason").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::Value::Array(rows)
}

pub(super) fn compact_lineage_stop_reason(reason: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(reason) = reason else {
        return serde_json::Value::Null;
    };
    let decision = reason.get("decision");
    serde_json::json!({
        "kind": reason.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        "seed": reason.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "decision_kind": decision
            .and_then(|v| v.get("kind"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "upstream_status": decision
            .and_then(|v| v.get("upstream_status"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "frontier": decision
            .and_then(|v| v.get("frontier"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) struct TreeSeed {
    pub(super) parent: Option<usize>,
    pub(super) depth: usize,
    pub(super) idx: usize,
    pub(super) reg: Option<String>,
    pub(super) via: serde_json::Value,
}

pub(super) fn tree_seed_from_next(
    parent: usize,
    depth: usize,
    next: serde_json::Value,
    via: serde_json::Value,
) -> Option<TreeSeed> {
    Some(TreeSeed {
        parent: Some(parent),
        depth,
        idx: next.get("idx")?.as_u64()? as usize,
        reg: next.get("reg").and_then(|v| v.as_str()).map(str::to_string),
        via,
    })
}

pub(super) fn frontier_nexts_from_step(
    step: &serde_json::Value,
    profile: &VmProfile,
) -> Vec<serde_json::Value> {
    step.get("frontier")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if profile.is_infrastructure_reg(reg) {
                return None;
            }
            Some(serde_json::json!({
                "idx": frontier.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": frontier.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": frontier.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "reason": "frontier",
                "frontier": frontier,
            }))
        })
        .collect()
}

pub(super) fn upstream_byte_nexts_from_step(step: &serde_json::Value) -> Vec<serde_json::Value> {
    step.get("upstream")
        .and_then(|v| v.get("byte_nexts"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

pub(super) fn same_tree_next(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("idx").and_then(|v| v.as_u64()) == b.get("idx").and_then(|v| v.as_u64())
        && a.get("reg").and_then(|v| v.as_str()) == b.get("reg").and_then(|v| v.as_str())
}

#[allow(clippy::too_many_arguments)] // tree compaction carries context; refactor is separate work
pub(super) fn compact_backtree_node(
    id: usize,
    parent: Option<usize>,
    depth: usize,
    via: &serde_json::Value,
    backstep: &serde_json::Value,
    upstream_next: &serde_json::Value,
    upstream_byte_nexts: &[serde_json::Value],
    frontier_nexts: &[serde_json::Value],
) -> serde_json::Value {
    let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "id": id,
        "parent": parent,
        "depth": depth,
        "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
        "via": via,
        "target": compact_vm_row(backstep.get("target")),
        "local_def": compact_vm_row(backstep.get("local_def")),
        "upstream": {
            "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "next": upstream_next,
            "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
            "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
            "byte_nexts": upstream_byte_nexts,
            "byte_writers": upstream.get("byte_writers").cloned().unwrap_or_else(|| serde_json::json!([])),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
        },
        "frontier_nexts": frontier_nexts,
    })
}

pub(super) fn compact_vm_row(row: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(row) = row else {
        return serde_json::Value::Null;
    };
    let formula = row_alu_formula(row);
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "def": row.get("def").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "vm_slot": row.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
        "formula": formula,
        "call_return": row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_return": row.get("syscall_return").cloned().unwrap_or(serde_json::Value::Null),
    })
}
