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
    multiplier: String,
    delta: String,
    multiplier_inverse: serde_json::Value,
    multiplier_odd: serde_json::Value,
    transitions: Vec<serde_json::Value>,
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

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn vm_backstep_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let start = idx.saturating_sub(context);
    let count = context.saturating_add(3);
    let regs = regs_with_vm_profile(regs, profile);
    let params = vec![
        ("start", start.to_string()),
        ("count", count.to_string()),
        ("regs", regs),
    ];
    let response = route_get_json_value_on(app, route_path("/api/records", &params)).await?;
    let records = response
        .get("records")
        .and_then(|v| v.as_array())
        .context("/api/records response missing records[]")?;
    let inferred_base = records
        .iter()
        .find_map(|rec| record_reg_u64(rec, &profile.ip_reg));
    let rows = records
        .iter()
        .enumerate()
        .map(|(pos, rec)| vm_row_from_record(rec, records.get(pos + 1), inferred_base, profile))
        .collect::<Vec<_>>();
    let target_pos = rows
        .iter()
        .position(|row| row.get("idx").and_then(|v| v.as_u64()) == Some(idx as u64))
        .with_context(|| format!("idx {idx} not present in local record window"))?;
    let target_row = &rows[target_pos];
    let target_record = &records[target_pos];
    let source_reg = reg.or_else(|| {
        target_row
            .get("store_src")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("reg"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let Some(source_reg) = source_reg else {
        return Ok(serde_json::json!({
            "status": "no_source_reg",
            "idx": idx,
            "target": target_row,
        }));
    };
    let source_key = register_value_key(&source_reg);
    let target_def = row_def_entry_for_key(target_row, &source_key);
    let target_defines_source = target_def
        .as_ref()
        .is_some_and(|def| !def_source_contains_reg(def, &source_key));
    let local_def = if target_defines_source {
        let def = target_def.expect("target_defines_source requires target def");
        let mut out = target_row.clone();
        if let Some(obj) = out.as_object_mut() {
            obj.insert("def".to_string(), def.clone());
            if let Some(mem_addr) = def.get("mem_addr") {
                obj.insert("mem_addr".to_string(), mem_addr.clone());
            }
        }
        Some(out)
    } else if let Some(call_return) =
        call_return_def_from_previous_call(&rows, records, target_pos, &source_key, target_record)
    {
        Some(call_return)
    } else if let Some(syscall_return) =
        syscall_return_def_from_previous_svc(&rows, records, target_pos, &source_key, target_record)
    {
        Some(syscall_return)
    } else {
        rows[..target_pos]
            .iter()
            .rev()
            .find_map(|row| row_for_def_reg(row, &source_key))
    };
    let upstream = if let Some(def_row) = local_def.as_ref() {
        upstream_writer_for_def_on(app, def_row, lookback, max_writes).await?
    } else {
        serde_json::json!({
            "status": "no_local_def",
            "searched_context": context,
        })
    };
    let frontier = local_def
        .as_ref()
        .map(backstep_frontier_from_def)
        .unwrap_or_default();
    Ok(serde_json::json!({
        "status": "ready",
        "idx": idx,
        "vm_profile": profile.to_json(),
        "source_reg": source_reg,
        "source_value": if target_defines_source {
            row_def_entry_for_key(target_row, &source_key)
                .and_then(|def| def.get("value_after").cloned())
                .unwrap_or(serde_json::Value::Null)
        } else {
            record_reg_value(target_record, &source_key).cloned().unwrap_or(serde_json::Value::Null)
        },
        "target": target_row,
        "local_def": local_def,
        "upstream": upstream,
        "frontier": frontier,
    }))
}

pub(super) fn row_def_reg_key(row: &serde_json::Value) -> Option<String> {
    row.get("def")
        .and_then(|v| v.get("reg"))
        .and_then(|v| v.as_str())
        .map(register_value_key)
}

pub(super) fn call_return_def_from_previous_call(
    rows: &[serde_json::Value],
    records: &[serde_json::Value],
    target_pos: usize,
    source_key: &str,
    target_record: &serde_json::Value,
) -> Option<serde_json::Value> {
    if source_key != "x0" || target_pos == 0 {
        return None;
    }
    let call_pos = (0..target_pos).rev().find(|pos| {
        let row = &rows[*pos];
        if row_defines_reg(row, source_key) {
            return false;
        }
        row.get("asm")
            .and_then(|v| v.as_str())
            .is_some_and(is_call_asm)
    })?;
    if rows[call_pos + 1..target_pos]
        .iter()
        .any(|row| row_defines_reg(row, source_key))
    {
        return None;
    }
    let call_row = rows.get(call_pos)?;
    let call_record = records.get(call_pos)?;
    let asm = call_row.get("asm").and_then(|v| v.as_str())?.trim();
    let target_reg = indirect_call_target_reg(asm);
    let target_value = target_reg
        .as_deref()
        .and_then(|reg| record_reg_value(call_record, reg))
        .cloned()
        .or_else(|| direct_call_target_value(asm).map(serde_json::Value::String))
        .unwrap_or(serde_json::Value::Null);
    let args = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        .into_iter()
        .map(|reg| {
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(call_record, reg).cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let mut src = args.clone();
    if let Some(reg) = target_reg.as_deref() {
        src.push(serde_json::json!({
            "reg": reg,
            "role": "call_target",
            "value": target_value.clone(),
        }));
    }
    let mut row = call_row.clone();
    if let Some(obj) = row.as_object_mut() {
        obj.insert("class".to_string(), serde_json::json!("call-return"));
        obj.insert(
            "def".to_string(),
            serde_json::json!({
                "reg": "x0",
                "src": src,
                "value_after": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
            }),
        );
        obj.insert(
            "call_return".to_string(),
            serde_json::json!({
                "call_idx": call_row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "call_pc": call_row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                "asm": asm,
                "return_reg": "x0",
                "return_value": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
                "target_reg": target_reg,
                "target_value": target_value,
                "args": args,
                "intervening_rows": target_pos.saturating_sub(call_pos + 1),
                "note": "x0 changed across a call; do not attribute it to pre-call local definitions",
            }),
        );
    }
    Some(row)
}

pub(super) fn is_call_asm(asm: &str) -> bool {
    let mnemonic = asm.split_whitespace().next().unwrap_or("");
    matches!(mnemonic, "bl" | "blr")
}

pub(super) fn syscall_return_def_from_previous_svc(
    rows: &[serde_json::Value],
    records: &[serde_json::Value],
    target_pos: usize,
    source_key: &str,
    target_record: &serde_json::Value,
) -> Option<serde_json::Value> {
    if source_key != "x0" || target_pos == 0 {
        return None;
    }
    let svc_pos = (0..target_pos).rev().find(|pos| {
        let row = &rows[*pos];
        if row_defines_reg(row, source_key) {
            return false;
        }
        row.get("asm")
            .and_then(|v| v.as_str())
            .is_some_and(is_svc_asm)
    })?;
    if rows[svc_pos + 1..target_pos]
        .iter()
        .any(|row| row_defines_reg(row, source_key))
    {
        return None;
    }
    let svc_row = rows.get(svc_pos)?;
    let svc_record = records.get(svc_pos)?;
    let args = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"]
        .into_iter()
        .map(|reg| {
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(svc_record, reg).cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let mut row = svc_row.clone();
    if let Some(obj) = row.as_object_mut() {
        obj.insert("class".to_string(), serde_json::json!("syscall-return"));
        obj.insert(
            "def".to_string(),
            serde_json::json!({
                "reg": "x0",
                "src": args.clone(),
                "value_after": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
            }),
        );
        obj.insert(
            "syscall_return".to_string(),
            serde_json::json!({
                "svc_idx": svc_row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "svc_pc": svc_row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                "asm": svc_row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "syscall_reg": "x8",
                "syscall_number": record_reg_value(svc_record, "x8").cloned().unwrap_or(serde_json::Value::Null),
                "return_reg": "x0",
                "return_value": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
                "args": args,
                "intervening_rows": target_pos.saturating_sub(svc_pos + 1),
                "note": "x0 changed across svc; treat it as a syscall return boundary",
            }),
        );
    }
    Some(row)
}

pub(super) fn is_svc_asm(asm: &str) -> bool {
    asm.split_whitespace().next().unwrap_or("") == "svc"
}

pub(super) fn indirect_call_target_reg(asm: &str) -> Option<String> {
    let mut parts = asm.trim().splitn(2, char::is_whitespace);
    if parts.next()? != "blr" {
        return None;
    }
    parts
        .next()
        .and_then(|operands| split_operands(operands).first().cloned())
        .and_then(|op| first_register_token(&op))
}

pub(super) fn direct_call_target_value(asm: &str) -> Option<String> {
    let mut parts = asm.trim().splitn(2, char::is_whitespace);
    if parts.next()? != "bl" {
        return None;
    }
    parts
        .next()
        .and_then(|operands| split_operands(operands).first().cloned())
        .and_then(|op| immediate_operand_value(&op))
}

pub(super) fn row_defines_reg(row: &serde_json::Value, reg_key: &str) -> bool {
    row_def_entry_for_key(row, reg_key).is_some()
}

pub(super) fn row_for_def_reg(row: &serde_json::Value, reg_key: &str) -> Option<serde_json::Value> {
    let def = row_def_entry_for_key(row, reg_key)?;
    let mut out = row.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("def".to_string(), def.clone());
        if let Some(mem_addr) = def.get("mem_addr") {
            obj.insert("mem_addr".to_string(), mem_addr.clone());
        }
    }
    Some(out)
}

pub(super) fn row_def_entry_for_key(
    row: &serde_json::Value,
    reg_key: &str,
) -> Option<serde_json::Value> {
    row.get("defs")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .find(|def| {
            def.get("reg")
                .and_then(|v| v.as_str())
                .map(register_value_key)
                .as_deref()
                == Some(reg_key)
        })
        .cloned()
        .or_else(|| {
            (row_def_reg_key(row).as_deref() == Some(reg_key))
                .then(|| row.get("def").cloned())
                .flatten()
        })
}

pub(super) fn def_source_contains_reg(def: &serde_json::Value, reg_key: &str) -> bool {
    let reg_key = register_value_key(reg_key);
    def.get("src")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .any(|src| {
            src.get("reg")
                .and_then(|v| v.as_str())
                .map(register_value_key)
                .as_deref()
                == Some(reg_key.as_str())
        })
}

pub(super) fn backstep_frontier_from_def(def_row: &serde_json::Value) -> Vec<serde_json::Value> {
    let idx = def_row
        .get("idx")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    def_row
        .get("def")
        .and_then(|v| v.get("src"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|src| {
            let reg = src.get("reg")?.clone();
            Some(serde_json::json!({
                "idx": idx,
                "reg": reg,
                "value": src.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "reason": "local_def_source_reg",
            }))
        })
        .collect()
}

pub(super) fn vm_row_from_record(
    rec: &serde_json::Value,
    next: Option<&serde_json::Value>,
    inferred_base: Option<u64>,
    profile: &VmProfile,
) -> serde_json::Value {
    let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let class = classify_vm_asm(asm, profile);
    let vm_ip = record_reg_u64(rec, &profile.ip_reg);
    let vm_off = vm_ip.and_then(|ip| inferred_base.map(|base| ip.wrapping_sub(base)));
    let vm_slot = vm_slot_from_asm(asm, rec, profile);
    let mem_addr = mem_addr_from_asm(asm, rec);
    let defs = def_entries_from_asm(asm, rec, next, mem_addr);
    let def = defs.first().cloned();
    let store_src = store_source_regs_from_asm(asm)
        .into_iter()
        .map(|reg| {
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(rec, &reg).cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "idx": rec.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": rec.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": rec.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "class": class,
        "def": def,
        "defs": defs,
        "store_src": store_src,
        "vm_ip": vm_ip.map(|v| format!("{v:#x}")),
        "vm_off": vm_off.map(|v| format!("{v:#x}")),
        "vm_slot": vm_slot,
        "mem_addr": mem_addr.map(|v| format!("{v:#x}")),
        "regs": rec.get("regs").cloned().unwrap_or_else(|| serde_json::json!({})),
    })
}

pub(super) fn def_entries_from_asm(
    asm: &str,
    rec: &serde_json::Value,
    next: Option<&serde_json::Value>,
    mem_addr: Option<u64>,
) -> Vec<serde_json::Value> {
    if let Some(dest_regs) = pair_load_dest_regs_from_asm(asm) {
        let src = memory_source_regs_from_asm(asm)
            .into_iter()
            .map(|src_reg| {
                serde_json::json!({
                    "reg": src_reg,
                    "value": record_reg_value(rec, &src_reg).cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>();
        let mut offset = 0u64;
        return dest_regs
            .into_iter()
            .map(|reg| {
                let width = register_load_width(&reg);
                let entry = serde_json::json!({
                    "reg": reg.clone(),
                    "src": src.clone(),
                    "value_after": next.and_then(|next| record_reg_value(next, &reg).cloned()).unwrap_or(serde_json::Value::Null),
                    "mem_addr": mem_addr.map(|addr| format!("{:#x}", addr.wrapping_add(offset))),
                });
                offset = offset.saturating_add(width);
                entry
            })
            .collect();
    }
    def_reg_from_asm(asm)
        .map(|reg| {
            let src = def_source_regs_from_asm(asm)
                .into_iter()
                .map(|src_reg| {
                    serde_json::json!({
                        "reg": src_reg,
                        "value": record_reg_value(rec, &src_reg).cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect::<Vec<_>>();
            vec![serde_json::json!({
                "reg": reg.clone(),
                "src": src,
                "value_after": next.and_then(|next| record_reg_value(next, &reg).cloned()).unwrap_or(serde_json::Value::Null),
                "mem_addr": mem_addr.map(|addr| format!("{addr:#x}")),
            })]
        })
        .unwrap_or_default()
}

pub(super) fn vm_ops_from_rows(rows: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut groups: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut current_key: Option<String> = None;
    for row in rows {
        let key = row
            .get("vm_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if current_key.as_deref() != Some(key.as_str()) {
            groups.push(Vec::new());
            current_key = Some(key);
        }
        if let Some(group) = groups.last_mut() {
            group.push(row.clone());
        }
    }
    groups
        .into_iter()
        .filter(|group| !group.is_empty())
        .map(|group| vm_op_from_group(&group))
        .collect()
}

pub(super) fn vm_op_from_group(group: &[serde_json::Value]) -> serde_json::Value {
    let first = &group[0];
    let last = group.last().unwrap_or(first);
    let mut class_counts = BTreeMap::<String, usize>::new();
    for row in group {
        let class = row
            .get("class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *class_counts.entry(class).or_default() += 1;
    }
    let bytecode_reads = group
        .iter()
        .filter_map(bytecode_read_summary)
        .collect::<Vec<_>>();
    let vm_slot_reads = group
        .iter()
        .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("vm-reg-load"))
        .flat_map(vm_slot_access_summaries)
        .collect::<Vec<_>>();
    let vm_slot_writes = group
        .iter()
        .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("vm-reg-store"))
        .flat_map(vm_slot_access_summaries)
        .collect::<Vec<_>>();
    let small_byte_loads = group
        .iter()
        .filter_map(byte_load_summary)
        .collect::<Vec<_>>();
    let memory_stores = group
        .iter()
        .filter(|row| {
            matches!(
                row.get("class").and_then(|v| v.as_str()),
                Some("mem-store" | "byte-store")
            )
        })
        .map(memory_access_summary)
        .collect::<Vec<_>>();
    let alu_formulas = group.iter().filter_map(row_alu_formula).collect::<Vec<_>>();
    serde_json::json!({
        "idx_start": first.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "idx_end": last
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|idx| serde_json::json!(idx + 1))
            .unwrap_or(serde_json::Value::Null),
        "vm_ip": first.get("vm_ip").cloned().unwrap_or(serde_json::Value::Null),
        "vm_off": first.get("vm_off").cloned().unwrap_or(serde_json::Value::Null),
        "rows": group.len(),
        "class_counts": class_counts,
        "bytecode_reads": bytecode_reads,
        "vm_slot_reads": vm_slot_reads,
        "vm_slot_writes": vm_slot_writes,
        "small_byte_loads": small_byte_loads,
        "memory_stores": memory_stores,
        "alu_formulas": alu_formulas,
        "dispatches": group
            .iter()
            .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("dispatch-branch"))
            .map(|row| {
                serde_json::json!({
                    "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(super) fn bytecode_read_summary(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("bytecode-read") {
        return None;
    }
    let asm = row.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let width = memory_access_width(asm).min(8);
    let value = row
        .pointer("/def/value_after")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let value_u64 = value
        .as_str()
        .and_then(parse_u64_str)
        .or_else(|| value.as_u64());
    let vm_ip = row
        .get("vm_ip")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let mem_addr = row
        .get("mem_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let offset = vm_ip.zip(mem_addr).map(|(ip, addr)| addr.wrapping_sub(ip));
    Some(serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
        "offset": offset.map(|v| format!("{v:#x}")),
        "width": width,
        "value": value,
        "bytes_le_hex": value_u64.map(|v| {
            let bytes = v.to_le_bytes();
            bytes_to_hex(&bytes[..width as usize])
        }),
    }))
}

#[allow(clippy::needless_return)] // branch style: every arm returns; tail-expression refactor is separate work
pub(super) fn vm_slot_access_summaries(row: &serde_json::Value) -> Vec<serde_json::Value> {
    let Some(slot) = row.get("vm_slot") else {
        return Vec::new();
    };
    let class = row.get("class").and_then(|v| v.as_str()).unwrap_or("");
    let base_slot = slot.get("slot").and_then(|v| v.as_u64()).unwrap_or(0);
    let base_mem_addr = row
        .get("mem_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    if class == "vm-reg-load" {
        let defs = row
            .get("defs")
            .and_then(|v| v.as_array())
            .filter(|defs| !defs.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                row.get("def")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .into_iter()
                    .collect()
            });
        return defs
            .iter()
            .enumerate()
            .map(|(idx, def)| {
                let def_mem_addr = def
                    .get("mem_addr")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)
                    .or_else(|| base_mem_addr.map(|addr| addr + (idx as u64) * 8));
                let slot_idx = vm_slot_index_for_mem_addr(base_slot, base_mem_addr, def_mem_addr);
                serde_json::json!({
                    "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "op": "load",
                    "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "slot": slot_idx,
                    "index_reg": slot.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                    "index_value": slot.get("index_value").cloned().unwrap_or(serde_json::Value::Null),
                    "reg": def.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                    "value": def.get("value_after").cloned().unwrap_or(serde_json::Value::Null),
                    "mem_addr": def_mem_addr.map(|addr| format!("{addr:#x}")),
                })
            })
            .collect();
    } else if class == "vm-reg-store" {
        let srcs = row
            .get("store_src")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut byte_offset = 0u64;
        return srcs
            .iter()
            .map(|src| {
                let reg = src
                    .get("reg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let width = register_load_width(&reg);
                let mem_addr = base_mem_addr.map(|addr| addr + byte_offset);
                let slot_idx = vm_slot_index_for_mem_addr(base_slot, base_mem_addr, mem_addr);
                byte_offset = byte_offset.saturating_add(width);
                serde_json::json!({
                    "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "op": "store",
                    "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "slot": slot_idx,
                    "index_reg": slot.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                    "index_value": slot.get("index_value").cloned().unwrap_or(serde_json::Value::Null),
                    "reg": src.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                    "value": src.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    "mem_addr": mem_addr.map(|addr| format!("{addr:#x}")),
                })
            })
            .collect();
    } else {
        Vec::new()
    }
}

pub(super) fn vm_slot_index_for_mem_addr(
    base_slot: u64,
    base_mem_addr: Option<u64>,
    mem_addr: Option<u64>,
) -> serde_json::Value {
    base_mem_addr
        .zip(mem_addr)
        .and_then(|(base, addr)| addr.checked_sub(base))
        .map(|offset| serde_json::json!(base_slot + offset / 8))
        .unwrap_or_else(|| serde_json::json!(base_slot))
}

pub(super) fn byte_load_summary(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("byte-load") {
        return None;
    }
    let value = row
        .pointer("/def/value_after")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    (value <= 0xff).then(|| {
        serde_json::json!({
            "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
            "value": format!("{value:#x}"),
            "byte_hex": format!("{:02x}", value as u8),
            "ascii": printable_ascii_char(value as u8),
            "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        })
    })
}

pub(super) fn memory_access_summary(row: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn row_alu_formula(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("alu") {
        return None;
    }
    let asm = row.get("asm").and_then(|v| v.as_str())?;
    let result = row.pointer("/def/value_after").and_then(|v| v.as_str())?;
    let operands = row
        .pointer("/def/src")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let operand_values = operands
        .iter()
        .filter_map(|operand| operand.get("value").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let expression = alu_expression_from_asm(asm, result, &operand_values)?;
    let op = asm
        .split_whitespace()
        .next()
        .map(|mnemonic| mnemonic.to_ascii_lowercase())
        .unwrap_or_default();
    let mut formula = serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": result,
        "op": op,
        "expression": expression,
        "operands": annotate_formula_operands(asm, operands),
    });
    if let Some(semantic) = recognize_alu_semantic(asm, result, &operand_values) {
        if let Some(obj) = formula.as_object_mut() {
            obj.insert("semantic".to_string(), semantic);
        }
    }
    Some(formula)
}

pub(super) async fn upstream_writer_for_def_on(
    app: &axum::Router,
    def_row: &serde_json::Value,
    lookback: usize,
    max_writes: usize,
) -> anyhow::Result<serde_json::Value> {
    let class = def_row.get("class").and_then(|v| v.as_str()).unwrap_or("");
    let idx = def_row.get("idx").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if class == "call-return" {
        return Ok(serde_json::json!({
            "status": "call_return_boundary",
            "reason": "register value came from a call return; inspect call_return target and args",
            "call_return": def_row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    if class == "syscall-return" {
        return Ok(serde_json::json!({
            "status": "syscall_return_boundary",
            "reason": "register value came from a syscall return; inspect syscall_return number and args",
            "syscall_return": def_row.get("syscall_return").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    if class == "bytecode-read" {
        return Ok(serde_json::json!({
            "status": "bytecode_read_boundary",
            "kind": "bytecode_read",
            "reason": "register value came from VM bytecode; treat the loaded byte/word as an opcode/immediate literal",
            "addr": def_row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "size": memory_access_width(def_row.get("asm").and_then(|v| v.as_str()).unwrap_or("")),
            "value": def_row.pointer("/def/value_after").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    let mut kind = None;
    let mut addr = None;
    let mut size = 1u64;
    if class == "vm-reg-load" {
        kind = Some("vm_slot_last_write");
        addr = def_row
            .get("mem_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str);
        size = 8;
    } else if matches!(class, "mem-load" | "byte-load") {
        kind = Some("memory_last_write");
        addr = def_row
            .get("mem_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str);
        size = memory_access_width(def_row.get("asm").and_then(|v| v.as_str()).unwrap_or(""));
    }
    let Some(kind) = kind else {
        return Ok(serde_json::json!({
            "status": "not_memory_backed",
            "reason": "local def is not a VM slot load or memory load",
        }));
    };
    let Some(addr) = addr else {
        return Ok(serde_json::json!({
            "status": "missing_address",
            "kind": kind,
        }));
    };
    let idx_lo = idx.saturating_sub(lookback);
    let idx_hi = idx;
    let addr_hi = addr.saturating_add(size);
    let params = vec![
        ("idx_lo", idx_lo.to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{addr:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", max_writes.to_string()),
    ];
    let response =
        route_get_json_value_on(app, route_path("/api/mem-writes-in-range", &params)).await?;
    let writes = response
        .get("writes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let range_truncated = response
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(writes.len() >= max_writes);
    let byte_writers = if range_truncated {
        exact_byte_writers_for_load_on(app, addr, size, idx).await?
    } else {
        byte_writers_from_range_writes(addr, size, &writes)
    };
    let observed_bytes = observed_load_bytes(def_row, size);
    let observed_mismatches = observed_bytes
        .as_deref()
        .map(|bytes| observed_byte_writer_mismatches(addr, bytes, &byte_writers))
        .unwrap_or_default();
    let matches_observed = observed_mismatches.is_empty();
    let byte_nexts = if matches_observed {
        dedupe_byte_nexts(&byte_writers)
    } else {
        Vec::new()
    };
    let last_write = if range_truncated {
        byte_writers
            .first()
            .and_then(|writer| writer.get("last_write").cloned())
    } else {
        writes.last().cloned()
    };
    let writes_tail = writes
        .iter()
        .rev()
        .take(16)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let status = if last_write.is_some() && matches_observed {
        "ready"
    } else if last_write.is_some() {
        "observed_read_without_matching_traced_write"
    } else {
        "not_found"
    };
    let gap_call_candidates = if status == "observed_read_without_matching_traced_write" {
        match gap_call_candidates_for_mismatch_on(app, addr, idx, last_write.as_ref()).await {
            Ok(value) => value,
            Err(err) => serde_json::json!({
                "status": "error",
                "error": err.to_string(),
            }),
        }
    } else {
        serde_json::Value::Null
    };
    Ok(serde_json::json!({
        "status": status,
        "kind": kind,
        "addr": format!("{addr:#x}"),
        "addr_hi": format!("{addr_hi:#x}"),
        "idx_lo": idx_lo,
        "idx_hi": idx_hi,
        "returned": writes.len(),
        "maybe_truncated": range_truncated,
        "observed_bytes_hex": observed_bytes.as_ref().map(|bytes| bytes_to_hex(bytes)),
        "last_write_matches_observed": matches_observed,
        "observed_mismatches": observed_mismatches,
        "last_write": last_write,
        "writes_tail": writes_tail,
        "byte_writers": byte_writers,
        "byte_nexts": byte_nexts,
        "gap_call_candidates": gap_call_candidates,
        "next": matches_observed.then(|| last_write.as_ref().and_then(|write| {
            Some(serde_json::json!({
                "idx": write.get("idx")?,
                "reg": write.get("src_reg")?,
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })).flatten(),
    }))
}

pub(super) async fn gap_call_candidates_for_mismatch_on(
    app: &axum::Router,
    addr: u64,
    read_idx: usize,
    last_write: Option<&serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let Some(last_write_idx) = last_write
        .and_then(|write| write.get("idx"))
        .and_then(|v| v.as_u64())
        .map(|idx| idx as usize)
    else {
        return Ok(serde_json::json!({
            "status": "no_last_write",
            "addr": format!("{addr:#x}"),
            "read_idx": read_idx,
            "candidates": [],
        }));
    };
    if last_write_idx >= read_idx {
        return Ok(serde_json::json!({
            "status": "empty_gap",
            "addr": format!("{addr:#x}"),
            "read_idx": read_idx,
            "last_write_idx": last_write_idx,
            "candidates": [],
        }));
    }

    let requested_scan_start = last_write_idx.saturating_add(1);
    let gap_len = read_idx.saturating_sub(requested_scan_start);
    let (scan_start, truncated_by_record_cap) = if gap_len > GAP_SCAN_MAX_RECORDS {
        (read_idx.saturating_sub(GAP_SCAN_MAX_RECORDS), true)
    } else {
        (requested_scan_start, false)
    };
    let meta = route_get_json_value_on(app, "/api/meta".to_string()).await?;
    let primary = primary_module_bounds(&meta);
    let mut candidates = Vec::new();
    let mut gap_records = Vec::new();
    let mut cursor = scan_start;
    let mut fetched = 0usize;

    while cursor < read_idx {
        let count = read_idx.saturating_sub(cursor).min(GAP_SCAN_CHUNK);
        if count == 0 {
            break;
        }
        let params = vec![
            ("start", cursor.to_string()),
            ("count", count.to_string()),
            ("regs", GAP_SCAN_REGS.to_string()),
            ("fields", "idx,pc,func,asm,regs".to_string()),
        ];
        let response = route_get_json_value_on(app, route_path("/api/records", &params)).await?;
        let records = response
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            break;
        }
        fetched = fetched.saturating_add(records.len());
        gap_records.extend(records.iter().cloned());
        for record in &records {
            if let Some(candidate) =
                gap_call_candidate_from_record(record, &meta, primary.as_ref(), addr)
            {
                candidates.push(candidate);
            }
        }
        let last_idx = records
            .last()
            .and_then(|record| record.get("idx"))
            .and_then(|v| v.as_u64())
            .map(|idx| idx as usize);
        cursor = last_idx
            .map(|idx| idx.saturating_add(1))
            .unwrap_or_else(|| cursor.saturating_add(records.len()));
        if records.len() < count {
            break;
        }
    }

    let candidate_count_total = candidates.len();
    for candidate in &mut candidates {
        enrich_gap_call_candidate_trace_writes(candidate, &gap_records, addr);
    }
    candidates.sort_by(|a, b| {
        let ascore = a.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        let bscore = b.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        let aidx = a.get("idx").and_then(|v| v.as_u64()).unwrap_or(0);
        let bidx = b.get("idx").and_then(|v| v.as_u64()).unwrap_or(0);
        bscore.cmp(&ascore).then_with(|| aidx.cmp(&bidx))
    });
    if candidates.len() > GAP_SCAN_MAX_CANDIDATES {
        candidates.truncate(GAP_SCAN_MAX_CANDIDATES);
    }

    Ok(serde_json::json!({
        "status": "ready",
        "addr": format!("{addr:#x}"),
        "read_idx": read_idx,
        "last_write_idx": last_write_idx,
        "scan_idx_lo": scan_start,
        "scan_idx_hi": read_idx,
        "requested_scan_idx_lo": requested_scan_start,
        "fetched_records": fetched,
        "truncated_by_record_cap": truncated_by_record_cap,
        "candidate_count_total": candidate_count_total,
        "candidate_count_returned": candidates.len(),
        "candidates": candidates,
    }))
}

pub(super) fn enrich_gap_call_candidate_trace_writes(
    candidate: &mut serde_json::Value,
    records: &[serde_json::Value],
    addr: u64,
) {
    if candidate
        .get("external_to_primary")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        if let Some(obj) = candidate.as_object_mut() {
            obj.insert(
                "callee_trace".to_string(),
                serde_json::json!({ "status": "external_or_untraced" }),
            );
        }
        return;
    }
    let Some(call_idx) = candidate
        .get("idx")
        .and_then(|v| v.as_u64())
        .map(|idx| idx as usize)
    else {
        return;
    };
    let Some(call_pc) = candidate
        .get("pc")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
    else {
        return;
    };
    let return_pc = call_pc.wrapping_add(4);
    let mut rows = 0usize;
    let mut return_idx = None;
    let mut target_writes = Vec::new();
    for record in records {
        let Some(idx) = record
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|idx| idx as usize)
        else {
            continue;
        };
        if idx <= call_idx {
            continue;
        }
        if record
            .get("pc")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            == Some(return_pc)
        {
            return_idx = Some(idx);
            break;
        }
        rows = rows.saturating_add(1);
        if let Some(write) = store_touch_for_addr(record, addr) {
            target_writes.push(write);
        }
    }
    let status = if !target_writes.is_empty() {
        "traced_callee_target_write"
    } else if return_idx.is_some() {
        "traced_callee_no_target_write"
    } else {
        "traced_callee_return_not_seen"
    };
    let score_adjustment = match status {
        "traced_callee_target_write" => 80,
        "traced_callee_no_target_write" => -50,
        _ => 0,
    };
    if let Some(obj) = candidate.as_object_mut() {
        let score = obj.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        obj.insert(
            "score".to_string(),
            serde_json::Value::from(score.saturating_add(score_adjustment)),
        );
        obj.insert(
            "score_adjustment_trace_write".to_string(),
            serde_json::Value::from(score_adjustment),
        );
        obj.insert(
            "callee_trace".to_string(),
            serde_json::json!({
                "status": status,
                "rows": rows,
                "return_pc": format!("{return_pc:#x}"),
                "return_idx": return_idx,
                "target_writes": target_writes,
            }),
        );
    }
}

pub(super) fn store_touch_for_addr(
    record: &serde_json::Value,
    addr: u64,
) -> Option<serde_json::Value> {
    let asm = record.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let source_regs = store_source_regs_from_asm(asm);
    if source_regs.is_empty() {
        return None;
    }
    let mem_addr = mem_addr_from_asm(asm, record)?;
    let width = store_access_width(asm, &source_regs);
    let end = mem_addr.saturating_add(width);
    if !(mem_addr..end).contains(&addr) {
        return None;
    }
    Some(serde_json::json!({
        "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "mem_addr": format!("{mem_addr:#x}"),
        "width": width,
        "offset": addr.saturating_sub(mem_addr),
    }))
}

pub(super) fn store_access_width(asm: &str, source_regs: &[String]) -> u64 {
    let mnemonic = asm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(mnemonic.as_str(), "stp" | "stnp" | "stxp" | "stlxp") {
        return source_regs
            .iter()
            .map(|reg| register_load_width(reg))
            .sum::<u64>()
            .max(1);
    }
    if mnemonic.ends_with('b') {
        return 1;
    }
    if mnemonic.ends_with('h') {
        return 2;
    }
    source_regs
        .first()
        .map(|reg| register_load_width(reg))
        .unwrap_or_else(|| memory_access_width(asm))
}

pub(super) fn gap_call_candidate_from_record(
    record: &serde_json::Value,
    meta: &serde_json::Value,
    primary: Option<&(u64, u64, String)>,
    addr: u64,
) -> Option<serde_json::Value> {
    let asm = record.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let (call_kind, target_addr) = call_target_from_asm_record(asm, record)?;
    let target_module = module_for_addr(meta, target_addr);
    let external_to_primary = primary
        .map(|(start, end, _)| target_addr < *start || target_addr >= *end)
        .unwrap_or(false);
    let arg_offsets = call_arg_offsets(record, addr);
    let span_matches = call_arg_span_matches(record, addr);
    let near_regs = call_near_regs(record, addr);

    if !external_to_primary
        && arg_offsets.is_empty()
        && span_matches.is_empty()
        && near_regs.is_empty()
    {
        return None;
    }

    let mut score = 0i64;
    if external_to_primary {
        score += 1000;
    }
    score += (span_matches.len() as i64) * 40;
    score += (arg_offsets.len() as i64) * 16;
    score += (near_regs.len() as i64) * 4;
    if target_module
        .get("name")
        .and_then(|v| v.as_str())
        .map(|name| name.contains("libc"))
        .unwrap_or(false)
    {
        score += 6;
    }

    let args = (0..=7)
        .map(|idx| {
            let reg = format!("x{idx}");
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(record, &reg)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();

    Some(serde_json::json!({
        "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": record.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": record.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "call_kind": call_kind,
        "target_addr": format!("{target_addr:#x}"),
        "target_module": target_module,
        "external_to_primary": external_to_primary,
        "arg_offsets": arg_offsets,
        "span_matches": span_matches,
        "near_regs": near_regs,
        "args": args,
        "score": score,
    }))
}

pub(super) fn call_target_from_asm_record(
    asm: &str,
    record: &serde_json::Value,
) -> Option<(String, u64)> {
    let mut parts = asm.split_whitespace();
    let op = parts.next()?;
    match op {
        "bl" => {
            let operand = parts.next()?.trim_start_matches('#').trim_end_matches(',');
            parse_u64_str(operand).map(|target| ("bl".to_string(), target))
        }
        "blr" => {
            let reg = parts.next()?.trim_end_matches(',');
            record_reg_u64(record, reg).map(|target| ("blr".to_string(), target))
        }
        _ => None,
    }
}

pub(super) fn call_arg_offsets(record: &serde_json::Value, addr: u64) -> Vec<serde_json::Value> {
    (0..=7)
        .filter_map(|idx| {
            let reg = format!("x{idx}");
            let value = record_reg_u64(record, &reg)?;
            let offset = addr.checked_sub(value)?;
            (offset <= GAP_ARG_STRUCT_SPAN).then(|| {
                serde_json::json!({
                    "reg": reg,
                    "base": format!("{value:#x}"),
                    "offset": format!("{offset:#x}"),
                    "addr": format!("{addr:#x}"),
                })
            })
        })
        .collect()
}

pub(super) fn call_arg_span_matches(
    record: &serde_json::Value,
    addr: u64,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    const PAIRS: &[(usize, usize)] = &[(0, 1), (0, 2), (1, 2), (1, 3), (2, 3), (3, 2)];
    for (base_idx, len_idx) in PAIRS {
        let base_reg = format!("x{base_idx}");
        let Some(base) = record_reg_u64(record, &base_reg) else {
            continue;
        };
        let len_reg = format!("x{len_idx}");
        let Some(len) = record_reg_u64(record, &len_reg) else {
            continue;
        };
        if len == 0 || len > GAP_SMALL_LEN_MAX {
            continue;
        }
        let end = base.saturating_add(len);
        if addr >= base && addr < end {
            out.push(serde_json::json!({
                "base_reg": base_reg,
                "base": format!("{base:#x}"),
                "len_reg": len_reg,
                "len": format!("{len:#x}"),
                "offset": format!("{:#x}", addr.saturating_sub(base)),
            }));
        }
    }
    out
}

pub(super) fn call_near_regs(record: &serde_json::Value, addr: u64) -> Vec<serde_json::Value> {
    const REGS: &[&str] = &[
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x19", "x20", "x21", "x22", "x23", "x25",
    ];
    REGS.iter()
        .filter_map(|reg| {
            let value = record_reg_u64(record, reg)?;
            let delta = value.abs_diff(addr);
            (delta <= GAP_NEAR_REG_SPAN).then(|| {
                let signed = if value <= addr {
                    format!("+{:#x}", addr - value)
                } else {
                    format!("-{:#x}", value - addr)
                };
                serde_json::json!({
                    "reg": reg,
                    "value": format!("{value:#x}"),
                    "delta_to_addr": signed,
                })
            })
        })
        .collect()
}

pub(super) fn primary_module_bounds(meta: &serde_json::Value) -> Option<(u64, u64, String)> {
    let module = meta.get("module")?;
    module_bounds(module)
}

pub(super) fn module_bounds(module: &serde_json::Value) -> Option<(u64, u64, String)> {
    let base = module.get("base").and_then(json_u64)?;
    let end = module.get("end").and_then(json_u64).or_else(|| {
        module
            .get("size")
            .and_then(json_u64)
            .map(|size| base.saturating_add(size))
    })?;
    let name = module
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((base, end, name))
}

pub(super) fn module_for_addr(meta: &serde_json::Value, addr: u64) -> serde_json::Value {
    let Some(modules) = meta.get("modules").and_then(|v| v.as_array()) else {
        return serde_json::Value::Null;
    };
    for module in modules {
        let Some((base, end, name)) = module_bounds(module) else {
            continue;
        };
        if addr >= base && addr < end {
            return serde_json::json!({
                "name": name,
                "base": format!("{base:#x}"),
                "end": format!("{end:#x}"),
                "offset": format!("{:#x}", addr.saturating_sub(base)),
            });
        }
    }
    serde_json::Value::Null
}

pub(super) fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_str))
}

pub(super) fn observed_load_bytes(def_row: &serde_json::Value, size: u64) -> Option<Vec<u8>> {
    let value = def_row
        .pointer("/def/value_after")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let width = (size as usize).min(8);
    Some(value.to_le_bytes()[..width].to_vec())
}

pub(super) fn observed_byte_writer_mismatches(
    addr: u64,
    observed_bytes: &[u8],
    byte_writers: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    observed_bytes
        .iter()
        .enumerate()
        .filter_map(|(offset, observed)| {
            let writer = byte_writers.iter().find(|writer| {
                writer.get("offset").and_then(|v| v.as_u64()) == Some(offset as u64)
            });
            let writer_byte =
                writer
                    .and_then(|writer| writer.get("last_write"))
                    .and_then(|write| {
                        source_byte_for_write_at(write, addr.saturating_add(offset as u64))
                    });
            (writer_byte != Some(*observed)).then(|| {
                serde_json::json!({
                    "offset": offset,
                    "addr": format!("{:#x}", addr.saturating_add(offset as u64)),
                    "observed_byte": format!("{observed:02x}"),
                    "writer_byte": writer_byte.map(|byte| format!("{byte:02x}")),
                    "writer_idx": writer
                        .and_then(|writer| writer.pointer("/last_write/idx"))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                })
            })
        })
        .collect()
}

pub(super) async fn exact_byte_writers_for_load_on(
    app: &axum::Router,
    addr: u64,
    size: u64,
    before_idx: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for offset in 0..size {
        let byte_addr = addr.saturating_add(offset);
        let params = vec![
            ("addr", format!("{byte_addr:#x}")),
            ("before_idx", before_idx.to_string()),
        ];
        let response =
            route_get_json_value_on(app, route_path("/api/last-write-of-addr", &params)).await?;
        let last_write = if response.get("status").and_then(|v| v.as_str()) == Some("found") {
            Some(serde_json::json!({
                "idx": response.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "pc": response.get("writer_pc").cloned().unwrap_or(serde_json::Value::Null),
                "rel": response.get("rel").cloned().unwrap_or(serde_json::Value::Null),
                "func": response.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": response.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "dst_addr": response
                    .get("dst_addr")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(format!("{byte_addr:#x}"))),
                "size": response
                    .get("size")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(1)),
                "src_reg": response.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": response.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        } else {
            None
        };
        out.push(byte_writer_entry(offset, byte_addr, last_write));
    }
    Ok(out)
}

pub(super) fn byte_writers_from_range_writes(
    addr: u64,
    size: u64,
    writes: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for offset in 0..size {
        let byte_addr = addr.saturating_add(offset);
        let last_write = writes
            .iter()
            .rev()
            .find(|write| mem_write_touches_addr(write, byte_addr))
            .cloned();
        out.push(byte_writer_entry(offset, byte_addr, last_write));
    }
    out
}

pub(super) fn byte_writer_map_output(
    addr: u64,
    size: usize,
    response: &serde_json::Value,
) -> serde_json::Value {
    let writes = response
        .get("writes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bytes = byte_writer_map_entries_from_range_writes(addr, size, &writes);
    let missing_offsets = bytes
        .iter()
        .filter(|entry| entry.get("status").and_then(|v| v.as_str()) != Some("ready"))
        .filter_map(|entry| entry.get("offset").cloned())
        .collect::<Vec<_>>();
    let byte_values = bytes
        .iter()
        .map(|entry| {
            entry
                .get("byte_hex")
                .and_then(|v| v.as_str())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect::<Vec<_>>();
    let bytes_hex = if byte_values.iter().all(Option::is_some) {
        Some(
            byte_values
                .iter()
                .flatten()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    } else {
        None
    };
    let ascii = byte_values
        .iter()
        .map(|byte| {
            byte.and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string())
        })
        .collect::<String>();
    let truncated = response
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    serde_json::json!({
        "status": if missing_offsets.is_empty() && !truncated { "ready" } else { "partial" },
        "addr": format!("{addr:#x}"),
        "size": size,
        "idx_range": response.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": {
            "endpoint": "/api/mem-writes-in-range",
            "matched": response.get("matched").cloned().unwrap_or(serde_json::Value::Null),
            "returned": response.get("returned").cloned().unwrap_or(serde_json::Value::Null),
            "truncated": truncated,
        },
        "complete": missing_offsets.is_empty() && !truncated,
        "bytes_hex": bytes_hex,
        "ascii": ascii,
        "missing_offsets": missing_offsets,
        "writer_runs": byte_writer_runs(&bytes),
        "bytes": bytes,
        "warning": if truncated {
            serde_json::Value::String(
                "source writes were truncated; increase --max or narrow --idx-lo/--idx-hi before trusting latest writers".to_string(),
            )
        } else {
            serde_json::Value::Null
        },
    })
}

pub(super) fn byte_writer_map_summary(output: &serde_json::Value) -> serde_json::Value {
    let bytes = output
        .get("bytes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let ready_count = bytes
        .iter()
        .filter(|entry| entry.get("status").and_then(|v| v.as_str()) == Some("ready"))
        .count();
    let writer_runs = output
        .get("writer_runs")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_byte_writer_run)
        .collect::<Vec<_>>();
    let vm_chains = output
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_byte_writer_chain)
        .collect::<Vec<_>>();
    let vm_source_ranges = byte_writer_vm_source_ranges(&vm_chains);
    serde_json::json!({
        "status": output.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "addr": output.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": output.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "idx_range": output.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": output.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "complete": output.get("complete").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": output.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": output.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "byte_count": bytes.len(),
        "ready_byte_count": ready_count,
        "missing_offsets": output.get("missing_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer_run_count": writer_runs.len(),
        "writer_runs": writer_runs,
        "vm_chain_summary": output.get("vm_chain_summary").cloned().unwrap_or(serde_json::Value::Null),
        "vm_source_ranges": vm_source_ranges,
        "vm_chains": vm_chains,
        "warning": output.get("warning").cloned().unwrap_or(serde_json::Value::Null),
    })
}
