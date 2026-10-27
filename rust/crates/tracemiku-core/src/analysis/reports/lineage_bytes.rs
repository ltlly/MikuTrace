use super::*;

pub(super) enum LineageSeed {
    AddrBefore {
        addr: u64,
        before_idx: usize,
    },
    RegAt {
        idx: usize,
        reg: String,
        byte_lane: Option<usize>,
    },
}

impl LineageSeed {
    pub(super) fn to_json(&self) -> serde_json::Value {
        match self {
            Self::AddrBefore { addr, before_idx } => serde_json::json!({
                "kind": "addr_before",
                "addr": format!("{addr:#x}"),
                "before_idx": before_idx,
            }),
            Self::RegAt {
                idx,
                reg,
                byte_lane,
            } => serde_json::json!({
                "kind": "reg_at",
                "idx": idx,
                "reg": reg,
                "byte_lane": byte_lane,
            }),
        }
    }
}

/// Derive the structured byte origin from a byte-lineage steps chain.
/// Reads only the existing step JSON (write_kind / src_reg / dst_addr /
/// writer_idx); never changes the analysis logic.
///
/// - external write (kind "x") wins over everything else;
/// - ordinary write (kind "w") with a source register is a register-origin
///   byte, without one it is a constant write (e.g. str xzr);
/// - a chain that only reaches a register backstep is a register-origin byte;
/// - anything else (no writer, depth limit, error) is Unknown.
pub(super) fn derive_byte_origin(
    steps: &[serde_json::Value],
    stop_reason: &serde_json::Value,
) -> ByteOrigin {
    for step in steps {
        if step.get("kind").and_then(|v| v.as_str()) != Some("last_write") {
            continue;
        }
        let write = step.get("write");
        let addr = write
            .and_then(|w| w.get("dst_addr"))
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .or_else(|| write.and_then(|w| w.get("addr")).and_then(|v| v.as_u64()));
        let idx = write
            .and_then(|w| w.get("writer_idx"))
            .and_then(|v| v.as_u64())
            .map(|i| i as usize);
        match write
            .and_then(|w| w.get("write_kind"))
            .and_then(|v| v.as_str())
        {
            Some("x") => {
                if step.get("memcpy_from").filter(|v| !v.is_null()).is_some()
                    || write
                        .and_then(|w| w.get("copy_from"))
                        .filter(|v| !v.is_null())
                        .is_some()
                {
                    continue;
                }
                return ByteOrigin::ExternalWrite {
                    addr: addr.unwrap_or(0),
                    idx,
                };
            }
            Some("w") => {
                return match write
                    .and_then(|w| w.get("src_reg"))
                    .and_then(|v| v.as_str())
                {
                    Some(reg) => ByteOrigin::Register {
                        reg: reg.to_string(),
                        idx,
                    },
                    None => ByteOrigin::Constant {
                        value: write
                            .and_then(|w| w.get("src_value"))
                            .and_then(|v| v.as_str())
                            .and_then(parse_u64_str)
                            .map(|v| v as i64)
                            .unwrap_or(0),
                    },
                };
            }
            _ => {}
        }
    }
    // No last_write step: a chain that terminates at a register backstep is
    // still a register-origin byte.
    for step in steps.iter().rev() {
        if step.get("kind").and_then(|v| v.as_str()) == Some("reg_source") {
            if let Some(reg) = step
                .get("backstep")
                .and_then(|b| b.get("source_reg"))
                .and_then(|v| v.as_str())
            {
                return ByteOrigin::Register {
                    reg: reg.to_string(),
                    idx: None,
                };
            }
        }
    }
    let _ = stop_reason;
    ByteOrigin::Unknown
}

/// Extract steps + stop_reason from a single-byte lineage value and derive
/// its origin (used by the count>1 batch path where the full value is
/// available before compact/summary conversion).
pub(super) fn derive_byte_origin_from_value(value: &serde_json::Value) -> ByteOrigin {
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let stop_reason = value
        .get("stop_reason")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    derive_byte_origin(&steps, &stop_reason)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn byte_lineage_value_on(
    analysis: &AnalysisContext,
    addr: u64,
    before_idx: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut seed = LineageSeed::AddrBefore { addr, before_idx };
    let mut steps = Vec::new();
    let mut seen = HashSet::new();
    let mut stop_reason = serde_json::json!({"kind": "depth_limit"});
    let mut logical_depth = 0usize;
    let mut raw_steps = 0usize;
    let max_raw_steps = depth.saturating_mul(8).max(depth);
    while logical_depth < depth && raw_steps < max_raw_steps {
        let step_idx = raw_steps;
        let seed_json = seed.to_json();
        let key = seed_json.to_string();
        if !seen.insert(key) {
            stop_reason = serde_json::json!({
                "kind": "cycle",
                "seed": seed_json,
            });
            break;
        }
        match seed {
            LineageSeed::AddrBefore { addr, before_idx } => {
                let write = last_write_of_addr_on(analysis, addr, before_idx)?;
                let source_byte_offset = source_byte_offset_for_write_at(&write, addr);
                let writer_idx = write
                    .get("writer_idx")
                    .and_then(|v| v.as_u64())
                    .map(|idx| idx as usize);
                let memshadow = analysis.inner.memshadow()?;
                let memcpy_src_addr = writer_idx
                    .and_then(|idx| memshadow.copy_source_at(addr, idx))
                    .or_else(|| {
                        write
                            .get("copy_from")
                            .and_then(|v| v.as_str())
                            .and_then(parse_u64_str)
                    });
                let next_seed = if let (Some(idx), Some(src_addr)) = (writer_idx, memcpy_src_addr) {
                    Some(LineageSeed::AddrBefore {
                        addr: src_addr,
                        before_idx: idx,
                    })
                } else {
                    writer_idx
                        .zip(write.get("src_reg").and_then(|v| v.as_str()))
                        .filter(|(_, reg)| is_gp_register_token(reg))
                        .map(|(idx, reg)| LineageSeed::RegAt {
                            idx,
                            reg: reg.to_string(),
                            byte_lane: source_byte_offset.map(|lane| lane as usize),
                        })
                };
                let state_base = (!profile.state_reg.is_empty())
                    .then(|| {
                        writer_idx
                            .map(|idx| analysis.inner.trace.record(idx))
                            .and_then(|rec| rec.reg_by_name(&profile.state_reg))
                    })
                    .flatten();
                let vm_slot_offset = profile
                    .matches_regfile_addr(addr, state_base)
                    .map(|off| format!("{off:#x}"));
                let is_vm_reg_slot = vm_slot_offset.is_some();
                let unlogged_write_gap = write
                    .get("unlogged_write_gap")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                let mut step_obj = serde_json::json!({
                    "step": step_idx,
                    "logical_depth": logical_depth,
                    "seed": seed_json,
                    "kind": "last_write",
                    "source_byte_offset": source_byte_offset,
                    "write": write,
                    "next": next_json,
                });
                if let Some(src_addr) = memcpy_src_addr {
                    if let Some(obj) = step_obj.as_object_mut() {
                        let formatted = format!("{src_addr:#x}");
                        obj.insert(
                            "memcpy_from".to_string(),
                            serde_json::json!(formatted.clone()),
                        );
                        obj.insert("copy_from".to_string(), serde_json::json!(formatted));
                    }
                }
                if !unlogged_write_gap.is_null() {
                    if let Some(obj) = step_obj.as_object_mut() {
                        obj.insert("unlogged_write_gap".to_string(), unlogged_write_gap);
                    }
                }
                if is_vm_reg_slot {
                    if let Some(obj) = step_obj.as_object_mut() {
                        obj.insert("is_vm_reg_slot".to_string(), serde_json::json!(true));
                        obj.insert(
                            "vm_slot_offset".to_string(),
                            serde_json::json!(vm_slot_offset),
                        );
                    }
                }
                steps.push(step_obj);
                raw_steps += 1;
                if !is_vm_reg_slot && memcpy_src_addr.is_none() {
                    logical_depth += 1;
                }
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "no_writer_source",
                    });
                    break;
                }
            }
            LineageSeed::RegAt {
                idx,
                ref reg,
                byte_lane,
            } => {
                let backstep = vm_backstep_value_on(
                    analysis,
                    idx,
                    Some(reg.clone()),
                    context,
                    lookback,
                    max_writes,
                    regs.clone(),
                    profile,
                )?;
                let (next_seed, decision) =
                    lineage_next_from_backstep(&backstep, byte_lane, profile);
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                let local_def = backstep.get("local_def");
                let vm_slot_offset = local_def
                    .and_then(|ld| ld.pointer("/vm_slot/offset"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        let mem_addr = local_def
                            .and_then(|ld| ld.get("mem_addr"))
                            .and_then(|v| v.as_str())
                            .and_then(parse_u64_str)?;
                        let state_base = (!profile.state_reg.is_empty())
                            .then(|| {
                                local_def
                                    .and_then(|ld| record_reg_u64(ld, &profile.state_reg))
                                    .or_else(|| {
                                        backstep
                                            .get("target")
                                            .and_then(|t| record_reg_u64(t, &profile.state_reg))
                                    })
                            })
                            .flatten();
                        profile
                            .matches_regfile_addr(mem_addr, state_base)
                            .map(|off| format!("{off:#x}"))
                    });
                let is_vm_reg_slot = local_def
                    .and_then(|ld| ld.get("class"))
                    .and_then(|v| v.as_str())
                    == Some("vm-reg-load")
                    || vm_slot_offset.is_some();
                let mut step_obj = serde_json::json!({
                    "step": step_idx,
                    "logical_depth": logical_depth,
                    "seed": seed_json,
                    "byte_lane": byte_lane,
                    "kind": "reg_source",
                    "backstep": compact_lineage_backstep(&backstep),
                    "decision": decision,
                    "next": next_json,
                });
                if is_vm_reg_slot {
                    if let Some(obj) = step_obj.as_object_mut() {
                        obj.insert("is_vm_reg_slot".to_string(), serde_json::json!(true));
                        obj.insert(
                            "vm_slot_offset".to_string(),
                            serde_json::json!(vm_slot_offset),
                        );
                    }
                }
                steps.push(step_obj);
                raw_steps += 1;
                if !is_vm_reg_slot {
                    logical_depth += 1;
                }
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "terminal",
                        "decision": decision,
                    });
                    break;
                }
            }
        }
    }
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "addr": format!("{addr:#x}"),
            "before_idx": before_idx,
        },
        "depth_requested": depth,
        "logical_depth_reached": logical_depth,
        "steps_returned": steps.len(),
        "stop_reason": stop_reason,
        "origin": derive_byte_origin(&steps, &stop_reason),
        "steps": steps,
    }))
}

pub(super) fn last_write_of_addr_on(
    analysis: &AnalysisContext,
    addr: u64,
    before_idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = crate::analysis::memory_query::LastWriteOfAddrQuery {
        addr: format!("{addr:#x}"),
        before_idx: isize::try_from(before_idx)?,
        with_external: true,
        size: None,
    };
    query_value_on(analysis, Query::LastWriteOfAddr(params))
}

pub(super) fn lineage_next_from_backstep(
    backstep: &serde_json::Value,
    current_byte_lane: Option<usize>,
    profile: &VmProfile,
) -> (Option<LineageSeed>, serde_json::Value) {
    if let Some(lane) = current_byte_lane {
        if let Some(next) = choose_laned_upstream_next(backstep, lane) {
            return (
                lineage_seed_from_next(&next, Some(lane)),
                serde_json::json!({
                    "kind": "upstream_byte_lane",
                    "byte_lane": lane,
                    "next": next,
                }),
            );
        }
    }
    let upstream_next = backstep
        .get("upstream")
        .and_then(|v| v.get("next"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(seed) = lineage_seed_from_next(&upstream_next, current_byte_lane) {
        return (
            Some(seed),
            serde_json::json!({
                "kind": "upstream_next",
                "next": upstream_next,
            }),
        );
    }
    let byte_nexts = backstep
        .get("upstream")
        .and_then(|v| v.get("byte_nexts"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if byte_nexts.len() == 1 {
        let next = byte_nexts[0].clone();
        if let Some(seed) = lineage_seed_from_next(&next, current_byte_lane) {
            return (
                Some(seed),
                serde_json::json!({
                    "kind": "single_byte_next",
                    "next": next,
                }),
            );
        }
    }
    if byte_nexts.len() > 1 {
        return (
            None,
            serde_json::json!({
                "kind": "branch_required",
                "reason": "multiple byte upstream candidates",
                "byte_nexts": byte_nexts,
            }),
        );
    }
    let upstream_status = backstep
        .pointer("/upstream/status")
        .and_then(|v| v.as_str());
    if upstream_status == Some("not_found") {
        return (
            None,
            serde_json::json!({
                "kind": "memory_not_found_boundary",
                "upstream_status": "not_found",
                "upstream": {
                    "addr": backstep.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "addr_hi": backstep.pointer("/upstream/addr_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_lo": backstep.pointer("/upstream/idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_hi": backstep.pointer("/upstream/idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": backstep.pointer("/upstream/observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "returned": backstep.pointer("/upstream/returned").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": backstep.pointer("/upstream/maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                    "unlogged_write_gap": backstep.pointer("/upstream/unlogged_write_gap").cloned().unwrap_or(serde_json::Value::Null),
                },
            }),
        );
    }
    if upstream_status == Some("observed_read_without_matching_traced_write") {
        return (
            None,
            serde_json::json!({
                "kind": "observed_read_without_matching_traced_write",
                "upstream": {
                    "addr": backstep.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "addr_hi": backstep.pointer("/upstream/addr_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": backstep.pointer("/upstream/observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_mismatches": backstep.pointer("/upstream/observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "last_write": backstep.pointer("/upstream/last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "gap_call_candidates": compact_gap_call_candidates(backstep.pointer("/upstream/gap_call_candidates")),
                    "unlogged_write_gap": backstep.pointer("/upstream/unlogged_write_gap").cloned().unwrap_or(serde_json::Value::Null),
                },
            }),
        );
    }
    if let Some(frontier_next) = choose_frontier_next_for_lane(backstep, current_byte_lane, profile)
    {
        return (
            lineage_seed_from_next(&frontier_next, current_byte_lane),
            serde_json::json!({
                "kind": "frontier_auto",
                "next": frontier_next,
            }),
        );
    }
    (
        None,
        serde_json::json!({
            "kind": "stop",
            "upstream_status": backstep.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
            "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
        }),
    )
}

pub(super) fn lineage_seed_from_next(
    next: &serde_json::Value,
    fallback_byte_lane: Option<usize>,
) -> Option<LineageSeed> {
    let idx = next.get("idx")?.as_u64()? as usize;
    if let Some(reg) = next.get("reg").and_then(|v| v.as_str()) {
        let byte_lane = next
            .get("source_byte_offset")
            .and_then(|v| v.as_u64())
            .map(|lane| lane as usize)
            .or(fallback_byte_lane);
        return Some(LineageSeed::RegAt {
            idx,
            reg: reg.to_string(),
            byte_lane,
        });
    }
    let copy_from = next.get("copy_from")?.as_str()?;
    let src_addr = parse_u64_str(copy_from)?;
    Some(LineageSeed::AddrBefore {
        addr: src_addr,
        before_idx: idx,
    })
}

pub(super) fn compact_lineage_backstep(backstep: &serde_json::Value) -> serde_json::Value {
    let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "status": backstep.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "source_reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
        "source_value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
        "target": compact_vm_row(backstep.get("target")),
        "local_def": compact_vm_row(backstep.get("local_def")),
        "upstream": {
            "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "addr_hi": upstream.get("addr_hi").cloned().unwrap_or(serde_json::Value::Null),
            "idx_lo": upstream.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
            "idx_hi": upstream.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
            "returned": upstream.get("returned").cloned().unwrap_or(serde_json::Value::Null),
            "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
            "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
            "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
            "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
            "byte_nexts": upstream.get("byte_nexts").cloned().unwrap_or_else(|| serde_json::json!([])),
            "gap_call_candidates": compact_gap_call_candidates(upstream.get("gap_call_candidates")),
            "unlogged_write_gap": upstream.get("unlogged_write_gap").cloned().unwrap_or(serde_json::Value::Null),
        },
        "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn byte_lineage_summary(lineage: &serde_json::Value) -> serde_json::Value {
    let chain = lineage
        .get("steps")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_lineage_summary_step)
        .collect::<Vec<_>>();
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
    let memory_boundaries = chain
        .iter()
        .filter_map(|step| {
            if step.get("kind").and_then(|v| v.as_str()) == Some("last_write") {
                let gap = step.get("unlogged_write_gap").filter(|v| !v.is_null())?;
                return Some(serde_json::json!({
                    "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "idx": step.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                    "reg": step.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
                    "value": step.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                    "kind": "observed_read_without_matching_traced_write",
                    "upstream": {
                        "addr": step.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                        "unlogged_write_gap": gap.clone(),
                    },
                }));
            }
            let decision = step.get("decision")?;
            let kind = decision.get("kind").and_then(|v| v.as_str());
            if !matches!(
                kind,
                Some("observed_read_without_matching_traced_write" | "memory_not_found_boundary")
            ) {
                return None;
            }
            Some(serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "kind": kind,
                "upstream": decision.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": lineage.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": lineage.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": lineage.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "logical_depth_reached": lineage.get("logical_depth_reached").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": lineage.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop_reason": compact_lineage_stop_reason(lineage.get("stop_reason")),
        "recognized_semantics": recognized_semantics,
        "memory_boundaries": memory_boundaries,
        "chain": chain,
    })
}
