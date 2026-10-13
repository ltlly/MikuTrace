use super::*;

pub(super) fn byte_lineage_compact_summary(lineage: &serde_json::Value) -> serde_json::Value {
    let summary = byte_lineage_summary(lineage);
    let chain = summary
        .get("chain")
        .and_then(|v| v.as_array())
        .map(|steps| {
            steps
                .iter()
                .map(compact_lineage_path_step)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let memory_boundaries = summary
        .get("chain")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(compact_lineage_memory_boundary)
        .collect::<Vec<_>>();
    let semantics = summary
        .get("recognized_semantics")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let terminal = summary
        .get("stop_reason")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let repeated_values = compact_lineage_repeated_values(&chain);
    let pointer_transitions = compact_lineage_pointer_transitions(&chain);
    let stable_pointer_loop = compact_lineage_stable_pointer_loop(&terminal, &repeated_values);
    let next_actions = compact_lineage_next_actions(
        &memory_boundaries,
        &terminal,
        &semantics,
        &repeated_values,
        &stable_pointer_loop,
    );
    serde_json::json!({
        "status": summary.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": summary.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": summary.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": summary.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "terminal": terminal,
        "recognized_semantics": semantics,
        "repeated_values": repeated_values,
        "pointer_transitions": pointer_transitions,
        "stable_pointer_loop": stable_pointer_loop,
        "memory_boundaries": memory_boundaries,
        "path": chain,
        "next_actions": next_actions,
    })
}

pub(super) fn compact_lineage_path_step(step: &serde_json::Value) -> serde_json::Value {
    match step.get("kind").and_then(|v| v.as_str()) {
        Some("last_write") => serde_json::json!({
            "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "kind": "last_write",
            "addr": step.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": step.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": step.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "src_reg": step.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
            "src_value": step.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
        }),
        Some("reg_source") => {
            let local_def = step.get("local_def").unwrap_or(&serde_json::Value::Null);
            let upstream = step.get("upstream").unwrap_or(&serde_json::Value::Null);
            let decision_kind = step
                .pointer("/decision/kind")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "reg_source",
                "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "local_def": {
                    "idx": local_def.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": local_def.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "class": local_def.get("class").cloned().unwrap_or(serde_json::Value::Null),
                    "vm_slot": local_def.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
                    "mem_addr": local_def.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
                    "formula": compact_lineage_formula(local_def.get("formula")),
                    "call_return": compact_lineage_call_return(local_def.get("call_return")),
                    "syscall_return": compact_lineage_syscall_return(local_def.get("syscall_return")),
                },
                "upstream": {
                    "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
                    "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "gap_call_count_total": upstream.pointer("/gap_call_candidates/candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
                },
                "decision_kind": decision_kind,
                "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        _ => serde_json::json!({
            "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "kind": step.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        }),
    }
}

pub(super) fn compact_lineage_formula(formula: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(formula) = formula else {
        return serde_json::Value::Null;
    };
    if formula.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "op": formula.get("op").cloned().unwrap_or(serde_json::Value::Null),
        "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_kind": formula.pointer("/semantic/kind").cloned().unwrap_or(serde_json::Value::Null),
        "operands": compact_lineage_formula_operands(formula),
    })
}

pub(super) fn compact_lineage_formula_operands(formula: &serde_json::Value) -> serde_json::Value {
    let op = formula.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let operands = formula
        .get("operands")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    serde_json::Value::Array(
        operands
            .iter()
            .enumerate()
            .map(|(idx, operand)| {
                let value = operand_effective_value_u64(operand);
                let mut item = serde_json::Map::new();
                item.insert("idx".to_string(), serde_json::json!(idx));
                item.insert(
                    "reg".to_string(),
                    operand
                        .get("reg")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
                item.insert(
                    "value".to_string(),
                    operand
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
                if let Some(shift) = operand.get("shift").cloned() {
                    item.insert("shift".to_string(), shift);
                }
                if let Some(amount) = operand.get("shift_amount").cloned() {
                    item.insert("shift_amount".to_string(), amount);
                }
                if let Some(effective) = operand.get("effective_value").cloned() {
                    item.insert("effective_value".to_string(), effective);
                }
                item.insert(
                    "role".to_string(),
                    serde_json::json!(compact_formula_operand_role(op, idx, value, &operands)),
                );
                serde_json::Value::Object(item)
            })
            .collect(),
    )
}

pub(super) fn compact_formula_operand_role(
    op: &str,
    idx: usize,
    value: Option<u64>,
    operands: &[serde_json::Value],
) -> &'static str {
    match op {
        "add" => {
            let other = operands
                .iter()
                .enumerate()
                .find(|(other_idx, _)| *other_idx != idx)
                .and_then(|(_, operand)| operand_effective_value_u64(operand));
            match (value, other) {
                (Some(value), Some(other))
                    if looks_like_pointer(value) && looks_like_delta(other) =>
                {
                    "pointer_base"
                }
                (Some(value), Some(other))
                    if looks_like_delta(value) && looks_like_pointer(other) =>
                {
                    "delta"
                }
                _ => "operand",
            }
        }
        "lsl" | "lsr" | "asr" => {
            if idx == 0 {
                "input"
            } else {
                "shift"
            }
        }
        "ubfx" => match idx {
            0 => "input",
            1 => "lsb",
            2 => "width",
            _ => "operand",
        },
        _ => "operand",
    }
}

pub(super) fn looks_like_pointer(value: u64) -> bool {
    value >= 0x1_0000_0000
}

pub(super) fn looks_like_delta(value: u64) -> bool {
    value <= 0x10_0000 || value >= u64::MAX - 0x10_0000
}

pub(super) fn compact_lineage_call_return(
    call_return: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(call_return) = call_return else {
        return serde_json::Value::Null;
    };
    if call_return.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "call_idx": call_return.get("call_idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": call_return.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "target_reg": call_return.get("target_reg").cloned().unwrap_or(serde_json::Value::Null),
        "target_value": call_return.get("target_value").cloned().unwrap_or(serde_json::Value::Null),
        "return_reg": call_return.get("return_reg").cloned().unwrap_or(serde_json::Value::Null),
        "return_value": call_return.get("return_value").cloned().unwrap_or(serde_json::Value::Null),
        "intervening_rows": call_return.get("intervening_rows").cloned().unwrap_or(serde_json::Value::Null),
        "args": call_return.get("args").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn compact_lineage_syscall_return(
    syscall_return: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(syscall_return) = syscall_return else {
        return serde_json::Value::Null;
    };
    if syscall_return.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "svc_idx": syscall_return.get("svc_idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": syscall_return.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_reg": syscall_return.get("syscall_reg").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_number": syscall_return.get("syscall_number").cloned().unwrap_or(serde_json::Value::Null),
        "return_reg": syscall_return.get("return_reg").cloned().unwrap_or(serde_json::Value::Null),
        "return_value": syscall_return.get("return_value").cloned().unwrap_or(serde_json::Value::Null),
        "intervening_rows": syscall_return.get("intervening_rows").cloned().unwrap_or(serde_json::Value::Null),
        "args": syscall_return.get("args").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn compact_lineage_memory_boundary(
    step: &serde_json::Value,
) -> Option<serde_json::Value> {
    let decision_kind = step.pointer("/decision/kind").and_then(|v| v.as_str())?;
    if !matches!(
        decision_kind,
        "observed_read_without_matching_traced_write" | "memory_not_found_boundary"
    ) {
        return None;
    }
    let upstream = step.get("upstream").unwrap_or(&serde_json::Value::Null);
    let mem_dump_command = compact_lineage_boundary_mem_dump_command(step, upstream);
    Some(serde_json::json!({
        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "kind": decision_kind,
        "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
        "gap_call_count_total": upstream.pointer("/gap_call_candidates/candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
        "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "mem_dump_command": mem_dump_command,
    }))
}

pub(super) fn compact_lineage_boundary_mem_dump_command(
    step: &serde_json::Value,
    upstream: &serde_json::Value,
) -> serde_json::Value {
    let Some(addr) = upstream.get("addr").and_then(|v| v.as_str()) else {
        return serde_json::Value::Null;
    };
    let Some(idx) = step.get("idx").and_then(|v| v.as_u64()) else {
        return serde_json::Value::Null;
    };
    let count = upstream
        .get("observed_bytes_hex")
        .and_then(|v| v.as_str())
        .map(|hex| (hex.len() / 2).max(1))
        .unwrap_or(1);
    serde_json::json!(format!(
        "./tracemiku mem-dump <call_dir> --addr {addr} --count {count} --cursor {idx} --summary"
    ))
}

pub(super) fn compact_lineage_next_actions(
    memory_boundaries: &[serde_json::Value],
    terminal: &serde_json::Value,
    semantics: &serde_json::Value,
    repeated_values: &serde_json::Value,
    stable_pointer_loop: &serde_json::Value,
) -> serde_json::Value {
    let mut actions = Vec::new();
    if !memory_boundaries.is_empty() {
        actions.push(serde_json::json!(
            "inspect boundary addresses with a larger lookback or earlier trace"
        ));
        actions.push(serde_json::json!(
            "check gap_call_candidates for helper calls that mutate the boundary"
        ));
        actions.push(serde_json::json!(
            "parameterize the boundary as an explicit input only after provenance is exhausted"
        ));
    }
    if terminal.get("decision_kind").and_then(|v| v.as_str()) == Some("stop")
        || terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("no_local_def")
    {
        actions.push(serde_json::json!(
            "increase --context/--lookback or switch to a memory seed if the value should be trace-derived"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("call_return_boundary") {
        actions.push(serde_json::json!(
            "inspect the compact call_return target and args, then trace or summarize the callee"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("syscall_return_boundary") {
        actions.push(serde_json::json!(
            "inspect the compact syscall_return number and args, then parameterize the syscall output"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("bytecode_read_boundary") {
        actions.push(serde_json::json!(
            "treat the compact bytecode-read value as a VM opcode/immediate literal or lift the containing opcode template"
        ));
    }
    if semantics.as_array().is_some_and(|rows| !rows.is_empty()) {
        actions.push(serde_json::json!(
            "lift recognized formula semantics into a replay template and replace concrete values with inputs"
        ));
    }
    if matches!(
        terminal.get("kind").and_then(|v| v.as_str()),
        Some("depth_limit" | "cycle")
    ) && repeated_values
        .as_array()
        .is_some_and(|values| !values.is_empty())
    {
        actions.push(serde_json::json!(
            "inspect repeated_values; repeated pointer/state values usually indicate a copy loop or stable VM base"
        ));
    }
    if !stable_pointer_loop.is_null() {
        actions.push(serde_json::json!(
            "treat stable_pointer_loop as a copy/base boundary; prove the repeated pointer once instead of chasing more depth"
        ));
    }
    serde_json::Value::Array(actions)
}

pub(super) fn compact_lineage_stable_pointer_loop(
    terminal: &serde_json::Value,
    repeated_values: &serde_json::Value,
) -> serde_json::Value {
    if !matches!(
        terminal.get("kind").and_then(|v| v.as_str()),
        Some("depth_limit" | "cycle")
    ) {
        return serde_json::Value::Null;
    }
    let Some(row) = repeated_values
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let value = row.get("value").and_then(|v| v.as_str())?;
            let count = row.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let parsed = parse_u64_str(value)?;
            (count >= 8 && looks_like_pointer(parsed)).then_some(row)
        })
        .max_by_key(|row| row.get("count").and_then(|v| v.as_u64()).unwrap_or(0))
    else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "kind": "stable_pointer_loop",
        "value": row.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "count": row.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "first_step": row.get("first_step").cloned().unwrap_or(serde_json::Value::Null),
        "last_step": row.get("last_step").cloned().unwrap_or(serde_json::Value::Null),
        "terminal_kind": terminal.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        "interpretation": "the lineage is walking a stable pointer/base copy chain; prove this pointer once or mark it as an allocation/base parameter",
    })
}

pub(super) fn compact_lineage_repeated_values(chain: &[serde_json::Value]) -> serde_json::Value {
    let mut counts = BTreeMap::<String, (usize, u64, u64)>::new();
    for step in chain {
        let Some(value) = step.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        let step_idx = step.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
        counts
            .entry(value.to_string())
            .and_modify(|entry| {
                entry.0 += 1;
                entry.2 = step_idx;
            })
            .or_insert((1, step_idx, step_idx));
    }
    let mut repeated = counts
        .into_iter()
        .filter(|(_, (count, _, _))| *count > 1)
        .map(|(value, (count, first_step, last_step))| {
            serde_json::json!({
                "value": value,
                "count": count,
                "first_step": first_step,
                "last_step": last_step,
            })
        })
        .collect::<Vec<_>>();
    repeated.sort_by(|a, b| {
        let acount = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bcount = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        bcount.cmp(&acount)
    });
    if repeated.len() > 8 {
        repeated.truncate(8);
    }
    serde_json::Value::Array(repeated)
}

pub(super) fn compact_lineage_pointer_transitions(
    chain: &[serde_json::Value],
) -> serde_json::Value {
    let mut by_expression = BTreeMap::<String, serde_json::Value>::new();
    for step in chain {
        let Some(formula) = step.pointer("/local_def/formula").filter(|v| !v.is_null()) else {
            continue;
        };
        let semantic_kind = formula
            .get("semantic_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pointer_delta = compact_formula_operand_by_role(formula, "pointer_base")
            .zip(compact_formula_operand_by_role(formula, "delta"));
        let semantic_pointer = matches!(semantic_kind, "align_down_mask" | "sub_small_delta")
            && step
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
                .is_some_and(looks_like_pointer);
        if pointer_delta.is_none() && !semantic_pointer {
            continue;
        }
        let expression = formula
            .get("expression")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if expression.is_empty() {
            continue;
        }
        let step_idx = step.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
        let row = by_expression.entry(expression.clone()).or_insert_with(|| {
            let mut item = serde_json::json!({
                "first_step": step_idx,
                "last_step": step_idx,
                "count": 0,
                "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                "op": formula.get("op").cloned().unwrap_or(serde_json::Value::Null),
                "semantic_kind": formula.get("semantic_kind").cloned().unwrap_or(serde_json::Value::Null),
                "result": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "expression": expression,
            });
            if let Some((base, delta)) = pointer_delta {
                if let Some(obj) = item.as_object_mut() {
                    obj.insert(
                        "pointer_base".to_string(),
                        base.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    );
                    obj.insert(
                        "delta".to_string(),
                        delta.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    );
                }
            }
            item
        });
        if let Some(obj) = row.as_object_mut() {
            let count = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
            obj.insert("count".to_string(), serde_json::json!(count));
            obj.insert("last_step".to_string(), serde_json::json!(step_idx));
        }
    }
    let mut rows = by_expression.into_values().collect::<Vec<_>>();
    rows.sort_by_key(|row| row.get("first_step").and_then(|v| v.as_u64()).unwrap_or(0));
    if rows.len() > 16 {
        rows.truncate(16);
    }
    serde_json::Value::Array(rows)
}

pub(super) fn compact_formula_operand_by_role<'a>(
    formula: &'a serde_json::Value,
    role: &str,
) -> Option<&'a serde_json::Value> {
    formula
        .get("operands")?
        .as_array()?
        .iter()
        .find(|operand| operand.get("role").and_then(|v| v.as_str()) == Some(role))
}
