use super::*;

#[allow(clippy::too_many_arguments)]
pub fn vm_slice(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let (rows, source_returned, inferred_base) =
        load_vm_rows(trace_dir, start, end, regs, only_vm, base_ip, &profile)?;

    Ok(serde_json::to_value(VmSliceReport {
        status: "ready",
        start,
        end,
        vm_profile: profile.to_json(),
        returned: rows.len(),
        source_returned,
        only_vm,
        vm_base_ip: inferred_base.map(|v| format!("{v:#x}")),
        records: rows,
    })?)
}

#[allow(clippy::too_many_arguments)]
pub fn vm_ops(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    base_ip: Option<String>,
    max_ops: usize,
    chunk_size: usize,
    summary: bool,
    effects_only: bool,
    compact: bool,
    replay_plan: bool,
    profile: VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let loaded = load_vm_rows_chunked(
        trace_dir, start, end, regs, true, base_ip, &profile, chunk_size,
    )?;
    let source_requested = end.saturating_sub(start);
    let all_ops = vm_ops_from_rows(&loaded.rows);
    let truncated = all_ops.len() > max_ops;
    let ops = all_ops.into_iter().take(max_ops).collect::<Vec<_>>();
    let vm_state_base = vm_state_base_from_rows(&loaded.rows, &profile);
    let output = serde_json::to_value(VmOpsReport {
        status: "ready",
        start,
        end,
        vm_profile: profile.to_json(),
        source_requested,
        source_returned: loaded.source_returned,
        source_maybe_truncated: loaded.source_maybe_truncated,
        source_chunks: loaded.chunks,
        chunk_size,
        vm_rows: loaded.rows.len(),
        vm_base_ip: loaded.inferred_base.map(|v| format!("{v:#x}")),
        vm_state_base: vm_state_base.map(|v| format!("{v:#x}")),
        ops_returned: ops.len(),
        truncated,
        ops,
    })?;
    if replay_plan {
        Ok(vm_ops_replay_plan_summary(&output))
    } else if compact {
        Ok(vm_ops_compact_replay_summary(&output))
    } else if effects_only {
        Ok(vm_ops_effects_only_summary(&output))
    } else if summary {
        Ok(vm_ops_output_summary(&output))
    } else {
        Ok(output)
    }
}

pub(super) fn vm_profile_infra_regs(value: &serde_json::Value) -> HashSet<String> {
    value
        .get("vm_profile")
        .and_then(|v| v.get("infra_regs"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .map(register_value_key)
        .collect()
}

pub(super) fn vm_profile_ip_reg(value: &serde_json::Value) -> Option<String> {
    value
        .get("vm_profile")
        .and_then(|v| v.get("ip_reg"))
        .and_then(|v| v.as_str())
        .map(register_value_key)
        .filter(|reg| !reg.is_empty())
}

pub(super) fn vm_ops_output_summary(value: &serde_json::Value) -> serde_json::Value {
    let infra_regs = vm_profile_infra_regs(value);
    let ip_reg = vm_profile_ip_reg(value);
    let ops = value
        .get("ops")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|op| vm_op_summary(op, &infra_regs, ip_reg.as_deref()))
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": value.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": value.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": value.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": value.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": value.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": value.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "source_chunks": value.get("source_chunks").cloned().unwrap_or(serde_json::Value::Null),
        "chunk_size": value.get("chunk_size").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": value.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_base_ip": value.get("vm_base_ip").cloned().unwrap_or(serde_json::Value::Null),
        "vm_state_base": value.get("vm_state_base").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": value.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_counts": vm_ops_semantic_counts(&ops),
        "state_updates": vm_ops_state_updates(&ops),
        "ops": ops,
    })
}

pub(super) fn vm_ops_effects_only_summary(value: &serde_json::Value) -> serde_json::Value {
    let infra_regs = vm_profile_infra_regs(value);
    let ip_reg = vm_profile_ip_reg(value);
    let ops = value
        .get("ops")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|op| vm_op_summary(op, &infra_regs, ip_reg.as_deref()))
        .collect::<Vec<_>>();
    let mut effects = Vec::new();
    let mut byte_load_effects = Vec::new();
    let mut memory_store_effects = Vec::new();
    let mut control_effects = Vec::new();
    let mut bytecode_reads = Vec::new();
    let mut op_effects = Vec::new();
    for op in &ops {
        let idx_start = op
            .get("idx_start")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let idx_end = op
            .get("idx_end")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let mut op_bytecode_reads = Vec::new();
        let mut op_effect_list = Vec::new();
        for read in op
            .get("bytecode_reads")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let mut compact = read.clone();
            if let Some(obj) = compact.as_object_mut() {
                obj.insert("op_idx_start".to_string(), idx_start.clone());
                obj.insert("op_idx_end".to_string(), idx_end.clone());
            }
            op_bytecode_reads.push(compact.clone());
            bytecode_reads.push(compact);
        }
        for effect in op
            .get("effects")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let mut compact = effect.clone();
            if let Some(obj) = compact.as_object_mut() {
                obj.insert("op_idx_start".to_string(), idx_start.clone());
                obj.insert("op_idx_end".to_string(), idx_end.clone());
            }
            if compact
                .get("source_byte_load")
                .map(|v| !v.is_null())
                .unwrap_or(false)
            {
                byte_load_effects.push(compact.clone());
            }
            if compact.get("kind").and_then(|v| v.as_str()) == Some("memory_store") {
                memory_store_effects.push(compact.clone());
            }
            if compact.get("kind").and_then(|v| v.as_str()) == Some("control") {
                control_effects.push(compact.clone());
            }
            op_effect_list.push(compact.clone());
            effects.push(compact);
        }
        if !op_bytecode_reads.is_empty() || !op_effect_list.is_empty() {
            op_effects.push(serde_json::json!({
                "idx_start": idx_start,
                "idx_end": idx_end,
                "dispatches": op.get("dispatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                "bytecode_reads": op_bytecode_reads,
                "effects": op_effect_list,
            }));
        }
    }
    let op_templates = vm_op_templates(&op_effects);
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": value.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": value.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": value.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": value.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": value.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": value.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "source_chunks": value.get("source_chunks").cloned().unwrap_or(serde_json::Value::Null),
        "chunk_size": value.get("chunk_size").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": value.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_base_ip": value.get("vm_base_ip").cloned().unwrap_or(serde_json::Value::Null),
        "vm_state_base": value.get("vm_state_base").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": value.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "effect_count": effects.len(),
        "byte_load_effect_count": byte_load_effects.len(),
        "memory_store_effect_count": memory_store_effects.len(),
        "control_effect_count": control_effects.len(),
        "bytecode_read_count": bytecode_reads.len(),
        "op_template_count": op_templates.len(),
        "semantic_counts": vm_ops_semantic_counts(&ops),
        "state_updates": vm_ops_state_updates(&ops),
        "byte_load_effects": byte_load_effects,
        "memory_store_effects": memory_store_effects,
        "control_effects": control_effects,
        "bytecode_reads": bytecode_reads,
        "op_effects": op_effects,
        "op_templates": op_templates,
        "effects": effects,
    })
}

pub(super) fn vm_ops_compact_replay_summary(value: &serde_json::Value) -> serde_json::Value {
    let summary = vm_ops_effects_only_summary(value);
    let compact_templates = summary
        .get("op_templates")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_compact_template)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": summary.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": summary.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": summary.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": summary.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": summary.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": summary.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": summary.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "source_chunks": summary.get("source_chunks").cloned().unwrap_or(serde_json::Value::Null),
        "chunk_size": summary.get("chunk_size").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": summary.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_base_ip": summary.get("vm_base_ip").cloned().unwrap_or(serde_json::Value::Null),
        "vm_state_base": summary.get("vm_state_base").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": summary.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": summary.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "effect_count": summary.get("effect_count").cloned().unwrap_or(serde_json::Value::Null),
        "byte_load_effect_count": summary.get("byte_load_effect_count").cloned().unwrap_or(serde_json::Value::Null),
        "memory_store_effect_count": summary.get("memory_store_effect_count").cloned().unwrap_or(serde_json::Value::Null),
        "control_effect_count": summary.get("control_effect_count").cloned().unwrap_or(serde_json::Value::Null),
        "bytecode_read_count": summary.get("bytecode_read_count").cloned().unwrap_or(serde_json::Value::Null),
        "op_template_count": summary.get("op_template_count").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_counts": summary.get("semantic_counts").cloned().unwrap_or(serde_json::Value::Null),
        "state_updates": summary.get("state_updates").cloned().unwrap_or(serde_json::Value::Null),
        "compact_template_count": compact_templates.len(),
        "compact_templates": compact_templates,
    })
}

pub(super) fn vm_op_compact_template(template: &serde_json::Value) -> serde_json::Value {
    let skeletons = template
        .get("template_skeletons")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|skeleton| {
            serde_json::json!({
                "python": skeleton.get("python").cloned().unwrap_or(serde_json::Value::Null),
                "python_with_roles": skeleton.get("python_with_roles").cloned().unwrap_or(serde_json::Value::Null),
                "role_binding": skeleton.get("role_binding").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let effect_shapes = template
        .get("effect_shapes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|shape| {
            let samples = shape
                .get("pseudocode_samples")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::json!({
                "signature": shape.get("signature").cloned().unwrap_or(serde_json::Value::Null),
                "kind": shape.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                "formula_op": shape.get("formula_op").cloned().unwrap_or(serde_json::Value::Null),
                "count": shape.get("count").cloned().unwrap_or(serde_json::Value::Null),
                "samples": samples,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "signature": template.get("signature").cloned().unwrap_or(serde_json::Value::Null),
        "count": template.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "effect_kind_counts": template.get("effect_kind_counts").cloned().unwrap_or(serde_json::Value::Null),
        "template_operands": template.get("template_operands").cloned().unwrap_or(serde_json::Value::Null),
        "skeletons": skeletons,
        "effect_shapes": effect_shapes,
    })
}

pub(super) fn vm_ops_replay_plan_summary(value: &serde_json::Value) -> serde_json::Value {
    let summary = vm_ops_effects_only_summary(value);
    let compact = vm_ops_compact_replay_summary(value);
    let replay_steps = summary
        .get("op_effects")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_replay_step)
        .filter(|step| {
            step.get("effects")
                .and_then(|v| v.as_array())
                .map(|effects| !effects.is_empty())
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": summary.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": summary.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": summary.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": summary.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": summary.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": summary.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": summary.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": summary.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_state_base": summary.get("vm_state_base").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": summary.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": summary.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "effect_count": summary.get("effect_count").cloned().unwrap_or(serde_json::Value::Null),
        "op_template_count": summary.get("op_template_count").cloned().unwrap_or(serde_json::Value::Null),
        "compact_templates": compact.get("compact_templates").cloned().unwrap_or_else(|| serde_json::json!([])),
        "replay_step_count": replay_steps.len(),
        "replay_steps": replay_steps,
    })
}

pub(super) fn vm_op_replay_step(op: &serde_json::Value) -> serde_json::Value {
    let bytecode_reads = op
        .get("bytecode_reads")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|read| {
            serde_json::json!({
                "name": read.get("name").cloned().unwrap_or(serde_json::Value::Null),
                "offset": read.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "width": read.get("width").cloned().unwrap_or(serde_json::Value::Null),
                "value": read.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "bytes_le_hex": read.get("bytes_le_hex").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let effects = op
        .get("effects")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_replay_effect)
        .collect::<Vec<_>>();
    serde_json::json!({
        "idx_start": op.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
        "idx_end": op.get("idx_end").cloned().unwrap_or(serde_json::Value::Null),
        "bytecode_reads": bytecode_reads,
        "effects": effects,
    })
}

pub(super) fn vm_op_replay_effect(effect: &serde_json::Value) -> serde_json::Value {
    let formula = effect.get("formula").unwrap_or(&serde_json::Value::Null);
    let source_byte_load = effect
        .get("source_byte_load")
        .unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "idx": effect.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "kind": effect.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        "class": effect.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "slot": effect.get("slot").cloned().unwrap_or(serde_json::Value::Null),
        "addr": effect.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "value": effect.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "src": effect.get("src").cloned().unwrap_or(serde_json::Value::Null),
        "source_slot": effect.get("source_slot").cloned().unwrap_or(serde_json::Value::Null),
        "store_width": vm_op_replay_store_width(effect),
        "pseudocode": effect.get("pseudocode").cloned().unwrap_or(serde_json::Value::Null),
        "python_with_values": effect.get("python_with_values").cloned().unwrap_or(serde_json::Value::Null),
        "formula": if formula.is_null() {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "op": formula.get("op").cloned().unwrap_or(serde_json::Value::Null),
                "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "semantic_kind": formula
                    .get("semantic")
                    .and_then(|v| v.get("kind"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            })
        },
        "source_byte_load": if source_byte_load.is_null() {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "mem_addr": source_byte_load.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
                "value": source_byte_load.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "byte_hex": source_byte_load.get("byte_hex").cloned().unwrap_or(serde_json::Value::Null),
                "ascii": source_byte_load.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
            })
        },
    })
}

pub(super) fn vm_op_replay_store_width(effect: &serde_json::Value) -> serde_json::Value {
    if effect.get("kind").and_then(|v| v.as_str()) != Some("memory_store") {
        return serde_json::Value::Null;
    }
    if effect.get("class").and_then(|v| v.as_str()) == Some("byte-store") {
        return serde_json::json!(1);
    }
    let reg = effect
        .get("src")
        .and_then(|v| v.get("reg"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let width = if reg.starts_with('w') {
        Some(4)
    } else if reg.starts_with('x') {
        Some(8)
    } else if reg.starts_with('b') {
        Some(1)
    } else if reg.starts_with('h') {
        Some(2)
    } else {
        None
    };
    width
        .map(|value| serde_json::json!(value))
        .unwrap_or(serde_json::Value::Null)
}
