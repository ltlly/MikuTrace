use super::*;

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn cmd_vm_slice(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let (rows, source_returned, inferred_base) =
        load_vm_rows(trace_dir, start, end, regs, only_vm, base_ip, &profile).await?;

    print_pretty(&serde_json::to_value(VmSliceReport {
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

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn cmd_vm_ops(
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
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let loaded = load_vm_rows_chunked(
        trace_dir, start, end, regs, true, base_ip, &profile, chunk_size,
    )
    .await?;
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
        print_pretty(&vm_ops_replay_plan_summary(&output))
    } else if compact {
        print_pretty(&vm_ops_compact_replay_summary(&output))
    } else if effects_only {
        print_pretty(&vm_ops_effects_only_summary(&output))
    } else if summary {
        print_pretty(&vm_ops_output_summary(&output))
    } else {
        print_pretty(&output)
    }
}

fn vm_profile_infra_regs(value: &serde_json::Value) -> HashSet<String> {
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

fn vm_profile_ip_reg(value: &serde_json::Value) -> Option<String> {
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

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateGroup {
    signature: String,
    count: usize,
    bytecode_operands: BTreeMap<String, VmOpTemplateOperand>,
    effect_kind_counts: BTreeMap<String, usize>,
    effect_shapes: BTreeMap<String, VmOpTemplateEffectShape>,
    sample_ops: Vec<serde_json::Value>,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateOperand {
    offset: serde_json::Value,
    width: serde_json::Value,
    values: BTreeMap<String, VmOpTemplateOperandValue>,
    roles: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateOperandValue {
    value: serde_json::Value,
    bytes_le_hex: serde_json::Value,
    count: usize,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateEffectShape {
    signature: String,
    kind: String,
    formula_op: String,
    count: usize,
    output_values: BTreeMap<String, CountedJsonValue>,
    input_slots: BTreeMap<String, CountedJsonValue>,
    pseudocode_samples: Vec<serde_json::Value>,
}

#[derive(Debug, Default)]
pub(super) struct CountedJsonValue {
    value: serde_json::Value,
    count: usize,
}

pub(super) fn vm_op_templates(op_effects: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut groups = BTreeMap::<String, VmOpTemplateGroup>::new();
    for op in op_effects {
        let signature = vm_op_template_signature(op);
        let group = groups
            .entry(signature.clone())
            .or_insert_with(|| VmOpTemplateGroup {
                signature,
                ..VmOpTemplateGroup::default()
            });
        group.count += 1;
        if group.sample_ops.len() < 3 {
            group.sample_ops.push(op.clone());
        }
        for read in op
            .get("bytecode_reads")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let offset = read
                .get("offset")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let width = read
                .get("width")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let (offset_key, width_key) = bytecode_read_sort_key(read);
            let key = format!("{offset_key:016x}:{width_key:016x}");
            let operand =
                group
                    .bytecode_operands
                    .entry(key)
                    .or_insert_with(|| VmOpTemplateOperand {
                        offset,
                        width,
                        ..VmOpTemplateOperand::default()
                    });
            let value = read
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let value_key = json_display(&value);
            let entry =
                operand
                    .values
                    .entry(value_key)
                    .or_insert_with(|| VmOpTemplateOperandValue {
                        value,
                        bytes_le_hex: read
                            .get("bytes_le_hex")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        count: 0,
                    });
            entry.count += 1;
        }
        for effect in op
            .get("effects")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let kind = effect
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            *group
                .effect_kind_counts
                .entry(kind.to_string())
                .or_insert(0) += 1;
            add_vm_op_template_effect_shape(group, effect);
        }
        add_vm_op_template_operand_roles(group, op);
    }
    groups
        .into_values()
        .map(|group| {
            let template_operands = vm_op_template_operand_params(&group.bytecode_operands);
            let template_skeletons =
                vm_op_template_skeletons(&template_operands, &group.effect_shapes);
            let bytecode_operands = group
                .bytecode_operands
                .into_values()
                .map(|operand| {
                    let values = operand
                        .values
                        .into_values()
                        .take(8)
                        .map(|value| {
                            serde_json::json!({
                                "value": value.value,
                                "bytes_le_hex": value.bytes_le_hex,
                                "count": value.count,
                            })
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({
                        "offset": operand.offset,
                        "width": operand.width,
                        "roles": counted_roles_json(&operand.roles),
                        "values": values,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "signature": group.signature,
                "count": group.count,
                "template_operands": template_operands,
                "template_skeletons": template_skeletons,
                "bytecode_operands": bytecode_operands,
                "effect_kind_counts": group.effect_kind_counts
                    .into_iter()
                    .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
                    .collect::<Vec<_>>(),
                "effect_shapes": group.effect_shapes
                    .into_values()
                    .map(VmOpTemplateEffectShape::into_json)
                    .collect::<Vec<_>>(),
                "sample_ops": group.sample_ops,
            })
        })
        .collect()
}

pub(super) fn vm_op_template_operand_params(
    operands: &BTreeMap<String, VmOpTemplateOperand>,
) -> Vec<serde_json::Value> {
    operands
        .values()
        .map(|operand| {
            serde_json::json!({
                "name": bytecode_operand_param_name(&operand.offset, &operand.width),
                "offset": operand.offset.clone(),
                "width": operand.width.clone(),
                "roles": counted_roles_json(&operand.roles),
            })
        })
        .collect()
}

pub(super) fn bytecode_operand_param_name(
    offset: &serde_json::Value,
    width: &serde_json::Value,
) -> String {
    let offset_text = value_as_u64(offset)
        .map(|v| format!("{v:#x}"))
        .unwrap_or_else(|| json_display(offset));
    let width_text = value_as_u64(width)
        .map(|v| match v {
            1 => "u8".to_string(),
            2 => "u16".to_string(),
            4 => "u32".to_string(),
            8 => "u64".to_string(),
            other => format!("u{}bytes", other),
        })
        .unwrap_or_else(|| sanitize_identifier_component(&json_display(width)));
    format!(
        "bc_{}_{}",
        sanitize_identifier_component(&offset_text),
        width_text
    )
}

pub(super) fn sanitize_identifier_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn vm_op_template_skeletons(
    template_operands: &[serde_json::Value],
    effect_shapes: &BTreeMap<String, VmOpTemplateEffectShape>,
) -> Vec<serde_json::Value> {
    let operand_names = template_operands
        .iter()
        .filter_map(|item| item.get("name").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    effect_shapes
        .values()
        .map(|shape| {
            let source = vm_op_effect_source_from_signature(&shape.signature);
            let python = vm_op_template_python_skeleton(
                &shape.kind,
                &source,
                &shape.formula_op,
                &operand_names,
            );
            let (role_binding, python_with_roles) = vm_op_template_role_binding(
                &shape.kind,
                &source,
                &shape.formula_op,
                template_operands,
                &python,
            );
            serde_json::json!({
                "signature": shape.signature.clone(),
                "kind": shape.kind.clone(),
                "source": source,
                "formula_op": shape.formula_op.clone(),
                "count": shape.count,
                "python": python,
                "python_with_roles": python_with_roles,
                "role_binding": role_binding,
                "bytecode_operands": operand_names.clone(),
                "binding": "shape_only",
            })
        })
        .collect()
}

pub(super) fn vm_op_effect_source_from_signature(signature: &str) -> String {
    signature
        .split(':')
        .nth(1)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

pub(super) fn vm_op_template_python_skeleton(
    kind: &str,
    source: &str,
    formula_op: &str,
    operand_names: &[String],
) -> String {
    let args = vm_op_template_args(operand_names, true);
    let operand_args = vm_op_template_args(operand_names, false);
    match (kind, source, formula_op) {
        ("slot_write", "byte_load", _) => "slot[dst] = byte_load(addr_expr)".to_string(),
        ("slot_write", "formula", op) if op != "none" => {
            format!("slot[dst] = {op}({args})")
        }
        ("slot_write", _, _) => "slot[dst] = observed_value".to_string(),
        ("memory_store", "formula", op) if op != "none" => {
            format!("mem[addr] = {op}({args})")
        }
        ("memory_store", _, _) => "mem[addr] = src_value".to_string(),
        ("control", "formula", op) if op != "none" => {
            if operand_args.is_empty() {
                format!("vm_ip = {op}(vm_ip)")
            } else {
                format!("vm_ip = {op}(vm_ip, {operand_args})")
            }
        }
        ("control", _, _) => "vm_ip = next_vm_ip".to_string(),
        _ => {
            if formula_op != "none" {
                format!("effect = {formula_op}({args})")
            } else {
                "effect = observed_value".to_string()
            }
        }
    }
}

pub(super) fn vm_op_template_args(operand_names: &[String], include_slot_srcs: bool) -> String {
    let mut args = Vec::new();
    if include_slot_srcs {
        args.push("slot_srcs".to_string());
    }
    args.extend(operand_names.iter().cloned());
    args.join(", ")
}

pub(super) fn vm_op_template_role_binding(
    kind: &str,
    source: &str,
    formula_op: &str,
    template_operands: &[serde_json::Value],
    fallback_python: &str,
) -> (serde_json::Value, serde_json::Value) {
    let dst_slots = best_template_operands_for_role(template_operands, "dst_slot");
    let src_slots = best_template_operands_for_role(template_operands, "src_slot");
    let control_operands = best_template_operands_for_role(template_operands, "control_operand");
    let mut bound_names = BTreeSet::new();
    bound_names.extend(dst_slots.iter().cloned());
    bound_names.extend(src_slots.iter().cloned());
    bound_names.extend(control_operands.iter().cloned());
    let extra_operands = template_operands
        .iter()
        .filter_map(|operand| operand.get("name").and_then(|v| v.as_str()))
        .filter(|name| !bound_names.contains(*name))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let python = match (kind, source, formula_op) {
        ("slot_write", "formula", op) if op != "none" && !dst_slots.is_empty() => {
            let dst = &dst_slots[0];
            let mut args = if src_slots.is_empty() {
                vec!["slot_srcs".to_string()]
            } else {
                src_slots
                    .iter()
                    .map(|name| format!("slot[{name}]"))
                    .collect::<Vec<_>>()
            };
            args.extend(extra_operands.iter().cloned());
            Some(format!("slot[{dst}] = {op}({})", args.join(", ")))
        }
        ("slot_write", "byte_load", _) if !dst_slots.is_empty() => {
            Some(format!("slot[{}] = byte_load(addr_expr)", dst_slots[0]))
        }
        ("slot_write", _, _) if !dst_slots.is_empty() => {
            Some(format!("slot[{}] = observed_value", dst_slots[0]))
        }
        ("memory_store", "formula", op) if op != "none" => {
            let mut args = if src_slots.is_empty() {
                vec!["src_value".to_string()]
            } else {
                src_slots
                    .iter()
                    .map(|name| format!("slot[{name}]"))
                    .collect::<Vec<_>>()
            };
            args.extend(extra_operands.iter().cloned());
            Some(format!("mem[addr] = {op}({})", args.join(", ")))
        }
        ("memory_store", _, _) if !src_slots.is_empty() => {
            Some(format!("mem[addr] = slot[{}]", src_slots[0]))
        }
        ("control", "formula", op) if op != "none" => {
            let args = if control_operands.is_empty() {
                extra_operands.clone()
            } else {
                control_operands.clone()
            };
            if args.is_empty() {
                Some(format!("vm_ip = {op}(vm_ip)"))
            } else {
                Some(format!("vm_ip = {op}(vm_ip, {})", args.join(", ")))
            }
        }
        _ => None,
    };
    (
        serde_json::json!({
            "dst_slots": dst_slots,
            "src_slots": src_slots,
            "control_operands": control_operands,
            "extra_operands": extra_operands,
        }),
        python
            .map(serde_json::Value::String)
            .unwrap_or_else(|| serde_json::Value::String(fallback_python.to_string())),
    )
}

pub(super) fn best_template_operands_for_role(
    template_operands: &[serde_json::Value],
    role: &str,
) -> Vec<String> {
    let mut candidates = template_operands
        .iter()
        .filter_map(|operand| {
            let name = operand.get("name").and_then(|v| v.as_str())?;
            let best_count = operand
                .get("roles")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter(|item| item.get("role").and_then(|v| v.as_str()) == Some(role))
                .filter_map(|item| item.get("count").and_then(|v| v.as_u64()))
                .max()
                .unwrap_or(0);
            (best_count > 0).then_some((best_count, name.to_string()))
        })
        .collect::<Vec<_>>();
    let Some(max_count) = candidates.iter().map(|(count, _)| *count).max() else {
        return Vec::new();
    };
    candidates.retain(|(count, _)| *count == max_count);
    candidates.sort_by(|(_, lhs), (_, rhs)| lhs.cmp(rhs));
    candidates
        .into_iter()
        .map(|(_, name)| name)
        .collect::<Vec<_>>()
}

pub(super) fn add_vm_op_template_operand_roles(
    group: &mut VmOpTemplateGroup,
    op: &serde_json::Value,
) {
    for read in op
        .get("bytecode_reads")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let (offset_key, width_key) = bytecode_read_sort_key(read);
        let key = format!("{offset_key:016x}:{width_key:016x}");
        let Some(operand) = group.bytecode_operands.get_mut(&key) else {
            continue;
        };
        for role in vm_op_bytecode_operand_roles(read, op) {
            *operand.roles.entry(role).or_insert(0) += 1;
        }
    }
}

pub(super) fn vm_op_bytecode_operand_roles(
    read: &serde_json::Value,
    op: &serde_json::Value,
) -> BTreeSet<String> {
    let mut roles = BTreeSet::new();
    let read_value = read.get("value").unwrap_or(&serde_json::Value::Null);
    for effect in op
        .get("effects")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        if json_values_match_u64(effect.get("slot"), read_value) {
            roles.insert("dst_slot".to_string());
        }
        if json_values_match_u64(effect.get("addr"), read_value) {
            roles.insert("dst_addr".to_string());
        }
        for input in effect
            .get("inputs")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if json_values_match_u64(input.get("slot"), read_value) {
                roles.insert("src_slot".to_string());
            }
        }
        if json_values_match_u64(effect.pointer("/source_slot/slot"), read_value) {
            roles.insert("src_slot".to_string());
        }
        let formula = effect.get("formula").unwrap_or(&serde_json::Value::Null);
        if json_values_match_u64(formula.pointer("/semantic/lsb"), read_value) {
            roles.insert("formula_lsb".to_string());
        }
        if json_values_match_u64(formula.pointer("/semantic/width"), read_value) {
            roles.insert("formula_width".to_string());
        }
        if formula
            .get("operands")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .any(|operand| json_values_match_u64(operand.get("value"), read_value))
        {
            roles.insert("formula_operand".to_string());
        }
        if effect.get("kind").and_then(|v| v.as_str()) == Some("control")
            && expression_mentions_value(formula.get("expression"), read_value)
        {
            roles.insert("control_operand".to_string());
        }
    }
    if roles.is_empty() {
        roles.insert("bytecode_operand".to_string());
    }
    roles
}

pub(super) fn json_values_match_u64(
    candidate: Option<&serde_json::Value>,
    wanted: &serde_json::Value,
) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    match (json_u64(candidate), json_u64(wanted)) {
        (Some(lhs), Some(rhs)) => lhs == rhs,
        _ => candidate == wanted,
    }
}

pub(super) fn expression_mentions_value(
    expression: Option<&serde_json::Value>,
    value: &serde_json::Value,
) -> bool {
    let Some(expression) = expression.and_then(|v| v.as_str()) else {
        return false;
    };
    if let Some(value) = json_u64(value) {
        expression.contains(&format!("{value:#x}")) || expression.contains(&value.to_string())
    } else {
        expression.contains(&json_display(value))
    }
}

pub(super) fn counted_roles_json(roles: &BTreeMap<String, usize>) -> Vec<serde_json::Value> {
    let mut roles = roles
        .iter()
        .map(|(role, count)| serde_json::json!({ "role": role, "count": count }))
        .collect::<Vec<_>>();
    roles.sort_by(|lhs, rhs| {
        let lhs_count = lhs.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let rhs_count = rhs.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        rhs_count.cmp(&lhs_count).then_with(|| {
            json_display(lhs.get("role").unwrap_or(&serde_json::Value::Null)).cmp(&json_display(
                rhs.get("role").unwrap_or(&serde_json::Value::Null),
            ))
        })
    });
    roles
}

impl VmOpTemplateEffectShape {
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "signature": self.signature,
            "kind": self.kind,
            "formula_op": self.formula_op,
            "count": self.count,
            "output_values": counted_values_json(self.output_values),
            "input_slots": counted_values_json(self.input_slots),
            "pseudocode_samples": self.pseudocode_samples,
        })
    }
}

pub(super) fn add_vm_op_template_effect_shape(
    group: &mut VmOpTemplateGroup,
    effect: &serde_json::Value,
) {
    let signature = vm_op_effect_signature(effect);
    let kind = effect
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let formula_op = effect
        .get("formula")
        .and_then(|v| v.get("op"))
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();
    let shape = group
        .effect_shapes
        .entry(signature.clone())
        .or_insert_with(|| VmOpTemplateEffectShape {
            signature,
            kind,
            formula_op,
            ..VmOpTemplateEffectShape::default()
        });
    shape.count += 1;
    if let Some(slot) = effect.get("slot") {
        add_counted_json_value(&mut shape.output_values, slot.clone());
    } else if let Some(addr) = effect.get("addr") {
        add_counted_json_value(&mut shape.output_values, addr.clone());
    }
    for input in effect
        .get("inputs")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(slot) = input.get("slot") {
            add_counted_json_value(&mut shape.input_slots, slot.clone());
        }
    }
    if shape.pseudocode_samples.len() < 3 {
        shape.pseudocode_samples.push(
            effect
                .get("pseudocode")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
    }
}

pub(super) fn add_counted_json_value(
    map: &mut BTreeMap<String, CountedJsonValue>,
    value: serde_json::Value,
) {
    let key = json_display(&value);
    let entry = map
        .entry(key)
        .or_insert_with(|| CountedJsonValue { value, count: 0 });
    entry.count += 1;
}

pub(super) fn counted_values_json(
    values: BTreeMap<String, CountedJsonValue>,
) -> Vec<serde_json::Value> {
    values
        .into_values()
        .map(|item| serde_json::json!({ "value": item.value, "count": item.count }))
        .collect()
}

pub(super) fn vm_op_template_signature(op: &serde_json::Value) -> String {
    let mut bytecode_parts = op
        .get("bytecode_reads")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|read| {
            let (offset_key, width_key) = bytecode_read_sort_key(read);
            let text = format!(
                "{}:{}",
                read.get("offset")
                    .map(json_display)
                    .unwrap_or_else(|| "null".to_string()),
                read.get("width")
                    .map(json_display)
                    .unwrap_or_else(|| "null".to_string())
            );
            (offset_key, width_key, text)
        })
        .collect::<Vec<_>>();
    bytecode_parts.sort_by_key(|(offset, width, _)| (*offset, *width));
    let bytecode = bytecode_parts
        .into_iter()
        .map(|(_, _, text)| text)
        .collect::<Vec<_>>()
        .join(",");
    let effects = op
        .get("effects")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_effect_signature)
        .collect::<Vec<_>>()
        .join(",");
    format!("bc[{bytecode}] effects[{effects}]")
}

pub(super) fn bytecode_read_sort_key(read: &serde_json::Value) -> (u64, u64) {
    let offset = read
        .get("offset")
        .and_then(value_as_u64)
        .unwrap_or(u64::MAX);
    let width = read.get("width").and_then(value_as_u64).unwrap_or(u64::MAX);
    (offset, width)
}

pub(super) fn vm_op_effect_signature(effect: &serde_json::Value) -> String {
    let kind = effect
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let formula_op = effect
        .get("formula")
        .and_then(|v| v.get("op"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let source = if effect
        .get("source_byte_load")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        "byte_load"
    } else if formula_op != "none" {
        "formula"
    } else {
        "literal"
    };
    format!("{kind}:{source}:{formula_op}")
}

pub(super) fn vm_ops_semantic_counts(ops: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut semantic_counts = BTreeMap::<String, usize>::new();
    for op in ops {
        if let Some(formulas) = op.get("alu_formulas").and_then(|v| v.as_array()) {
            for formula in formulas {
                if let Some(kind) = formula
                    .get("semantic")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                {
                    *semantic_counts.entry(kind.to_string()).or_default() += 1;
                }
            }
        }
    }
    semantic_counts
        .into_iter()
        .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
        .collect::<Vec<_>>()
}

pub(super) fn vm_op_summary(
    op: &serde_json::Value,
    infra_regs: &HashSet<String>,
    ip_reg: Option<&str>,
) -> serde_json::Value {
    let bytecode_reads = op
        .get("bytecode_reads")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            let offset = item.get("offset").cloned().unwrap_or(serde_json::Value::Null);
            let width = item.get("width").cloned().unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "idx": item.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "name": bytecode_operand_param_name(&offset, &width),
                "offset": offset,
                "width": width,
                "bytes_le_hex": item.get("bytes_le_hex").cloned().unwrap_or(serde_json::Value::Null),
                "value": item.get("value").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let alu_formulas = op
        .get("alu_formulas")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|formula| {
            serde_json::json!({
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "idx_start": op.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
        "idx_end": op.get("idx_end").cloned().unwrap_or(serde_json::Value::Null),
        "rows": op.get("rows").cloned().unwrap_or(serde_json::Value::Null),
        "class_counts": op.get("class_counts").cloned().unwrap_or(serde_json::Value::Null),
        "bytecode_reads": bytecode_reads,
        "vm_slot_reads": op.get("vm_slot_reads").cloned().unwrap_or_else(|| serde_json::json!([])),
        "vm_slot_writes": op.get("vm_slot_writes").cloned().unwrap_or_else(|| serde_json::json!([])),
        "small_byte_loads": op.get("small_byte_loads").cloned().unwrap_or_else(|| serde_json::json!([])),
        "memory_stores": op.get("memory_stores").cloned().unwrap_or_else(|| serde_json::json!([])),
        "alu_formulas": alu_formulas,
        "effects": vm_op_effect_summaries(op, infra_regs, ip_reg),
        "dispatches": op.get("dispatches").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn vm_op_effect_summaries(
    op: &serde_json::Value,
    infra_regs: &HashSet<String>,
    ip_reg: Option<&str>,
) -> Vec<serde_json::Value> {
    let mut effects = Vec::new();
    let formulas = op
        .get("alu_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for write in op
        .get("vm_slot_writes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let value = write
            .get("value")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let formula = matching_formula_for_value(&formulas, &value);
        let source_byte_load = matching_byte_load_for_value(
            op.get("small_byte_loads")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten(),
            &value,
        );
        let slot = write
            .get("slot")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let inputs = op
            .get("vm_slot_reads")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let python_with_values = slot_write_effect_python(
            &slot,
            &value,
            formula.as_ref(),
            source_byte_load.as_ref(),
            inputs.as_array().map(Vec::as_slice).unwrap_or(&[]),
        );
        let rhs = formula
            .as_ref()
            .and_then(|f| f.get("expression"))
            .map(json_display)
            .or_else(|| {
                source_byte_load.as_ref().map(|load| {
                    format!(
                        "byte[{}] ({})",
                        json_display(load.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                        json_display(load.get("value").unwrap_or(&serde_json::Value::Null))
                    )
                })
            })
            .unwrap_or_else(|| json_display(&value));
        let pseudocode = format!("slot[{}] = {}", json_display(&slot), rhs);
        effects.push(serde_json::json!({
            "kind": "slot_write",
            "idx": write.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "slot": slot,
            "value": value,
            "pseudocode": pseudocode,
            "python_with_values": python_with_values,
            "formula": formula.unwrap_or(serde_json::Value::Null),
            "source_byte_load": source_byte_load.unwrap_or(serde_json::Value::Null),
            "inputs": inputs,
        }));
    }
    for store in op
        .get("memory_stores")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let src = store
            .get("store_src")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let src_value = src.get("value").cloned().unwrap_or(serde_json::Value::Null);
        let src_slot = source_slot_for_value(
            op.get("vm_slot_reads")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten(),
            &src_value,
        );
        if is_probable_vm_infra_store(store, src_slot.as_ref(), &src, infra_regs) {
            continue;
        }
        let pseudocode = if store.get("class").and_then(|v| v.as_str()) == Some("byte-store") {
            if let Some(slot) = src_slot.as_ref().and_then(|slot| slot.get("slot")) {
                format!(
                    "mem[{}] = low8(slot[{}])",
                    json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                    json_display(slot)
                )
            } else {
                format!(
                    "mem[{}] = low8({})",
                    json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                    json_display(&src_value)
                )
            }
        } else {
            format!(
                "mem[{}] = {}",
                json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                json_display(&src_value)
            )
        };
        effects.push(serde_json::json!({
            "kind": "memory_store",
            "idx": store.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "class": store.get("class").cloned().unwrap_or(serde_json::Value::Null),
            "addr": store.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "src": src,
            "source_slot": src_slot.unwrap_or(serde_json::Value::Null),
            "pseudocode": pseudocode,
            "python_with_values": pseudocode,
        }));
    }
    if effects.is_empty() {
        if let Some(formula) = formulas.iter().find(|formula| {
            formula
                .get("asm")
                .and_then(|v| v.as_str())
                .map(|asm| ip_reg.is_some_and(|ip| asm.contains(ip)))
                .unwrap_or(false)
        }) {
            effects.push(serde_json::json!({
                "kind": "control",
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "pseudocode": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "python_with_values": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "formula": formula,
            }));
        }
    }
    effects
}

pub(super) fn slot_write_effect_python(
    slot: &serde_json::Value,
    value: &serde_json::Value,
    formula: Option<&serde_json::Value>,
    source_byte_load: Option<&serde_json::Value>,
    inputs: &[serde_json::Value],
) -> String {
    let dst = format!("slot[{}]", json_display(slot));
    if let Some(load) = source_byte_load {
        return format!(
            "{dst} = byte_load({})",
            json_display(load.get("mem_addr").unwrap_or(&serde_json::Value::Null))
        );
    }
    if let Some(formula) = formula {
        if formula.pointer("/semantic/kind").and_then(|v| v.as_str()) == Some("ubfx") {
            let src = formula
                .pointer("/semantic/input")
                .and_then(|input| source_slot_for_value(inputs.iter(), input))
                .and_then(|input| input.get("slot").cloned())
                .map(|slot| format!("slot[{}]", json_display(&slot)))
                .unwrap_or_else(|| {
                    formula
                        .pointer("/semantic/input")
                        .map(json_display)
                        .unwrap_or_else(|| "input".to_string())
                });
            return format!(
                "{dst} = ubfx({}, {}, {})",
                src,
                formula
                    .pointer("/semantic/lsb")
                    .map(json_display)
                    .unwrap_or_else(|| "lsb".to_string()),
                formula
                    .pointer("/semantic/width")
                    .map(json_display)
                    .unwrap_or_else(|| "width".to_string())
            );
        }
        if let Some(op) = formula.get("op").and_then(|v| v.as_str()) {
            let terms = formula_operand_terms(formula, inputs);
            if !terms.is_empty() {
                return format!("{dst} = {op}({})", terms.join(", "));
            }
        }
        if let Some(expression) = formula.get("expression") {
            return format!("{dst} = {}", json_display(expression));
        }
    }
    format!("{dst} = {}", json_display(value))
}

pub(super) fn formula_operand_terms(
    formula: &serde_json::Value,
    inputs: &[serde_json::Value],
) -> Vec<String> {
    formula
        .get("operands")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|operand| {
            let value = operand.get("value").unwrap_or(&serde_json::Value::Null);
            source_slot_for_value(inputs.iter(), value)
                .and_then(|input| input.get("slot").cloned())
                .map(|slot| format!("slot[{}]", json_display(&slot)))
                .unwrap_or_else(|| json_display(value))
        })
        .collect()
}

pub(super) fn is_probable_vm_infra_store(
    store: &serde_json::Value,
    src_slot: Option<&serde_json::Value>,
    src: &serde_json::Value,
    infra_regs: &HashSet<String>,
) -> bool {
    if store.get("class").and_then(|v| v.as_str()) != Some("mem-store") {
        return false;
    }
    if src_slot.is_some() {
        return false;
    }
    let Some(reg) = src.get("reg").and_then(|v| v.as_str()) else {
        return false;
    };
    matches!(reg, "sp" | "fp" | "lr") || infra_regs.contains(&register_value_key(reg))
}

pub(super) fn matching_formula_for_value(
    formulas: &[serde_json::Value],
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    formulas
        .iter()
        .find(|formula| {
            formula
                .pointer("/semantic/result")
                .and_then(json_u64)
                .or_else(|| formula.get("expression").and_then(expression_lhs_u64))
                == Some(wanted)
        })
        .cloned()
}

pub(super) fn source_slot_for_value<'a>(
    mut reads: impl Iterator<Item = &'a serde_json::Value>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    reads
        .find(|read| read.get("value").and_then(json_u64) == Some(wanted))
        .cloned()
}

pub(super) fn matching_byte_load_for_value<'a>(
    mut loads: impl Iterator<Item = &'a serde_json::Value>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    loads
        .find(|load| load.get("value").and_then(json_u64) == Some(wanted))
        .cloned()
}

/// 表达式左值（`lhs = rhs` 的 lhs）转 u64；字符串数值解析统一走
/// cli_support 的 parse_u64_str，不再平行实现。
pub(super) fn expression_lhs_u64(value: &serde_json::Value) -> Option<u64> {
    let text = value.as_str()?;
    let lhs = text.split('=').next()?.trim();
    parse_u64_str(lhs)
}

pub(super) fn json_display(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

pub(super) fn vm_ops_state_updates(ops: &[serde_json::Value]) -> serde_json::Value {
    let mut updates = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        let formulas = op
            .get("alu_formulas")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|formula| {
                formula.pointer("/semantic/kind").and_then(|v| v.as_str()) == Some("add32_mix")
            });
        for formula in formulas {
            let Some(result) = formula.pointer("/semantic/result").and_then(|v| v.as_str()) else {
                continue;
            };
            for candidate in ops.iter().skip(idx).take(3) {
                let stores = candidate
                    .get("memory_stores")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten();
                for store in stores {
                    let Some(src) = memory_store_src_with_value(store, result) else {
                        continue;
                    };
                    updates.push(serde_json::json!({
                        "formula_op_start": op.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
                        "formula_idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "formula_asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
                        "store_op_start": candidate.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
                        "store_idx": store.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "store_asm": store.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                        "store_addr": store.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
                        "store_src": src,
                    }));
                }
            }
        }
    }
    serde_json::Value::Array(updates)
}

pub(super) fn memory_store_src_with_value(
    store: &serde_json::Value,
    value: &str,
) -> Option<serde_json::Value> {
    store
        .get("store_src")?
        .as_array()?
        .iter()
        .find(|src| src.get("value").and_then(|v| v.as_str()) == Some(value))
        .cloned()
}

pub(super) struct LoadedVmRows {
    rows: Vec<serde_json::Value>,
    source_returned: usize,
    source_maybe_truncated: bool,
    chunks: usize,
    inferred_base: Option<u64>,
}

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn load_vm_rows_chunked(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
    chunk_size: usize,
) -> anyhow::Result<LoadedVmRows> {
    let total = end.saturating_sub(start);
    if total == 0 {
        return Ok(LoadedVmRows {
            rows: Vec::new(),
            source_returned: 0,
            source_maybe_truncated: false,
            chunks: 0,
            inferred_base: base_ip.as_deref().and_then(parse_u64_str),
        });
    }

    let effective_chunk_size = if chunk_size == 0 {
        total
    } else {
        chunk_size.max(1)
    };
    // 每个 chunk 都请求 /api/records（不需要 MemShadow）：router 只构建
    // 一次并在循环内复用，否则每个 chunk 都会经 AppState::load 重新读
    // TraceMeta/Trace/Index。
    let app = build_cli_router(trace_dir, "/api/records", None)?;
    let mut cursor = start;
    let mut rows = Vec::new();
    let mut source_returned = 0usize;
    let mut source_maybe_truncated = false;
    let mut chunks = 0usize;
    let mut inferred_base = base_ip.as_deref().and_then(parse_u64_str);
    let mut base_arg = base_ip;

    while cursor < end {
        let chunk_end = cursor.saturating_add(effective_chunk_size).min(end);
        let request_end = if chunk_end < end {
            chunk_end.saturating_add(1)
        } else {
            chunk_end
        };
        let requested = request_end.saturating_sub(cursor);
        let non_overlap_requested = chunk_end.saturating_sub(cursor);
        let (mut chunk_rows, returned, chunk_base) = load_vm_rows_on(
            &app,
            cursor,
            request_end,
            regs.clone(),
            only_vm,
            base_arg.clone(),
            profile,
        )
        .await?;
        chunks += 1;
        source_returned += returned.min(non_overlap_requested);
        if returned < requested {
            source_maybe_truncated = true;
        }
        if inferred_base.is_none() {
            inferred_base = chunk_base;
            if let Some(base) = chunk_base {
                base_arg = Some(format!("{base:#x}"));
            }
        }
        chunk_rows.retain(|row| {
            row.get("idx")
                .and_then(|v| v.as_u64())
                .map(|idx| {
                    let idx = idx as usize;
                    idx >= cursor && idx < chunk_end
                })
                .unwrap_or(false)
        });
        rows.extend(chunk_rows);
        cursor = chunk_end;
    }

    Ok(LoadedVmRows {
        rows,
        source_returned,
        source_maybe_truncated,
        chunks,
        inferred_base,
    })
}

pub(super) async fn load_vm_rows(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let app = build_cli_router(trace_dir, "/api/records", None)?;
    load_vm_rows_on(&app, start, end, regs, only_vm, base_ip, profile).await
}

/// load_vm_rows 的共用 router 版本：分块调用方（load_vm_rows_chunked）在
/// 循环外构建一次 router 后经本函数复用，避免逐 chunk 重新加载 trace。
#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn load_vm_rows_on(
    app: &axum::Router,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let count = end.saturating_sub(start);
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
    let inferred_base = base_ip.as_deref().and_then(parse_u64_str).or_else(|| {
        records
            .iter()
            .find_map(|rec| record_reg_u64(rec, &profile.ip_reg))
    });

    let mut rows = Vec::new();
    for (pos, rec) in records.iter().enumerate() {
        let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
        let class = classify_vm_asm(asm, profile);
        if only_vm && class == "other" {
            continue;
        }
        let next = records.get(pos + 1);
        rows.push(vm_row_from_record(rec, next, inferred_base, profile));
    }
    Ok((rows, records.len(), inferred_base))
}

pub(super) fn regs_with_vm_profile(regs: String, profile: &VmProfile) -> String {
    let mut items = split_csv(&regs);
    let mut seen = items
        .iter()
        .map(|reg| register_value_key(reg))
        .collect::<HashSet<_>>();
    for reg in [&profile.ip_reg, &profile.state_reg, &profile.dispatch_reg] {
        if seen.insert(reg.clone()) {
            items.push(reg.clone());
        }
    }
    items.join(",")
}

pub(super) fn vm_state_base_from_rows(
    rows: &[serde_json::Value],
    profile: &VmProfile,
) -> Option<u64> {
    rows.iter().find_map(|row| {
        row.get("regs")
            .and_then(|regs| regs.get(profile.state_reg.as_str()))
            .and_then(json_u64)
    })
}
