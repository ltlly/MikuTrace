use super::*;

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateGroup {
    pub(super) signature: String,
    pub(super) count: usize,
    pub(super) bytecode_operands: BTreeMap<String, VmOpTemplateOperand>,
    pub(super) effect_kind_counts: BTreeMap<String, usize>,
    pub(super) effect_shapes: BTreeMap<String, VmOpTemplateEffectShape>,
    pub(super) sample_ops: Vec<serde_json::Value>,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateOperand {
    pub(super) offset: serde_json::Value,
    pub(super) width: serde_json::Value,
    pub(super) values: BTreeMap<String, VmOpTemplateOperandValue>,
    pub(super) roles: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateOperandValue {
    pub(super) value: serde_json::Value,
    pub(super) bytes_le_hex: serde_json::Value,
    pub(super) count: usize,
}

#[derive(Debug, Default)]
pub(super) struct VmOpTemplateEffectShape {
    pub(super) signature: String,
    pub(super) kind: String,
    pub(super) formula_op: String,
    pub(super) count: usize,
    pub(super) output_values: BTreeMap<String, CountedJsonValue>,
    pub(super) input_slots: BTreeMap<String, CountedJsonValue>,
    pub(super) pseudocode_samples: Vec<serde_json::Value>,
}

#[derive(Debug, Default)]
pub(super) struct CountedJsonValue {
    pub(super) value: serde_json::Value,
    pub(super) count: usize,
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
