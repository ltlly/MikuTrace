use super::*;

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
    pub(super) rows: Vec<serde_json::Value>,
    pub(super) source_returned: usize,
    pub(super) source_maybe_truncated: bool,
    pub(super) chunks: usize,
    pub(super) inferred_base: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn load_vm_rows_chunked(
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
    // 分块读取 records；复用分析上下文，避免每个 chunk 重新读
    // TraceMeta/Trace/Index。
    let context = AnalysisContext::load(trace_dir)?;
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
            &context,
            cursor,
            request_end,
            regs.clone(),
            only_vm,
            base_arg.clone(),
            profile,
        )?;
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

pub(super) fn load_vm_rows(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let context = AnalysisContext::load(trace_dir)?;
    load_vm_rows_on(&context, start, end, regs, only_vm, base_ip, profile)
}

/// load_vm_rows 的共用 分析上下文 版本：分块调用方（load_vm_rows_chunked）在
/// 循环外构建一次 分析上下文 后经本函数复用，避免逐 chunk 重新加载 trace。
#[allow(clippy::too_many_arguments)]
pub(super) fn load_vm_rows_on(
    context: &AnalysisContext,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let count = end.saturating_sub(start);
    let regs = regs_with_vm_profile(regs, profile);
    let params = crate::analysis::records::RecordsQuery {
        start,
        count,
        regs,
        ..Default::default()
    };
    let response = query_value_on(context, Query::Records(params))?;
    let records = response
        .get("records")
        .and_then(|v| v.as_array())
        .context("records response missing records[]")?;
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
        if !reg.is_empty() && seen.insert(reg.clone()) {
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
