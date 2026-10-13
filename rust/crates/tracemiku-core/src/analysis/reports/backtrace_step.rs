use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn vm_backstep_value_on(
    analysis: &AnalysisContext,
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
    let params = crate::analysis::records::RecordsQuery {
        start,
        count,
        regs,
        ..Default::default()
    };
    let response = query_value_on(analysis, Query::Records(params))?;
    let records = response
        .get("records")
        .and_then(|v| v.as_array())
        .context("records response missing records[]")?;
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
        upstream_writer_for_def_on(analysis, def_row, lookback, max_writes)?
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
