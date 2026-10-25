use super::*;

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
    super::GAP_SCAN_REGS
        .split(',')
        .map(str::trim)
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

pub(super) fn exact_byte_writers_for_load_on(
    context: &AnalysisContext,
    addr: u64,
    size: u64,
    before_idx: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for offset in 0..size {
        let byte_addr = addr.saturating_add(offset);
        let params = crate::analysis::memory_query::LastWriteOfAddrQuery {
            addr: format!("{byte_addr:#x}"),
            before_idx: isize::try_from(before_idx)?,
            with_external: true,
            ..Default::default()
        };
        let response = query_value_on(context, Query::LastWriteOfAddr(params))?;
        let last_write = if response.get("status").and_then(|v| v.as_str()) == Some("found") {
            let mut lw = serde_json::json!({
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
            });
            if let Some(copy_from) = response.get("copy_from").filter(|v| !v.is_null()) {
                if let Some(obj) = lw.as_object_mut() {
                    obj.insert("copy_from".to_string(), copy_from.clone());
                }
            }
            Some(lw)
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
