use super::*;

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
    let Some(base_slot) = slot.get("slot").and_then(|v| v.as_u64()) else {
        return Vec::new();
    };
    let Some(slot_bytes) = slot
        .get("slot_bytes")
        .and_then(|v| v.as_u64())
        .filter(|v| *v > 0)
    else {
        return Vec::new();
    };
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
        let mut byte_offset = 0u64;
        return defs
            .iter()
            .map(|def| {
                let def_mem_addr = def
                    .get("mem_addr")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)
                    .or_else(|| base_mem_addr.and_then(|addr| addr.checked_add(byte_offset)));
                byte_offset = byte_offset.saturating_add(register_load_width(def.get("reg").and_then(|v| v.as_str()).unwrap_or("")));
                let slot_idx = vm_slot_index_for_mem_addr(base_slot, slot_bytes, base_mem_addr, def_mem_addr);
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
                let slot_idx = vm_slot_index_for_mem_addr(base_slot, slot_bytes, base_mem_addr, mem_addr);
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
    slot_bytes: u64,
    base_mem_addr: Option<u64>,
    mem_addr: Option<u64>,
) -> serde_json::Value {
    base_mem_addr
        .zip(mem_addr)
        .and_then(|(base, addr)| addr.checked_sub(base))
        .filter(|offset| *offset % slot_bytes == 0)
        .and_then(|offset| base_slot.checked_add(offset / slot_bytes))
        .map(serde_json::Value::from)
        .unwrap_or(serde_json::Value::Null)
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

pub(super) fn upstream_writer_for_def_on(
    context: &AnalysisContext,
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
        size = memory_access_width(def_row.get("asm").and_then(|v| v.as_str()).unwrap_or(""));
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
    let unlogged_write_gap = (0..size).find_map(|off| {
        context
            .inner
            .memshadow()
            .unlogged_write_gap_before(addr.saturating_add(off), idx.saturating_add(1))
    });
    let idx_lo = idx.saturating_sub(lookback);
    let idx_hi = idx;
    let addr_hi = addr.saturating_add(size);
    let params = crate::analysis::memory_query::MemWritesInRangeQuery {
        idx_lo,
        idx_hi: isize::try_from(idx_hi)?,
        addr_lo: Some(format!("{addr:#x}")),
        addr_hi: Some(format!("{addr_hi:#x}")),
        max: max_writes,
        ..Default::default()
    };
    let response = query_value_on(context, Query::MemWritesInRange(params))?;
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
        exact_byte_writers_for_load_on(context, addr, size, idx)?
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
        match gap_call_candidates_for_mismatch_on(context, addr, idx, last_write.as_ref()) {
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
        "unlogged_write_gap": unlogged_write_gap,
        "next": matches_observed.then(|| last_write.as_ref().and_then(|write| {
            Some(serde_json::json!({
                "idx": write.get("idx")?,
                "reg": write.get("src_reg")?,
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })).flatten(),
    }))
}

pub(super) fn gap_call_candidates_for_mismatch_on(
    context: &AnalysisContext,
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
    let meta = query_value_on(context, Query::Meta)?;
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
        let params = crate::analysis::records::RecordsQuery {
            start: cursor,
            count,
            regs: GAP_SCAN_REGS.to_string(),
            ..Default::default()
        };
        let response = query_value_on(context, Query::Records(params))?;
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
