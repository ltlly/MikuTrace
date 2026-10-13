use super::*;

#[derive(Debug, Default)]
pub(super) struct ByteWriterVmSourceGroup {
    pub(super) source_class: String,
    pub(super) start_offset: u64,
    pub(super) end_offset: u64,
    pub(super) bytes_hex: String,
    pub(super) ascii: String,
    pub(super) chain_count: usize,
    pub(super) writer_idxs: Vec<serde_json::Value>,
    pub(super) memory_boundaries: Vec<serde_json::Value>,
    pub(super) static_memory_loads: Vec<serde_json::Value>,
    pub(super) static_memory_load_count: usize,
    pub(super) semantic_kind_counts: BTreeMap<String, usize>,
    pub(super) stops: Vec<serde_json::Value>,
}

impl ByteWriterVmSourceGroup {
    fn new(source_class: String, chain: &serde_json::Value) -> Self {
        let start_offset = chain
            .get("start_offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let end_offset = chain
            .get("end_offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(start_offset);
        let mut group = Self {
            source_class,
            start_offset,
            end_offset,
            bytes_hex: chain
                .get("bytes_hex")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            ascii: chain
                .get("ascii")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            chain_count: 0,
            ..Self::default()
        };
        group.add_chain(chain);
        group
    }

    fn can_extend(&self, source_class: &str, chain: &serde_json::Value) -> bool {
        self.source_class == source_class
            && chain
                .get("start_offset")
                .and_then(|v| v.as_u64())
                .is_some_and(|start| self.end_offset.saturating_add(1) == start)
    }

    fn add_chain(&mut self, chain: &serde_json::Value) {
        if self.chain_count > 0 {
            if let Some(bytes_hex) = chain.get("bytes_hex").and_then(|v| v.as_str()) {
                self.bytes_hex.push_str(bytes_hex);
            }
            if let Some(ascii) = chain.get("ascii").and_then(|v| v.as_str()) {
                self.ascii.push_str(ascii);
            }
        }
        if let Some(end_offset) = chain.get("end_offset").and_then(|v| v.as_u64()) {
            self.end_offset = end_offset;
        }
        self.chain_count += 1;
        self.writer_idxs.push(
            chain
                .get("writer_idx")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
        for boundary in chain
            .pointer("/recognized_pattern_summary/memory_boundary_reads")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .map(compact_memory_boundary_read)
        {
            push_unique_json(&mut self.memory_boundaries, boundary);
        }
        let static_loads = chain
            .pointer("/recognized_pattern_summary/static_memory_loads")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        self.static_memory_load_count += static_loads.len();
        for load in static_loads.into_iter().map(compact_static_memory_load) {
            push_unique_json(&mut self.static_memory_loads, load);
        }
        for item in chain
            .get("recognized_semantics")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(kind) = item
                .get("semantic")
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
            {
                *self
                    .semantic_kind_counts
                    .entry(kind.to_string())
                    .or_insert(0) += 1;
            }
        }
        if let Some(stop) = chain.get("stop").filter(|v| !v.is_null()) {
            push_unique_json(&mut self.stops, compact_vm_chain_stop(stop));
        }
    }

    fn into_json(self) -> serde_json::Value {
        let size = self.end_offset.saturating_sub(self.start_offset) + 1;
        serde_json::json!({
            "source_class": self.source_class,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": size,
            "bytes_hex": self.bytes_hex,
            "ascii": self.ascii,
            "chain_count": self.chain_count,
            "writer_idxs": self.writer_idxs,
            "memory_boundary_reads": self.memory_boundaries,
            "static_memory_load_count": self.static_memory_load_count,
            "static_memory_loads": self.static_memory_loads,
            "semantic_kind_counts": self.semantic_kind_counts
                .into_iter()
                .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
                .collect::<Vec<_>>(),
            "stops": self.stops,
            "interpretation": vm_source_class_interpretation(&self.source_class),
        })
    }
}

pub(super) fn byte_writer_vm_source_ranges(
    vm_chains: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut groups = Vec::<ByteWriterVmSourceGroup>::new();
    for chain in vm_chains {
        let source_class = byte_writer_chain_source_class(chain);
        if let Some(last) = groups.last_mut() {
            if last.can_extend(&source_class, chain) {
                last.add_chain(chain);
                continue;
            }
        }
        groups.push(ByteWriterVmSourceGroup::new(source_class, chain));
    }
    groups
        .into_iter()
        .map(ByteWriterVmSourceGroup::into_json)
        .collect()
}

pub(super) fn byte_writer_chain_source_class(chain: &serde_json::Value) -> String {
    if chain
        .pointer("/recognized_pattern_summary/memory_boundary_reads")
        .and_then(|v| v.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        return "memory_boundary_read".to_string();
    }
    if chain
        .pointer("/recognized_pattern_summary/static_memory_loads")
        .and_then(|v| v.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        return "static_memory_load_constant".to_string();
    }
    if chain
        .get("recognized_semantics")
        .and_then(|v| v.as_array())
        .is_some_and(|items| !items.is_empty())
    {
        return "traced_formula_only".to_string();
    }
    "unclassified".to_string()
}

pub(super) fn compact_memory_boundary_read(pattern: &serde_json::Value) -> serde_json::Value {
    let last_write = pattern
        .get("last_write")
        .unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "idx": pattern.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "step": pattern.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "addr": pattern.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": pattern.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "value": pattern.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": pattern.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "observed_mismatch_count": pattern
            .get("observed_mismatches")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0),
        "last_write": {
            "idx": last_write.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": last_write.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "dst_addr": last_write.get("dst_addr").cloned().unwrap_or(serde_json::Value::Null),
            "src_reg": last_write.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
            "src_value": last_write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
        }
    })
}

pub(super) fn compact_static_memory_load(pattern: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "idx": pattern.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "step": pattern.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "addr": pattern.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": pattern.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "value": pattern.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": pattern.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "idx_lo": pattern.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
        "idx_hi": pattern.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
        "source_boundary": pattern.get("source_boundary").cloned().unwrap_or(serde_json::Value::Null),
        "caution": pattern.get("caution").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn push_unique_json(items: &mut Vec<serde_json::Value>, value: serde_json::Value) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}

pub(super) fn vm_source_class_interpretation(source_class: &str) -> &'static str {
    match source_class {
        "memory_boundary_read" => {
            "chain reaches an observed memory value that is not explained by the latest traced write"
        }
        "static_memory_load_constant" => {
            "chain reaches a memory load with no writer in the selected lookback window"
        }
        "traced_formula_only" => {
            "chain has recognized ALU semantics but no memory/static boundary in the returned depth"
        }
        _ => "chain did not expose a recognized source class in the returned depth",
    }
}

pub(super) fn compact_byte_writer_run(run: &serde_json::Value) -> serde_json::Value {
    let writer = run.get("writer").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": run.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": run.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": run.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offset": run.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": run.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer": {
            "idx": writer.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "dst_addr": writer.get("dst_addr").cloned().unwrap_or(serde_json::Value::Null),
            "size": writer.get("size").cloned().unwrap_or(serde_json::Value::Null),
            "src_reg": writer.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
            "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
        }
    })
}

pub(super) fn compact_byte_writer_chain(chain: &serde_json::Value) -> serde_json::Value {
    let inner = chain.get("chain").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "start_offset": chain.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": chain.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": chain.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": chain.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": chain.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": chain.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer_idx": chain.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
        "seed": chain.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "chain_status": inner.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": inner.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop": inner
            .get("stop")
            .filter(|v| !v.is_null())
            .map(compact_vm_chain_stop)
            .unwrap_or(serde_json::Value::Null),
        "recognized_pattern_summary": inner.get("recognized_pattern_summary").cloned().unwrap_or(serde_json::Value::Null),
        "recognized_semantics": inner.get("recognized_semantics").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn compact_vm_chain_stop(stop: &serde_json::Value) -> serde_json::Value {
    if stop.is_null() {
        return serde_json::Value::Null;
    }
    let local_def = stop.get("local_def").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "step": stop.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "idx": stop.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": stop.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": stop.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "decision": stop.get("decision").cloned().unwrap_or(serde_json::Value::Null),
        "local_def": {
            "idx": local_def.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": local_def.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": local_def.get("class").cloned().unwrap_or(serde_json::Value::Null),
        },
        "upstream_status": stop
            .get("upstream")
            .and_then(|v| v.get("status"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    })
}

pub fn mem_dump_summary(response: &serde_json::Value, cstr: bool) -> serde_json::Value {
    let bytes = response
        .get("bytes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let byte_values = bytes
        .iter()
        .map(|entry| entry.get("byte").and_then(|v| v.as_u64()).map(|b| b as u8))
        .collect::<Vec<_>>();
    let known_count = byte_values.iter().filter(|byte| byte.is_some()).count();
    let bytes_hex = byte_values
        .iter()
        .map(|byte| {
            byte.map(|value| format!("{value:02x}"))
                .unwrap_or_else(|| "..".to_string())
        })
        .collect::<String>();
    let ascii = byte_values
        .iter()
        .map(|byte| {
            byte.and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string())
        })
        .collect::<String>();
    let words_le64 = mem_dump_known_le_words(&bytes, &byte_values, 8);
    let nul_offset = byte_values.iter().position(|byte| matches!(byte, Some(0)));
    let c_string = if cstr {
        let raw = byte_values
            .iter()
            .take(nul_offset.unwrap_or(byte_values.len()))
            .filter_map(|byte| *byte)
            .collect::<Vec<_>>();
        serde_json::Value::String(String::from_utf8_lossy(&raw).into_owned())
    } else {
        serde_json::Value::Null
    };
    serde_json::json!({
        "status": response.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "addr": response.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "count": response.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "cursor": response.get("cursor").cloned().unwrap_or(serde_json::Value::Null),
        "known_byte_count": known_count,
        "bytes_hex": bytes_hex,
        "ascii": ascii,
        "words_le64": words_le64,
        "c_string": c_string,
        "c_string_terminated": if cstr {
            serde_json::Value::Bool(nul_offset.is_some())
        } else {
            serde_json::Value::Null
        },
        "nul_offset": nul_offset
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn mem_dump_known_le_words(
    entries: &[serde_json::Value],
    byte_values: &[Option<u8>],
    width: usize,
) -> Vec<serde_json::Value> {
    if width == 0 {
        return Vec::new();
    }
    if byte_values.len() < width {
        return Vec::new();
    }
    (0..=byte_values.len() - width)
        .filter_map(|offset| {
            let addr = entries
                .get(offset)
                .and_then(|entry| entry.get("addr"))
                .and_then(json_u64)?;
            if addr % width as u64 != 0 {
                return None;
            }
            let chunk = &byte_values[offset..offset + width];
            if chunk.iter().any(Option::is_none) {
                return None;
            }
            let mut value = 0u64;
            let mut bytes = Vec::with_capacity(width);
            for (idx, byte) in chunk.iter().enumerate() {
                let byte = byte.unwrap_or(0);
                bytes.push(byte);
                if idx < 8 {
                    value |= (byte as u64) << (idx * 8);
                }
            }
            Some(serde_json::json!({
                "offset": offset,
                "addr": format!("{addr:#x}"),
                "width": width,
                "value": format!("{value:#x}"),
                "bytes_hex": bytes_to_hex(&bytes),
            }))
        })
        .collect()
}

pub(super) fn burst_candidate_byte_map(
    context: &AnalysisContext,
    candidate: &serde_json::Value,
    target_hex: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let addr_raw = candidate
        .get("addr")
        .and_then(|v| v.as_str())
        .context("hash candidate missing addr")?;
    let addr =
        parse_addr_str(addr_raw).with_context(|| format!("invalid candidate addr {addr_raw:?}"))?;
    let size = candidate
        .get("size")
        .and_then(|v| v.as_u64())
        .context("hash candidate missing size")?;
    let size_usize = usize::try_from(size).context("candidate size does not fit in usize")?;
    let enter_idx = candidate
        .get("enter_idx")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exit_idx = candidate
        .get("exit_idx")
        .and_then(|v| v.as_u64())
        .unwrap_or(enter_idx as u64) as usize;
    let addr_hi = addr
        .checked_add(size)
        .context("candidate addr + size overflowed u64")?;
    let params = crate::analysis::memory_query::MemWritesInRangeQuery {
        idx_lo: enter_idx,
        idx_hi: isize::try_from(exit_idx.saturating_add(1))?,
        addr_lo: Some(format!("{addr:#x}")),
        addr_hi: Some(format!("{addr_hi:#x}")),
        max: usize::try_from(5000)?,
        ..Default::default()
    };
    let response = query_value_on(context, Query::MemWritesInRange(params))?;
    let map = byte_writer_map_output(addr, size_usize, &response);
    let bytes_hex = map
        .get("bytes_hex")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let all_zero = bytes_hex
        .as_deref()
        .is_some_and(|hex| !hex.is_empty() && hex.as_bytes().iter().all(|&b| b == b'0'));
    let target_hits = target_hex
        .zip(bytes_hex.as_deref())
        .map(|(target, needle)| {
            if all_zero {
                Vec::new()
            } else {
                find_hex_byte_offsets(target, needle)
            }
        })
        .unwrap_or_default();
    Ok(serde_json::json!({
        "candidate": candidate,
        "bytes_hex": bytes_hex,
        "all_zero": all_zero,
        "target_hits": target_hits,
        "map": map,
    }))
}

pub(super) fn byte_writer_map_entries_from_range_writes(
    addr: u64,
    size: usize,
    writes: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut latest: Vec<Option<serde_json::Value>> = vec![None; size];
    for write in writes {
        let Some(start) = write
            .get("dst_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
        else {
            continue;
        };
        let write_size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
        let Some(write_end) = start.checked_add(write_size) else {
            continue;
        };
        let Some(range_end) = addr.checked_add(size as u64) else {
            continue;
        };
        let overlap_start = start.max(addr);
        let overlap_end = write_end.min(range_end);
        if overlap_start >= overlap_end {
            continue;
        }
        for byte_addr in overlap_start..overlap_end {
            let offset = (byte_addr - addr) as usize;
            latest[offset] = Some(write.clone());
        }
    }

    latest
        .into_iter()
        .enumerate()
        .map(|(offset, write)| byte_writer_map_entry(addr + offset as u64, offset, write))
        .collect()
}

pub(super) fn byte_writer_map_entry(
    byte_addr: u64,
    offset: usize,
    last_write: Option<serde_json::Value>,
) -> serde_json::Value {
    let byte = last_write
        .as_ref()
        .and_then(|write| source_byte_for_write_at(write, byte_addr));
    let source_byte_offset = last_write
        .as_ref()
        .and_then(|write| source_byte_offset_for_write_at(write, byte_addr));
    let next = last_write.as_ref().and_then(|write| {
        Some(serde_json::json!({
            "idx": write.get("idx")?,
            "reg": write.get("src_reg")?,
            "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": source_byte_offset,
            "reason": "buffer_byte_last_writer",
            "offset": offset,
            "addr": format!("{byte_addr:#x}"),
            "byte_hex": byte.map(|b| format!("{b:02x}")),
        }))
    });
    serde_json::json!({
        "offset": offset,
        "addr": format!("{byte_addr:#x}"),
        "status": if last_write.is_some() && byte.is_some() { "ready" } else { "not_found" },
        "byte_hex": byte.map(|b| format!("{b:02x}")),
        "ascii": byte.and_then(printable_ascii_char),
        "source_byte_offset": source_byte_offset,
        "writer": last_write,
        "next": next,
    })
}

pub(super) fn source_byte_offset_for_write_at(
    write: &serde_json::Value,
    byte_addr: u64,
) -> Option<u64> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    (offset < 8).then_some(offset)
}

pub(super) fn source_byte_for_write_at(write: &serde_json::Value, byte_addr: u64) -> Option<u8> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    let shift = offset.checked_mul(8)?;
    if shift >= 64 {
        return None;
    }
    let value = write
        .get("src_value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    Some(((value >> shift) & 0xff) as u8)
}

pub(super) fn byte_writer_runs(bytes: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut runs = Vec::new();
    let mut current: Option<ByteWriterRun> = None;
    for entry in bytes {
        let Some(byte_hex) = entry.get("byte_hex").and_then(|v| v.as_str()) else {
            if let Some(run) = current.take() {
                runs.push(run.into_json());
            }
            continue;
        };
        let Some(writer) = entry.get("writer").filter(|v| !v.is_null()) else {
            if let Some(run) = current.take() {
                runs.push(run.into_json());
            }
            continue;
        };
        let offset = entry
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or_default() as usize;
        let source_byte_offset = entry
            .get("source_byte_offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let identity = byte_writer_identity(writer);
        if let Some(run) = current.as_mut() {
            if run.identity == identity && run.end_offset + 1 == offset {
                run.end_offset = offset;
                run.bytes_hex.push_str(byte_hex);
                run.source_byte_offsets.push(source_byte_offset);
                run.ascii.push_str(
                    &u8::from_str_radix(byte_hex, 16)
                        .ok()
                        .and_then(printable_ascii_char)
                        .unwrap_or_else(|| ".".to_string()),
                );
                continue;
            }
            runs.push(current.take().unwrap().into_json());
        }
        current = Some(ByteWriterRun {
            identity,
            start_offset: offset,
            end_offset: offset,
            bytes_hex: byte_hex.to_string(),
            ascii: u8::from_str_radix(byte_hex, 16)
                .ok()
                .and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string()),
            source_byte_offsets: vec![source_byte_offset],
            writer: writer.clone(),
        });
    }
    if let Some(run) = current {
        runs.push(run.into_json());
    }
    runs
}
