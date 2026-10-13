use super::*;

pub(super) fn output_semantic_byte_equations(value: &serde_json::Value) -> serde_json::Value {
    let equations = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(output_semantic_byte_equation)
        .collect::<Vec<_>>();
    serde_json::Value::Array(equations)
}

#[cfg(test)]
pub(super) fn output_semantic_byte_equation_summary(
    equations: &serde_json::Value,
) -> serde_json::Value {
    output_semantic_byte_equation_summary_with_context(equations, None)
}

pub(super) fn output_semantic_byte_equation_summary_with_context(
    equations: &serde_json::Value,
    semantic_context: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);
    let covered_set = parsed
        .iter()
        .map(|item| item.offset)
        .collect::<HashSet<_>>();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    for item in &parsed {
        *kind_counts.entry(item.kind.clone()).or_insert(0) += 1;
    }
    let covered_offsets = parsed
        .iter()
        .map(|item| serde_json::json!(item.offset))
        .collect::<Vec<_>>();
    let min_offset = parsed.first().map(|item| item.offset);
    let max_offset = parsed.last().map(|item| item.offset);
    let missing_offsets = match (min_offset, max_offset) {
        (Some(lo), Some(hi)) => (lo..=hi)
            .filter(|offset| !covered_set.contains(offset))
            .map(|offset| serde_json::json!(offset))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let requested_range = semantic_context.and_then(semantic_requested_range);
    let semantic_global_range = semantic_context.and_then(semantic_global_requested_range);
    let missing_offsets_in_requested_range = requested_range
        .map(|(start, end)| {
            (start..end)
                .filter(|offset| !covered_set.contains(offset))
                .map(|offset| serde_json::json!(offset))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let covered_count_in_requested_range = requested_range
        .map(|(start, end)| {
            (start..end)
                .filter(|offset| covered_set.contains(offset))
                .count()
        })
        .unwrap_or(0);
    let requested_range_json = requested_range
        .map(|(start, end)| serde_json::json!([start, end]))
        .unwrap_or(serde_json::Value::Null);
    let requested_coverage_status = requested_range
        .map(|(start, end)| {
            if start == end {
                "empty_requested_range"
            } else if missing_offsets_in_requested_range.is_empty() {
                "complete_in_requested_range"
            } else {
                "partial_in_requested_range"
            }
        })
        .map(|status| serde_json::json!(status))
        .unwrap_or(serde_json::Value::Null);
    let xor_lhs_run_chunks = semantic_xor_lhs_run_chunks(&parsed);
    serde_json::json!({
        "count": parsed.len(),
        "covered_offsets": covered_offsets,
        "covered_range": match (min_offset, max_offset) {
            (Some(lo), Some(hi)) => serde_json::json!([lo, hi + 1]),
            _ => serde_json::Value::Null,
        },
        "missing_offsets_in_covered_range": missing_offsets,
        "requested_range": requested_range_json,
        "requested_offset_basis": semantic_context
            .map(semantic_requested_offset_basis)
            .unwrap_or("local"),
        "semantic_global_range": semantic_global_range
            .map(|(start, end)| serde_json::json!([start, end]))
            .unwrap_or(serde_json::Value::Null),
        "covered_count_in_requested_range": covered_count_in_requested_range,
        "missing_count_in_requested_range": missing_offsets_in_requested_range.len(),
        "missing_offsets_in_requested_range": missing_offsets_in_requested_range,
        "requested_coverage_status": requested_coverage_status,
        "kind_counts": kind_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "xor_rhs_pattern": semantic_xor_rhs_offset_pattern(&parsed),
        "xor_lhs_runs": semantic_xor_lhs_runs(&parsed),
        "xor_lhs_run_chunks": xor_lhs_run_chunks.clone(),
        "xor_lhs_word_chunks": xor_lhs_run_chunks,
    })
}

pub(super) fn semantic_requested_range(context: &serde_json::Value) -> Option<(u64, u64)> {
    if context.get("mode").and_then(|v| v.as_str()) == Some("selected_output_buffer_pre_encoding") {
        let count = context.get("semantic_count").and_then(value_as_u64)?;
        return Some((0, count));
    }
    let start = context.get("semantic_offset").and_then(value_as_u64)?;
    let count = context.get("semantic_count").and_then(value_as_u64)?;
    let end = start.checked_add(count)?;
    Some((start, end))
}

pub(super) fn semantic_global_requested_range(context: &serde_json::Value) -> Option<(u64, u64)> {
    let start = context.get("semantic_offset").and_then(value_as_u64)?;
    let count = context.get("semantic_count").and_then(value_as_u64)?;
    let end = start.checked_add(count)?;
    Some((start, end))
}

pub(super) fn semantic_requested_offset_basis(context: &serde_json::Value) -> &'static str {
    if context.get("mode").and_then(|v| v.as_str()) == Some("selected_output_buffer_pre_encoding") {
        "selected_slice_local"
    } else {
        "semantic_global"
    }
}

#[derive(Debug, Default)]
pub(super) struct ByteLaneInputGroup {
    pub(super) source_value: String,
    pub(super) offsets: Vec<u64>,
    pub(super) source_byte_offsets: BTreeSet<u64>,
    pub(super) result: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct Mod255InputGroup {
    pub(super) input: String,
    pub(super) output_byte: String,
    pub(super) quotient: Option<String>,
    pub(super) offsets: Vec<u64>,
}

pub(super) fn output_semantic_byte_equation_input_summary(
    equations: &serde_json::Value,
) -> serde_json::Value {
    let mut byte_lane_sources = BTreeMap::<String, ByteLaneInputGroup>::new();
    let mut mod255_inputs = BTreeMap::<String, Mod255InputGroup>::new();
    let mut xor_lhs_offsets = Vec::<u64>::new();
    for item in equations.as_array().into_iter().flatten() {
        let Some(kind) = item.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(offset) = item.get("offset").and_then(value_as_u64) else {
            continue;
        };
        match kind {
            "byte_lane_extract" => {
                let Some(source_value) = item.get("source_value").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(source_byte_offset) =
                    item.get("source_byte_offset").and_then(value_as_u64)
                else {
                    continue;
                };
                let result = item
                    .get("result")
                    .and_then(value_as_u64)
                    .map(|v| (v & 0xff) as u8)
                    .or_else(|| {
                        item.get("bytes_hex")
                            .and_then(|v| v.as_str())
                            .and_then(first_hex_byte)
                    });
                let group = byte_lane_sources
                    .entry(source_value.to_string())
                    .or_insert_with(|| ByteLaneInputGroup {
                        source_value: source_value.to_string(),
                        ..ByteLaneInputGroup::default()
                    });
                group.offsets.push(offset);
                group.source_byte_offsets.insert(source_byte_offset);
                if let Some(result) = result {
                    group.result.push(result);
                }
            }
            "mod255_low_byte" => {
                let Some(input) = item.get("input").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(output_byte) = item.get("output_byte").and_then(|v| v.as_str()) else {
                    continue;
                };
                let key = format!("{input}|{output_byte}");
                let group = mod255_inputs
                    .entry(key)
                    .or_insert_with(|| Mod255InputGroup {
                        input: input.to_string(),
                        output_byte: output_byte.to_string(),
                        quotient: item
                            .get("quotient")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        ..Mod255InputGroup::default()
                    });
                group.offsets.push(offset);
            }
            "xor_mix" => {
                xor_lhs_offsets.push(offset);
            }
            _ => {}
        }
    }
    xor_lhs_offsets.sort_unstable();
    serde_json::json!({
        "byte_lane_sources": byte_lane_sources
            .into_values()
            .map(|group| serde_json::json!({
                "source_value": group.source_value,
                "offsets": group.offsets,
                "source_byte_offsets": group.source_byte_offsets.into_iter().collect::<Vec<_>>(),
                "result_hex": bytes_to_hex(&group.result),
                "count": group.result.len(),
            }))
            .collect::<Vec<_>>(),
        "mod255_inputs": mod255_inputs
            .into_values()
            .map(|group| serde_json::json!({
                "input": group.input,
                "output_byte": group.output_byte,
                "quotient": group.quotient,
                "offsets": group.offsets,
                "count": group.offsets.len(),
            }))
            .collect::<Vec<_>>(),
        "xor_lhs_offsets": xor_lhs_offsets,
    })
}

#[derive(Debug)]
pub(super) struct XorByteRun {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) lhs: Vec<u8>,
    pub(super) rhs: Vec<u8>,
    pub(super) result: Vec<u8>,
}

impl XorByteRun {
    fn new(offset: u64, lhs: u8, rhs: u8, result: u8) -> Self {
        Self {
            start: offset,
            end: offset + 1,
            lhs: vec![lhs],
            rhs: vec![rhs],
            result: vec![result],
        }
    }

    fn push(&mut self, offset: u64, lhs: u8, rhs: u8, result: u8) -> bool {
        if offset != self.end {
            return false;
        }
        self.end += 1;
        self.lhs.push(lhs);
        self.rhs.push(rhs);
        self.result.push(result);
        true
    }

    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "range": [self.start, self.end],
            "size": self.end.saturating_sub(self.start),
            "lhs_hex": bytes_to_hex(&self.lhs),
            "rhs_hex": bytes_to_hex(&self.rhs),
            "result_hex": bytes_to_hex(&self.result),
        })
    }
}

pub(super) fn semantic_xor_lhs_runs(equations: &[CompactByteEquation]) -> serde_json::Value {
    let mut runs = Vec::<XorByteRun>::new();
    let mut current: Option<XorByteRun> = None;
    for item in equations.iter().filter(|item| item.kind == "xor_mix") {
        let Some(lhs) = item.lhs.map(|v| (v & 0xff) as u8) else {
            continue;
        };
        let Some(rhs) = item.rhs.map(|v| (v & 0xff) as u8) else {
            continue;
        };
        let result = (item.result & 0xff) as u8;
        if let Some(run) = current.as_mut() {
            if run.push(item.offset, lhs, rhs, result) {
                continue;
            }
            runs.push(current.take().unwrap());
        }
        current = Some(XorByteRun::new(item.offset, lhs, rhs, result));
    }
    if let Some(run) = current {
        runs.push(run);
    }
    serde_json::Value::Array(runs.into_iter().map(XorByteRun::into_json).collect())
}

pub(super) fn semantic_xor_lhs_run_chunks(equations: &[CompactByteEquation]) -> serde_json::Value {
    let mut chunks = Vec::new();
    let mut current = Vec::<CompactByteEquation>::new();
    for item in equations.iter().filter(|item| item.kind == "xor_mix") {
        if current
            .last()
            .is_some_and(|prev| item.offset != prev.offset + 1)
        {
            push_xor_lhs_word_chunks(&mut chunks, &current, equations);
            current.clear();
        }
        current.push(item.clone());
    }
    if !current.is_empty() {
        push_xor_lhs_word_chunks(&mut chunks, &current, equations);
    }
    serde_json::Value::Array(chunks)
}

pub(super) fn push_xor_lhs_word_chunks(
    chunks: &mut Vec<serde_json::Value>,
    run: &[CompactByteEquation],
    equations: &[CompactByteEquation],
) {
    let Some(first) = run.first() else {
        return;
    };
    let Some(last) = run.last() else {
        return;
    };
    let run_range = serde_json::json!([first.offset, last.offset + 1]);
    for (chunk_index, chunk) in run.chunks(4).enumerate() {
        if chunk.len() == 4 {
            if let Some(mut value) = semantic_xor_word_template(chunk, equations) {
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("kind".to_string(), serde_json::json!("word32"));
                    obj.insert("run_range".to_string(), run_range.clone());
                    obj.insert("run_chunk".to_string(), serde_json::json!(chunk_index));
                }
                chunks.push(value);
            }
            continue;
        }

        let lhs = chunk
            .iter()
            .filter_map(|item| item.lhs.map(|v| (v & 0xff) as u8))
            .collect::<Vec<_>>();
        let rhs = chunk
            .iter()
            .filter_map(|item| item.rhs.map(|v| (v & 0xff) as u8))
            .collect::<Vec<_>>();
        if lhs.len() != chunk.len() || rhs.len() != chunk.len() {
            continue;
        }
        let result = chunk
            .iter()
            .map(|item| (item.result & 0xff) as u8)
            .collect::<Vec<_>>();
        let start = chunk
            .first()
            .map(|item| item.offset)
            .unwrap_or(first.offset);
        let end = chunk.last().map(|item| item.offset + 1).unwrap_or(start);
        chunks.push(serde_json::json!({
            "kind": "tail_bytes",
            "run_range": run_range,
            "run_chunk": chunk_index,
            "semantic_range": [start, end],
            "size": end.saturating_sub(start),
            "lhs_hex": bytes_to_hex(&lhs),
            "rhs_hex": bytes_to_hex(&rhs),
            "result_hex": bytes_to_hex(&result),
        }));
    }
}

pub(super) fn semantic_xor_rhs_offset_pattern(
    equations: &[CompactByteEquation],
) -> serde_json::Value {
    let xor_items = equations
        .iter()
        .filter(|item| item.kind == "xor_mix")
        .filter_map(|item| item.rhs.map(|rhs| (item.offset, (rhs & 0xff) as u8)))
        .collect::<Vec<_>>();
    if xor_items.is_empty() {
        return serde_json::Value::Null;
    }
    let mut even = Vec::<u8>::new();
    let mut odd = Vec::<u8>::new();
    for (offset, rhs) in &xor_items {
        let values = if offset % 2 == 0 { &mut even } else { &mut odd };
        if !values.contains(rhs) {
            values.push(*rhs);
        }
    }
    let values_to_json = |values: &[u8]| {
        values
            .iter()
            .map(|value| serde_json::json!(format!("{value:#x}")))
            .collect::<Vec<_>>()
    };
    if even.len() == 1 && odd.len() == 1 {
        serde_json::json!({
            "kind": "offset_parity_mask",
            "formula": "xor rhs = even_byte when equation offset is even, odd_byte when equation offset is odd",
            "even_byte": format!("{:#x}", even[0]),
            "odd_byte": format!("{:#x}", odd[0]),
            "matched_offsets": xor_items.len(),
        })
    } else {
        serde_json::json!({
            "kind": "mixed_rhs_values",
            "even_values": values_to_json(&even),
            "odd_values": values_to_json(&odd),
            "matched_offsets": xor_items.len(),
        })
    }
}

pub(super) fn output_semantic_byte_equation(item: &serde_json::Value) -> Option<serde_json::Value> {
    let offset = item
        .get("start_offset")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let bytes_hex = item.get("bytes_hex").and_then(|v| v.as_str())?;
    let byte = first_hex_byte(bytes_hex)?;
    let semantics = item
        .pointer("/chain/recognized_semantics")
        .and_then(|v| v.as_array())?;
    let mut first_mismatch: Option<serde_json::Value> = None;
    for entry in semantics {
        let semantic = entry.get("semantic")?;
        let kind = semantic.get("kind").and_then(|v| v.as_str())?;
        match kind {
            "xor_mix" => {
                let result = semantic
                    .get("result")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)?;
                let equation = serde_json::json!({
                    "offset": offset,
                    "bytes_hex": bytes_hex,
                    "kind": "xor_mix",
                    "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": entry.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "lhs": semantic.get("lhs").cloned().unwrap_or(serde_json::Value::Null),
                    "rhs": semantic.get("rhs").cloned().unwrap_or(serde_json::Value::Null),
                    "result": semantic.get("result").cloned().unwrap_or(serde_json::Value::Null),
                    "expression": "result == (lhs ^ rhs) & 0xff",
                    "matches_first_byte": (result & 0xff) as u8 == byte,
                });
                if equation.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(true) {
                    return Some(equation);
                }
                first_mismatch.get_or_insert(equation);
            }
            "mod255_low_byte" => {
                let output_byte = semantic
                    .get("output_byte")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)?;
                let equation = serde_json::json!({
                    "offset": offset,
                    "bytes_hex": bytes_hex,
                    "kind": "mod255_low_byte",
                    "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": entry.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "input": semantic.get("input").cloned().unwrap_or(serde_json::Value::Null),
                    "quotient": semantic.get("quotient").cloned().unwrap_or(serde_json::Value::Null),
                    "output_byte": semantic.get("output_byte").cloned().unwrap_or(serde_json::Value::Null),
                    "result": semantic.get("output_byte").cloned().unwrap_or(serde_json::Value::Null),
                    "expression": "result == (input + floor(input / 0xff)) & 0xff",
                    "matches_first_byte": (output_byte & 0xff) as u8 == byte,
                });
                if equation.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(true) {
                    return Some(equation);
                }
                first_mismatch.get_or_insert(equation);
            }
            _ => {}
        }
    }
    output_semantic_byte_lane_equation(item, offset.clone(), bytes_hex, byte)
        .or_else(|| {
            output_semantic_writer_byte_lane_equation(
                item,
                offset,
                bytes_hex,
                byte,
                first_mismatch.clone(),
            )
        })
        .or(first_mismatch)
}

pub(super) fn output_semantic_writer_byte_lane_equation(
    item: &serde_json::Value,
    offset: serde_json::Value,
    bytes_hex: &str,
    byte: u8,
    rejected_semantic: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let source_byte_offset = item
        .get("source_byte_offset")
        .or_else(|| item.pointer("/seed/byte_lane"))
        .and_then(value_as_u64)?;
    if source_byte_offset >= 8 {
        return None;
    }
    let src_value = item.pointer("/seed/src_value").and_then(value_as_u64)?;
    let result = ((src_value >> (source_byte_offset * 8)) & 0xff) as u8;
    if result != byte {
        return None;
    }
    Some(serde_json::json!({
        "offset": offset,
        "bytes_hex": bytes_hex,
        "kind": "writer_byte_lane_extract",
        "step": serde_json::Value::Null,
        "idx": item.pointer("/seed/idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": item.pointer("/seed/asm").cloned().unwrap_or(serde_json::Value::Null),
        "source_value": format!("{src_value:#x}"),
        "source_byte_offset": source_byte_offset,
        "result": format!("{result:#x}"),
        "expression": "result == byte_lane_le(writer_src_value, source_byte_offset)",
        "matches_first_byte": true,
        "rejected_semantic": rejected_semantic.unwrap_or(serde_json::Value::Null),
    }))
}

pub(super) fn output_semantic_byte_lane_equation(
    item: &serde_json::Value,
    offset: serde_json::Value,
    bytes_hex: &str,
    byte: u8,
) -> Option<serde_json::Value> {
    let steps = item.pointer("/chain/chain").and_then(|v| v.as_array())?;
    for entry in steps {
        let next = entry.get("next").unwrap_or(&serde_json::Value::Null);
        if next.get("reason").and_then(|v| v.as_str()) != Some("memory_load_byte") {
            continue;
        }
        let source_byte_offset = next.get("source_byte_offset").and_then(value_as_u64)?;
        if source_byte_offset >= 8 {
            continue;
        }
        let src_value = next.get("src_value").and_then(value_as_u64)?;
        if src_value <= 0xff {
            continue;
        }
        let result = ((src_value >> (source_byte_offset * 8)) & 0xff) as u8;
        if result != byte {
            continue;
        }
        return Some(serde_json::json!({
            "offset": offset,
            "bytes_hex": bytes_hex,
            "kind": "byte_lane_extract",
            "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": entry.pointer("/local_def/asm").or_else(|| entry.pointer("/target/asm")).cloned().unwrap_or(serde_json::Value::Null),
            "source_value": format!("{src_value:#x}"),
            "source_byte_offset": source_byte_offset,
            "result": format!("{result:#x}"),
            "expression": "result == byte_lane_le(source_value, source_byte_offset)",
            "matches_first_byte": true,
        }));
    }
    None
}

#[derive(Clone, Debug)]
pub(super) struct CompactByteEquation {
    pub(super) offset: u64,
    pub(super) kind: String,
    pub(super) result: u64,
    pub(super) lhs: Option<u64>,
    pub(super) rhs: Option<u64>,
    pub(super) output_byte: Option<u64>,
}
