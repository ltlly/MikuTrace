use super::*;

pub(super) fn output_semantic_xor_word_templates(
    equations: &serde_json::Value,
) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);

    let mut templates = Vec::new();
    for window in parsed.windows(4) {
        if let Some(template) = semantic_xor_word_template(window, &parsed) {
            templates.push(template);
        }
    }
    serde_json::Value::Array(templates)
}

pub(super) fn output_semantic_xor_word_degenerate_templates(
    equations: &serde_json::Value,
) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);

    let mut templates = Vec::new();
    for window in parsed.windows(4) {
        if let Some(template) = semantic_xor_word_zero_lane_template(window, &parsed) {
            templates.push(template);
        }
    }
    serde_json::Value::Array(templates)
}

pub(super) fn output_semantic_xor_word_run_templates(
    equations: &serde_json::Value,
) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);
    let chunks = semantic_xor_lhs_run_chunks(&parsed)
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| item.get("kind").and_then(|v| v.as_str()) == Some("word32"))
        .collect::<Vec<_>>();
    serde_json::Value::Array(chunks)
}

pub(super) fn compact_byte_equation(value: &serde_json::Value) -> Option<CompactByteEquation> {
    if value.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    let offset = value.get("offset").and_then(value_as_u64)?;
    let kind = value.get("kind")?.as_str()?.to_string();
    let result = value
        .get("result")
        .or_else(|| value.get("output_byte"))
        .and_then(value_as_u64)?;
    let lhs = value.get("lhs").and_then(value_as_u64);
    let rhs = value.get("rhs").and_then(value_as_u64);
    let output_byte = value.get("output_byte").and_then(value_as_u64);
    Some(CompactByteEquation {
        offset,
        kind,
        result,
        lhs,
        rhs,
        output_byte,
    })
}

pub(super) fn semantic_xor_word_template(
    window: &[CompactByteEquation],
    equations: &[CompactByteEquation],
) -> Option<serde_json::Value> {
    let start = window.first()?.offset;
    if !window
        .iter()
        .enumerate()
        .all(|(idx, item)| item.offset == start + idx as u64 && item.kind == "xor_mix")
    {
        return None;
    }

    let lhs = window
        .iter()
        .map(|item| item.lhs.map(|v| (v & 0xff) as u8))
        .collect::<Option<Vec<_>>>()?;
    let rhs = window
        .iter()
        .map(|item| item.rhs.map(|v| (v & 0xff) as u8))
        .collect::<Option<Vec<_>>>()?;
    let result = window
        .iter()
        .map(|item| (item.result & 0xff) as u8)
        .collect::<Vec<_>>();
    if result
        .iter()
        .zip(lhs.iter().zip(rhs.iter()))
        .any(|(out, (l, r))| *out != (*l ^ *r))
    {
        return None;
    }

    let rhs_pattern = if rhs[0] == rhs[2] && rhs[1] == rhs[3] {
        serde_json::json!({
            "kind": "alternating_two_byte_mask",
            "bytes_hex": bytes_to_hex(&rhs[..2]),
            "repeat_hex": bytes_to_hex(&rhs),
            "source_offsets": [
                equation_offset_for_byte(equations, start, rhs[0]),
                equation_offset_for_byte(equations, start, rhs[1]),
            ],
        })
    } else {
        serde_json::json!({
            "kind": "literal_bytes",
            "bytes_hex": bytes_to_hex(&rhs),
        })
    };

    Some(serde_json::json!({
        "semantic_range": [start, start + 4],
        "formula": "semantic[start..start+4] = word32_le(lhs_word_le) xor rhs_bytes",
        "lhs_bytes_hex": bytes_to_hex(&lhs),
        "lhs_word_le": format!("0x{:08x}", le_word_u32(&lhs)),
        "rhs_bytes_hex": bytes_to_hex(&rhs),
        "rhs_word_le": format!("0x{:08x}", le_word_u32(&rhs)),
        "rhs_pattern": rhs_pattern,
        "result_bytes_hex": bytes_to_hex(&result),
        "result_word_le": format!("0x{:08x}", le_word_u32(&result)),
    }))
}

pub(super) fn semantic_xor_word_zero_lane_template(
    window: &[CompactByteEquation],
    equations: &[CompactByteEquation],
) -> Option<serde_json::Value> {
    let start = window.first()?.offset;
    if !window
        .iter()
        .enumerate()
        .all(|(idx, item)| item.offset == start + idx as u64)
    {
        return None;
    }

    let mut lhs = Vec::new();
    let mut rhs = Vec::new();
    let mut result = Vec::new();
    let mut zero_lhs_offsets = Vec::new();
    let mut lane_kinds = Vec::new();
    for item in window {
        let out = (item.result & 0xff) as u8;
        if item.kind == "xor_mix" {
            let l = (item.lhs? & 0xff) as u8;
            let r = (item.rhs? & 0xff) as u8;
            if out != (l ^ r) {
                return None;
            }
            lhs.push(l);
            rhs.push(r);
            result.push(out);
            lane_kinds.push(serde_json::json!({
                "offset": item.offset,
                "kind": "xor_mix",
            }));
            continue;
        }

        let r = xor_rhs_byte_for_offset(equations, item.offset)?;
        if out != r {
            return None;
        }
        lhs.push(0);
        rhs.push(r);
        result.push(out);
        zero_lhs_offsets.push(item.offset);
        lane_kinds.push(serde_json::json!({
            "offset": item.offset,
            "kind": item.kind,
            "equivalent": "xor_mix(lhs=0, rhs=result)",
        }));
    }
    if zero_lhs_offsets.is_empty() || zero_lhs_offsets.len() == window.len() {
        return None;
    }

    Some(serde_json::json!({
        "kind": "word32_zero_lane",
        "semantic_range": [start, start + 4],
        "formula": "semantic[start..start+4] = word32_le(lhs_word_le) xor rhs_bytes, with zero-lhs lanes inferred from the parity mask",
        "lhs_bytes_hex": bytes_to_hex(&lhs),
        "lhs_word_le": format!("0x{:08x}", le_word_u32(&lhs)),
        "rhs_bytes_hex": bytes_to_hex(&rhs),
        "rhs_word_le": format!("0x{:08x}", le_word_u32(&rhs)),
        "result_bytes_hex": bytes_to_hex(&result),
        "result_word_le": format!("0x{:08x}", le_word_u32(&result)),
        "zero_lhs_offsets": zero_lhs_offsets,
        "lane_kinds": lane_kinds,
        "confidence": "equivalent_xor_with_zero_lhs_from_parity_mask",
    }))
}

pub(super) fn xor_rhs_byte_for_offset(
    equations: &[CompactByteEquation],
    offset: u64,
) -> Option<u8> {
    let mut values = Vec::new();
    for item in equations.iter().filter(|item| item.kind == "xor_mix") {
        if item.offset % 2 != offset % 2 {
            continue;
        }
        let rhs = (item.rhs? & 0xff) as u8;
        if !values.contains(&rhs) {
            values.push(rhs);
        }
    }
    if values.len() == 1 {
        values.first().copied()
    } else {
        None
    }
}

pub(super) fn equation_offset_for_byte(
    equations: &[CompactByteEquation],
    before_offset: u64,
    byte: u8,
) -> serde_json::Value {
    equations
        .iter()
        .rev()
        .find(|item| {
            item.offset < before_offset
                && (item.output_byte.or(Some(item.result)).unwrap_or_default() & 0xff) as u8 == byte
        })
        .map(|item| serde_json::json!(item.offset))
        .unwrap_or(serde_json::Value::Null)
}

pub(super) fn le_word_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .take(4)
        .enumerate()
        .fold(0u32, |acc, (idx, byte)| acc | ((*byte as u32) << (idx * 8)))
}

pub(super) fn output_semantic_xor_word_state_sources(
    value: &serde_json::Value,
    templates: &serde_json::Value,
) -> serde_json::Value {
    let Some(templates) = templates.as_array() else {
        return serde_json::json!([]);
    };
    let chains = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut sources = Vec::new();
    for template in templates {
        let Some(start) = template
            .get("semantic_range")
            .and_then(|v| v.as_array())
            .and_then(|range| range.first())
            .and_then(value_as_u64)
        else {
            continue;
        };
        let Some(chain) = chains
            .iter()
            .find(|chain| chain.get("start_offset").and_then(value_as_u64) == Some(start))
        else {
            continue;
        };
        let semantics = chain
            .pointer("/chain/recognized_semantics")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let lhs_word_le = template
            .get("lhs_word_le")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .map(|v| (v as u32).swap_bytes() as u64);
        let Some(source) = xor_word_source_from_semantics(&semantics, lhs_word_le) else {
            continue;
        };
        let source_status = if source
            .get("state_update")
            .is_some_and(|state_update| !state_update.is_null())
        {
            "state_update_found"
        } else {
            "word_source_only"
        };
        sources.push(serde_json::json!({
            "semantic_range": template.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
            "lhs_word_le": template.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
            "source_offset": start,
            "source_status": source_status,
            "source_word": source.get("source_word").cloned().unwrap_or(serde_json::Value::Null),
            "source_word_be": source.get("source_word_be").cloned().unwrap_or(serde_json::Value::Null),
            "source_word_match": source.get("source_word_match").cloned().unwrap_or(serde_json::Value::Null),
            "word_extract": source.get("word_extract").cloned().unwrap_or(serde_json::Value::Null),
            "state_update": source.get("state_update").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    serde_json::Value::Array(sources)
}

pub(super) fn output_semantic_xor_word_state_source_summary(
    templates: &serde_json::Value,
    sources: &serde_json::Value,
) -> serde_json::Value {
    let templates = templates.as_array().cloned().unwrap_or_default();
    let sources = sources.as_array().cloned().unwrap_or_default();
    let mut source_status_counts = BTreeMap::<String, usize>::new();
    let mut source_status_ranges = BTreeMap::<String, Vec<serde_json::Value>>::new();
    for source in &sources {
        let Some(status) = source.get("source_status").and_then(|v| v.as_str()) else {
            continue;
        };
        *source_status_counts.entry(status.to_string()).or_insert(0) += 1;
        source_status_ranges
            .entry(status.to_string())
            .or_default()
            .push(serde_json::json!({
                "semantic_range": source.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
                "lhs_word_le": source.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
                "source_word": source.get("source_word").cloned().unwrap_or(serde_json::Value::Null),
            }));
    }
    let source_starts = sources
        .iter()
        .filter_map(|source| {
            source
                .get("semantic_range")
                .and_then(|v| v.as_array())
                .and_then(|range| range.first())
                .and_then(value_as_u64)
        })
        .collect::<HashSet<_>>();
    let missing_templates = templates
        .iter()
        .filter_map(|template| {
            let range = template.get("semantic_range")?.as_array()?;
            let start = range.first().and_then(value_as_u64)?;
            if source_starts.contains(&start) {
                return None;
            }
            Some(serde_json::json!({
                "semantic_range": template.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
                "lhs_word_le": template.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "template_count": templates.len(),
        "source_count": sources.len(),
        "missing_count": missing_templates.len(),
        "coverage_status": if templates.is_empty() {
            "no_xor_word_templates"
        } else if missing_templates.is_empty() {
            "complete"
        } else {
            "partial"
        },
        "missing_templates": missing_templates,
        "source_status_counts": source_status_counts
            .into_iter()
            .map(|(status, count)| serde_json::json!({ "status": status, "count": count }))
            .collect::<Vec<_>>(),
        "source_status_ranges": source_status_ranges
            .into_iter()
            .map(|(status, ranges)| serde_json::json!({ "status": status, "ranges": ranges }))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn xor_word_source_from_semantics(
    semantics: &[serde_json::Value],
    expected_source_word_be: Option<u64>,
) -> Option<serde_json::Value> {
    let candidates = expected_source_word_be
        .map(xor_source_word_candidates)
        .unwrap_or_default();
    let word_extract = semantics
        .iter()
        .filter(|entry| {
            let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
            semantic.get("kind").and_then(|v| v.as_str()) == Some("shift_right")
                && semantic.get("shift").and_then(value_as_u64) == Some(0x18)
        })
        .find(|entry| {
            if candidates.is_empty() {
                return true;
            }
            let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
            semantic_word_candidate_match(semantic, &candidates, &["input"]).is_some()
        })
        .or_else(|| {
            semantics.iter().find(|entry| {
                let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
                semantic_word_candidate_match(semantic, &candidates, &["input", "result"]).is_some()
            })
        })?;
    let semantic = word_extract
        .get("semantic")
        .unwrap_or(&serde_json::Value::Null);
    let source_word = word_extract
        .pointer("/semantic/input")
        .and_then(value_as_u64)
        .or_else(|| {
            word_extract
                .pointer("/semantic/result")
                .and_then(value_as_u64)
        })?;
    let source_match = semantic_word_candidate_match(semantic, &candidates, &["input", "result"])
        .map(|(word, relation, field)| {
            serde_json::json!({
                "word": format!("{word:#x}"),
                "relation": relation,
                "field": field,
            })
        });
    let state_update = semantics.iter().find(|entry| {
        let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
        if semantic.get("kind").and_then(|v| v.as_str()) != Some("add32_mix") {
            return false;
        }
        semantic
            .get("result_low32")
            .or_else(|| semantic.get("result"))
            .and_then(value_as_u64)
            .is_some_and(|result| (result & 0xffff_ffff) == source_word)
    });
    Some(serde_json::json!({
        "source_word": format!("{source_word:#x}"),
        "source_word_be": format!("{source_word:#x}"),
        "source_word_match": source_match.unwrap_or(serde_json::Value::Null),
        "word_extract": word_extract,
        "state_update": state_update.cloned().unwrap_or(serde_json::Value::Null),
    }))
}

pub(super) fn xor_source_word_candidates(lhs_word_le_bswap: u64) -> Vec<(u64, &'static str)> {
    let be = lhs_word_le_bswap & 0xffff_ffff;
    let le = (be as u32).swap_bytes() as u64;
    if be == le {
        vec![(be, "lhs_word_le_or_bswap")]
    } else {
        vec![(be, "bswap_lhs_word_le"), (le, "lhs_word_le")]
    }
}

pub(super) fn semantic_word_candidate_match(
    semantic: &serde_json::Value,
    candidates: &[(u64, &'static str)],
    fields: &[&'static str],
) -> Option<(u64, &'static str, &'static str)> {
    for field in fields {
        let Some(value) = semantic.get(*field).and_then(value_as_u64) else {
            continue;
        };
        let value = value & 0xffff_ffff;
        for (candidate, relation) in candidates {
            if value == *candidate {
                return Some((value, *relation, *field));
            }
        }
    }
    None
}

pub(super) fn first_hex_byte(hex: &str) -> Option<u8> {
    let compact = hex
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if compact.len() < 2 {
        return None;
    }
    u8::from_str_radix(&compact[..2], 16).ok()
}

pub(super) fn output_semantic_vm_chain_summaries(value: &serde_json::Value) -> serde_json::Value {
    let chains = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_semantic_vm_chain_summary)
        .collect::<Vec<_>>();
    serde_json::Value::Array(chains)
}

pub(super) fn output_semantic_vm_chain_summary(item: &serde_json::Value) -> serde_json::Value {
    let semantics = item
        .pointer("/chain/recognized_semantics")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let semantic_kinds = semantics
        .iter()
        .filter_map(|entry| {
            entry
                .get("semantic")
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    serde_json::json!({
        "start_offset": item.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": item.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": item.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": item.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": item.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offset": item.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": item.get("source_byte_offsets").cloned().unwrap_or(serde_json::Value::Null),
        "writer_idx": item.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
        "seed": item.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_kinds": semantic_kinds,
        "recognized_semantics": semantics,
    })
}

pub(super) fn output_map_group_summary(group: &serde_json::Value) -> serde_json::Value {
    let indices = group
        .pointer("/base64/indices")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            serde_json::json!({
                "pos": item.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                "char": item.get("char").cloned().unwrap_or(serde_json::Value::Null),
                "index_hex": item.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let decoded = group
        .pointer("/base64/decoded_bytes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            serde_json::json!({
                "byte": item.get("byte").cloned().unwrap_or(serde_json::Value::Null),
                "value_hex": item.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "formula": item.get("formula").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let lookups = group
        .get("base64_lookup_matches")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_lookup_summary)
        .collect::<Vec<_>>();
    let decoded_payload = output_map_decoded_payload_summary(group, &lookups);
    let trees = group
        .get("trees")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_tree_summary)
        .collect::<Vec<_>>();
    let payload_formula_table = output_map_payload_formula_table(&decoded_payload);
    serde_json::json!({
        "group": group.get("group").cloned().unwrap_or(serde_json::Value::Null),
        "offset": group.get("offset").cloned().unwrap_or(serde_json::Value::Null),
        "end": group.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "original_output_start": group.get("original_output_start").cloned().unwrap_or(serde_json::Value::Null),
        "original_output_end": group.get("original_output_end").cloned().unwrap_or(serde_json::Value::Null),
        "chars": group.get("chars").cloned().unwrap_or(serde_json::Value::Null),
        "decoded_hex": group.get("decoded_hex").cloned().unwrap_or(serde_json::Value::Null),
        "indices": indices,
        "decoded": decoded,
        "decoded_payload": decoded_payload,
        "payload_formula_table": payload_formula_table,
        "lookups": lookups,
        "trees": trees,
    })
}

pub(super) fn output_map_tree_summary(item: &serde_json::Value) -> serde_json::Value {
    let tree = item
        .get("tree")
        .map(vm_backtree_summary)
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "seed": item.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "tree": tree,
    })
}
