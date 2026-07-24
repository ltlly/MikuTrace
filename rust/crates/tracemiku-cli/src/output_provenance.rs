use super::*;

pub(super) fn output_map_decoded_payload_summary(
    group: &serde_json::Value,
    lookups: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let decoded_base = group
        .get("decoded_offset_base")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| group.get("group").and_then(|v| v.as_u64()).unwrap_or(0) * 3);
    let semantic_drop = group
        .get("semantic_drop_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    group
        .pointer("/base64/decoded_bytes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            let byte_idx = item.get("byte").and_then(|v| v.as_u64()).unwrap_or(0);
            let aligned_decoded_offset = decoded_base.saturating_add(byte_idx);
            let semantic_offset = aligned_decoded_offset.checked_sub(semantic_drop);
            let index_sources = item
                .get("indices")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|idx| idx.as_u64())
                .filter_map(|idx| {
                    lookups
                        .iter()
                        .find(|lookup| lookup.get("pos").and_then(|v| v.as_u64()) == Some(idx))
                        .map(compact_lookup_source_for_payload)
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "payload_offset": aligned_decoded_offset,
                "aligned_decoded_offset": aligned_decoded_offset,
                "semantic_offset": semantic_offset,
                "dropped_by_alignment": semantic_offset.is_none(),
                "byte_in_group": byte_idx,
                "value_hex": item.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "formula": item.get("formula").cloned().unwrap_or(serde_json::Value::Null),
                "index_sources": index_sources,
            })
        })
        .collect()
}

pub(super) fn output_map_payload_formula_table(
    decoded_payload: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    decoded_payload
        .iter()
        .filter(|row| {
            row.get("dropped_by_alignment")
                .and_then(|v| v.as_bool())
                != Some(true)
        })
        .map(|row| {
            let index_sources = row
                .get("index_sources")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .map(|source| {
                    serde_json::json!({
                        "pos": source.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                        "char": source.get("char").cloned().unwrap_or(serde_json::Value::Null),
                        "index_hex": source.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
                        "match_count": source.get("match_count").cloned().unwrap_or(serde_json::Value::Null),
                        "interesting": formula_expression_list(source.pointer("/formulas/interesting")),
                        "semantic": formula_expression_list(source.pointer("/formulas/semantic")),
                        "interesting_refs": formula_reference_list(source.pointer("/formulas/interesting")),
                        "semantic_refs": formula_reference_list(source.pointer("/formulas/semantic")),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "semantic_offset": row.get("semantic_offset").cloned().unwrap_or(serde_json::Value::Null),
                "payload_offset": row.get("payload_offset").cloned().unwrap_or(serde_json::Value::Null),
                "value_hex": row.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "base64_formula": row.get("formula").cloned().unwrap_or(serde_json::Value::Null),
                "index_sources": index_sources,
            })
        })
        .collect()
}

pub(super) fn formula_expression_list(value: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    value
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|formula| {
            formula
                .get("expression")
                .cloned()
                .or_else(|| formula.get("asm").cloned())
        })
        .take(4)
        .collect()
}

pub(super) fn formula_reference_list(value: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    value
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .take(4)
        .map(|formula| {
            let idx = formula
                .get("idx")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let reg = formula
                .get("reg")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let continue_with = if idx.is_null() || reg.is_null() {
                serde_json::Value::Null
            } else {
                serde_json::json!({
                    "cmd": "vm-backtree",
                    "idx": idx,
                    "reg": reg,
                })
            };
            serde_json::json!({
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": formula.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": formula.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "expression": formula
                    .get("expression")
                    .cloned()
                    .or_else(|| formula.get("asm").cloned())
                    .unwrap_or(serde_json::Value::Null),
                "kind": formula
                    .pointer("/semantic/kind")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "continue_with": continue_with,
            })
        })
        .collect()
}

pub(super) fn compact_lookup_source_for_payload(lookup: &serde_json::Value) -> serde_json::Value {
    let formulas = lookup
        .get("matches")
        .and_then(|v| v.as_array())
        .and_then(|matches| matches.first())
        .map(|first| {
            let interesting = first
                .get("interesting_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            let semantic = first
                .get("semantic_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::json!({
                "interesting": interesting,
                "semantic": semantic,
            })
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "interesting": [],
                "semantic": [],
            })
        });
    serde_json::json!({
        "pos": lookup.get("pos").cloned().unwrap_or(serde_json::Value::Null),
        "char": lookup.get("char").cloned().unwrap_or(serde_json::Value::Null),
        "index_hex": lookup.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
        "match_count": lookup.get("match_count").cloned().unwrap_or(serde_json::Value::Null),
        "formulas": formulas,
    })
}

pub(super) fn output_map_lookup_summary(lookup: &serde_json::Value) -> serde_json::Value {
    let matches = lookup
        .get("matches")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            let interesting = item
                .pointer("/index_summary/interesting_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(6)
                .map(compact_formula_summary)
                .collect::<Vec<_>>();
            let semantic = item
                .pointer("/index_summary/semantic_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(6)
                .map(compact_formula_summary)
                .collect::<Vec<_>>();
            serde_json::json!({
                "idx": item.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": item.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "index_reg": item.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                "base_value": item.get("base_value").cloned().unwrap_or(serde_json::Value::Null),
                "interesting_formulas": interesting,
                "semantic_formulas": semantic,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "pos": lookup.get("pos").cloned().unwrap_or(serde_json::Value::Null),
        "char": lookup.get("char").cloned().unwrap_or(serde_json::Value::Null),
        "index_hex": lookup.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
        "match_count": lookup
            .get("matches")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0),
        "matches": matches,
    })
}

pub(super) fn compact_formula_summary(formula: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": formula.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": formula.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
        "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) async fn output_runs_overlapping(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    start: usize,
    end: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for run in writer_runs {
        let run_start = run.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let run_len = run.get("length").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let run_end = run_start.saturating_add(run_len);
        if run_start >= end || run_end <= start {
            continue;
        }
        let mut row = run.clone();
        if row
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .is_none_or(|items| items.is_empty())
        {
            if let Some(idx) = row.get("writer_idx").and_then(|v| v.as_u64()) {
                let record = route_get_json_value_on(app, format!("/api/record/{idx}")).await?;
                row["record"] = record.clone();
                row["writer_seeds"] =
                    serde_json::Value::Array(writer_taint_seeds_from_record(&record));
            }
        }
        out.push(row);
    }
    Ok(out)
}

pub(super) async fn resolve_output_source(
    app: &axum::Router,
    opts: &OutputBacktraceOpts,
) -> anyhow::Result<OutputSource> {
    let source_count = opts.key.is_some() as usize
        + opts.value.is_some() as usize
        + opts.bytes_hex.is_some() as usize;
    if source_count != 1 {
        bail!("choose exactly one of --key, --value, or --bytes-hex");
    }

    if let Some(raw) = opts.bytes_hex.as_deref() {
        let bytes = parse_hex_bytes_cli(raw)?;
        return Ok(OutputSource {
            json: serde_json::json!({
                "kind": "bytes_hex",
                "bytes_hex": bytes_to_hex(&bytes),
                "length": bytes.len(),
            }),
            primary_bytes: bytes,
            text: None,
            value_idx: None,
        });
    }

    if let Some(value) = opts.value.as_deref() {
        return Ok(OutputSource {
            json: serde_json::json!({
                "kind": "value",
                "value": value,
                "value_len": value.len(),
            }),
            primary_bytes: value.as_bytes().to_vec(),
            text: Some(value.to_string()),
            value_idx: None,
        });
    }

    let key = opts.key.as_deref().unwrap_or_default();
    let pairs =
        jni_output_string_pairs_on(app, Some(key.to_string()), None, opts.jni_limit).await?;
    let pair = pairs
        .get("pairs")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .cloned()
        .with_context(|| format!("no NewStringUTF key/value pair matched key {key:?}"))?;
    let value = pair
        .get("value")
        .and_then(|v| v.as_str())
        .context("matched pair missing value")?;
    let value_idx = pair
        .get("value_idx")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    Ok(OutputSource {
        json: serde_json::json!({
            "kind": "jni_output_string_pair",
            "key": key,
            "pair": pair,
            "source_events": pairs.get("source_events").cloned().unwrap_or(serde_json::Value::Null),
            "source_truncated": pairs.get("source_truncated").cloned().unwrap_or(serde_json::Value::Null),
        }),
        primary_bytes: value.as_bytes().to_vec(),
        text: Some(value.to_string()),
        value_idx,
    })
}

pub(super) fn writer_taint_seeds_from_record(record: &serde_json::Value) -> Vec<serde_json::Value> {
    let Some(idx) = record.get("idx").and_then(|v| v.as_u64()) else {
        return Vec::new();
    };
    let Some(asm) = record.get("asm").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    store_source_regs_from_asm(asm)
        .into_iter()
        .map(|reg| {
            let reg_key = register_value_key(&reg);
            let src_value = record
                .get("regs")
                .and_then(|v| v.get(&reg_key))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "kind": "memory_writer_src_reg",
                "start": idx,
                "reg": reg,
                "src_value": src_value,
                "writer": {
                    "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "pc": record.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                    "rel": record.get("rel").cloned().unwrap_or(serde_json::Value::Null),
                    "func": record.get("func").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": record.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                },
            })
        })
        .collect()
}

pub(super) fn store_source_regs_from_asm(asm: &str) -> Vec<String> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let Some(mnemonic) = parts.next() else {
        return Vec::new();
    };
    let Some(operands) = parts.next() else {
        return Vec::new();
    };
    let mnemonic = mnemonic.to_ascii_lowercase();
    let operands = split_operands(operands);
    let source_ops: Vec<String> = if matches!(mnemonic.as_str(), "stp" | "stnp") {
        operands.into_iter().take(2).collect()
    } else if matches!(mnemonic.as_str(), "stxp" | "stlxp") {
        operands.into_iter().skip(1).take(2).collect()
    } else if matches!(mnemonic.as_str(), "stxr" | "stlxr") {
        operands.into_iter().skip(1).take(1).collect()
    } else if mnemonic.starts_with("str")
        || mnemonic.starts_with("stur")
        || mnemonic.starts_with("sttr")
        || mnemonic.starts_with("stlr")
    {
        operands.into_iter().take(1).collect()
    } else {
        Vec::new()
    };
    source_ops
        .into_iter()
        .filter_map(|op| first_register_token(&op))
        .collect()
}

pub(super) fn split_operands(operands: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut bracket_depth = 0i32;
    for (idx, ch) in operands.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            ',' if bracket_depth == 0 => {
                out.push(operands[start..idx].trim().to_string());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start < operands.len() {
        out.push(operands[start..].trim().to_string());
    }
    out
}

pub(super) fn first_register_token(op: &str) -> Option<String> {
    let token = op
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == '[' || ch == ']')
        .find(|part| !part.is_empty())?;
    let token = token.trim_end_matches('!').to_ascii_lowercase();
    is_gp_register_token(&token).then_some(token)
}

pub(super) fn register_value_key(reg: &str) -> String {
    let reg = reg.to_ascii_lowercase();
    if let Some(rest) = reg.strip_prefix('w') {
        if rest.parse::<u8>().is_ok() {
            return match rest {
                "29" => "fp".to_string(),
                "30" => "lr".to_string(),
                _ => format!("x{rest}"),
            };
        }
    }
    match reg.as_str() {
        "x29" => "fp".to_string(),
        "x30" => "lr".to_string(),
        "wsp" => "sp".to_string(),
        "wzr" => "xzr".to_string(),
        other => other.to_string(),
    }
}

pub(super) fn provenance_writer_counts(
    provenance: &serde_json::Value,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    if let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) {
        for byte in bytes {
            if let Some(idx) = byte.get("current_writer_idx").and_then(|v| v.as_u64()) {
                *counts.entry(idx as usize).or_default() += 1;
            }
        }
    }
    if counts.is_empty() {
        if let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) {
            for byte in bytes {
                if let Some(writers) = byte.get("writers").and_then(|v| v.as_array()) {
                    for writer in writers {
                        if let Some(idx) = writer.as_u64() {
                            *counts.entry(idx as usize).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    let mut rows: Vec<_> = counts
        .into_iter()
        .map(|(idx, byte_count)| serde_json::json!({ "idx": idx, "byte_count": byte_count }))
        .collect();
    rows.sort_by(|a, b| {
        let ac = a.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bc = b.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            a.get("idx")
                .and_then(|v| v.as_u64())
                .cmp(&b.get("idx").and_then(|v| v.as_u64()))
        })
    });
    rows.into_iter().take(limit).collect()
}

pub(super) fn sorted_pattern_hits(
    find_response: &serde_json::Value,
    value_idx: Option<usize>,
) -> Vec<serde_json::Value> {
    sorted_pattern_hits_by(find_response, value_idx, HitOrder::Nearest)
}

pub(super) fn sorted_pattern_hits_by(
    find_response: &serde_json::Value,
    value_idx: Option<usize>,
    order: HitOrder,
) -> Vec<serde_json::Value> {
    let mut hits = find_response
        .get("hits")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    match order {
        HitOrder::Earliest => hits.sort_by_key(|hit| {
            hit.get("first_idx")
                .and_then(|v| v.as_u64())
                .map(|idx| idx as usize)
                .unwrap_or(usize::MAX)
        }),
        HitOrder::Nearest => {
            if let Some(value_idx) = value_idx {
                hits.sort_by_key(|hit| {
                    hit.get("first_idx")
                        .and_then(|v| v.as_u64())
                        .map(|idx| value_idx.abs_diff(idx as usize))
                        .unwrap_or(usize::MAX)
                });
            }
        }
        HitOrder::Latest => hits.sort_by_key(|hit| {
            std::cmp::Reverse(
                hit.get("first_idx")
                    .and_then(|v| v.as_u64())
                    .map(|idx| idx as usize)
                    .unwrap_or(0),
            )
        }),
    }
    hits
}

pub(super) fn hit_candidate_summaries(
    hits: &[serde_json::Value],
    value_idx: Option<usize>,
) -> Vec<serde_json::Value> {
    hits.iter()
        .enumerate()
        .map(|(rank, hit)| {
            let first_idx = hit
                .get("first_idx")
                .and_then(|v| v.as_u64())
                .map(|idx| idx as usize);
            serde_json::json!({
                "rank": rank,
                "addr": hit.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "first_idx": first_idx,
                "distance_to_value_idx": value_idx.and_then(|idx| first_idx.map(|first| idx.abs_diff(first))),
            })
        })
        .collect()
}

pub(super) fn provenance_writer_runs(
    provenance: &serde_json::Value,
    writer_details: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut details_by_idx = BTreeMap::new();
    for detail in writer_details {
        if let Some(idx) = detail
            .get("writer")
            .and_then(|v| v.get("idx"))
            .and_then(|v| v.as_u64())
        {
            details_by_idx.insert(idx, detail);
        }
    }

    let mut runs: Vec<(Option<u64>, usize, Vec<u8>)> = Vec::new();
    let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut current_idx: Option<u64> = None;
    for byte in bytes {
        let idx = byte.get("current_writer_idx").and_then(|v| v.as_u64());
        let offset = byte.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let b = byte.get("byte").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        if runs.last().is_none_or(|(run_idx, _, _)| *run_idx != idx) {
            runs.push((idx, offset, Vec::new()));
            current_idx = idx;
        }
        if current_idx == idx {
            if let Some((_, _, data)) = runs.last_mut() {
                data.push(b);
            }
        }
    }

    runs.into_iter()
        .map(|(writer_idx, offset, data)| {
            let detail = writer_idx.and_then(|idx| details_by_idx.get(&idx));
            serde_json::json!({
                "offset": offset,
                "length": data.len(),
                "writer_idx": writer_idx,
                "bytes_hex": bytes_to_hex(&data),
                "text": utf8_preview(&data, 80),
                "record": detail
                    .and_then(|v| v.get("record"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "writer_seeds": detail
                    .and_then(|v| v.get("writer_seeds"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            })
        })
        .collect()
}

pub(super) async fn vm_chains_for_writer_runs(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    opts: &OutputBacktraceOpts,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
    let mut out = Vec::new();
    for run in writer_runs.iter().take(opts.vm_chain_runs) {
        let mut seed_value = run
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .and_then(|seeds| {
                seeds.iter().find(|seed| {
                    seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                })
            })
            .cloned();
        let fetched_record = if seed_value.is_none() {
            if let Some(idx) = run.get("writer_idx").and_then(|v| v.as_u64()) {
                let record = route_get_json_value_on(app, format!("/api/record/{idx}")).await?;
                let seeds = writer_taint_seeds_from_record(&record);
                seed_value = seeds
                    .iter()
                    .find(|seed| {
                        seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                    })
                    .cloned();
                Some(serde_json::json!({
                    "record": record,
                    "writer_seeds": seeds,
                }))
            } else {
                None
            }
        } else {
            None
        };
        let Some(seed_value) = seed_value else {
            out.push(serde_json::json!({
                "offset": run.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "length": run.get("length").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": run.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "fetched_record": fetched_record,
                "status": "no_writer_seed",
            }));
            continue;
        };
        let Some(start) = seed_value.get("start").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = seed_value.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let chain = vm_backchain_value_on(
            app,
            start as usize,
            Some(reg.to_string()),
            opts.vm_chain_steps,
            120,
            opts.vm_chain_lookback,
            5000,
            opts.vm_chain_follow_frontier,
            None,
            regs.to_string(),
            &opts.vm_profile,
        )
        .await?;
        out.push(serde_json::json!({
            "offset": run.get("offset").cloned().unwrap_or(serde_json::Value::Null),
            "length": run.get("length").cloned().unwrap_or(serde_json::Value::Null),
            "text": run.get("text").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": run.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
            "seed": seed_value,
            "chain": chain,
        }));
    }
    Ok(out)
}

pub(super) async fn vm_chains_for_byte_writer_runs(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    steps: usize,
    max_runs: usize,
    lookback: usize,
    follow_frontier: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
    let mut out = Vec::new();
    for run in writer_runs.iter().take(max_runs) {
        let writer = run.get("writer").unwrap_or(&serde_json::Value::Null);
        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
            out.push(serde_json::json!({
                "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
                "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
                "status": "no_writer_idx",
            }));
            continue;
        };
        let Some(reg) = writer.get("src_reg").and_then(|v| v.as_str()) else {
            out.push(serde_json::json!({
                "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
                "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": idx,
                "status": "no_source_reg",
                "writer": writer,
            }));
            continue;
        };
        let chain = vm_backchain_value_on(
            app,
            idx as usize,
            Some(reg.to_string()),
            steps,
            120,
            lookback,
            5000,
            follow_frontier,
            byte_lane_from_writer_run(run),
            regs.to_string(),
            profile,
        )
        .await?;
        let seed_byte_lane = byte_lane_from_writer_run(run);
        out.push(serde_json::json!({
            "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
            "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
            "size": run.get("size").cloned().unwrap_or(serde_json::Value::Null),
            "bytes_hex": run.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "ascii": run.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offsets": run.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
            "writer_idx": idx,
            "seed": {
                "idx": idx,
                "reg": reg,
                "byte_lane": seed_byte_lane,
                "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            },
            "chain": vm_backchain_summary(&chain),
        }));
    }
    Ok(out)
}

pub(super) async fn vm_chains_for_byte_writer_entries(
    app: &axum::Router,
    bytes: &[serde_json::Value],
    steps: usize,
    max_bytes: usize,
    lookback: usize,
    follow_frontier: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
    let mut out = Vec::new();
    for entry in bytes.iter().take(max_bytes) {
        let offset = entry
            .get("offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let writer = entry.get("writer").unwrap_or(&serde_json::Value::Null);
        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
            out.push(serde_json::json!({
                "start_offset": offset,
                "end_offset": offset,
                "size": 1,
                "status": "no_writer_idx",
            }));
            continue;
        };
        let Some(reg) = writer.get("src_reg").and_then(|v| v.as_str()) else {
            out.push(serde_json::json!({
                "start_offset": offset,
                "end_offset": offset,
                "size": 1,
                "writer_idx": idx,
                "status": "no_source_reg",
                "writer": writer,
            }));
            continue;
        };
        let seed_byte_lane = byte_lane_from_writer_map_entry(entry);
        let chain = vm_backchain_value_on(
            app,
            idx as usize,
            Some(reg.to_string()),
            steps,
            120,
            lookback,
            5000,
            follow_frontier,
            seed_byte_lane,
            regs.to_string(),
            profile,
        )
        .await?;
        let byte_hex = entry
            .get("byte_hex")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(serde_json::json!({
            "start_offset": offset,
            "end_offset": offset,
            "size": 1,
            "bytes_hex": byte_hex,
            "ascii": entry.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": entry.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offsets": [
                entry.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null)
            ],
            "addr": entry.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": idx,
            "seed": {
                "idx": idx,
                "reg": reg,
                "byte_lane": seed_byte_lane,
                "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            },
            "chain": vm_backchain_summary(&chain),
        }));
    }
    Ok(out)
}

pub(super) fn byte_lane_from_writer_run(run: &serde_json::Value) -> Option<usize> {
    run.get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            run.get("source_byte_offsets")
                .and_then(|v| v.as_array())
                .and_then(|items| items.first())
                .and_then(|v| v.as_u64())
        })
        .map(|v| v as usize)
}

pub(super) fn byte_lane_from_writer_map_entry(entry: &serde_json::Value) -> Option<usize> {
    entry
        .get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
}

pub(super) fn vm_chain_batch_summary(chains: &[serde_json::Value]) -> serde_json::Value {
    let mut semantic_counts = BTreeMap::<String, usize>::new();
    let mut pattern_counts = BTreeMap::<String, usize>::new();
    for chain in chains {
        if let Some(semantics) = chain
            .pointer("/chain/recognized_semantics")
            .and_then(|v| v.as_array())
        {
            for item in semantics {
                if let Some(kind) = item
                    .get("semantic")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                {
                    *semantic_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }
        if let Some(patterns) = chain
            .pointer("/chain/recognized_patterns")
            .and_then(|v| v.as_array())
        {
            for item in patterns {
                if let Some(kind) = item.get("kind").and_then(|v| v.as_str()) {
                    *pattern_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    serde_json::json!({
        "chain_count": chains.len(),
        "semantic_kind_counts": semantic_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "pattern_counts": pattern_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn push_taint_seed(
    seen: &mut HashSet<String>,
    queue: &mut Vec<serde_json::Value>,
    seed: serde_json::Value,
) {
    let Some(start) = seed.get("start").and_then(|v| v.as_u64()) else {
        return;
    };
    let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
        return;
    };
    if seen.insert(format!("{start}:{reg}")) {
        queue.push(seed);
    }
}

pub(super) async fn run_backward_taint_summaries(
    app: &axum::Router,
    seeds: &[serde_json::Value],
    max_seeds: usize,
    max_count: usize,
) -> anyhow::Result<serde_json::Value> {
    let mut runs = Vec::new();
    for seed in seeds.iter().take(max_seeds) {
        let Some(start) = seed.get("start").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let params = vec![
            ("start", start.to_string()),
            ("reg", reg.to_string()),
            ("through_mem", "true".to_string()),
            ("data_only", "false".to_string()),
            ("cross_fn_call", "true".to_string()),
            ("max_count", max_count.to_string()),
        ];
        let response =
            route_get_json_value_on(app, route_path("/api/backward-taint", &params)).await?;
        runs.push(serde_json::json!({
            "seed": seed,
            "summary": summarize_backward_taint(&response),
        }));
    }
    Ok(serde_json::json!({
        "skipped": false,
        "queued": seeds.len(),
        "returned": runs.len(),
        "truncated_seed_list": seeds.len() > runs.len(),
        "runs": runs,
    }))
}

pub(super) fn summarize_backward_taint(response: &serde_json::Value) -> serde_json::Value {
    let rows = response
        .get("chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in &rows {
        let func = row
            .get("func")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        *counts.entry(func.to_string()).or_default() += 1;
    }
    let mut function_counts: Vec<_> = counts
        .into_iter()
        .map(|(func, count)| serde_json::json!({ "func": func, "count": count }))
        .collect();
    function_counts.sort_by(|a, b| {
        let ac = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bc = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            a.get("func")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("func").and_then(|v| v.as_str()).unwrap_or(""))
        })
    });

    let sample_chain: Vec<_> = rows
        .iter()
        .take(40)
        .map(|row| {
            serde_json::json!({
                "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "pc": row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "via": row.get("via").cloned().unwrap_or(serde_json::Value::Null),
                "taint_depth": row.get("taint_depth").cloned().unwrap_or(serde_json::Value::Null),
                "parent_idxs": row.get("parent_idxs").cloned().unwrap_or(serde_json::json!([])),
            })
        })
        .collect();

    serde_json::json!({
        "status": response.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "from": response.get("from").cloned().unwrap_or(serde_json::Value::Null),
        "reg": response.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "count": response.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "stopped_at_max": response.get("stopped_at_max").cloned().unwrap_or(serde_json::Value::Null),
        "max_count_used": response.get("max_count_used").cloned().unwrap_or(serde_json::Value::Null),
        "function_counts": function_counts.into_iter().take(30).collect::<Vec<_>>(),
        "sample_chain": sample_chain,
    })
}
