use super::*;

pub(super) fn resolve_output_source(opts: &OutputBacktraceOpts) -> anyhow::Result<OutputSource> {
    if opts.value.is_some() == opts.bytes_hex.is_some() {
        bail!("choose exactly one of --value or --bytes-hex");
    }
    let (bytes, text, mut source) = if let Some(raw) = opts.bytes_hex.as_deref() {
        let bytes = parse_hex_bytes_cli(raw)?;
        let source = serde_json::json!({
            "kind": "bytes_hex", "bytes_hex": bytes_to_hex(&bytes), "length": bytes.len(),
        });
        (bytes, None, source)
    } else {
        let value = opts.value.as_ref().unwrap();
        if value.is_empty() {
            bail!("--value must not be empty");
        }
        (
            value.as_bytes().to_vec(),
            Some(value.clone()),
            serde_json::json!({
                "kind": "value", "value": value, "value_len": value.len(),
            }),
        )
    };
    source["at_idx"] = serde_json::json!(opts.at_idx);
    Ok(OutputSource {
        json: source,
        primary_bytes: bytes,
        text,
        value_idx: opts.at_idx,
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
    let mut hits = find_response
        .get("hits")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(value_idx) = value_idx {
        hits.sort_by_key(|hit| {
            hit.get("first_idx")
                .and_then(|v| v.as_u64())
                .map_or(usize::MAX, |idx| value_idx.abs_diff(idx as usize))
        });
    }
    hits
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

pub(super) fn run_backward_taint_summaries(
    context: &AnalysisContext,
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
        let params = crate::analysis::backward_taint::BackwardTaintQuery {
            start: usize::try_from(start)?,
            reg: reg.to_string(),
            through_mem: true,
            data_only: false,
            cross_fn_call: true,
            max_count: Some(max_count),
            ..Default::default()
        };
        let response = query_value_on(context, Query::BackwardTaint(params))?;
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
