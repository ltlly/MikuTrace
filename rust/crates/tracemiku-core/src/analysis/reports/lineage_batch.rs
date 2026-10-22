use super::*;

#[allow(clippy::too_many_arguments)]
pub fn vm_backstep(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let analysis = AnalysisContext::load(trace_dir)?;
    let value = vm_backstep_value_on(
        &analysis, idx, reg, context, lookback, max_writes, regs, &profile,
    )?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn byte_lineage(
    trace_dir: PathBuf,
    addr: String,
    before_idx: usize,
    count: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    summary: bool,
    compact: bool,
    profile: VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let addr = parse_addr_str(&addr).with_context(|| format!("parse addr {addr}"))?;
    if count == 0 {
        bail!("--count must be at least 1");
    }
    if count > 4096 {
        bail!("--count is capped at 4096 bytes");
    }
    let analysis = AnalysisContext::load(trace_dir)?;
    if count > 1 {
        let mut results = Vec::with_capacity(count);
        // 逐字节串行执行：分析上下文 已在循环外构建一次（每次 build 都要
        // 加载 Trace + MemShadow），循环内只剩路由调用成本。保持串行是
        // 为了结果按 offset 有序、单字节失败互不影响；如需并发应改成
        // 有界窗口（如 8），但那需要为本 crate 引入 futures 依赖，暂不做。
        for offset in 0..count {
            let byte_addr = addr + offset as u64;
            let entry = match byte_lineage_value_on(
                &analysis,
                byte_addr,
                before_idx,
                depth,
                context,
                lookback,
                max_writes,
                regs.clone(),
                &profile,
            ) {
                Ok(value) => {
                    let origin = derive_byte_origin_from_value(&value);
                    let lineage = if compact {
                        byte_lineage_compact_summary(&value)
                    } else if summary {
                        byte_lineage_summary(&value)
                    } else {
                        value
                    };
                    LineageRow {
                        offset,
                        addr: format!("{byte_addr:#x}"),
                        lineage,
                        origin,
                    }
                }
                Err(err) => LineageRow {
                    offset,
                    addr: format!("{byte_addr:#x}"),
                    lineage: serde_json::json!({
                        "status": "error",
                        "error": format!("{err:#}"),
                    }),
                    origin: ByteOrigin::Unknown,
                },
            };
            results.push(entry);
        }
        let error_count = results
            .iter()
            .filter(|entry| {
                entry.lineage.pointer("/status").and_then(|v| v.as_str()) == Some("error")
            })
            .count();
        let status = if error_count > 0 {
            "partial_error"
        } else {
            "ready"
        };
        let mut decision_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut upstream_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut step_values = Vec::new();
        // batch_lineage_decision/upstream read `/lineage/...` paths, so feed
        // them the serialized rows (same shape as the previous json! rows).
        let rows_value = serde_json::to_value(&results)?;
        let rows = rows_value.as_array().cloned().unwrap_or_default();
        for entry in &rows {
            let decision = batch_lineage_decision(entry);
            *decision_counts.entry(decision.clone()).or_default() += 1;
            let upstream = batch_lineage_upstream(entry, &decision);
            *upstream_counts.entry(upstream).or_default() += 1;
            if let Some(steps) = entry
                .pointer("/lineage/steps_returned")
                .and_then(|v| v.as_u64())
            {
                step_values.push(steps);
            }
        }
        let count_rows = |counts: BTreeMap<String, usize>, key: &str| {
            counts
                .into_iter()
                .map(|(name, count)| serde_json::json!({ key: name, "count": count }))
                .collect::<Vec<_>>()
        };
        let step_stats = if step_values.is_empty() {
            serde_json::Value::Null
        } else {
            let min = step_values.iter().min().copied().unwrap_or(0);
            let max = step_values.iter().max().copied().unwrap_or(0);
            let avg = step_values.iter().copied().sum::<u64>() as f64 / step_values.len() as f64;
            serde_json::json!({
                "min": min,
                "max": max,
                "avg": avg,
            })
        };
        let mode = if compact {
            "compact".to_string()
        } else if summary {
            "summary".to_string()
        } else {
            "full".to_string()
        };
        let frontier_groups = byte_lineage_batch_frontier_groups(&rows);
        return Ok(serde_json::to_value(LineageBatchReport {
            status: status.to_string(),
            start_addr: format!("{addr:#x}"),
            before_idx,
            count,
            mode,
            error_count,
            decision_counts: count_rows(decision_counts, "decision"),
            upstream_counts: count_rows(upstream_counts, "upstream"),
            step_stats,
            frontier_groups,
            results,
        })?);
    }
    let value = byte_lineage_value_on(
        &analysis, addr, before_idx, depth, context, lookback, max_writes, regs, &profile,
    )?;
    if compact {
        Ok(byte_lineage_compact_summary(&value))
    } else if summary {
        Ok(byte_lineage_summary(&value))
    } else {
        Ok(value)
    }
}

#[derive(Default)]
pub(super) struct ByteLineageBatchGroup {
    pub(super) offsets: Vec<usize>,
    pub(super) addrs: Vec<String>,
    pub(super) addr_values: Vec<u64>,
    pub(super) steps: Vec<u64>,
    pub(super) terminal_addrs: BTreeMap<String, usize>,
    pub(super) observed_bytes: BTreeMap<String, usize>,
    pub(super) repeated_values: BTreeMap<String, (usize, u64)>,
    pub(super) stable_pointer_loops: BTreeMap<String, (usize, u64)>,
    pub(super) representative: Option<serde_json::Value>,
}

pub(super) fn byte_lineage_batch_frontier_groups(
    results: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut groups = BTreeMap::<(String, String), ByteLineageBatchGroup>::new();
    for entry in results {
        let decision = batch_lineage_decision(entry);
        let upstream = batch_lineage_upstream(entry, &decision);
        let group = groups.entry((decision, upstream)).or_default();
        if let Some(offset) = entry.get("offset").and_then(value_as_u64) {
            group.offsets.push(offset as usize);
        }
        if let Some(addr) = entry.get("addr").and_then(|v| v.as_str()) {
            group.addrs.push(addr.to_string());
            if let Some(addr_value) = parse_addr_str(addr) {
                group.addr_values.push(addr_value);
            }
        }
        if let Some(steps) = entry
            .pointer("/lineage/steps_returned")
            .and_then(value_as_u64)
        {
            group.steps.push(steps);
        }
        if group.representative.is_none() {
            group.representative = Some(serde_json::json!({
                "offset": entry.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "addr": entry.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            }));
        }
        for repeated in entry
            .pointer("/lineage/repeated_values")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let Some(value) = repeated.get("value").and_then(|v| v.as_str()) else {
                continue;
            };
            let count = repeated.get("count").and_then(value_as_u64).unwrap_or(1);
            group
                .repeated_values
                .entry(value.to_string())
                .and_modify(|row| {
                    row.0 += 1;
                    row.1 += count;
                })
                .or_insert((1, count));
        }
        if let Some(loop_value) = entry
            .pointer("/lineage/stable_pointer_loop/value")
            .and_then(|v| v.as_str())
        {
            let count = entry
                .pointer("/lineage/stable_pointer_loop/count")
                .and_then(value_as_u64)
                .unwrap_or(1);
            group
                .stable_pointer_loops
                .entry(loop_value.to_string())
                .and_modify(|row| {
                    row.0 += 1;
                    row.1 += count;
                })
                .or_insert((1, count));
        }
        for boundary in batch_lineage_boundaries(entry) {
            if let Some(addr) = batch_lineage_string_at(
                &boundary,
                &["/addr", "/upstream/addr", "/terminal/upstream/addr"],
            ) {
                *group.terminal_addrs.entry(addr).or_default() += 1;
            }
            if let Some(bytes_hex) = batch_lineage_string_at(
                &boundary,
                &[
                    "/observed_bytes_hex",
                    "/upstream/observed_bytes_hex",
                    "/terminal/upstream/observed_bytes_hex",
                ],
            ) {
                *group.observed_bytes.entry(bytes_hex).or_default() += 1;
            }
        }
    }

    groups
        .into_iter()
        .map(|((decision, upstream), mut group)| {
            group.offsets.sort_unstable();
            group.offsets.dedup();
            group.addr_values.sort_unstable();
            group.addr_values.dedup();
            let offset_ranges = stable_ranges(&group.offsets)
                .into_iter()
                .map(|(start, end)| serde_json::json!([start, end]))
                .collect::<Vec<_>>();
            let addr_range = match (group.addr_values.first(), group.addr_values.last()) {
                (Some(start), Some(end)) => serde_json::json!([
                    format!("{start:#x}"),
                    format!("{:#x}", end.saturating_add(1))
                ]),
                _ => serde_json::Value::Null,
            };
            let has_stable_pointer_loop = !group.stable_pointer_loops.is_empty();
            serde_json::json!({
                "decision": decision,
                "upstream": upstream,
                "count": group.offsets.len().max(group.addrs.len()),
                "offsets": group.offsets,
                "offset_ranges": offset_ranges,
                "addr_range": addr_range,
                "step_stats": batch_u64_stats(&group.steps),
                "top_repeated_values": top_count_rows_with_total(group.repeated_values, "value", 8),
                "stable_pointer_loops": top_count_rows_with_total(group.stable_pointer_loops, "value", 8),
                "terminal_addrs": top_count_rows(group.terminal_addrs, "addr", 8),
                "observed_bytes_hex": top_count_rows(group.observed_bytes, "bytes_hex", 8),
                "representative": group.representative.unwrap_or(serde_json::Value::Null),
                "next_action": batch_lineage_next_action(&decision, &upstream, has_stable_pointer_loop),
            })
        })
        .collect()
}

pub(super) fn batch_lineage_decision(entry: &serde_json::Value) -> String {
    batch_lineage_string_at(
        entry,
        &[
            "/lineage/terminal/decision_kind",
            "/lineage/stop_reason/decision_kind",
            "/lineage/terminal/kind",
            "/lineage/stop_reason/kind",
        ],
    )
    .filter(|value| value != "null")
    .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn batch_lineage_upstream(entry: &serde_json::Value, decision: &str) -> String {
    batch_lineage_string_at(
        entry,
        &[
            "/lineage/terminal/upstream_status",
            "/lineage/stop_reason/upstream_status",
        ],
    )
    .filter(|value| value != "null")
    .or_else(|| match decision {
        "memory_not_found_boundary" => Some("not_found".to_string()),
        "observed_read_without_matching_traced_write" => {
            Some("observed_read_without_matching_traced_write".to_string())
        }
        _ => None,
    })
    .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn batch_lineage_boundaries(entry: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(boundaries) = entry
        .pointer("/lineage/memory_boundaries")
        .and_then(|v| v.as_array())
    {
        return boundaries.clone();
    }
    let terminal = entry
        .pointer("/lineage/terminal")
        .or_else(|| entry.pointer("/lineage/stop_reason"));
    terminal.cloned().into_iter().collect()
}

pub(super) fn batch_lineage_string_at(value: &serde_json::Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        let item = value.pointer(path)?;
        match item {
            serde_json::Value::String(raw) => Some(raw.clone()),
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) => Some(item.to_string()),
            _ => None,
        }
    })
}

pub(super) fn batch_u64_stats(values: &[u64]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::Value::Null;
    }
    let min = values.iter().min().copied().unwrap_or(0);
    let max = values.iter().max().copied().unwrap_or(0);
    let avg = values.iter().copied().sum::<u64>() as f64 / values.len() as f64;
    serde_json::json!({
        "min": min,
        "max": max,
        "avg": avg,
    })
}

pub(super) fn top_count_rows(
    counts: BTreeMap<String, usize>,
    key: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut rows = counts
        .into_iter()
        .map(|(name, count)| serde_json::json!({ key: name, "count": count }))
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        let acount = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bcount = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        bcount.cmp(&acount).then_with(|| {
            a.get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get(key).and_then(|v| v.as_str()).unwrap_or(""))
        })
    });
    rows.truncate(limit);
    rows
}

pub(super) fn top_count_rows_with_total(
    counts: BTreeMap<String, (usize, u64)>,
    key: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut rows = counts
        .into_iter()
        .map(|(name, (byte_count, total_count))| {
            serde_json::json!({
                key: name,
                "byte_count": byte_count,
                "total_count": total_count,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        let abytes = a.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bbytes = b.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let atotal = a.get("total_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let btotal = b.get("total_count").and_then(|v| v.as_u64()).unwrap_or(0);
        bbytes
            .cmp(&abytes)
            .then_with(|| btotal.cmp(&atotal))
            .then_with(|| {
                a.get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .cmp(b.get(key).and_then(|v| v.as_str()).unwrap_or(""))
            })
    });
    rows.truncate(limit);
    rows
}

pub(super) fn batch_lineage_next_action(
    decision: &str,
    upstream: &str,
    has_stable_pointer_loop: bool,
) -> &'static str {
    if has_stable_pointer_loop {
        return "prove the stable pointer/base once or mark it as an allocation/base parameter; increasing depth is unlikely to help";
    }
    match (decision, upstream) {
        ("memory_not_found_boundary", _) => {
            "verify the boundary bytes with the emitted mem-dump cursor, then classify them as pre-trace table/input or capture an earlier trace"
        }
        ("observed_read_without_matching_traced_write", _) => {
            "inspect gap call candidates or widen tracing around the producer; do not treat the observed value as portable yet"
        }
        ("stop", "bytecode_read_boundary") => {
            "lift the surrounding VM opcode/template and parameterize this bytecode or immediate source"
        }
        ("depth_limit", _) => {
            "increase --depth or inspect repeated_values for a copy loop, stable VM base, or redundant state walk"
        }
        ("cycle", _) => "inspect repeated_values and break the copy/state cycle at a stable input boundary",
        _ => "inspect the representative byte lineage and decide whether to lift, parameterize, or widen the trace",
    }
}
