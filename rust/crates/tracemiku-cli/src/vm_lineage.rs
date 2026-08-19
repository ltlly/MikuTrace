use super::*;

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn cmd_vm_backstep(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backstep_value_on(
        &app, idx, reg, context, lookback, max_writes, regs, &profile,
    )
    .await?;
    print_pretty(&value)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn cmd_byte_lineage(
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
) -> anyhow::Result<()> {
    let addr = parse_addr_str(&addr).with_context(|| format!("parse addr {addr}"))?;
    if count == 0 {
        bail!("--count must be at least 1");
    }
    if count > 4096 {
        bail!("--count is capped at 4096 bytes");
    }
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    if count > 1 {
        let mut results = Vec::with_capacity(count);
        // 逐字节串行执行：router 已在循环外构建一次（每次 build 都要
        // 加载 Trace + MemShadow），循环内只剩路由调用成本。保持串行是
        // 为了结果按 offset 有序、单字节失败互不影响；如需并发应改成
        // 有界窗口（如 8），但那需要为本 crate 引入 futures 依赖，暂不做。
        for offset in 0..count {
            let byte_addr = addr + offset as u64;
            let entry = match byte_lineage_value_on(
                &app,
                byte_addr,
                before_idx,
                depth,
                context,
                lookback,
                max_writes,
                regs.clone(),
                &VmProfile::disabled(),
            )
            .await
            {
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
        return print_pretty(&serde_json::to_value(LineageBatchReport {
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
        &app,
        addr,
        before_idx,
        depth,
        context,
        lookback,
        max_writes,
        regs,
        &VmProfile::disabled(),
    )
    .await?;
    if compact {
        print_pretty(&byte_lineage_compact_summary(&value))
    } else if summary {
        print_pretty(&byte_lineage_summary(&value))
    } else {
        print_pretty(&value)
    }
}

#[derive(Default)]
pub(super) struct ByteLineageBatchGroup {
    offsets: Vec<usize>,
    addrs: Vec<String>,
    addr_values: Vec<u64>,
    steps: Vec<u64>,
    terminal_addrs: BTreeMap<String, usize>,
    observed_bytes: BTreeMap<String, usize>,
    repeated_values: BTreeMap<String, (usize, u64)>,
    stable_pointer_loops: BTreeMap<String, (usize, u64)>,
    representative: Option<serde_json::Value>,
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

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn cmd_vm_backchain(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    steps: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    follow_frontier: bool,
    byte_lane: Option<usize>,
    regs: String,
    summary: bool,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backchain_value_on(
        &app,
        idx,
        reg,
        steps,
        context,
        lookback,
        max_writes,
        follow_frontier,
        byte_lane,
        regs,
        &profile,
    )
    .await?;
    if summary {
        print_pretty(&vm_backchain_summary(&value))
    } else {
        print_pretty(&value)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn cmd_vm_backtree(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    summary: bool,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backtree_value_on(
        &app,
        idx,
        reg,
        depth,
        max_nodes,
        context,
        lookback,
        max_writes,
        frontier_with_next,
        regs,
        &profile,
    )
    .await?;
    if summary {
        print_pretty(&vm_backtree_summary(&value))
    } else {
        print_pretty(&value)
    }
}

#[allow(clippy::too_many_arguments)] // wire orchestration; refactor is separate work
pub(super) async fn vm_backchain_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    steps: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    follow_frontier: bool,
    byte_lane: Option<usize>,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut current_idx = idx;
    let mut current_reg = reg.clone();
    let mut current_byte_lane = byte_lane;
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for step_idx in 0..steps {
        if !seen.insert(format!(
            "{}:{}:{}",
            current_idx,
            current_reg.as_deref().unwrap_or(""),
            current_byte_lane
                .map(|lane| lane.to_string())
                .unwrap_or_default()
        )) {
            rows.push(serde_json::json!({
                "step": step_idx,
                "status": "cycle",
                "idx": current_idx,
                "reg": current_reg,
                "byte_lane": current_byte_lane,
            }));
            break;
        }
        let step = vm_backstep_value_on(
            app,
            current_idx,
            current_reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
            profile,
        )
        .await?;
        let upstream_next = step
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let lane_next = current_byte_lane
            .and_then(|lane| choose_laned_upstream_next(&step, lane).map(|next| (lane, next)));
        let inferred_low_byte_next = current_byte_lane
            .is_none()
            .then(|| choose_zero_extended_low_byte_upstream_next(&step))
            .flatten();
        let (chosen_next, decision) = if let Some((lane, next)) = lane_next {
            (
                next.clone(),
                serde_json::json!({
                    "kind": "upstream_byte_lane",
                    "byte_lane": lane,
                    "next": next,
                }),
            )
        } else if let Some(next) = inferred_low_byte_next {
            (
                next.clone(),
                serde_json::json!({
                    "kind": "upstream_zero_extended_low_byte",
                    "byte_lane": 0,
                    "next": next,
                }),
            )
        } else if upstream_next.get("idx").and_then(|v| v.as_u64()).is_some() {
            (
                upstream_next,
                serde_json::json!({
                    "kind": "upstream_next",
                }),
            )
        } else if follow_frontier {
            match choose_frontier_next_for_lane(&step, current_byte_lane, profile) {
                Some(frontier_next) => (
                    frontier_next.clone(),
                    serde_json::json!({
                        "kind": "frontier_auto",
                        "next": frontier_next,
                    }),
                ),
                None => (
                    serde_json::Value::Null,
                    serde_json::json!({
                        "kind": "stop",
                        "reason": "no_upstream_next_or_frontier",
                    }),
                ),
            }
        } else {
            (
                serde_json::Value::Null,
                serde_json::json!({
                    "kind": "stop",
                    "reason": "no_upstream_next",
                }),
            )
        };
        current_idx = match chosen_next.get("idx").and_then(|v| v.as_u64()) {
            Some(idx) => idx as usize,
            None => {
                rows.push(serde_json::json!({
                    "step": step_idx,
                    "backstep": step,
                    "next": serde_json::Value::Null,
                    "decision": decision,
                }));
                break;
            }
        };
        current_reg = chosen_next
            .get("reg")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        current_byte_lane = chosen_next
            .get("source_byte_offset")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .or(current_byte_lane);
        rows.push(serde_json::json!({
            "step": step_idx,
            "byte_lane": current_byte_lane,
            "backstep": step,
            "next": chosen_next,
            "decision": decision,
        }));
        if current_reg.is_none() {
            break;
        }
    }
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "idx": idx,
            "reg": reg,
            "byte_lane": byte_lane,
        },
        "follow_frontier": follow_frontier,
        "vm_profile": profile.to_json(),
        "steps_requested": steps,
        "steps_returned": rows.len(),
        "chain": rows,
    }))
}

pub(super) fn choose_laned_upstream_next(
    step: &serde_json::Value,
    byte_lane: usize,
) -> Option<serde_json::Value> {
    upstream_byte_nexts_from_step(step)
        .into_iter()
        .find(|next| next_matches_byte_lane(next, byte_lane))
        .map(|next| next_with_selected_byte_lane(next, byte_lane))
}

pub(super) fn next_matches_byte_lane(next: &serde_json::Value, byte_lane: usize) -> bool {
    next.get("offset")
        .and_then(|v| v.as_u64())
        .is_some_and(|offset| offset as usize == byte_lane)
        || next
            .get("offsets")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .any(|offset| {
                offset
                    .as_u64()
                    .is_some_and(|offset| offset as usize == byte_lane)
            })
}

pub(super) fn next_with_selected_byte_lane(
    mut next: serde_json::Value,
    byte_lane: usize,
) -> serde_json::Value {
    let selected_idx = next
        .get("offsets")
        .and_then(|v| v.as_array())
        .and_then(|offsets| {
            offsets
                .iter()
                .position(|offset| offset.as_u64().is_some_and(|v| v as usize == byte_lane))
        });
    if let Some(obj) = next.as_object_mut() {
        obj.insert(
            "selected_byte_lane".to_string(),
            serde_json::json!(byte_lane),
        );
        if let Some(idx) = selected_idx {
            if let Some(source_byte_offset) = obj
                .get("source_byte_offsets")
                .and_then(|v| v.as_array())
                .and_then(|items| items.get(idx))
                .cloned()
            {
                obj.insert("source_byte_offset".to_string(), source_byte_offset);
            }
            if let Some(addr) = obj
                .get("addrs")
                .and_then(|v| v.as_array())
                .and_then(|items| items.get(idx))
                .cloned()
            {
                obj.insert("addr".to_string(), addr);
            }
        }
    }
    next
}

pub(super) fn choose_zero_extended_low_byte_upstream_next(
    step: &serde_json::Value,
) -> Option<serde_json::Value> {
    let source_value = step.get("source_value").and_then(value_as_u64)?;
    if source_value == 0 || source_value > 0xff {
        return None;
    }
    let observed_hex = step
        .pointer("/upstream/observed_bytes_hex")
        .and_then(|v| v.as_str())?;
    let observed = parse_hex_bytes_cli(observed_hex).ok()?;
    if observed.len() <= 1
        || observed.first().copied() != Some(source_value as u8)
        || observed[1..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    upstream_byte_nexts_from_step(step)
        .into_iter()
        .find(|next| {
            next.get("offset").and_then(|v| v.as_u64()) == Some(0)
                && upstream_next_byte_value(next) == Some(source_value as u8)
        })
        .map(|next| next_with_selected_byte_lane(next, 0))
}

pub(super) fn upstream_next_byte_value(next: &serde_json::Value) -> Option<u8> {
    let value = next.get("src_value").and_then(value_as_u64)?;
    let lane = next
        .get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .map(|lane| lane as usize)
        .unwrap_or(0);
    byte_at_lane(value, lane)
}

#[cfg(test)]
pub(super) fn choose_frontier_next(step: &serde_json::Value) -> Option<serde_json::Value> {
    let profile = VmProfile::new(
        "x9".to_string(),
        "x10".to_string(),
        "x11".to_string(),
        "x12".to_string(),
    );
    choose_frontier_next_for_lane(step, None, &profile)
}

pub(super) fn choose_frontier_next_for_lane(
    step: &serde_json::Value,
    byte_lane: Option<usize>,
    profile: &VmProfile,
) -> Option<serde_json::Value> {
    if matches!(
        step.pointer("/local_def/class").and_then(|v| v.as_str()),
        Some("call-return" | "syscall-return" | "bytecode-read")
    ) {
        return None;
    }
    if let Some(next) = choose_semantic_frontier_next(step, byte_lane) {
        return Some(next);
    }
    let frontiers = step.get("frontier")?.as_array()?;
    let mut candidates = frontiers
        .iter()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if profile.is_infrastructure_reg(reg) {
                return None;
            }
            let value = frontier
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let score = frontier_value_score(&value);
            Some((score, frontier))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = frontiers
            .iter()
            .map(|frontier| {
                let value = frontier
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let score = frontier_value_score(&value);
                (score, frontier)
            })
            .collect::<Vec<_>>();
    }
    candidates.sort_by_key(|(score, _)| *score);
    let (_, frontier) = candidates.first()?;
    frontier_to_next(frontier)
}

pub(super) fn choose_semantic_frontier_next(
    step: &serde_json::Value,
    byte_lane: Option<usize>,
) -> Option<serde_json::Value> {
    let local_def = step.get("local_def")?;
    if matches!(
        local_def.get("class").and_then(|v| v.as_str()),
        Some("call-return" | "syscall-return" | "bytecode-read")
    ) {
        return None;
    }
    let formula = row_alu_formula(local_def)?;
    let op = formula.get("op").and_then(|v| v.as_str());
    if formula
        .pointer("/semantic/input")
        .and_then(|v| v.as_str())
        .is_some()
        && !matches!(op, Some("lsl" | "lsr" | "asr" | "ubfx"))
    {
        let input = formula
            .pointer("/semantic/input")
            .and_then(|v| v.as_str())?;
        let next = frontier_next_by_value(step, input)?;
        let next = annotate_next_source_lane(next, byte_lane);
        let next = formula_operand_by_value(&formula, input)
            .map(|operand| adjust_self_def_formula_next(step, operand, next.clone()))
            .unwrap_or(next);
        return Some(next);
    }
    if formula.get("op").and_then(|v| v.as_str()) == Some("udiv") {
        let numerator = formula
            .get("operands")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())?;
        return next_for_formula_operand(step, numerator, byte_lane);
    }
    if matches!(
        formula.get("op").and_then(|v| v.as_str()),
        Some("add" | "orr" | "and")
    ) {
        let operands = formula.get("operands").and_then(|v| v.as_array())?;
        if operands.len() >= 2 {
            if formula.get("op").and_then(|v| v.as_str()) == Some("add") {
                if let Some(input) = choose_pointer_add_operand(operands) {
                    return next_for_formula_operand(step, input, byte_lane);
                }
            }
            if formula.get("op").and_then(|v| v.as_str()) == Some("orr") {
                if let Some(lane) = byte_lane {
                    if let Some(input) =
                        choose_or_operand_for_lane(&operands[0], &operands[1], lane)
                    {
                        return next_for_formula_operand(step, input, Some(lane));
                    }
                }
            }
            if formula.get("op").and_then(|v| v.as_str()) == Some("and") {
                if let Some(lane) = byte_lane {
                    if let Some(input) =
                        choose_and_operand_for_lane(&operands[0], &operands[1], lane)
                    {
                        return next_for_formula_operand(step, input, Some(lane));
                    }
                }
            }
            let lhs_value = operands[0]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let rhs_value = operands[1]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let chosen = match (lhs_value, rhs_value) {
                (Some(lhs), Some(0)) if lhs != 0 => Some(&operands[0]),
                (Some(0), Some(rhs)) if rhs != 0 => Some(&operands[1]),
                _ => None,
            };
            if let Some(input) = chosen {
                return next_for_formula_operand(step, input, byte_lane);
            }
        }
    }
    if formula.pointer("/semantic/kind").and_then(|v| v.as_str()) == Some("mul_mod64") {
        let operands = formula.get("operands").and_then(|v| v.as_array())?;
        if operands.len() >= 2 {
            let lhs_value = operands[0]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let rhs_value = operands[1]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let chosen = match (lhs_value, rhs_value) {
                (Some(lhs), Some(rhs)) if lhs > 0xff && rhs <= 0xff => Some(&operands[0]),
                (Some(lhs), Some(rhs)) if rhs > 0xff && lhs <= 0xff => Some(&operands[1]),
                _ => None,
            };
            if let Some(input) = chosen {
                return next_for_formula_operand(step, input, byte_lane);
            }
        }
    }
    if matches!(
        formula.get("op").and_then(|v| v.as_str()),
        Some("lsl" | "lsr" | "asr" | "ubfx")
    ) {
        let input = formula
            .get("operands")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())?;
        let source_lane = byte_lane.and_then(|lane| source_lane_for_shift_formula(&formula, lane));
        return next_for_formula_operand(step, input, source_lane.or(byte_lane));
    }
    None
}

pub(super) fn choose_pointer_add_operand(
    operands: &[serde_json::Value],
) -> Option<&serde_json::Value> {
    operands.iter().enumerate().find_map(|(idx, operand)| {
        let value = operand
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str);
        (compact_formula_operand_role("add", idx, value, operands) == "pointer_base")
            .then_some(operand)
    })
}

pub(super) fn choose_and_operand_for_lane<'a>(
    lhs: &'a serde_json::Value,
    rhs: &'a serde_json::Value,
    lane: usize,
) -> Option<&'a serde_json::Value> {
    let lhs_byte = operand_value_u64(lhs).and_then(|value| byte_at_lane(value, lane));
    let rhs_byte = operand_value_u64(rhs).and_then(|value| byte_at_lane(value, lane));
    match (lhs_byte, rhs_byte) {
        (Some(lhs_byte), Some(0xff)) if lhs_byte != 0 => Some(lhs),
        (Some(0xff), Some(rhs_byte)) if rhs_byte != 0 => Some(rhs),
        _ => None,
    }
}

pub(super) fn choose_or_operand_for_lane<'a>(
    lhs: &'a serde_json::Value,
    rhs: &'a serde_json::Value,
    lane: usize,
) -> Option<&'a serde_json::Value> {
    let lhs_byte = operand_value_u64(lhs).map(|value| byte_at_lane(value, lane));
    let rhs_byte = operand_value_u64(rhs).map(|value| byte_at_lane(value, lane));
    match (lhs_byte, rhs_byte) {
        (Some(Some(lhs_byte)), Some(Some(0))) if lhs_byte != 0 => Some(lhs),
        (Some(Some(0)), Some(Some(rhs_byte))) if rhs_byte != 0 => Some(rhs),
        _ => None,
    }
}

pub(super) fn formula_operand_by_value<'a>(
    formula: &'a serde_json::Value,
    value: &str,
) -> Option<&'a serde_json::Value> {
    formula
        .get("operands")?
        .as_array()?
        .iter()
        .find(|operand| operand.get("value").and_then(|v| v.as_str()) == Some(value))
}

pub(super) fn next_for_formula_operand(
    step: &serde_json::Value,
    operand: &serde_json::Value,
    source_lane: Option<usize>,
) -> Option<serde_json::Value> {
    if let Some(reg) = operand.get("reg").and_then(|v| v.as_str()) {
        return frontier_next_by_reg(step, reg)
            .map(|next| annotate_next_source_lane(next, source_lane))
            .map(|next| adjust_self_def_formula_next(step, operand, next));
    }
    if let Some(value) = operand.get("value").and_then(|v| v.as_str()) {
        return frontier_next_by_value(step, value)
            .map(|next| annotate_next_source_lane(next, source_lane))
            .map(|next| adjust_self_def_formula_next(step, operand, next));
    }
    None
}

pub(super) fn adjust_self_def_formula_next(
    step: &serde_json::Value,
    operand: &serde_json::Value,
    mut next: serde_json::Value,
) -> serde_json::Value {
    let Some(operand_reg) = operand.get("reg").and_then(|v| v.as_str()) else {
        return next;
    };
    let Some(def_reg) = step.pointer("/local_def/def/reg").and_then(|v| v.as_str()) else {
        return next;
    };
    if register_value_key(operand_reg) != register_value_key(def_reg) {
        return next;
    }
    let local_idx = step.pointer("/local_def/idx").and_then(|v| v.as_u64());
    let next_idx = next.get("idx").and_then(|v| v.as_u64());
    let Some(local_idx) = local_idx.filter(|idx| Some(*idx) == next_idx) else {
        return next;
    };
    if let Some(obj) = next.as_object_mut() {
        obj.insert(
            "idx".to_string(),
            serde_json::json!(local_idx.saturating_sub(1)),
        );
        obj.insert(
            "reason".to_string(),
            serde_json::json!("self_def_input_before_idx"),
        );
    }
    next
}

pub(super) fn annotate_next_source_lane(
    mut next: serde_json::Value,
    source_lane: Option<usize>,
) -> serde_json::Value {
    if let Some(lane) = source_lane {
        if let Some(obj) = next.as_object_mut() {
            obj.insert("source_byte_offset".to_string(), serde_json::json!(lane));
        }
    }
    next
}

pub(super) fn source_lane_for_shift_formula(
    formula: &serde_json::Value,
    result_lane: usize,
) -> Option<usize> {
    let semantic = formula.get("semantic");
    let op = formula.get("op").and_then(|v| v.as_str());
    let kind = semantic
        .and_then(|v| v.get("kind"))
        .and_then(|v| v.as_str())
        .or(op)?;
    let result_bit = result_lane.checked_mul(8)?;
    let source_bit = match kind {
        "shift_right" | "lsr" | "asr" => {
            let shift = shift_amount_from_formula(formula, semantic)?;
            result_bit.checked_add(shift as usize)?
        }
        "shift_left" | "lsl" => {
            let shift = shift_amount_from_formula(formula, semantic)? as usize;
            result_bit.checked_sub(shift)?
        }
        "ubfx" | "bitmask_extract" => {
            let lsb = semantic
                .and_then(|v| v.get("lsb").or_else(|| v.get("shift")))
                .and_then(value_as_u64)
                .or_else(|| formula_operand_value_u64(formula, 2))? as usize;
            result_bit.checked_add(lsb)?
        }
        _ => return Some(result_lane),
    };
    (source_bit % 8 == 0).then_some(source_bit / 8)
}

pub(super) fn shift_amount_from_formula(
    formula: &serde_json::Value,
    semantic: Option<&serde_json::Value>,
) -> Option<u64> {
    semantic
        .and_then(|v| v.get("shift"))
        .and_then(value_as_u64)
        .or_else(|| formula_operand_value_u64(formula, 1))
}

pub(super) fn formula_operand_value_u64(formula: &serde_json::Value, idx: usize) -> Option<u64> {
    formula
        .get("operands")
        .and_then(|v| v.as_array())
        .and_then(|items| items.get(idx))
        .and_then(operand_value_u64)
}

pub(super) fn operand_value_u64(operand: &serde_json::Value) -> Option<u64> {
    operand
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
}

pub(super) fn operand_effective_value_u64(operand: &serde_json::Value) -> Option<u64> {
    operand
        .get("effective_value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
        .or_else(|| operand_value_u64(operand))
}

/// json_u64 的薄包装（沿用历史调用名）；实现统一在 cli_support::json_u64。
pub(super) fn value_as_u64(value: &serde_json::Value) -> Option<u64> {
    json_u64(value)
}

pub(super) fn byte_at_lane(value: u64, lane: usize) -> Option<u8> {
    let shift = lane.checked_mul(8)?;
    (shift < 64).then_some(((value >> shift) & 0xff) as u8)
}

pub(super) fn frontier_next_by_reg(
    step: &serde_json::Value,
    reg: &str,
) -> Option<serde_json::Value> {
    step.get("frontier")?
        .as_array()?
        .iter()
        .find(|frontier| frontier.get("reg").and_then(|v| v.as_str()) == Some(reg))
        .and_then(frontier_to_next)
}

pub(super) fn frontier_next_by_value(
    step: &serde_json::Value,
    value: &str,
) -> Option<serde_json::Value> {
    step.get("frontier")?
        .as_array()?
        .iter()
        .find(|frontier| frontier.get("value").and_then(|v| v.as_str()) == Some(value))
        .and_then(frontier_to_next)
}

pub(super) fn frontier_to_next(frontier: &serde_json::Value) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "idx": frontier.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": frontier.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "src_value": frontier.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "reason": "frontier_auto",
        "frontier": (*frontier).clone(),
    }))
}

pub(super) fn frontier_value_score(value: &serde_json::Value) -> u8 {
    let parsed = value
        .as_str()
        .and_then(parse_u64_str)
        .or_else(|| value.as_u64());
    match parsed {
        Some(v) if v <= 0xff => 0,
        Some(v) if v <= 0xffff => 1,
        Some(v) if v <= 0xffff_ffff => 2,
        Some(_) => 3,
        None => 4,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn vm_backtree_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut queue = VecDeque::new();
    queue.push_back(TreeSeed {
        parent: None,
        depth: 0,
        idx,
        reg: reg.clone(),
        via: serde_json::json!({"kind": "root"}),
    });
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    while let Some(seed) = queue.pop_front() {
        if nodes.len() >= max_nodes {
            truncated = true;
            break;
        }
        let key = format!("{}:{}", seed.idx, seed.reg.as_deref().unwrap_or(""));
        if !seen.insert(key) {
            nodes.push(serde_json::json!({
                "id": nodes.len(),
                "parent": seed.parent,
                "depth": seed.depth,
                "idx": seed.idx,
                "reg": seed.reg,
                "via": seed.via,
                "status": "cycle",
            }));
            continue;
        }
        let backstep = vm_backstep_value_on(
            app,
            seed.idx,
            seed.reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
            profile,
        )
        .await?;
        let node_id = nodes.len();
        let upstream_next = backstep
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let upstream_byte_nexts = upstream_byte_nexts_from_step(&backstep);
        let frontier_nexts = frontier_nexts_from_step(&backstep, profile);
        let enqueue_frontiers =
            frontier_with_next || upstream_next.get("idx").and_then(|v| v.as_u64()).is_none();
        nodes.push(compact_backtree_node(
            node_id,
            seed.parent,
            seed.depth,
            &seed.via,
            &backstep,
            &upstream_next,
            &upstream_byte_nexts,
            &frontier_nexts,
        ));
        if seed.depth >= depth {
            continue;
        }
        if let Some(next_seed) = tree_seed_from_next(
            node_id,
            seed.depth + 1,
            upstream_next.clone(),
            serde_json::json!({"kind": "upstream_next"}),
        ) {
            queue.push_back(next_seed);
        }
        for byte_next in upstream_byte_nexts {
            if same_tree_next(&upstream_next, &byte_next) {
                continue;
            }
            if let Some(next_seed) = tree_seed_from_next(
                node_id,
                seed.depth + 1,
                byte_next.clone(),
                serde_json::json!({
                    "kind": "upstream_byte",
                    "byte": byte_next,
                }),
            ) {
                queue.push_back(next_seed);
            }
        }
        if enqueue_frontiers {
            for frontier_next in frontier_nexts {
                if let Some(next_seed) = tree_seed_from_next(
                    node_id,
                    seed.depth + 1,
                    frontier_next.clone(),
                    serde_json::json!({
                        "kind": "frontier",
                        "frontier": frontier_next.get("frontier").cloned().unwrap_or(serde_json::Value::Null),
                    }),
                ) {
                    queue.push_back(next_seed);
                }
            }
        }
    }
    let highlights = vm_backtree_highlights(&nodes);
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "idx": idx,
            "reg": reg,
        },
        "depth_requested": depth,
        "max_nodes": max_nodes,
        "frontier_with_next": frontier_with_next,
        "vm_profile": profile.to_json(),
        "nodes_returned": nodes.len(),
        "truncated": truncated || !queue.is_empty(),
        "highlights": highlights,
        "nodes": nodes,
    }))
}

pub(super) fn vm_backtree_summary(tree: &serde_json::Value) -> serde_json::Value {
    let nodes = tree
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let formula_summary = index_tree_summary(tree);
    let interesting_formulas = formula_summary
        .get("interesting_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let semantic_formulas = formula_summary
        .get("semantic_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bytecode_frontiers = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("bytecode-read")
                && node
                    .get("frontier_nexts")
                    .and_then(|v| v.as_array())
                    .is_none_or(|items| items.is_empty())
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let bytecode_operands = bytecode_frontiers
        .iter()
        .map(bytecode_operand_summary)
        .collect::<Vec<_>>();
    let small_byte_loads = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("byte-load")
                && node_value_u64(node).is_some_and(|value| value <= 0xff)
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let terminal_nodes = nodes
        .iter()
        .filter(|node| {
            node.get("status").and_then(|v| v.as_str()) == Some("cycle")
                || (node
                    .get("upstream")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                    != Some("ready")
                    && node
                        .get("frontier_nexts")
                        .and_then(|v| v.as_array())
                        .is_none_or(|items| items.is_empty()))
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": tree.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": tree.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": tree.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "max_nodes": tree.get("max_nodes").cloned().unwrap_or(serde_json::Value::Null),
        "frontier_with_next": tree.get("frontier_with_next").cloned().unwrap_or(serde_json::Value::Null),
        "nodes_returned": tree.get("nodes_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": tree.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "highlights": {
            "word_loads": tree.pointer("/highlights/word_loads").cloned().unwrap_or_else(|| serde_json::json!([])),
            "table_lookups": tree.pointer("/highlights/table_lookups").cloned().unwrap_or_else(|| serde_json::json!([])),
            "interesting_formulas": interesting_formulas,
            "semantic_formulas": semantic_formulas,
        },
        "small_byte_loads": small_byte_loads,
        "bytecode_frontiers": bytecode_frontiers,
        "bytecode_operands": bytecode_operands,
        "terminal_nodes": terminal_nodes,
    })
}

pub(super) fn bytecode_operand_summary(node: &serde_json::Value) -> serde_json::Value {
    let producer_asm = node.pointer("/producer/asm").and_then(|v| v.as_str());
    serde_json::json!({
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "offset": producer_asm.and_then(bytecode_offset_from_asm).map(|off| format!("{off:#x}")),
        "producer_asm": node.pointer("/producer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "producer_addr": node.pointer("/producer/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_asm": node.pointer("/consumer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_class": node.pointer("/consumer/class").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn bytecode_offset_from_asm(asm: &str) -> Option<u64> {
    let hash = asm.find('#')?;
    let tail = &asm[hash + 1..];
    let raw = tail
        .split(|c: char| c == ']' || c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    parse_u64_str(raw)
}

pub(super) fn local_class(node: &serde_json::Value) -> Option<&str> {
    node.pointer("/local_def/class").and_then(|v| v.as_str())
}

/// 节点 value 字段转 u64；数值解析统一走 cli_support::json_u64。
pub(super) fn node_value_u64(node: &serde_json::Value) -> Option<u64> {
    node.get("value").and_then(json_u64)
}

pub(super) fn compact_tree_node_summary(node: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "parent": node.get("parent").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "producer": {
            "asm": node.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/local_def/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/local_def/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/local_def/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/local_def/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "formula": node.pointer("/local_def/formula").cloned().unwrap_or(serde_json::Value::Null),
        },
        "consumer": {
            "asm": node.pointer("/target/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/target/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/target/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/target/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/target/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        },
        "upstream_status": node.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
        "via_kind": node.pointer("/via/kind").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) enum LineageSeed {
    AddrBefore {
        addr: u64,
        before_idx: usize,
    },
    RegAt {
        idx: usize,
        reg: String,
        byte_lane: Option<usize>,
    },
}

impl LineageSeed {
    pub(super) fn to_json(&self) -> serde_json::Value {
        match self {
            Self::AddrBefore { addr, before_idx } => serde_json::json!({
                "kind": "addr_before",
                "addr": format!("{addr:#x}"),
                "before_idx": before_idx,
            }),
            Self::RegAt {
                idx,
                reg,
                byte_lane,
            } => serde_json::json!({
                "kind": "reg_at",
                "idx": idx,
                "reg": reg,
                "byte_lane": byte_lane,
            }),
        }
    }
}

/// Derive the structured byte origin from a byte-lineage steps chain.
/// Reads only the existing step JSON (write_kind / src_reg / dst_addr /
/// writer_idx); never changes the analysis logic.
///
/// - external write (kind "x") wins over everything else;
/// - ordinary write (kind "w") with a source register is a register-origin
///   byte, without one it is a constant write (e.g. str xzr);
/// - a chain that only reaches a register backstep is a register-origin byte;
/// - anything else (no writer, depth limit, error) is Unknown.
pub(super) fn derive_byte_origin(
    steps: &[serde_json::Value],
    stop_reason: &serde_json::Value,
) -> ByteOrigin {
    for step in steps {
        if step.get("kind").and_then(|v| v.as_str()) != Some("last_write") {
            continue;
        }
        let write = step.get("write");
        let addr = write
            .and_then(|w| w.get("dst_addr"))
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .or_else(|| write.and_then(|w| w.get("addr")).and_then(|v| v.as_u64()));
        let idx = write
            .and_then(|w| w.get("writer_idx"))
            .and_then(|v| v.as_u64())
            .map(|i| i as usize);
        match write
            .and_then(|w| w.get("write_kind"))
            .and_then(|v| v.as_str())
        {
            Some("x") => {
                return ByteOrigin::ExternalWrite {
                    addr: addr.unwrap_or(0),
                    idx,
                }
            }
            Some("w") => {
                return match write
                    .and_then(|w| w.get("src_reg"))
                    .and_then(|v| v.as_str())
                {
                    Some(reg) => ByteOrigin::Register {
                        reg: reg.to_string(),
                        idx,
                    },
                    None => ByteOrigin::Constant {
                        value: write
                            .and_then(|w| w.get("src_value"))
                            .and_then(|v| v.as_str())
                            .and_then(parse_u64_str)
                            .map(|v| v as i64)
                            .unwrap_or(0),
                    },
                };
            }
            _ => {}
        }
    }
    // No last_write step: a chain that terminates at a register backstep is
    // still a register-origin byte.
    for step in steps.iter().rev() {
        if step.get("kind").and_then(|v| v.as_str()) == Some("reg_source") {
            if let Some(reg) = step
                .get("backstep")
                .and_then(|b| b.get("source_reg"))
                .and_then(|v| v.as_str())
            {
                return ByteOrigin::Register {
                    reg: reg.to_string(),
                    idx: None,
                };
            }
        }
    }
    let _ = stop_reason;
    ByteOrigin::Unknown
}

/// Extract steps + stop_reason from a single-byte lineage value and derive
/// its origin (used by the count>1 batch path where the full value is
/// available before compact/summary conversion).
pub(super) fn derive_byte_origin_from_value(value: &serde_json::Value) -> ByteOrigin {
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let stop_reason = value
        .get("stop_reason")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    derive_byte_origin(&steps, &stop_reason)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn byte_lineage_value_on(
    app: &axum::Router,
    addr: u64,
    before_idx: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut seed = LineageSeed::AddrBefore { addr, before_idx };
    let mut steps = Vec::new();
    let mut seen = HashSet::new();
    let mut stop_reason = serde_json::json!({"kind": "depth_limit"});
    for step_idx in 0..depth {
        let seed_json = seed.to_json();
        let key = seed_json.to_string();
        if !seen.insert(key) {
            stop_reason = serde_json::json!({
                "kind": "cycle",
                "seed": seed_json,
            });
            break;
        }
        match seed {
            LineageSeed::AddrBefore { addr, before_idx } => {
                let write = last_write_of_addr_on(app, addr, before_idx).await?;
                let source_byte_offset = source_byte_offset_for_write_at(&write, addr);
                let next_seed = write
                    .get("writer_idx")
                    .and_then(|v| v.as_u64())
                    .zip(write.get("src_reg").and_then(|v| v.as_str()))
                    .map(|(idx, reg)| LineageSeed::RegAt {
                        idx: idx as usize,
                        reg: reg.to_string(),
                        byte_lane: source_byte_offset.map(|lane| lane as usize),
                    });
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "kind": "last_write",
                    "source_byte_offset": source_byte_offset,
                    "write": write,
                    "next": next_json,
                }));
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "no_writer_source",
                    });
                    break;
                }
            }
            LineageSeed::RegAt {
                idx,
                ref reg,
                byte_lane,
            } => {
                let backstep = vm_backstep_value_on(
                    app,
                    idx,
                    Some(reg.clone()),
                    context,
                    lookback,
                    max_writes,
                    regs.clone(),
                    profile,
                )
                .await?;
                let (next_seed, decision) =
                    lineage_next_from_backstep(&backstep, byte_lane, profile);
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "byte_lane": byte_lane,
                    "kind": "reg_source",
                    "backstep": compact_lineage_backstep(&backstep),
                    "decision": decision,
                    "next": next_json,
                }));
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "terminal",
                        "decision": decision,
                    });
                    break;
                }
            }
        }
    }
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "addr": format!("{addr:#x}"),
            "before_idx": before_idx,
        },
        "depth_requested": depth,
        "steps_returned": steps.len(),
        "stop_reason": stop_reason,
        "origin": derive_byte_origin(&steps, &stop_reason),
        "steps": steps,
    }))
}

pub(super) async fn last_write_of_addr_on(
    app: &axum::Router,
    addr: u64,
    before_idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("addr", format!("{addr:#x}")),
        ("before_idx", before_idx.to_string()),
        ("with_external", "true".to_string()),
    ];
    route_get_json_value_on(app, route_path("/api/last-write-of-addr", &params)).await
}

pub(super) fn lineage_next_from_backstep(
    backstep: &serde_json::Value,
    current_byte_lane: Option<usize>,
    profile: &VmProfile,
) -> (Option<LineageSeed>, serde_json::Value) {
    if let Some(lane) = current_byte_lane {
        if let Some(next) = choose_laned_upstream_next(backstep, lane) {
            return (
                lineage_seed_from_next(&next, Some(lane)),
                serde_json::json!({
                    "kind": "upstream_byte_lane",
                    "byte_lane": lane,
                    "next": next,
                }),
            );
        }
    }
    let upstream_next = backstep
        .get("upstream")
        .and_then(|v| v.get("next"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(seed) = lineage_seed_from_next(&upstream_next, current_byte_lane) {
        return (
            Some(seed),
            serde_json::json!({
                "kind": "upstream_next",
                "next": upstream_next,
            }),
        );
    }
    let byte_nexts = backstep
        .get("upstream")
        .and_then(|v| v.get("byte_nexts"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if byte_nexts.len() == 1 {
        let next = byte_nexts[0].clone();
        if let Some(seed) = lineage_seed_from_next(&next, current_byte_lane) {
            return (
                Some(seed),
                serde_json::json!({
                    "kind": "single_byte_next",
                    "next": next,
                }),
            );
        }
    }
    if byte_nexts.len() > 1 {
        return (
            None,
            serde_json::json!({
                "kind": "branch_required",
                "reason": "multiple byte upstream candidates",
                "byte_nexts": byte_nexts,
            }),
        );
    }
    let upstream_status = backstep
        .pointer("/upstream/status")
        .and_then(|v| v.as_str());
    if upstream_status == Some("not_found") {
        return (
            None,
            serde_json::json!({
                "kind": "memory_not_found_boundary",
                "upstream_status": "not_found",
                "upstream": {
                    "addr": backstep.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "addr_hi": backstep.pointer("/upstream/addr_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_lo": backstep.pointer("/upstream/idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_hi": backstep.pointer("/upstream/idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": backstep.pointer("/upstream/observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "returned": backstep.pointer("/upstream/returned").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": backstep.pointer("/upstream/maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                },
            }),
        );
    }
    if upstream_status == Some("observed_read_without_matching_traced_write") {
        return (
            None,
            serde_json::json!({
                "kind": "observed_read_without_matching_traced_write",
                "upstream": {
                    "addr": backstep.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "addr_hi": backstep.pointer("/upstream/addr_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": backstep.pointer("/upstream/observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_mismatches": backstep.pointer("/upstream/observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "last_write": backstep.pointer("/upstream/last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "gap_call_candidates": compact_gap_call_candidates(backstep.pointer("/upstream/gap_call_candidates")),
                },
            }),
        );
    }
    if let Some(frontier_next) = choose_frontier_next_for_lane(backstep, current_byte_lane, profile)
    {
        return (
            lineage_seed_from_next(&frontier_next, current_byte_lane),
            serde_json::json!({
                "kind": "frontier_auto",
                "next": frontier_next,
            }),
        );
    }
    (
        None,
        serde_json::json!({
            "kind": "stop",
            "upstream_status": backstep.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
            "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
        }),
    )
}

pub(super) fn lineage_seed_from_next(
    next: &serde_json::Value,
    fallback_byte_lane: Option<usize>,
) -> Option<LineageSeed> {
    let idx = next.get("idx")?.as_u64()? as usize;
    let reg = next.get("reg")?.as_str()?.to_string();
    let byte_lane = next
        .get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .map(|lane| lane as usize)
        .or(fallback_byte_lane);
    Some(LineageSeed::RegAt {
        idx,
        reg,
        byte_lane,
    })
}

pub(super) fn compact_lineage_backstep(backstep: &serde_json::Value) -> serde_json::Value {
    let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "status": backstep.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "source_reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
        "source_value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
        "target": compact_vm_row(backstep.get("target")),
        "local_def": compact_vm_row(backstep.get("local_def")),
        "upstream": {
            "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "addr_hi": upstream.get("addr_hi").cloned().unwrap_or(serde_json::Value::Null),
            "idx_lo": upstream.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
            "idx_hi": upstream.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
            "returned": upstream.get("returned").cloned().unwrap_or(serde_json::Value::Null),
            "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
            "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
            "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
            "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
            "byte_nexts": upstream.get("byte_nexts").cloned().unwrap_or_else(|| serde_json::json!([])),
            "gap_call_candidates": compact_gap_call_candidates(upstream.get("gap_call_candidates")),
        },
        "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn byte_lineage_summary(lineage: &serde_json::Value) -> serde_json::Value {
    let chain = lineage
        .get("steps")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_lineage_summary_step)
        .collect::<Vec<_>>();
    let recognized_semantics = chain
        .iter()
        .filter_map(|step| {
            step.pointer("/local_def/formula/semantic")
                .cloned()
                .map(|semantic| {
                    serde_json::json!({
                        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                        "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                        "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": semantic,
                    })
                })
        })
        .collect::<Vec<_>>();
    let memory_boundaries = chain
        .iter()
        .filter_map(|step| {
            let decision = step.get("decision")?;
            let kind = decision.get("kind").and_then(|v| v.as_str());
            if !matches!(
                kind,
                Some("observed_read_without_matching_traced_write" | "memory_not_found_boundary")
            ) {
                return None;
            }
            Some(serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "kind": kind,
                "upstream": decision.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": lineage.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": lineage.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": lineage.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": lineage.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop_reason": compact_lineage_stop_reason(lineage.get("stop_reason")),
        "recognized_semantics": recognized_semantics,
        "memory_boundaries": memory_boundaries,
        "chain": chain,
    })
}

pub(super) fn byte_lineage_compact_summary(lineage: &serde_json::Value) -> serde_json::Value {
    let summary = byte_lineage_summary(lineage);
    let chain = summary
        .get("chain")
        .and_then(|v| v.as_array())
        .map(|steps| {
            steps
                .iter()
                .map(compact_lineage_path_step)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let memory_boundaries = summary
        .get("chain")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(compact_lineage_memory_boundary)
        .collect::<Vec<_>>();
    let semantics = summary
        .get("recognized_semantics")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let terminal = summary
        .get("stop_reason")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let repeated_values = compact_lineage_repeated_values(&chain);
    let pointer_transitions = compact_lineage_pointer_transitions(&chain);
    let stable_pointer_loop = compact_lineage_stable_pointer_loop(&terminal, &repeated_values);
    let next_actions = compact_lineage_next_actions(
        &memory_boundaries,
        &terminal,
        &semantics,
        &repeated_values,
        &stable_pointer_loop,
    );
    serde_json::json!({
        "status": summary.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": summary.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": summary.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": summary.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "terminal": terminal,
        "recognized_semantics": semantics,
        "repeated_values": repeated_values,
        "pointer_transitions": pointer_transitions,
        "stable_pointer_loop": stable_pointer_loop,
        "memory_boundaries": memory_boundaries,
        "path": chain,
        "next_actions": next_actions,
    })
}

pub(super) fn compact_lineage_path_step(step: &serde_json::Value) -> serde_json::Value {
    match step.get("kind").and_then(|v| v.as_str()) {
        Some("last_write") => serde_json::json!({
            "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "kind": "last_write",
            "addr": step.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": step.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": step.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "src_reg": step.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
            "src_value": step.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
        }),
        Some("reg_source") => {
            let local_def = step.get("local_def").unwrap_or(&serde_json::Value::Null);
            let upstream = step.get("upstream").unwrap_or(&serde_json::Value::Null);
            let decision_kind = step
                .pointer("/decision/kind")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "reg_source",
                "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "local_def": {
                    "idx": local_def.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": local_def.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "class": local_def.get("class").cloned().unwrap_or(serde_json::Value::Null),
                    "vm_slot": local_def.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
                    "mem_addr": local_def.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
                    "formula": compact_lineage_formula(local_def.get("formula")),
                    "call_return": compact_lineage_call_return(local_def.get("call_return")),
                    "syscall_return": compact_lineage_syscall_return(local_def.get("syscall_return")),
                },
                "upstream": {
                    "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
                    "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "gap_call_count_total": upstream.pointer("/gap_call_candidates/candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
                },
                "decision_kind": decision_kind,
                "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        _ => serde_json::json!({
            "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "kind": step.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        }),
    }
}

pub(super) fn compact_lineage_formula(formula: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(formula) = formula else {
        return serde_json::Value::Null;
    };
    if formula.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "op": formula.get("op").cloned().unwrap_or(serde_json::Value::Null),
        "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_kind": formula.pointer("/semantic/kind").cloned().unwrap_or(serde_json::Value::Null),
        "operands": compact_lineage_formula_operands(formula),
    })
}

pub(super) fn compact_lineage_formula_operands(formula: &serde_json::Value) -> serde_json::Value {
    let op = formula.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let operands = formula
        .get("operands")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    serde_json::Value::Array(
        operands
            .iter()
            .enumerate()
            .map(|(idx, operand)| {
                let value = operand_effective_value_u64(operand);
                let mut item = serde_json::Map::new();
                item.insert("idx".to_string(), serde_json::json!(idx));
                item.insert(
                    "reg".to_string(),
                    operand
                        .get("reg")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
                item.insert(
                    "value".to_string(),
                    operand
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
                if let Some(shift) = operand.get("shift").cloned() {
                    item.insert("shift".to_string(), shift);
                }
                if let Some(amount) = operand.get("shift_amount").cloned() {
                    item.insert("shift_amount".to_string(), amount);
                }
                if let Some(effective) = operand.get("effective_value").cloned() {
                    item.insert("effective_value".to_string(), effective);
                }
                item.insert(
                    "role".to_string(),
                    serde_json::json!(compact_formula_operand_role(op, idx, value, &operands)),
                );
                serde_json::Value::Object(item)
            })
            .collect(),
    )
}

pub(super) fn compact_formula_operand_role(
    op: &str,
    idx: usize,
    value: Option<u64>,
    operands: &[serde_json::Value],
) -> &'static str {
    match op {
        "add" => {
            let other = operands
                .iter()
                .enumerate()
                .find(|(other_idx, _)| *other_idx != idx)
                .and_then(|(_, operand)| operand_effective_value_u64(operand));
            match (value, other) {
                (Some(value), Some(other))
                    if looks_like_pointer(value) && looks_like_delta(other) =>
                {
                    "pointer_base"
                }
                (Some(value), Some(other))
                    if looks_like_delta(value) && looks_like_pointer(other) =>
                {
                    "delta"
                }
                _ => "operand",
            }
        }
        "lsl" | "lsr" | "asr" => {
            if idx == 0 {
                "input"
            } else {
                "shift"
            }
        }
        "ubfx" => match idx {
            0 => "input",
            1 => "lsb",
            2 => "width",
            _ => "operand",
        },
        _ => "operand",
    }
}

pub(super) fn looks_like_pointer(value: u64) -> bool {
    value >= 0x1_0000_0000
}

pub(super) fn looks_like_delta(value: u64) -> bool {
    value <= 0x10_0000 || value >= u64::MAX - 0x10_0000
}

pub(super) fn compact_lineage_call_return(
    call_return: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(call_return) = call_return else {
        return serde_json::Value::Null;
    };
    if call_return.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "call_idx": call_return.get("call_idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": call_return.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "target_reg": call_return.get("target_reg").cloned().unwrap_or(serde_json::Value::Null),
        "target_value": call_return.get("target_value").cloned().unwrap_or(serde_json::Value::Null),
        "return_reg": call_return.get("return_reg").cloned().unwrap_or(serde_json::Value::Null),
        "return_value": call_return.get("return_value").cloned().unwrap_or(serde_json::Value::Null),
        "intervening_rows": call_return.get("intervening_rows").cloned().unwrap_or(serde_json::Value::Null),
        "args": call_return.get("args").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn compact_lineage_syscall_return(
    syscall_return: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(syscall_return) = syscall_return else {
        return serde_json::Value::Null;
    };
    if syscall_return.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "svc_idx": syscall_return.get("svc_idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": syscall_return.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_reg": syscall_return.get("syscall_reg").cloned().unwrap_or(serde_json::Value::Null),
        "syscall_number": syscall_return.get("syscall_number").cloned().unwrap_or(serde_json::Value::Null),
        "return_reg": syscall_return.get("return_reg").cloned().unwrap_or(serde_json::Value::Null),
        "return_value": syscall_return.get("return_value").cloned().unwrap_or(serde_json::Value::Null),
        "intervening_rows": syscall_return.get("intervening_rows").cloned().unwrap_or(serde_json::Value::Null),
        "args": syscall_return.get("args").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

pub(super) fn compact_lineage_memory_boundary(
    step: &serde_json::Value,
) -> Option<serde_json::Value> {
    let decision_kind = step.pointer("/decision/kind").and_then(|v| v.as_str())?;
    if !matches!(
        decision_kind,
        "observed_read_without_matching_traced_write" | "memory_not_found_boundary"
    ) {
        return None;
    }
    let upstream = step.get("upstream").unwrap_or(&serde_json::Value::Null);
    let mem_dump_command = compact_lineage_boundary_mem_dump_command(step, upstream);
    Some(serde_json::json!({
        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "kind": decision_kind,
        "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
        "gap_call_count_total": upstream.pointer("/gap_call_candidates/candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
        "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "mem_dump_command": mem_dump_command,
    }))
}

pub(super) fn compact_lineage_boundary_mem_dump_command(
    step: &serde_json::Value,
    upstream: &serde_json::Value,
) -> serde_json::Value {
    let Some(addr) = upstream.get("addr").and_then(|v| v.as_str()) else {
        return serde_json::Value::Null;
    };
    let Some(idx) = step.get("idx").and_then(|v| v.as_u64()) else {
        return serde_json::Value::Null;
    };
    let count = upstream
        .get("observed_bytes_hex")
        .and_then(|v| v.as_str())
        .map(|hex| (hex.len() / 2).max(1))
        .unwrap_or(1);
    serde_json::json!(format!(
        "tracemiku-cli mem-dump <call_dir> --addr {addr} --count {count} --cursor {idx} --summary"
    ))
}

pub(super) fn compact_lineage_next_actions(
    memory_boundaries: &[serde_json::Value],
    terminal: &serde_json::Value,
    semantics: &serde_json::Value,
    repeated_values: &serde_json::Value,
    stable_pointer_loop: &serde_json::Value,
) -> serde_json::Value {
    let mut actions = Vec::new();
    if !memory_boundaries.is_empty() {
        actions.push(serde_json::json!(
            "inspect boundary addresses with a larger lookback or earlier trace"
        ));
        actions.push(serde_json::json!(
            "check gap_call_candidates for helper calls that mutate the boundary"
        ));
        actions.push(serde_json::json!(
            "parameterize the boundary as an explicit input only after provenance is exhausted"
        ));
    }
    if terminal.get("decision_kind").and_then(|v| v.as_str()) == Some("stop")
        || terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("no_local_def")
    {
        actions.push(serde_json::json!(
            "increase --context/--lookback or switch to a memory seed if the value should be trace-derived"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("call_return_boundary") {
        actions.push(serde_json::json!(
            "inspect the compact call_return target and args, then trace or summarize the callee"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("syscall_return_boundary") {
        actions.push(serde_json::json!(
            "inspect the compact syscall_return number and args, then parameterize the syscall output"
        ));
    }
    if terminal.get("upstream_status").and_then(|v| v.as_str()) == Some("bytecode_read_boundary") {
        actions.push(serde_json::json!(
            "treat the compact bytecode-read value as a VM opcode/immediate literal or lift the containing opcode template"
        ));
    }
    if semantics.as_array().is_some_and(|rows| !rows.is_empty()) {
        actions.push(serde_json::json!(
            "lift recognized formula semantics into a replay template and replace concrete values with inputs"
        ));
    }
    if matches!(
        terminal.get("kind").and_then(|v| v.as_str()),
        Some("depth_limit" | "cycle")
    ) && repeated_values
        .as_array()
        .is_some_and(|values| !values.is_empty())
    {
        actions.push(serde_json::json!(
            "inspect repeated_values; repeated pointer/state values usually indicate a copy loop or stable VM base"
        ));
    }
    if !stable_pointer_loop.is_null() {
        actions.push(serde_json::json!(
            "treat stable_pointer_loop as a copy/base boundary; prove the repeated pointer once instead of chasing more depth"
        ));
    }
    serde_json::Value::Array(actions)
}

pub(super) fn compact_lineage_stable_pointer_loop(
    terminal: &serde_json::Value,
    repeated_values: &serde_json::Value,
) -> serde_json::Value {
    if !matches!(
        terminal.get("kind").and_then(|v| v.as_str()),
        Some("depth_limit" | "cycle")
    ) {
        return serde_json::Value::Null;
    }
    let Some(row) = repeated_values
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let value = row.get("value").and_then(|v| v.as_str())?;
            let count = row.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let parsed = parse_u64_str(value)?;
            (count >= 8 && looks_like_pointer(parsed)).then_some(row)
        })
        .max_by_key(|row| row.get("count").and_then(|v| v.as_u64()).unwrap_or(0))
    else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "kind": "stable_pointer_loop",
        "value": row.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "count": row.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "first_step": row.get("first_step").cloned().unwrap_or(serde_json::Value::Null),
        "last_step": row.get("last_step").cloned().unwrap_or(serde_json::Value::Null),
        "terminal_kind": terminal.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        "interpretation": "the lineage is walking a stable pointer/base copy chain; prove this pointer once or mark it as an allocation/base parameter",
    })
}

pub(super) fn compact_lineage_repeated_values(chain: &[serde_json::Value]) -> serde_json::Value {
    let mut counts = BTreeMap::<String, (usize, u64, u64)>::new();
    for step in chain {
        let Some(value) = step.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        let step_idx = step.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
        counts
            .entry(value.to_string())
            .and_modify(|entry| {
                entry.0 += 1;
                entry.2 = step_idx;
            })
            .or_insert((1, step_idx, step_idx));
    }
    let mut repeated = counts
        .into_iter()
        .filter(|(_, (count, _, _))| *count > 1)
        .map(|(value, (count, first_step, last_step))| {
            serde_json::json!({
                "value": value,
                "count": count,
                "first_step": first_step,
                "last_step": last_step,
            })
        })
        .collect::<Vec<_>>();
    repeated.sort_by(|a, b| {
        let acount = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bcount = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        bcount.cmp(&acount)
    });
    if repeated.len() > 8 {
        repeated.truncate(8);
    }
    serde_json::Value::Array(repeated)
}

pub(super) fn compact_lineage_pointer_transitions(
    chain: &[serde_json::Value],
) -> serde_json::Value {
    let mut by_expression = BTreeMap::<String, serde_json::Value>::new();
    for step in chain {
        let Some(formula) = step.pointer("/local_def/formula").filter(|v| !v.is_null()) else {
            continue;
        };
        let semantic_kind = formula
            .get("semantic_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pointer_delta = compact_formula_operand_by_role(formula, "pointer_base")
            .zip(compact_formula_operand_by_role(formula, "delta"));
        let semantic_pointer = matches!(semantic_kind, "align_down_mask" | "sub_small_delta")
            && step
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
                .is_some_and(looks_like_pointer);
        if pointer_delta.is_none() && !semantic_pointer {
            continue;
        }
        let expression = formula
            .get("expression")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if expression.is_empty() {
            continue;
        }
        let step_idx = step.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
        let row = by_expression.entry(expression.clone()).or_insert_with(|| {
            let mut item = serde_json::json!({
                "first_step": step_idx,
                "last_step": step_idx,
                "count": 0,
                "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                "op": formula.get("op").cloned().unwrap_or(serde_json::Value::Null),
                "semantic_kind": formula.get("semantic_kind").cloned().unwrap_or(serde_json::Value::Null),
                "result": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "expression": expression,
            });
            if let Some((base, delta)) = pointer_delta {
                if let Some(obj) = item.as_object_mut() {
                    obj.insert(
                        "pointer_base".to_string(),
                        base.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    );
                    obj.insert(
                        "delta".to_string(),
                        delta.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    );
                }
            }
            item
        });
        if let Some(obj) = row.as_object_mut() {
            let count = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
            obj.insert("count".to_string(), serde_json::json!(count));
            obj.insert("last_step".to_string(), serde_json::json!(step_idx));
        }
    }
    let mut rows = by_expression.into_values().collect::<Vec<_>>();
    rows.sort_by_key(|row| row.get("first_step").and_then(|v| v.as_u64()).unwrap_or(0));
    if rows.len() > 16 {
        rows.truncate(16);
    }
    serde_json::Value::Array(rows)
}

pub(super) fn compact_formula_operand_by_role<'a>(
    formula: &'a serde_json::Value,
    role: &str,
) -> Option<&'a serde_json::Value> {
    formula
        .get("operands")?
        .as_array()?
        .iter()
        .find(|operand| operand.get("role").and_then(|v| v.as_str()) == Some(role))
}
