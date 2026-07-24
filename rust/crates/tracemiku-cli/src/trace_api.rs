use super::*;

pub(super) fn cmd_stats(
    trace_dir: PathBuf,
    all_modules: bool,
    top_modules: usize,
) -> anyhow::Result<()> {
    let meta = tracemiku_core::prelude::TraceMeta::load(&trace_dir)?;
    let trace = tracemiku_core::prelude::Trace::load(&trace_dir)?;

    let modules_sorted: Vec<&tracemiku_core::prelude::ModuleInfo> = {
        let mut m: Vec<_> = meta.modules.iter().collect();
        m.sort_by_key(|x| std::cmp::Reverse(x.size));
        m
    };

    let target_name = meta.module.as_ref().map(|m| m.name.as_str());
    let modules_total = modules_sorted.len();
    let modules_out: Vec<&tracemiku_core::prelude::ModuleInfo> = if all_modules {
        modules_sorted.clone()
    } else {
        let n = top_modules.max(1);
        let mut kept: Vec<_> = if let Some(tn) = target_name {
            modules_sorted
                .iter()
                .copied()
                .filter(|m| m.name == tn)
                .take(1)
                .collect()
        } else {
            Vec::new()
        };
        let already = kept.iter().map(|m| m.name.as_str()).collect::<HashSet<_>>();
        let need = n.saturating_sub(kept.len());
        kept.extend(
            modules_sorted
                .iter()
                .copied()
                .filter(|m| !already.contains(m.name.as_str()))
                .take(need),
        );
        kept
    };

    print_pretty(&serde_json::json!({
        "path": trace_dir.display().to_string(),
        "records": trace.len(),
        "method": meta.method,
        "cmd": meta.cmd,
        "fn_addr": meta.fn_addr,
        "module": meta.module,
        "modules": modules_out,
        "modules_total": modules_total,
        "modules_truncated": modules_out.len() < modules_total,
    }))
}

pub(super) async fn route_get_json(trace_dir: PathBuf, path: String) -> anyhow::Result<()> {
    let value = route_get_json_value(trace_dir, path).await?;
    print_pretty(&value)
}

pub(super) async fn route_get_json_value(
    trace_dir: PathBuf,
    path: String,
) -> anyhow::Result<serde_json::Value> {
    let app = build_cli_router(trace_dir, &path, None)?;
    route_get_json_value_on(&app, path).await
}

pub(super) async fn route_get_json_value_on(
    app: &axum::Router,
    path: String,
) -> anyhow::Result<serde_json::Value> {
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(&path)
                .body(Body::empty())?,
        )
        .await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        bail!(
            "{} returned {}: {}",
            path,
            status,
            String::from_utf8_lossy(&body)
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    Ok(value)
}

/// Resolve a tool-neutral `(SO, offset)` coordinate to a concrete trace record
/// index, so lineage/taint commands (which seed on an idx) accept the same
/// coordinate a reverse engineer reads from IDA/BN/Ghidra. `occurrence` picks
/// which execution of that PC to seed from (0 = first). Reuses the in-process
/// `/api/resolve` + `/api/idxs-for-pc` routes on the SAME app so the trace is
/// loaded once. Returns `(idx, pc)`.
pub(super) async fn resolve_offset_to_idx(
    app: &axum::Router,
    so: &str,
    off: &str,
    occurrence: usize,
) -> anyhow::Result<(usize, u64)> {
    let rparams = vec![("so", so.to_string()), ("off", off.to_string())];
    let resolved = route_get_json_value_on(app, route_path("/api/resolve", &rparams)).await?;
    let status = resolved
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if status != "hit" {
        bail!(
            "could not resolve (so={so}, off={off}) to a PC: {}",
            serde_json::to_string(&resolved).unwrap_or_default()
        );
    }
    let pc_str = resolved
        .pointer("/coord/pc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("resolve response missing coord.pc"))?;
    let pc = parse_addr_str(pc_str)
        .ok_or_else(|| anyhow::anyhow!("resolve returned unparseable pc: {pc_str}"))?;
    let executed = resolved
        .pointer("/coord/executed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !executed {
        bail!("(so={so}, off={off}) -> {pc_str} was never executed in this trace");
    }
    // idxs-for-pc with cursor=0 puts every execution in `after` (ascending).
    let iparams = vec![
        ("pc", pc_str.to_string()),
        ("cursor", "0".to_string()),
        ("limit", (occurrence + 1).to_string()),
    ];
    let idxs = route_get_json_value_on(app, route_path("/api/idxs-for-pc", &iparams)).await?;
    let after = idxs
        .get("after")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("idxs-for-pc response missing after[]"))?;
    let total_after = idxs
        .get("total_after")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let idx = after
        .get(occurrence)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "occurrence {occurrence} out of range: PC {pc_str} executed {total_after} time(s)"
            )
        })?;
    Ok((idx as usize, pc))
}

pub(super) async fn cmd_byte_writer_map(
    trace_dir: PathBuf,
    addr: String,
    size: u64,
    idx_lo: usize,
    idx_hi: isize,
    max: usize,
    vm_chain_steps: usize,
    vm_chain_runs: usize,
    vm_chain_lookback: usize,
    vm_chain_follow_frontier: bool,
    summary: bool,
    vm_profile: VmProfile,
) -> anyhow::Result<()> {
    let addr_value =
        parse_addr_str(&addr).with_context(|| format!("invalid --addr value {addr:?}"))?;
    if size == 0 {
        bail!("byte-writer-map requires --size > 0");
    }
    let size_usize = usize::try_from(size).context("--size does not fit in usize")?;
    if size_usize > 1_000_000 {
        bail!("byte-writer-map refuses buffers larger than 1,000,000 bytes");
    }
    let addr_hi = addr_value
        .checked_add(size)
        .context("--addr + --size overflowed u64")?;
    let params = vec![
        ("idx_lo", idx_lo.to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{addr_value:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", max.to_string()),
    ];
    let path = route_path("/api/mem-writes-in-range", &params);
    let app = if vm_chain_steps > 0 && vm_chain_runs > 0 {
        tracemiku_server::build_router_with_memshadow(trace_dir)?
    } else {
        build_cli_router(trace_dir, &path, None)?
    };
    let response = route_get_json_value_on(&app, path).await?;
    let mut output = byte_writer_map_output(addr_value, size_usize, &response);
    if vm_chain_steps > 0 && vm_chain_runs > 0 {
        let runs = output
            .get("writer_runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let chains = vm_chains_for_byte_writer_runs(
            &app,
            &runs,
            vm_chain_steps,
            vm_chain_runs,
            vm_chain_lookback,
            vm_chain_follow_frontier,
            &vm_profile,
        )
        .await?;
        let chain_summary = vm_chain_batch_summary(&chains);
        if let Some(obj) = output.as_object_mut() {
            obj.insert("vm_chain_summary".to_string(), chain_summary);
            obj.insert("vm_chains".to_string(), serde_json::Value::Array(chains));
        }
    }
    let output = if summary {
        byte_writer_map_summary(&output)
    } else {
        output
    };
    print_pretty(&output)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn cmd_hash_finalize_detect(
    trace_dir: PathBuf,
    window: usize,
    min_size: u64,
    limit: usize,
    map_bytes: bool,
    map_candidates: usize,
    nonzero_only: bool,
    target_bytes: Option<String>,
) -> anyhow::Result<()> {
    let params = vec![
        ("window", window.to_string()),
        ("min_size", min_size.to_string()),
        ("limit", limit.to_string()),
    ];
    let path = route_path("/api/hash-finalize-detect", &params);
    let needs_map = map_bytes || nonzero_only || target_bytes.is_some();
    if !needs_map {
        return route_get_json(trace_dir, path).await;
    }
    let target = target_bytes
        .as_deref()
        .map(parse_hex_bytes_cli)
        .transpose()?;
    let target_hex = target.as_ref().map(|bytes| bytes_to_hex(bytes));
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let mut response = route_get_json_value_on(&app, path).await?;
    let candidates = response
        .get("candidates")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut maps = Vec::new();
    let mut zero_candidates = 0usize;
    let mut nonzero_candidates = 0usize;
    let mut target_hits = 0usize;
    for candidate in candidates.iter().take(map_candidates) {
        let map = hash_candidate_byte_map(&app, candidate, target_hex.as_deref()).await?;
        let all_zero = map
            .get("all_zero")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let has_target_hit = map
            .get("target_hits")
            .and_then(|v| v.as_array())
            .is_some_and(|hits| !hits.is_empty());
        if all_zero {
            zero_candidates += 1;
        } else {
            nonzero_candidates += 1;
        }
        if has_target_hit {
            target_hits += 1;
        }
        if nonzero_only && all_zero {
            continue;
        }
        maps.push(map);
    }
    if let Some(obj) = response.as_object_mut() {
        obj.insert(
            "candidate_map_summary".to_string(),
            serde_json::json!({
                "mapped": maps.len(),
                "inspected": candidates.len().min(map_candidates),
                "map_candidates_limit": map_candidates,
                "zero_candidates": zero_candidates,
                "nonzero_candidates": nonzero_candidates,
                "target_hit_candidates": target_hits,
                "nonzero_only": nonzero_only,
                "target_bytes_len": target.as_ref().map(|bytes| bytes.len()),
            }),
        );
        obj.insert("candidate_maps".to_string(), serde_json::Value::Array(maps));
    }
    print_pretty(&response)
}

pub(super) async fn cmd_api(
    trace_dir: PathBuf,
    path: String,
    method: String,
    params: Vec<String>,
    json_body: Option<String>,
) -> anyhow::Result<()> {
    let path = route_path(&normalize_api_path(&path)?, &parse_key_values(params)?);
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => {
            if json_body.is_some() {
                bail!("--json-body is only valid for POST");
            }
            route_get_json(trace_dir, path).await
        }
        "POST" => {
            let body = match json_body {
                Some(raw) => serde_json::from_str(&raw).context("parse --json-body")?,
                None => serde_json::json!({}),
            };
            route_post_json(trace_dir, path, body).await
        }
        other => bail!("unsupported --method {other}; expected GET or POST"),
    }
}

pub(super) async fn cmd_jni_output_strings(
    trace_dir: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    let report = jni_output_string_pairs(trace_dir, key, contains, limit).await?;
    print_pretty(&report)
}

pub(super) async fn jni_output_string_pairs(
    trace_dir: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("limit", limit.to_string()),
        ("id", "NewStringUTF".to_string()),
    ];
    let path = route_path("/api/jni-events", &params);
    let app = build_cli_router(trace_dir, &path, None)?;
    jni_output_string_pairs_on(&app, key, contains, limit).await
}

pub(super) async fn jni_output_string_pairs_on(
    app: &axum::Router,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("limit", limit.to_string()),
        ("id", "NewStringUTF".to_string()),
    ];
    let value = route_get_json_value_on(app, route_path("/api/jni-events", &params)).await?;
    let events = value
        .get("events")
        .and_then(|v| v.as_array())
        .context("/api/jni-events response missing events[]")?;

    let mut strings = Vec::new();
    for event in events {
        if event.get("id").and_then(|v| v.as_str()) != Some("NewStringUTF") {
            continue;
        }
        let Some(text) = event
            .get("args")
            .and_then(|v| v.get("bytes"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        strings.push(serde_json::json!({
            "idx": event.get("trace_idx").cloned().unwrap_or(serde_json::Value::Null),
            "ret": event.get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
    }

    let key_filter = key.as_deref();
    let contains_filter = contains.as_deref();
    let mut pairs = Vec::new();
    let mut iter = strings.chunks_exact(2);
    for pair in &mut iter {
        let key_text = pair[0].get("text").and_then(|v| v.as_str()).unwrap_or("");
        let value_text = pair[1].get("text").and_then(|v| v.as_str()).unwrap_or("");
        if key_filter.is_some_and(|needle| key_text != needle) {
            continue;
        }
        if contains_filter
            .is_some_and(|needle| !key_text.contains(needle) && !value_text.contains(needle))
        {
            continue;
        }
        pairs.push(serde_json::json!({
            "key_idx": pair[0].get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "key_ret": pair[0].get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "key": key_text,
            "value_idx": pair[1].get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "value_ret": pair[1].get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "value": value_text,
            "value_len": value_text.len(),
        }));
    }

    let unpaired = iter
        .remainder()
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({
        "count": pairs.len(),
        "pairs": pairs,
        "source_events": strings.len(),
        "source_truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Bool(false)),
        "unpaired": unpaired,
    }))
}

pub(super) fn cmd_scan_jni_output_strings(
    path: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
    decode_url: bool,
    decode_base64: bool,
    decode_base64_full: bool,
    diff_base64: bool,
    base64_tail_start: Option<usize>,
    base64_tail_align_prefix: String,
    base64_tail_drop: usize,
    prior_inputs: usize,
) -> anyhow::Result<()> {
    let hook_files = find_jni_hook_files(&path)?;
    let mut pairs = Vec::new();
    let mut scanned_events = 0usize;
    for file in &hook_files {
        let all_events = read_jni_string_events(file)?;
        scanned_events += all_events.len();
        let events = all_events
            .iter()
            .filter(|event| event.get("id").and_then(|v| v.as_str()) == Some("NewStringUTF"))
            .cloned()
            .collect::<Vec<_>>();
        let mut iter = events.chunks_exact(2);
        for pair in &mut iter {
            let key_text = pair[0].get("text").and_then(|v| v.as_str()).unwrap_or("");
            let value_text = pair[1].get("text").and_then(|v| v.as_str()).unwrap_or("");
            if key.as_deref().is_some_and(|needle| key_text != needle) {
                continue;
            }
            if contains
                .as_deref()
                .is_some_and(|needle| !key_text.contains(needle) && !value_text.contains(needle))
            {
                continue;
            }
            let mut row = serde_json::json!({
                "call_dir": file.parent().map(|p| p.display().to_string()).unwrap_or_default(),
                "hook_file": file.display().to_string(),
                "key_idx": pair[0].get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "key_ret": pair[0].get("ret").cloned().unwrap_or(serde_json::Value::Null),
                "key": key_text,
                "value_idx": pair[1].get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "value_ret": pair[1].get("ret").cloned().unwrap_or(serde_json::Value::Null),
                "value": value_text,
                "value_len": value_text.len(),
            });
            if decode_url {
                let decoded = percent_decode_bytes(value_text.as_bytes());
                if decoded != value_text.as_bytes() {
                    row["url_decoded"] =
                        serde_json::Value::String(String::from_utf8_lossy(&decoded).into_owned());
                    row["url_decoded_len"] = serde_json::json!(decoded.len());
                }
            }
            if decode_base64 || diff_base64 {
                let base64_text = row
                    .get("url_decoded")
                    .and_then(|v| v.as_str())
                    .unwrap_or(value_text);
                row["base64"] = base64_summary(base64_text, decode_base64_full || diff_base64);
            }
            if let Some(tail_start) = base64_tail_start {
                let base64_text = row
                    .get("url_decoded")
                    .and_then(|v| v.as_str())
                    .unwrap_or(value_text);
                row["base64_tail"] = base64_tail_summary(
                    base64_text,
                    tail_start,
                    &base64_tail_align_prefix,
                    base64_tail_drop,
                    decode_base64_full || diff_base64,
                );
            }
            if prior_inputs > 0 {
                let value_idx = pair[1].get("idx").and_then(|v| v.as_u64());
                row["prior_inputs"] = serde_json::Value::Array(prior_get_string_inputs(
                    &all_events,
                    value_idx,
                    prior_inputs,
                ));
            }
            pairs.push(row);
            if limit != 0 && pairs.len() >= limit {
                break;
            }
        }
        if limit != 0 && pairs.len() >= limit {
            break;
        }
    }
    let base64_diff = diff_base64.then(|| decoded_base64_diff(&pairs));
    let base64_tail_diff =
        (diff_base64 && base64_tail_start.is_some()).then(|| decoded_base64_tail_diff(&pairs));
    let mut out = serde_json::json!({
        "status": "ready",
        "path": path.display().to_string(),
        "hook_files": hook_files.len(),
        "source_events": scanned_events,
        "count": pairs.len(),
        "truncated": limit != 0 && pairs.len() >= limit,
        "pairs": pairs,
    });
    if let Some(diff) = base64_diff {
        out["base64_diff"] = diff;
    }
    if let Some(diff) = base64_tail_diff {
        out["base64_tail_diff"] = diff;
    }
    print_pretty(&out)
}

pub(super) fn find_jni_hook_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if path.is_file() {
        if path.file_name().and_then(|v| v.to_str()) == Some("jni_hooks.jsonl") {
            out.push(path.to_path_buf());
        }
        return Ok(out);
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    collect_jni_hook_files(path, &mut out)?;
    out.sort();
    Ok(out)
}

pub(super) fn collect_jni_hook_files(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_jni_hook_files(&path, out)?;
        } else if path.file_name().and_then(|v| v.to_str()) == Some("jni_hooks.jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

pub(super) fn read_jni_string_events(path: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut events = Vec::new();
    for line in raw.lines() {
        if !line.contains("StringUTF") {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(id) = event.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let text = match id {
            "NewStringUTF" => event
                .get("args")
                .and_then(|v| v.get("bytes"))
                .and_then(|v| v.as_str()),
            "GetStringUTFChars" => event.get("ret").and_then(|v| v.as_str()),
            _ => None,
        };
        let Some(text) = text else {
            continue;
        };
        events.push(serde_json::json!({
            "id": id,
            "idx": event.get("trace_idx").cloned().unwrap_or(serde_json::Value::Null),
            "ret": event.get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
    }
    Ok(events)
}

pub(super) fn prior_get_string_inputs(
    events: &[serde_json::Value],
    before_idx: Option<u64>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for event in events.iter().rev() {
        if event.get("id").and_then(|v| v.as_str()) != Some("GetStringUTFChars") {
            continue;
        }
        let idx = event.get("idx").and_then(|v| v.as_u64());
        if let (Some(idx), Some(before_idx)) = (idx, before_idx) {
            if idx >= before_idx {
                continue;
            }
        }
        let Some(text) = event.get("text").and_then(|v| v.as_str()) else {
            continue;
        };
        if !seen.insert(text.to_string()) {
            continue;
        }
        out.push(serde_json::json!({
            "idx": event.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
        if out.len() >= limit {
            break;
        }
    }
    out.reverse();
    out
}

pub(super) fn base64_summary(raw: &str, include_full_hex: bool) -> serde_json::Value {
    match base64_decoded_bytes(raw) {
        Ok(bytes) => {
            let mut summary = serde_json::json!({
                "ok": true,
                "decoded_len": bytes.len(),
                "prefix_hex": bytes_to_hex(&bytes[..bytes.len().min(16)]),
                "suffix_hex": bytes_to_hex(&bytes[bytes.len().saturating_sub(16)..]),
            });
            if include_full_hex {
                summary["decoded_hex"] = serde_json::Value::String(bytes_to_hex(&bytes));
            }
            summary
        }
        Err(err) => serde_json::json!({
            "ok": false,
            "error": err.to_string(),
        }),
    }
}

pub(super) fn base64_tail_summary(
    raw: &str,
    tail_start: usize,
    align_prefix: &str,
    drop_bytes: usize,
    include_full_hex: bool,
) -> serde_json::Value {
    let Some(tail) = raw.get(tail_start..) else {
        return serde_json::json!({
            "ok": false,
            "error": "tail_start is not a valid UTF-8 boundary or is past end",
            "tail_start_chars": tail_start,
        });
    };
    let aligned = format!("{align_prefix}{tail}");
    match base64_decoded_bytes(&aligned) {
        Ok(bytes) => {
            if drop_bytes > bytes.len() {
                return serde_json::json!({
                    "ok": false,
                    "error": "drop_bytes exceeds aligned decoded length",
                    "tail_start_chars": tail_start,
                    "tail_chars": tail.len(),
                    "align_prefix": align_prefix,
                    "drop_bytes": drop_bytes,
                    "aligned_decoded_len": bytes.len(),
                });
            }
            let semantic = &bytes[drop_bytes..];
            let mut summary = serde_json::json!({
                "ok": true,
                "tail_start_chars": tail_start,
                "tail_chars": tail.len(),
                "align_prefix": align_prefix,
                "drop_bytes": drop_bytes,
                "aligned_decoded_len": bytes.len(),
                "semantic_len": semantic.len(),
                "aligned_prefix_hex": bytes_to_hex(&bytes[..bytes.len().min(16)]),
                "semantic_prefix_hex": bytes_to_hex(&semantic[..semantic.len().min(16)]),
                "semantic_suffix_hex": bytes_to_hex(&semantic[semantic.len().saturating_sub(16)..]),
            });
            if include_full_hex {
                summary["aligned_decoded_hex"] = serde_json::Value::String(bytes_to_hex(&bytes));
                summary["semantic_hex"] = serde_json::Value::String(bytes_to_hex(semantic));
            }
            summary
        }
        Err(err) => serde_json::json!({
            "ok": false,
            "error": err.to_string(),
            "tail_start_chars": tail_start,
            "tail_chars": tail.len(),
            "align_prefix": align_prefix,
            "drop_bytes": drop_bytes,
        }),
    }
}

pub(super) fn decoded_base64_diff(pairs: &[serde_json::Value]) -> serde_json::Value {
    let samples = pairs
        .iter()
        .enumerate()
        .filter_map(|(sample, pair)| {
            let decoded_hex = pair
                .get("base64")
                .and_then(|v| v.get("decoded_hex"))
                .and_then(|v| v.as_str())?;
            let bytes = parse_hex_bytes_cli(decoded_hex).ok()?;
            Some((sample, pair, bytes))
        })
        .collect::<Vec<_>>();
    decoded_byte_samples_diff(samples)
}

pub(super) fn decoded_base64_tail_diff(pairs: &[serde_json::Value]) -> serde_json::Value {
    let samples = pairs
        .iter()
        .enumerate()
        .filter_map(|(sample, pair)| {
            let decoded_hex = pair
                .get("base64_tail")
                .and_then(|v| v.get("semantic_hex"))
                .and_then(|v| v.as_str())?;
            let bytes = parse_hex_bytes_cli(decoded_hex).ok()?;
            Some((sample, pair, bytes))
        })
        .collect::<Vec<_>>();
    let mut diff = decoded_byte_samples_diff(samples);
    diff["source"] = serde_json::json!("base64_tail.semantic_hex");
    diff
}

pub(super) fn decoded_byte_samples_diff(
    samples: Vec<(usize, &serde_json::Value, Vec<u8>)>,
) -> serde_json::Value {
    if samples.is_empty() {
        return serde_json::json!({
            "status": "no-decoded-samples",
            "sample_count": 0,
        });
    }
    let min_len = samples
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .min()
        .unwrap_or(0);
    let max_len = samples
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .max()
        .unwrap_or(0);
    let mut per_byte = Vec::new();
    let mut stable_offsets = Vec::new();
    let mut variable_offsets = Vec::new();
    for off in 0..min_len {
        let mut values = samples
            .iter()
            .map(|(_, _, bytes)| bytes[off])
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        if values.len() == 1 {
            stable_offsets.push(off);
            per_byte.push(serde_json::json!({
                "off": off,
                "kind": "STABLE",
                "value": format!("{:#x}", values[0]),
            }));
        } else {
            variable_offsets.push(off);
            per_byte.push(serde_json::json!({
                "off": off,
                "kind": "VARIABLE",
                "values": values.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>(),
            }));
        }
    }
    let stable_range_rows = stable_ranges(&stable_offsets)
        .into_iter()
        .map(|(start, end)| {
            let bytes = &samples[0].2[start..end];
            serde_json::json!({
                "start": start,
                "end": end,
                "length": end - start,
                "hex": bytes_to_hex(bytes),
            })
        })
        .collect::<Vec<_>>();
    let variable_ranges = stable_ranges(&variable_offsets)
        .into_iter()
        .map(|(start, end)| {
            let group_start = start / 3;
            let group_end = end.div_ceil(3);
            serde_json::json!({
                "start": start,
                "end": end,
                "length": end - start,
                "base64_group_start": group_start,
                "base64_group_end": group_end,
                "base64_groups": group_end.saturating_sub(group_start),
                "base64_char_start": group_start * 4,
                "base64_char_end": group_end * 4,
            })
        })
        .collect::<Vec<_>>();
    let first_variable = variable_offsets.first().map(|off| {
        let group = off / 3;
        serde_json::json!({
            "off": off,
            "base64_group": group,
            "base64_char_start": group * 4,
            "base64_char_end": (group + 1) * 4,
            "output_map_args": {
                "group_start": group,
                "groups": 1,
            },
        })
    });
    let sample_rows = samples
        .iter()
        .map(|(sample, pair, bytes)| {
            serde_json::json!({
                "sample": sample,
                "call_dir": pair.get("call_dir").cloned().unwrap_or(serde_json::Value::Null),
                "value_idx": pair.get("value_idx").cloned().unwrap_or(serde_json::Value::Null),
                "decoded_len": bytes.len(),
                "decoded_hex": bytes_to_hex(bytes),
            })
        })
        .collect::<Vec<_>>();
    let repeated_ranges = repeated_ranges_all_samples(&samples, 3, 64);
    serde_json::json!({
        "status": "ready",
        "sample_count": samples.len(),
        "min_len": min_len,
        "max_len": max_len,
        "compared_len": min_len,
        "length_variable": min_len != max_len,
        "range_semantics": "[start,end)",
        "stable_count": stable_offsets.len(),
        "variable_count": min_len.saturating_sub(stable_offsets.len()),
        "stable_ranges": stable_range_rows,
        "variable_ranges": variable_ranges,
        "first_variable": first_variable,
        "repeated_ranges_all_samples": repeated_ranges,
        "per_byte": per_byte,
        "samples": sample_rows,
    })
}

pub(super) fn repeated_ranges_all_samples(
    samples: &[(usize, &serde_json::Value, Vec<u8>)],
    min_len: usize,
    max_rows: usize,
) -> Vec<serde_json::Value> {
    let Some(compared_len) = samples.iter().map(|(_, _, bytes)| bytes.len()).min() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for src in 0..compared_len {
        for dst in src + 1..compared_len {
            if src > 0
                && dst > 0
                && samples
                    .iter()
                    .all(|(_, _, bytes)| bytes[src - 1] == bytes[dst - 1])
            {
                continue;
            }
            let mut len = 0usize;
            while src + len < compared_len
                && dst + len < compared_len
                && samples
                    .iter()
                    .all(|(_, _, bytes)| bytes[src + len] == bytes[dst + len])
            {
                len += 1;
            }
            if len < min_len {
                continue;
            }
            let examples = samples
                .iter()
                .take(4)
                .map(|(sample, pair, bytes)| {
                    serde_json::json!({
                        "sample": sample,
                        "call_dir": pair.get("call_dir").cloned().unwrap_or(serde_json::Value::Null),
                        "src_hex": bytes_to_hex(&bytes[src..src + len]),
                        "dst_hex": bytes_to_hex(&bytes[dst..dst + len]),
                    })
                })
                .collect::<Vec<_>>();
            rows.push(serde_json::json!({
                "src_start": src,
                "src_end": src + len,
                "dst_start": dst,
                "dst_end": dst + len,
                "length": len,
                "examples": examples,
            }));
        }
    }
    rows.sort_by_key(|row| {
        (
            std::cmp::Reverse(row.get("length").and_then(|v| v.as_u64()).unwrap_or(0)),
            row.get("src_start").and_then(|v| v.as_u64()).unwrap_or(0),
            row.get("dst_start").and_then(|v| v.as_u64()).unwrap_or(0),
        )
    });
    rows.truncate(max_rows);
    rows
}

pub(super) fn stable_ranges(offsets: &[usize]) -> Vec<(usize, usize)> {
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = offsets[0];
    let mut prev = offsets[0];
    for &off in offsets.iter().skip(1) {
        if off != prev + 1 {
            ranges.push((start, prev + 1));
            start = off;
        }
        prev = off;
    }
    ranges.push((start, prev + 1));
    ranges
}

pub(super) fn base64_decoded_bytes(raw: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut padded = trimmed.replace('-', "+").replace('_', "/");
    let rem = padded.len() % 4;
    if rem != 0 {
        padded.push_str(&"=".repeat(4 - rem));
    }
    let engine = GeneralPurpose::new(
        &BASE64_STANDARD_ALPHABET,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    engine.decode(padded.as_bytes())
}

pub(super) fn base64_group_analysis(raw: &str) -> serde_json::Value {
    let chars = raw.as_bytes();
    let indices = chars
        .iter()
        .enumerate()
        .map(|(pos, &byte)| {
            let index = base64_char_index(byte);
            serde_json::json!({
                "pos": pos,
                "char": char::from(byte).to_string(),
                "index": index,
                "index_hex": index.map(|idx| format!("{idx:#x}")),
            })
        })
        .collect::<Vec<_>>();
    let values = chars
        .iter()
        .filter_map(|&byte| base64_char_index(byte))
        .collect::<Vec<_>>();
    let mut decoded = Vec::new();
    if values.len() >= 2 {
        decoded.push(serde_json::json!({
            "byte": 0,
            "value_hex": format!("{:02x}", (values[0] << 2) | (values[1] >> 4)),
            "formula": "(i0 << 2) | (i1 >> 4)",
            "indices": [0, 1],
        }));
    }
    if values.len() >= 3 && chars.get(2) != Some(&b'=') {
        decoded.push(serde_json::json!({
            "byte": 1,
            "value_hex": format!("{:02x}", ((values[1] & 0x0f) << 4) | (values[2] >> 2)),
            "formula": "((i1 & 0x0f) << 4) | (i2 >> 2)",
            "indices": [1, 2],
        }));
    }
    if values.len() >= 4 && chars.get(3) != Some(&b'=') {
        decoded.push(serde_json::json!({
            "byte": 2,
            "value_hex": format!("{:02x}", ((values[2] & 0x03) << 6) | values[3]),
            "formula": "((i2 & 0x03) << 6) | i3",
            "indices": [2, 3],
        }));
    }
    serde_json::json!({
        "indices": indices,
        "decoded_bytes": decoded,
    })
}

pub(super) fn base64_lookup_matches(
    base64: &serde_json::Value,
    trees: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let lookups = trees
        .iter()
        .flat_map(|tree| {
            tree.get("tree")
                .and_then(|v| v.get("highlights"))
                .and_then(|v| v.get("table_lookups"))
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    base64
        .get("indices")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|index| {
            let ch = index.get("char").and_then(|v| v.as_str()).unwrap_or("");
            let index_hex = index
                .get("index_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let matches = lookups
                .iter()
                .filter(|lookup| {
                    lookup.get("char").and_then(|v| v.as_str()) == Some(ch)
                        && lookup.get("index_value").and_then(|v| v.as_str()) == Some(index_hex)
                })
                .map(|lookup| {
                    serde_json::json!({
                        "idx": lookup.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "reg": lookup.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                        "index_reg": lookup.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                        "base_value": lookup.get("base_value").cloned().unwrap_or(serde_json::Value::Null),
                        "node": lookup.get("node").cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "pos": index.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                "char": ch,
                "index": index.get("index").cloned().unwrap_or(serde_json::Value::Null),
                "index_hex": index_hex,
                "matches": matches,
            })
        })
        .collect()
}

pub(super) async fn attach_base64_index_trees_on(
    app: &axum::Router,
    lookup_matches: &mut [serde_json::Value],
    opts: &OutputMapOpts,
) -> anyhow::Result<()> {
    for row in lookup_matches {
        let Some(matches) = row.get_mut("matches").and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for lookup in matches {
            let Some(idx) = lookup.get("idx").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(reg) = lookup.get("index_reg").and_then(|v| v.as_str()) else {
                continue;
            };
            let tree = vm_backtree_value_on(
                app,
                idx as usize,
                Some(reg.to_string()),
                opts.index_tree_depth,
                opts.index_tree_max_nodes,
                120,
                opts.lookback,
                5000,
                opts.tree_frontier_with_next,
                "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28".to_string(),
                &opts.vm_profile,
            )
            .await?;
            let summary = index_tree_summary(&tree);
            if let Some(obj) = lookup.as_object_mut() {
                obj.insert("index_summary".to_string(), summary);
                obj.insert("index_tree".to_string(), tree);
            }
        }
    }
    Ok(())
}

pub(super) fn index_tree_summary(tree: &serde_json::Value) -> serde_json::Value {
    let formulas = tree
        .get("highlights")
        .and_then(|v| v.get("alu_formulas"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let interesting_formulas = tree
        .get("highlights")
        .and_then(|v| v.get("alu_formulas"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|formula| {
            formula
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
                .is_some_and(|value| value <= 0x3f)
                && formula_operands_below(formula, 0xfff)
                && !formula_is_low_signal(formula)
        })
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    let semantic_formulas = formulas
        .iter()
        .filter(|formula| {
            (formula.get("semantic").is_some()
                || formula.get("op").and_then(|v| v.as_str()) == Some("udiv"))
                && !formula_is_low_signal(formula)
        })
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "interesting_formulas": interesting_formulas,
        "semantic_formulas": semantic_formulas,
    })
}

pub(super) fn formula_is_low_signal(formula: &serde_json::Value) -> bool {
    let op = formula.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let value = formula
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let operands = formula
        .get("operands")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|operand| {
            operand
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
        })
        .collect::<Vec<_>>();
    match op {
        "ubfx" => formula
            .get("expression")
            .and_then(|v| v.as_str())
            .is_some_and(|expr| expr.contains(", 0x0, 0x20)")),
        "lsl" | "lsr" => operands.get(1).copied() == Some(0),
        "orr" | "add" => operands
            .iter()
            .enumerate()
            .any(|(idx, &operand)| operand == 0 && operands.get(1 - idx).copied() == value),
        _ => value == Some(0),
    }
}

pub(super) fn formula_operands_below(formula: &serde_json::Value, max_value: u64) -> bool {
    formula
        .get("operands")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|operand| {
            operand
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
        })
        .all(|value| value <= max_value)
}

pub(super) fn base64_char_index(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ALPHABET
        .iter()
        .position(|&item| item == byte)
        .map(|idx| idx as u8)
}
