use super::*;

#[derive(Debug)]
pub struct OutputBacktraceOpts {
    pub key: Option<String>,
    pub value: Option<String>,
    pub bytes_hex: Option<String>,
    pub jni_limit: usize,
    pub max_mem_hits: usize,
    pub writes_per_hit: usize,
    pub taint_seeds: usize,
    pub taint_max_count: usize,
    pub vm_chain_steps: usize,
    pub vm_chain_runs: usize,
    pub vm_chain_lookback: usize,
    pub vm_chain_follow_frontier: bool,
    pub vm_profile: VmProfile,
    pub skip_taint: bool,
    pub url_decode: bool,
    pub base64_decode: bool,
}

#[derive(Debug)]
pub struct OutputMapOpts {
    pub key: Option<String>,
    pub value: Option<String>,
    pub jni_limit: usize,
    pub max_mem_hits: usize,
    pub hit_rank: usize,
    pub hit_order: HitOrder,
    pub group_start: usize,
    pub groups: usize,
    pub semantic_offset: Option<usize>,
    pub semantic_count: usize,
    pub tree_depth: usize,
    pub tree_max_nodes: usize,
    pub index_tree_depth: usize,
    pub index_tree_max_nodes: usize,
    pub tree_frontier_with_next: bool,
    pub lookback: usize,
    pub url_decode: bool,
    pub base64_tail_start: Option<usize>,
    pub base64_tail_align_prefix: String,
    pub base64_tail_drop: usize,
    pub semantic_writer_map: bool,
    pub semantic_writer_map_idx_hi: Option<usize>,
    pub semantic_writer_map_max: usize,
    pub semantic_writer_map_vm_chain_steps: usize,
    pub semantic_writer_map_vm_chain_runs: usize,
    pub semantic_writer_map_vm_chain_bytes: bool,
    pub semantic_writer_map_vm_chain_lookback: usize,
    pub semantic_writer_map_vm_chain_follow_frontier: bool,
    pub vm_profile: VmProfile,
    pub summary: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HitOrder {
    /// Earliest first write of a full output buffer. Best for walking generation backward.
    Earliest,
    /// Closest full output buffer to the JNI value trace index.
    Nearest,
    /// Latest first write of a full output buffer.
    Latest,
}

impl HitOrder {
    fn as_str(self) -> &'static str {
        match self {
            HitOrder::Earliest => "earliest",
            HitOrder::Nearest => "nearest",
            HitOrder::Latest => "latest",
        }
    }
}

#[derive(Debug)]
pub(super) struct OutputSource {
    pub(super) json: serde_json::Value,
    pub(super) primary_bytes: Vec<u8>,
    pub(super) text: Option<String>,
    pub(super) value_idx: Option<usize>,
}

pub fn output_backtrace(
    trace_dir: PathBuf,
    opts: OutputBacktraceOpts,
) -> anyhow::Result<serde_json::Value> {
    let context = AnalysisContext::load(trace_dir)?;
    let source = resolve_output_source(&context, &opts)?;
    let mut patterns: Vec<(&'static str, Vec<u8>)> =
        vec![("observed", source.primary_bytes.clone())];
    let mut text_for_decoders = source.text.clone();
    if opts.url_decode {
        if let Some(text) = source.text.as_deref() {
            let decoded = percent_decode_bytes(text.as_bytes());
            if decoded != source.primary_bytes {
                if let Ok(decoded_text) = String::from_utf8(decoded.clone()) {
                    text_for_decoders = Some(decoded_text);
                }
                patterns.push(("percent_decoded", decoded));
            }
        }
    }
    if opts.base64_decode {
        if let Some(text) = text_for_decoders.as_deref() {
            if let Ok(decoded) = base64_decoded_bytes(text) {
                if !decoded.is_empty() && decoded != source.primary_bytes {
                    patterns.push(("base64_decoded", decoded));
                }
            }
        }
    }

    let mut seen_patterns = HashSet::new();
    let mut pattern_reports = Vec::new();
    let mut taint_seed_seen = HashSet::new();
    let mut taint_seed_queue: Vec<serde_json::Value> = Vec::new();

    if let Some(value_idx) = source.value_idx {
        if value_idx > 0 {
            push_taint_seed(
                &mut taint_seed_seen,
                &mut taint_seed_queue,
                serde_json::json!({
                    "kind": "jni_new_string_utf_callsite",
                    "start": value_idx - 1,
                    "reg": "x1",
                    "reason": "NewStringUTF callsite; x1 normally points at the C string bytes on ARM64",
                }),
            );
        }
    }

    for (kind, bytes) in patterns {
        if bytes.is_empty() {
            continue;
        }
        let hex = bytes_to_hex(&bytes);
        if !seen_patterns.insert(hex.clone()) {
            continue;
        }
        let mut hit_reports = Vec::new();
        let find = if opts.max_mem_hits > 0 {
            let params = crate::analysis::memory_query::FindMemPatternQuery {
                bytes_hex: hex.clone(),
                max: opts.max_mem_hits,
                ..Default::default()
            };
            query_value_on(&context, Query::FindMemPattern(params))?
        } else {
            serde_json::json!({
                "status": "skipped",
                "pattern": hex,
                "count": 0,
                "returned": 0,
                "truncated": false,
                "hits": [],
            })
        };

        if opts.writes_per_hit > 0 {
            let hits = sorted_pattern_hits(&find, source.value_idx);
            if !hits.is_empty() {
                for hit in hits {
                    let Some(addr) = hit
                        .get("addr")
                        .and_then(|v| v.as_str())
                        .and_then(parse_u64_str)
                    else {
                        continue;
                    };
                    let addr_hi = addr.saturating_add(bytes.len() as u64);
                    let provenance_params =
                        crate::analysis::string_provenance::StringProvenanceQuery {
                            addr: format!("{addr:#x}"),
                            length: bytes.len(),
                        };
                    let provenance =
                        query_value_on(&context, Query::StringProvenance(provenance_params))?;
                    let top_writers = provenance_writer_counts(&provenance, opts.writes_per_hit);
                    let mut writer_details = Vec::new();
                    for writer in &top_writers {
                        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let record =
                            query_value_on(&context, Query::Record(usize::try_from(idx)?))?;
                        let writer_seeds = writer_taint_seeds_from_record(&record);
                        for seed in &writer_seeds {
                            push_taint_seed(
                                &mut taint_seed_seen,
                                &mut taint_seed_queue,
                                seed.clone(),
                            );
                        }
                        writer_details.push(serde_json::json!({
                            "writer": writer,
                            "record": record,
                            "writer_seeds": writer_seeds,
                        }));
                    }
                    let writer_runs = provenance_writer_runs(&provenance, &writer_details);
                    let vm_chains = if opts.vm_chain_steps > 0 && opts.vm_chain_runs > 0 {
                        vm_chains_for_writer_runs(&context, &writer_runs, &opts)?
                    } else {
                        Vec::new()
                    };
                    hit_reports.push(serde_json::json!({
                        "hit": hit,
                        "distance_to_value_idx": source.value_idx.and_then(|idx| {
                            hit.get("first_idx")
                                .and_then(|v| v.as_u64())
                                .map(|first| idx.abs_diff(first as usize))
                        }),
                        "range": {
                            "addr_lo": format!("{addr:#x}"),
                            "addr_hi": format!("{addr_hi:#x}"),
                            "length": bytes.len(),
                        },
                        "provenance": provenance,
                        "top_provenance_writers": top_writers,
                        "writer_details": writer_details,
                        "writer_runs": writer_runs,
                        "vm_chains": vm_chains,
                    }));
                }
            }
        }

        pattern_reports.push(serde_json::json!({
            "kind": kind,
            "length": bytes.len(),
            "bytes_hex": hex,
            "text_preview": utf8_preview(&bytes, 160),
            "find_mem_pattern": find,
            "hit_reports": hit_reports,
        }));
    }

    let taint_reports = if opts.skip_taint {
        serde_json::json!({
            "skipped": true,
            "reason": "--skip-taint was set",
            "queued": taint_seed_queue,
        })
    } else {
        run_backward_taint_summaries(
            &context,
            &taint_seed_queue,
            opts.taint_seeds,
            opts.taint_max_count,
        )?
    };

    Ok(serde_json::to_value(BacktraceReport {
        status: "ready",
        strategy: "output_to_input_backward_trace",
        source: source.json,
        patterns: pattern_reports,
        taint: taint_reports,
        notes: BACKTRACE_NOTES.to_vec(),
    })?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn output_map_group_vm_trees(
    context: &AnalysisContext,
    runs: &[serde_json::Value],
    depth: usize,
    max_nodes: usize,
    lookback: usize,
    frontier_with_next: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    if depth == 0 {
        return Ok(Vec::new());
    }
    let mut trees = Vec::new();
    let mut seen_tree_seeds = HashSet::new();
    for run in runs {
        if let Some(seed) = run
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .and_then(|seeds| {
                seeds.iter().find(|seed| {
                    seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                })
            })
        {
            let Some(idx) = seed.get("start").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
                continue;
            };
            if !seen_tree_seeds.insert((idx, reg.to_string())) {
                continue;
            }
            let tree = vm_backtree_value_on(
                context,
                idx as usize,
                Some(reg.to_string()),
                depth,
                max_nodes,
                120,
                lookback,
                5000,
                frontier_with_next,
                "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28".to_string(),
                profile,
            )?;
            trees.push(serde_json::json!({
                "seed": seed,
                "tree": tree,
            }));
            if trees.len() >= 8 {
                break;
            }
        }
    }
    Ok(trees)
}

pub fn output_map(trace_dir: PathBuf, opts: OutputMapOpts) -> anyhow::Result<serde_json::Value> {
    let context = AnalysisContext::load(trace_dir)?;
    let source = resolve_output_source(
        &context,
        &OutputBacktraceOpts {
            key: opts.key.clone(),
            value: opts.value.clone(),
            bytes_hex: None,
            jni_limit: opts.jni_limit,
            max_mem_hits: opts.max_mem_hits,
            writes_per_hit: 0,
            taint_seeds: 0,
            taint_max_count: 0,
            vm_chain_steps: 0,
            vm_chain_runs: 0,
            vm_chain_lookback: opts.lookback,
            vm_chain_follow_frontier: false,
            vm_profile: opts.vm_profile.clone(),
            skip_taint: true,
            url_decode: opts.url_decode,
            base64_decode: true,
        },
    )?;
    let Some(source_text) = source.text.as_deref() else {
        bail!("output-map requires textual --key or --value source");
    };
    let mapped_text = if opts.url_decode {
        let decoded = percent_decode_bytes(source_text.as_bytes());
        String::from_utf8(decoded).unwrap_or_else(|_| source_text.to_string())
    } else {
        source_text.to_string()
    };
    let base64_context = base64_output_context(&mapped_text, &opts)?;
    let grouped_text = base64_context
        .get("grouped_text")
        .and_then(|v| v.as_str())
        .unwrap_or(mapped_text.as_str())
        .to_string();
    let align_prefix_len = base64_context
        .get("align_prefix_chars")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let tail_start = base64_context
        .get("tail_start_chars")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let semantic_drop = base64_context
        .get("semantic_drop_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let selected_semantic_range = opts.semantic_offset.map(|start| {
        let count = opts.semantic_count.max(1);
        let end = start.saturating_add(count);
        serde_json::json!({
            "start": start,
            "end": end,
            "length": count,
        })
    });
    let find = if opts.max_mem_hits > 0 {
        let params = crate::analysis::memory_query::FindMemPatternQuery {
            bytes_hex: bytes_to_hex(&source.primary_bytes),
            max: opts.max_mem_hits,
            ..Default::default()
        };
        query_value_on(&context, Query::FindMemPattern(params))?
    } else {
        serde_json::json!({
            "status": "skipped",
            "hits": [],
        })
    };
    let hits = sorted_pattern_hits_by(&find, source.value_idx, opts.hit_order);
    let hit_candidates = hit_candidate_summaries(&hits, source.value_idx);
    let selected_hit = hits.get(opts.hit_rank).cloned();
    let mut writer_runs = Vec::new();
    let mut selected_range = serde_json::Value::Null;
    let mut selected_addr = None;
    let mut first_output_writer_idx = None;
    if let Some(hit) = selected_hit.as_ref() {
        if let Some(addr) = hit
            .get("addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
        {
            selected_addr = Some(addr);
            let params = crate::analysis::string_provenance::StringProvenanceQuery {
                addr: format!("{addr:#x}"),
                length: source.primary_bytes.len(),
            };
            let provenance = query_value_on(&context, Query::StringProvenance(params))?;
            writer_runs = provenance_writer_runs(&provenance, &[]);
            first_output_writer_idx = min_writer_idx(&writer_runs);
            selected_range = serde_json::json!({
                "addr_lo": format!("{addr:#x}"),
                "addr_hi": format!("{:#x}", addr.saturating_add(source.primary_bytes.len() as u64)),
                "length": source.primary_bytes.len(),
            });
        }
    }

    let group_total = grouped_text.len().div_ceil(4);
    let (selected_group_start, selected_group_end) =
        if let Some(semantic_start) = opts.semantic_offset {
            let count = opts.semantic_count.max(1);
            let aligned_start = (semantic_start as u64).saturating_add(semantic_drop) as usize;
            let aligned_end = (semantic_start.saturating_add(count) as u64)
                .saturating_add(semantic_drop) as usize;
            (
                (aligned_start / 3).min(group_total),
                aligned_end.div_ceil(3).min(group_total),
            )
        } else {
            let group_end = if opts.groups == 0 {
                group_total
            } else {
                opts.group_start
                    .saturating_add(opts.groups)
                    .min(group_total)
            };
            (opts.group_start.min(group_total), group_end)
        };
    let mut group_rows = Vec::new();
    for group_idx in selected_group_start..selected_group_end {
        let start = group_idx * 4;
        let end = (start + 4).min(grouped_text.len());
        let chars = &grouped_text[start..end];
        let decoded = base64_decoded_bytes(chars).unwrap_or_default();
        let base64 = base64_group_analysis(chars);
        let original_range =
            original_output_range_for_group(start, end, tail_start, align_prefix_len);
        let runs = if let Some((orig_start, orig_end)) = original_range {
            output_runs_overlapping(&context, &writer_runs, orig_start, orig_end)?
        } else {
            Vec::new()
        };
        let trees = output_map_group_vm_trees(
            &context,
            &runs,
            opts.tree_depth,
            opts.tree_max_nodes,
            opts.lookback,
            opts.tree_frontier_with_next,
            &opts.vm_profile,
        )?;
        let hidden_lookup_trees;
        let lookup_trees = if opts.index_tree_depth > 0 && trees.is_empty() {
            hidden_lookup_trees = output_map_group_vm_trees(
                &context,
                &runs,
                BASE64_LOOKUP_TREE_DEPTH,
                BASE64_LOOKUP_TREE_MAX_NODES.max(opts.index_tree_max_nodes),
                opts.lookback,
                true,
                &opts.vm_profile,
            )?;
            hidden_lookup_trees.as_slice()
        } else {
            trees.as_slice()
        };
        let mut lookup_matches = base64_lookup_matches(&base64, lookup_trees);
        if opts.index_tree_depth > 0 {
            attach_base64_index_trees_on(&context, &mut lookup_matches, &opts)?;
        }
        group_rows.push(serde_json::json!({
            "group": group_idx,
            "offset": start,
            "end": end,
            "original_output_start": original_range.map(|(start, _)| start),
            "original_output_end": original_range.map(|(_, end)| end),
            "decoded_offset_base": group_idx.saturating_mul(3),
            "semantic_drop_bytes": semantic_drop,
            "chars": chars,
            "base64": base64,
            "base64_lookup_matches": lookup_matches,
            "decoded_hex": bytes_to_hex(&decoded),
            "runs": runs,
            "trees": trees,
        }));
    }
    let semantic_writer_map = if opts.semantic_writer_map {
        output_semantic_writer_map(
            &context,
            &grouped_text,
            selected_addr,
            first_output_writer_idx,
            &opts,
        )?
    } else {
        serde_json::Value::Null
    };

    let output = serde_json::to_value(OutputMapReport {
        status: "ready",
        strategy: "output_base64_group_map",
        source: source.json,
        text_len: mapped_text.len(),
        base64_context,
        group_total,
        selected_group_start,
        selected_group_end,
        selected_semantic_range,
        selected_hit_order: opts.hit_order.as_str().to_string(),
        selected_hit_rank: opts.hit_rank,
        tree_frontier_with_next: opts.tree_frontier_with_next,
        index_tree_depth: opts.index_tree_depth,
        index_tree_max_nodes: opts.index_tree_max_nodes,
        hit_candidates,
        selected_hit,
        selected_range,
        find_mem_pattern: find,
        semantic_writer_map,
        groups: group_rows,
    })?;
    if opts.summary {
        Ok(output_map_summary(&output))
    } else {
        Ok(output)
    }
}

pub(super) fn min_writer_idx(runs: &[serde_json::Value]) -> Option<usize> {
    runs.iter()
        .filter_map(|run| run.get("writer_idx").and_then(|v| v.as_u64()))
        .filter_map(|idx| usize::try_from(idx).ok())
        .min()
}

pub(super) fn output_semantic_writer_map(
    context: &AnalysisContext,
    grouped_text: &str,
    selected_addr: Option<u64>,
    first_output_writer_idx: Option<usize>,
    opts: &OutputMapOpts,
) -> anyhow::Result<serde_json::Value> {
    let Some(base_addr) = selected_addr else {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "no selected output memory hit",
        }));
    };
    let idx_hi = opts.semantic_writer_map_idx_hi.or(first_output_writer_idx);
    let Some(idx_hi) = idx_hi else {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "no final-output writer idx found; pass --semantic-writer-map-idx-hi",
        }));
    };
    let decoded = base64_decoded_bytes(grouped_text)
        .context("failed to decode selected output text for --semantic-writer-map")?;
    let drop = opts.base64_tail_drop;
    if drop >= decoded.len() {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "semantic drop is past decoded byte length",
            "decoded_len": decoded.len(),
            "semantic_drop_bytes": drop,
        }));
    }
    let semantic_total = decoded.len() - drop;
    let semantic_start = opts.semantic_offset.unwrap_or(0);
    if semantic_start >= semantic_total {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "semantic offset is past decoded semantic byte length",
            "semantic_offset": semantic_start,
            "semantic_total": semantic_total,
        }));
    }
    let requested_count = if opts.semantic_offset.is_some() {
        opts.semantic_count.max(1)
    } else {
        semantic_total
    };
    let semantic_len = requested_count.min(semantic_total - semantic_start);
    let addr_offset = drop
        .checked_add(semantic_start)
        .context("semantic writer-map offset overflowed")?;
    let map_addr = base_addr
        .checked_add(addr_offset as u64)
        .context("semantic writer-map address overflowed")?;
    let addr_hi = map_addr
        .checked_add(semantic_len as u64)
        .context("semantic writer-map end address overflowed")?;
    let params = crate::analysis::memory_query::MemWritesInRangeQuery {
        idx_lo: usize::try_from(0)?,
        idx_hi: isize::try_from(idx_hi)?,
        addr_lo: Some(format!("{map_addr:#x}")),
        addr_hi: Some(format!("{addr_hi:#x}")),
        max: opts.semantic_writer_map_max,
        ..Default::default()
    };
    let response = query_value_on(context, Query::MemWritesInRange(params))?;
    let mut map = byte_writer_map_output(map_addr, semantic_len, &response);
    if opts.semantic_writer_map_vm_chain_steps > 0 && opts.semantic_writer_map_vm_chain_runs > 0 {
        let (seed_mode, chains) = if opts.semantic_writer_map_vm_chain_bytes {
            let bytes = map
                .get("bytes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            (
                "bytes",
                vm_chains_for_byte_writer_entries(
                    context,
                    &bytes,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )?,
            )
        } else {
            let runs = map
                .get("writer_runs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            (
                "writer_runs",
                vm_chains_for_byte_writer_runs(
                    context,
                    &runs,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )?,
            )
        };
        let chain_summary = vm_chain_batch_summary(&chains);
        if let Some(obj) = map.as_object_mut() {
            obj.insert(
                "vm_chain_seed_mode".to_string(),
                serde_json::json!(seed_mode),
            );
            obj.insert("vm_chain_summary".to_string(), chain_summary);
            obj.insert("vm_chains".to_string(), serde_json::Value::Array(chains));
        }
    }
    if let Some(obj) = map.as_object_mut() {
        obj.insert(
            "semantic_context".to_string(),
            serde_json::json!({
                "mode": "selected_output_buffer_pre_encoding",
                "base_addr": format!("{base_addr:#x}"),
                "addr_offset_from_base": addr_offset,
                "semantic_offset": semantic_start,
                "semantic_count": semantic_len,
                "semantic_total": semantic_total,
                "decoded_len": decoded.len(),
                "idx_hi": idx_hi,
                "idx_hi_source": if opts.semantic_writer_map_idx_hi.is_some() {
                    "explicit"
                } else {
                    "first_final_output_writer"
                },
                "note": "Uses the selected final output buffer as the earlier pre-encoding scratch buffer and stops before the final output overwrite.",
            }),
        );
    }
    Ok(map)
}

pub(super) fn base64_output_context(
    mapped_text: &str,
    opts: &OutputMapOpts,
) -> anyhow::Result<serde_json::Value> {
    if let Some(tail_start) = opts.base64_tail_start {
        let Some(tail) = mapped_text.get(tail_start..) else {
            bail!("--base64-tail-start is not a valid boundary or is past the output text");
        };
        let grouped_text = format!("{}{}", opts.base64_tail_align_prefix, tail);
        Ok(serde_json::json!({
            "mode": "aligned_tail",
            "tail_start_chars": tail_start,
            "tail_chars": tail.len(),
            "align_prefix": opts.base64_tail_align_prefix,
            "align_prefix_chars": opts.base64_tail_align_prefix.len(),
            "semantic_drop_bytes": opts.base64_tail_drop,
            "grouped_text_len": grouped_text.len(),
            "grouped_text": grouped_text,
        }))
    } else {
        Ok(serde_json::json!({
            "mode": "whole_output",
            "tail_start_chars": serde_json::Value::Null,
            "tail_chars": mapped_text.len(),
            "align_prefix": "",
            "align_prefix_chars": 0,
            "semantic_drop_bytes": 0,
            "grouped_text_len": mapped_text.len(),
            "grouped_text": mapped_text,
        }))
    }
}

pub(super) fn original_output_range_for_group(
    grouped_start: usize,
    grouped_end: usize,
    tail_start: Option<usize>,
    align_prefix_len: usize,
) -> Option<(usize, usize)> {
    match tail_start {
        Some(tail_start) => {
            if grouped_end <= align_prefix_len {
                None
            } else {
                let start =
                    tail_start.saturating_add(grouped_start.saturating_sub(align_prefix_len));
                let end = tail_start.saturating_add(grouped_end.saturating_sub(align_prefix_len));
                (start < end).then_some((start, end))
            }
        }
        None => Some((grouped_start, grouped_end)),
    }
}

pub(super) fn output_map_summary(value: &serde_json::Value) -> serde_json::Value {
    let groups = value
        .get("groups")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_group_summary)
        .collect::<Vec<_>>();
    let semantic_writer_map = output_semantic_writer_map_summary(
        value
            .get("semantic_writer_map")
            .unwrap_or(&serde_json::Value::Null),
    );
    let semantic_byte_equation_summary = semantic_writer_map
        .get("byte_equation_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let semantic_byte_input_summary = semantic_writer_map
        .get("byte_equation_input_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let semantic_vm_chain_summary = semantic_writer_map
        .get("vm_chain_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "strategy": value.get("strategy").cloned().unwrap_or(serde_json::Value::Null),
        "source": value.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "text_len": value.get("text_len").cloned().unwrap_or(serde_json::Value::Null),
        "base64_context": {
            "mode": value.pointer("/base64_context/mode").cloned().unwrap_or(serde_json::Value::Null),
            "tail_start_chars": value.pointer("/base64_context/tail_start_chars").cloned().unwrap_or(serde_json::Value::Null),
            "align_prefix": value.pointer("/base64_context/align_prefix").cloned().unwrap_or(serde_json::Value::Null),
            "semantic_drop_bytes": value.pointer("/base64_context/semantic_drop_bytes").cloned().unwrap_or(serde_json::Value::Null),
            "grouped_text_len": value.pointer("/base64_context/grouped_text_len").cloned().unwrap_or(serde_json::Value::Null),
        },
        "group_total": value.get("group_total").cloned().unwrap_or(serde_json::Value::Null),
        "selected_group_start": value.get("selected_group_start").cloned().unwrap_or(serde_json::Value::Null),
        "selected_group_end": value.get("selected_group_end").cloned().unwrap_or(serde_json::Value::Null),
        "selected_semantic_range": value.get("selected_semantic_range").cloned().unwrap_or(serde_json::Value::Null),
        "selected_hit_order": value.get("selected_hit_order").cloned().unwrap_or(serde_json::Value::Null),
        "selected_hit_rank": value.get("selected_hit_rank").cloned().unwrap_or(serde_json::Value::Null),
        "selected_range": value.get("selected_range").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_byte_equation_summary": semantic_byte_equation_summary,
        "semantic_byte_input_summary": semantic_byte_input_summary,
        "semantic_vm_chain_summary": semantic_vm_chain_summary,
        "semantic_writer_map": semantic_writer_map,
        "groups": groups,
    })
}

pub(super) fn output_semantic_writer_map_summary(value: &serde_json::Value) -> serde_json::Value {
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let writer_run_count = value
        .get("writer_runs")
        .and_then(|v| v.as_array())
        .map(|runs| runs.len())
        .unwrap_or(0);
    let byte_equations = output_semantic_byte_equations(value);
    let byte_equation_summary = output_semantic_byte_equation_summary_with_context(
        &byte_equations,
        value.get("semantic_context"),
    );
    let byte_equation_input_summary = output_semantic_byte_equation_input_summary(&byte_equations);
    let xor_word_templates = output_semantic_xor_word_templates(&byte_equations);
    let xor_word_template_count = xor_word_templates
        .as_array()
        .map(|templates| templates.len())
        .unwrap_or(0);
    let xor_word_degenerate_templates =
        output_semantic_xor_word_degenerate_templates(&byte_equations);
    let xor_word_degenerate_template_count = xor_word_degenerate_templates
        .as_array()
        .map(|templates| templates.len())
        .unwrap_or(0);
    let xor_word_run_templates = output_semantic_xor_word_run_templates(&byte_equations);
    let xor_word_run_template_count = xor_word_run_templates
        .as_array()
        .map(|templates| templates.len())
        .unwrap_or(0);
    let xor_word_state_sources =
        output_semantic_xor_word_state_sources(value, &xor_word_run_templates);
    let xor_word_state_source_summary = output_semantic_xor_word_state_source_summary(
        &xor_word_run_templates,
        &xor_word_state_sources,
    );
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_context": value.get("semantic_context").cloned().unwrap_or(serde_json::Value::Null),
        "addr": value.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": value.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "idx_range": value.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": value.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "complete": value.get("complete").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": value.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": value.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "missing_offsets": value.get("missing_offsets").cloned().unwrap_or(serde_json::Value::Null),
        "writer_run_count": writer_run_count,
        "writer_runs": value.get("writer_runs").cloned().unwrap_or(serde_json::Value::Null),
        "vm_chain_seed_mode": value.get("vm_chain_seed_mode").cloned().unwrap_or(serde_json::Value::Null),
        "vm_chain_summary": value.get("vm_chain_summary").cloned().unwrap_or(serde_json::Value::Null),
        "byte_equation_summary": byte_equation_summary,
        "byte_equation_input_summary": byte_equation_input_summary,
        "byte_equations": byte_equations,
        "xor_word_template_count": xor_word_template_count,
        "xor_word_templates": xor_word_templates,
        "xor_word_degenerate_template_count": xor_word_degenerate_template_count,
        "xor_word_degenerate_templates": xor_word_degenerate_templates,
        "xor_word_run_template_count": xor_word_run_template_count,
        "xor_word_run_templates": xor_word_run_templates,
        "xor_word_state_source_summary": xor_word_state_source_summary,
        "xor_word_state_sources": xor_word_state_sources,
        "vm_chains": output_semantic_vm_chain_summaries(value),
    })
}
