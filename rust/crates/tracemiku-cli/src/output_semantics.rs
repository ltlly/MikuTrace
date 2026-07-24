use super::*;

#[derive(Debug)]
pub(super) struct OutputBacktraceOpts {
    pub(super) key: Option<String>,
    pub(super) value: Option<String>,
    pub(super) bytes_hex: Option<String>,
    pub(super) jni_limit: usize,
    pub(super) max_mem_hits: usize,
    pub(super) writes_per_hit: usize,
    pub(super) taint_seeds: usize,
    pub(super) taint_max_count: usize,
    pub(super) vm_chain_steps: usize,
    pub(super) vm_chain_runs: usize,
    pub(super) vm_chain_lookback: usize,
    pub(super) vm_chain_follow_frontier: bool,
    pub(super) vm_profile: VmProfile,
    pub(super) skip_taint: bool,
    pub(super) url_decode: bool,
    pub(super) base64_decode: bool,
}

#[derive(Debug)]
pub(super) struct OutputMapOpts {
    pub(super) key: Option<String>,
    pub(super) value: Option<String>,
    pub(super) jni_limit: usize,
    pub(super) max_mem_hits: usize,
    pub(super) hit_rank: usize,
    pub(super) hit_order: HitOrder,
    pub(super) group_start: usize,
    pub(super) groups: usize,
    pub(super) semantic_offset: Option<usize>,
    pub(super) semantic_count: usize,
    pub(super) tree_depth: usize,
    pub(super) tree_max_nodes: usize,
    pub(super) index_tree_depth: usize,
    pub(super) index_tree_max_nodes: usize,
    pub(super) tree_frontier_with_next: bool,
    pub(super) lookback: usize,
    pub(super) url_decode: bool,
    pub(super) base64_tail_start: Option<usize>,
    pub(super) base64_tail_align_prefix: String,
    pub(super) base64_tail_drop: usize,
    pub(super) semantic_writer_map: bool,
    pub(super) semantic_writer_map_idx_hi: Option<usize>,
    pub(super) semantic_writer_map_max: usize,
    pub(super) semantic_writer_map_vm_chain_steps: usize,
    pub(super) semantic_writer_map_vm_chain_runs: usize,
    pub(super) semantic_writer_map_vm_chain_bytes: bool,
    pub(super) semantic_writer_map_vm_chain_lookback: usize,
    pub(super) semantic_writer_map_vm_chain_follow_frontier: bool,
    pub(super) vm_profile: VmProfile,
    pub(super) summary: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum HitOrder {
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

pub(super) async fn cmd_output_backtrace(
    trace_dir: PathBuf,
    opts: OutputBacktraceOpts,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let source = resolve_output_source(&app, &opts).await?;
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
            let params = vec![
                ("bytes_hex", hex.clone()),
                ("max", opts.max_mem_hits.to_string()),
            ];
            route_get_json_value_on(&app, route_path("/api/find-mem-pattern", &params)).await?
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
                    let provenance_params = vec![
                        ("addr", format!("{addr:#x}")),
                        ("length", bytes.len().to_string()),
                    ];
                    let provenance = route_get_json_value_on(
                        &app,
                        route_path("/api/string-provenance", &provenance_params),
                    )
                    .await?;
                    let top_writers = provenance_writer_counts(&provenance, opts.writes_per_hit);
                    let mut writer_details = Vec::new();
                    for writer in &top_writers {
                        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let record =
                            route_get_json_value_on(&app, format!("/api/record/{idx}")).await?;
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
                        vm_chains_for_writer_runs(&app, &writer_runs, &opts).await?
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
            &app,
            &taint_seed_queue,
            opts.taint_seeds,
            opts.taint_max_count,
        )
        .await?
    };

    print_pretty(&serde_json::json!({
        "status": "ready",
        "strategy": "output_to_input_backward_trace",
        "source": source.json,
        "patterns": pattern_reports,
        "taint": taint_reports,
        "notes": [
            "This report intentionally starts at the observed output and walks upward through memory writers and register taint.",
            "For JNI NewStringUTF outputs, the hooked bytes are treated as ground truth; memory dumps can show object/runtime layout noise.",
            "Continue with patterns[].hit_reports[].writer_seeds or taint.runs[].summary.function_counts to choose the next function to decompile."
        ],
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn output_map_group_vm_trees(
    app: &axum::Router,
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
                app,
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
            )
            .await?;
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

pub(super) async fn cmd_output_map(trace_dir: PathBuf, opts: OutputMapOpts) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let source = resolve_output_source(
        &app,
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
    )
    .await?;
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
        let params = vec![
            ("bytes_hex", bytes_to_hex(&source.primary_bytes)),
            ("max", opts.max_mem_hits.to_string()),
        ];
        route_get_json_value_on(&app, route_path("/api/find-mem-pattern", &params)).await?
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
            let params = vec![
                ("addr", format!("{addr:#x}")),
                ("length", source.primary_bytes.len().to_string()),
            ];
            let provenance =
                route_get_json_value_on(&app, route_path("/api/string-provenance", &params))
                    .await?;
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
            output_runs_overlapping(&app, &writer_runs, orig_start, orig_end).await?
        } else {
            Vec::new()
        };
        let trees = output_map_group_vm_trees(
            &app,
            &runs,
            opts.tree_depth,
            opts.tree_max_nodes,
            opts.lookback,
            opts.tree_frontier_with_next,
            &opts.vm_profile,
        )
        .await?;
        let hidden_lookup_trees;
        let lookup_trees = if opts.index_tree_depth > 0 && trees.is_empty() {
            hidden_lookup_trees = output_map_group_vm_trees(
                &app,
                &runs,
                BASE64_LOOKUP_TREE_DEPTH,
                BASE64_LOOKUP_TREE_MAX_NODES.max(opts.index_tree_max_nodes),
                opts.lookback,
                true,
                &opts.vm_profile,
            )
            .await?;
            hidden_lookup_trees.as_slice()
        } else {
            trees.as_slice()
        };
        let mut lookup_matches = base64_lookup_matches(&base64, lookup_trees);
        if opts.index_tree_depth > 0 {
            attach_base64_index_trees_on(&app, &mut lookup_matches, &opts).await?;
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
            &app,
            &grouped_text,
            selected_addr,
            first_output_writer_idx,
            &opts,
        )
        .await?
    } else {
        serde_json::Value::Null
    };

    let output = serde_json::json!({
        "status": "ready",
        "strategy": "output_base64_group_map",
        "source": source.json,
        "text_len": mapped_text.len(),
        "base64_context": base64_context,
        "group_total": group_total,
        "selected_group_start": selected_group_start,
        "selected_group_end": selected_group_end,
        "selected_semantic_range": selected_semantic_range,
        "selected_hit_order": opts.hit_order.as_str(),
        "selected_hit_rank": opts.hit_rank,
        "tree_frontier_with_next": opts.tree_frontier_with_next,
        "index_tree_depth": opts.index_tree_depth,
        "index_tree_max_nodes": opts.index_tree_max_nodes,
        "hit_candidates": hit_candidates,
        "selected_hit": selected_hit,
        "selected_range": selected_range,
        "find_mem_pattern": find,
        "semantic_writer_map": semantic_writer_map,
        "groups": group_rows,
    });
    if opts.summary {
        print_pretty(&output_map_summary(&output))
    } else {
        print_pretty(&output)
    }
}

pub(super) fn min_writer_idx(runs: &[serde_json::Value]) -> Option<usize> {
    runs.iter()
        .filter_map(|run| run.get("writer_idx").and_then(|v| v.as_u64()))
        .filter_map(|idx| usize::try_from(idx).ok())
        .min()
}

pub(super) async fn output_semantic_writer_map(
    app: &axum::Router,
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
    let params = vec![
        ("idx_lo", "0".to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{map_addr:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", opts.semantic_writer_map_max.to_string()),
    ];
    let response =
        route_get_json_value_on(app, route_path("/api/mem-writes-in-range", &params)).await?;
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
                    app,
                    &bytes,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )
                .await?,
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
                    app,
                    &runs,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )
                .await?,
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
    source_value: String,
    offsets: Vec<u64>,
    source_byte_offsets: BTreeSet<u64>,
    result: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct Mod255InputGroup {
    input: String,
    output_byte: String,
    quotient: Option<String>,
    offsets: Vec<u64>,
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
    start: u64,
    end: u64,
    lhs: Vec<u8>,
    rhs: Vec<u8>,
    result: Vec<u8>,
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
    offset: u64,
    kind: String,
    result: u64,
    lhs: Option<u64>,
    rhs: Option<u64>,
    output_byte: Option<u64>,
}

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
