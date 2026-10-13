use super::*;

#[derive(Debug)]
pub struct OutputBacktraceOpts {
    pub value: Option<String>,
    pub bytes_hex: Option<String>,
    pub at_idx: Option<usize>,
    pub max_mem_hits: usize,
    pub writes_per_hit: usize,
    pub taint_seeds: usize,
    pub taint_max_count: usize,
    pub skip_taint: bool,
    pub url_decode: bool,
    pub base64_decode: bool,
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
    let source = resolve_output_source(&opts)?;
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
