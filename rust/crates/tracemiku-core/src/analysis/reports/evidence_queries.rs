use super::*;

/// 从 MemShadow 导出内存区间的逐字节来源，返回可序列化证据。
pub fn mem_provenance(
    trace_dir: PathBuf,
    addr: String,
    length: usize,
) -> anyhow::Result<serde_json::Value> {
    let trace = crate::prelude::Trace::load(&trace_dir)?;
    let mem = crate::prelude::MemShadow::load_or_build(&trace);
    let addr = parse_addr_str(&addr).ok_or_else(|| anyhow::anyhow!("invalid addr: {addr}"))?;
    let dump = mem.tenet_export(addr, length).map_err(anyhow::Error::msg)?;
    Ok(serde_json::to_value(&dump)?)
}

pub(super) fn query_value(trace_dir: PathBuf, query: Query) -> anyhow::Result<serde_json::Value> {
    query_value_on(&AnalysisContext::load(trace_dir)?, query)
}

pub(super) fn query_value_on(
    context: &AnalysisContext,
    query: Query,
) -> anyhow::Result<serde_json::Value> {
    Ok(crate::analysis::execute(context, query)?)
}

/// Resolve a tool-neutral `(SO, offset)` coordinate to a concrete trace record
/// index, so lineage/taint commands (which seed on an idx) accept the same
/// coordinate a reverse engineer reads from IDA/BN/Ghidra. `occurrence` picks
/// which execution of that PC to seed from (0 = first). Reuses the analysis
/// context for coordinate resolution and record lookup. Returns `(idx, pc)`.
pub fn resolve_offset_to_idx(
    context: &AnalysisContext,
    so: &str,
    off: &str,
    occurrence: usize,
) -> anyhow::Result<(usize, u64)> {
    let rparams = crate::analysis::resolve::ResolveQuery {
        so: Some(so.to_string()),
        off: Some(off.to_string()),
        ..Default::default()
    };
    let resolved = query_value_on(context, Query::Resolve(rparams))?;
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
    // pc-hits with cursor=0 puts every execution in `after` (ascending).
    let iparams = crate::analysis::idxs_for_pc::IdxsForPcQuery {
        pc: pc_str.to_string(),
        cursor: usize::try_from(0)?,
        limit: occurrence + 1,
    };
    let idxs = query_value_on(context, Query::IdxsForPc(iparams))?;
    let after = idxs
        .get("after")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("pc-hits response missing after[]"))?;
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

#[allow(clippy::too_many_arguments)]
pub fn byte_writer_map(
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
) -> anyhow::Result<serde_json::Value> {
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
    let params = crate::analysis::memory_query::MemWritesInRangeQuery {
        idx_lo,
        idx_hi,
        addr_lo: Some(format!("{addr_value:#x}")),
        addr_hi: Some(format!("{addr_hi:#x}")),
        max,
        ..Default::default()
    };
    let path = Query::MemWritesInRange(params);
    let context = AnalysisContext::load(trace_dir)?;
    let response = query_value_on(&context, path)?;
    let mut output = byte_writer_map_output(addr_value, size_usize, &response);
    if vm_chain_steps > 0 && vm_chain_runs > 0 {
        let runs = output
            .get("writer_runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let chains = vm_chains_for_byte_writer_runs(
            &context,
            &runs,
            vm_chain_steps,
            vm_chain_runs,
            vm_chain_lookback,
            vm_chain_follow_frontier,
            &vm_profile,
        )?;
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
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub fn mem_write_bursts(
    trace_dir: PathBuf,
    window: usize,
    min_size: u64,
    limit: usize,
    map_bytes: bool,
    map_candidates: usize,
    nonzero_only: bool,
    target_bytes: Option<String>,
) -> anyhow::Result<serde_json::Value> {
    let params = crate::analysis::mem_write_bursts::WriteBurstsQuery {
        window,
        min_size,
        limit,
    };
    let path = Query::MemWriteBursts(params);
    let needs_map = map_bytes || nonzero_only || target_bytes.is_some();
    if !needs_map {
        return query_value(trace_dir, path);
    }
    let target = target_bytes
        .as_deref()
        .map(parse_hex_bytes_cli)
        .transpose()?;
    let target_hex = target.as_ref().map(|bytes| bytes_to_hex(bytes));
    let context = AnalysisContext::load(trace_dir)?;
    let mut response = query_value_on(&context, path)?;
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
        let map = burst_candidate_byte_map(&context, candidate, target_hex.as_deref())?;
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
    Ok(response)
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

pub(super) fn attach_base64_index_trees_on(
    context: &AnalysisContext,
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
                context,
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
            )?;
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
