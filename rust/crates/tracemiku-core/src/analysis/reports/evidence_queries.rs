use super::*;

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
