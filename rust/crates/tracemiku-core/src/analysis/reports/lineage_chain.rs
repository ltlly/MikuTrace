use super::*;

#[allow(clippy::too_many_arguments)]
pub fn vm_backchain(
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
) -> anyhow::Result<serde_json::Value> {
    let analysis = AnalysisContext::load(trace_dir)?;
    let value = vm_backchain_value_on(
        &analysis,
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
    )?;
    if summary {
        Ok(vm_backchain_summary(&value))
    } else {
        Ok(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn vm_backtree(
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
) -> anyhow::Result<serde_json::Value> {
    let analysis = AnalysisContext::load(trace_dir)?;
    let value = vm_backtree_value_on(
        &analysis,
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
    )?;
    if summary {
        Ok(vm_backtree_summary(&value))
    } else {
        Ok(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn vm_backchain_value_on(
    analysis: &AnalysisContext,
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
            analysis,
            current_idx,
            current_reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
            profile,
        )?;
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
        8.try_into().unwrap(),
        "x12".to_string(),
    )
    .unwrap();
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
