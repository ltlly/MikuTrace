use super::*;

#[derive(Debug)]
pub(super) struct ByteWriterRun {
    pub(super) identity: String,
    pub(super) start_offset: usize,
    pub(super) end_offset: usize,
    pub(super) bytes_hex: String,
    pub(super) ascii: String,
    pub(super) source_byte_offsets: Vec<serde_json::Value>,
    pub(super) writer: serde_json::Value,
}

impl ByteWriterRun {
    pub(super) fn into_json(self) -> serde_json::Value {
        let source_byte_offset = if self.source_byte_offsets.len() == 1 {
            self.source_byte_offsets
                .first()
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        };
        serde_json::json!({
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.end_offset.saturating_sub(self.start_offset) + 1,
            "bytes_hex": self.bytes_hex,
            "ascii": self.ascii,
            "source_byte_offset": source_byte_offset,
            "source_byte_offsets": self.source_byte_offsets,
            "writer": self.writer,
        })
    }
}

pub(super) fn byte_writer_identity(writer: &serde_json::Value) -> String {
    [
        writer
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string()),
        writer
            .get("dst_addr")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        writer
            .get("size")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string()),
        writer
            .get("src_reg")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        writer
            .get("src_value")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("|")
}

pub(super) fn byte_writer_entry(
    offset: u64,
    byte_addr: u64,
    last_write: Option<serde_json::Value>,
) -> serde_json::Value {
    let source_byte_offset = last_write
        .as_ref()
        .and_then(|write| source_byte_offset_for_write_at(write, byte_addr));
    let next = last_write.as_ref().and_then(|write| {
        Some(serde_json::json!({
            "idx": write.get("idx")?,
            "reg": write.get("src_reg")?,
            "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": source_byte_offset,
            "reason": "memory_load_byte",
            "offset": offset,
            "addr": format!("{byte_addr:#x}"),
        }))
    });
    serde_json::json!({
        "offset": offset,
        "addr": format!("{byte_addr:#x}"),
        "status": if last_write.is_some() { "ready" } else { "not_found" },
        "source_byte_offset": source_byte_offset,
        "last_write": last_write,
        "next": next,
    })
}

pub(super) fn dedupe_byte_nexts(byte_writers: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    for writer in byte_writers {
        let Some(next) = writer.get("next") else {
            continue;
        };
        let Some(idx) = next.get("idx").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = next.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let offset = writer
            .get("offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let addr = writer
            .get("addr")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let source_byte_offset = writer
            .get("source_byte_offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if let Some(existing) = out.iter_mut().find(|item| {
            item.get("idx").and_then(|v| v.as_u64()) == Some(idx)
                && item.get("reg").and_then(|v| v.as_str()) == Some(reg)
        }) {
            if let Some(offsets) = existing.get_mut("offsets").and_then(|v| v.as_array_mut()) {
                offsets.push(offset);
            }
            if let Some(addrs) = existing.get_mut("addrs").and_then(|v| v.as_array_mut()) {
                addrs.push(addr);
            }
            if let Some(source_byte_offsets) = existing
                .get_mut("source_byte_offsets")
                .and_then(|v| v.as_array_mut())
            {
                source_byte_offsets.push(source_byte_offset);
            }
            continue;
        }
        let mut item = next.clone();
        if let Some(obj) = item.as_object_mut() {
            obj.insert("offsets".to_string(), serde_json::json!([offset]));
            obj.insert("addrs".to_string(), serde_json::json!([addr]));
            obj.insert(
                "source_byte_offsets".to_string(),
                serde_json::json!([source_byte_offset]),
            );
        }
        out.push(item);
    }
    out
}

pub(super) fn mem_write_touches_addr(write: &serde_json::Value, addr: u64) -> bool {
    let Some(start) = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
    else {
        return false;
    };
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    addr >= start && addr < start.saturating_add(size)
}

pub(super) fn vm_backtree_highlights(nodes: &[serde_json::Value]) -> serde_json::Value {
    let word_loads = nodes
        .iter()
        .filter_map(highlight_word_load)
        .collect::<Vec<_>>();
    let table_lookups = nodes
        .iter()
        .filter_map(highlight_table_lookup)
        .collect::<Vec<_>>();
    let alu_formulas = nodes
        .iter()
        .filter_map(highlight_alu_formula)
        .collect::<Vec<_>>();
    serde_json::json!({
        "word_loads": word_loads,
        "table_lookups": table_lookups,
        "alu_formulas": alu_formulas,
    })
}

pub(super) fn highlight_word_load(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    let asm = local.get("asm")?.as_str()?;
    if !asm.trim_start().starts_with("ldr w") {
        return None;
    }
    let byte_nexts = node
        .get("upstream")?
        .get("byte_nexts")?
        .as_array()
        .filter(|items| items.len() > 1)?;
    let mut byte_sources = Vec::new();
    for next in byte_nexts {
        let offsets = next
            .get("offsets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_else(|| {
                vec![next
                    .get("offset")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)]
            });
        for offset_value in offsets {
            let offset = offset_value.as_u64().unwrap_or(0);
            let src_value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let byte = src_value.map(|v| (v & 0xff) as u8);
            byte_sources.push(serde_json::json!({
                "offset": offset,
                "addr": next.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "idx": next.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": next.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": next.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "byte_hex": byte.map(|b| format!("{b:02x}")),
                "ascii": byte.and_then(printable_ascii_char),
            }));
        }
    }
    byte_sources.sort_by_key(|source| {
        source
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX)
    });
    let bytes = byte_sources
        .iter()
        .filter_map(|source| {
            source
                .get("byte_hex")
                .and_then(|v| v.as_str())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect::<Vec<_>>();
    Some(serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "bytes_hex": bytes_to_hex(&bytes),
        "ascii": ascii_preview(&bytes),
        "byte_sources": byte_sources,
    }))
}

pub(super) fn highlight_table_lookup(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    if local.get("class").and_then(|v| v.as_str()) != Some("byte-load") {
        return None;
    }
    let asm = local.get("asm")?.as_str()?;
    if !asm.contains('[') {
        return None;
    }
    let frontier_nexts = node.get("frontier_nexts").and_then(|v| v.as_array())?;
    let index = frontier_nexts
        .iter()
        .filter_map(|next| {
            let value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)?;
            (value <= 0x3f).then_some((next, value))
        })
        .min_by_key(|(_, value)| *value)?;
    let base = frontier_nexts
        .iter()
        .filter_map(|next| {
            let value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)?;
            (value > 0x1000).then_some((next, value))
        })
        .next();
    let char_value = node
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
        .map(|v| (v & 0xff) as u8);
    if char_value != Some(base64_char_for_index(index.1)?) {
        return None;
    }
    Some(serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "char_hex": char_value.map(|b| format!("{b:02x}")),
        "char": char_value.and_then(printable_ascii_char),
        "index_reg": index.0.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "index_value": format!("{:#x}", index.1),
        "base_reg": base.map(|(next, _)| next.get("reg").cloned().unwrap_or(serde_json::Value::Null)),
        "base_value": base.map(|(_, value)| format!("{value:#x}")),
    }))
}

pub(super) fn base64_char_for_index(index: u64) -> Option<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ALPHABET.get(index as usize).copied()
}

pub(super) fn highlight_alu_formula(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    if local.get("class").and_then(|v| v.as_str()) != Some("alu") {
        return None;
    }
    let asm = local.get("asm")?.as_str()?;
    let mnemonic = asm.split_whitespace().next()?.to_ascii_lowercase();
    if !matches!(
        mnemonic.as_str(),
        "orr" | "eor" | "and" | "lsl" | "lsr" | "add" | "sub" | "ubfx" | "udiv"
    ) {
        return None;
    }
    let operands = local
        .get("def")
        .and_then(|v| v.get("src"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let operand_values = operands
        .iter()
        .filter_map(|operand| operand.get("value").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let result = node
        .get("value")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            local
                .get("def")
                .and_then(|v| v.get("value_after"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })?;
    let expression = alu_expression_from_asm(asm, &result, &operand_values)?;
    let mut formula = serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": result,
        "asm": asm,
        "op": mnemonic,
        "expression": expression,
        "operands": annotate_formula_operands(asm, operands),
    });
    if let Some(semantic) = recognize_alu_semantic(asm, &result, &operand_values) {
        if let Some(obj) = formula.as_object_mut() {
            obj.insert("semantic".to_string(), semantic);
        }
    }
    Some(formula)
}

pub(super) fn alu_expression_from_asm(
    asm: &str,
    result: &str,
    values: &[String],
) -> Option<String> {
    let mut parts = asm.trim().splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    let operands = parts.next().map(split_operands).unwrap_or_default();
    match mnemonic.as_str() {
        "mul" if values.len() >= 2 => Some(format!(
            "{result} = ({} * {}) mod 2^64",
            values[0], values[1]
        )),
        "orr" | "eor" | "and" | "add" | "sub" if !values.is_empty() => {
            let op = match mnemonic.as_str() {
                "orr" => "|",
                "eor" => "^",
                "and" => "&",
                "add" => "+",
                "sub" => "-",
                _ => unreachable!(),
            };
            let rhs = values
                .get(1)
                .map(|value| shifted_rhs_display(asm, value))
                .or_else(|| operands.get(2).and_then(|op| immediate_operand_value(op)))?;
            Some(format!("{result} = {} {op} {rhs}", values[0]))
        }
        "lsl" | "lsr" if !values.is_empty() => {
            let op = if mnemonic == "lsl" { "<<" } else { ">>" };
            let shift = values
                .get(1)
                .cloned()
                .or_else(|| operands.get(2).and_then(|op| immediate_operand_value(op)))
                .unwrap_or_else(|| "?".to_string());
            Some(format!("{result} = {} {op} {shift}", values[0]))
        }
        "ubfx" if !values.is_empty() => {
            let lsb = operands
                .get(2)
                .and_then(|op| immediate_operand_value(op))
                .unwrap_or_else(|| "?".to_string());
            let width = operands
                .get(3)
                .and_then(|op| immediate_operand_value(op))
                .unwrap_or_else(|| "?".to_string());
            Some(format!("{result} = ubfx({}, {lsb}, {width})", values[0]))
        }
        "udiv" if values.len() >= 2 => Some(format!("{result} = {} / {}", values[0], values[1])),
        _ => None,
    }
}

pub(super) fn annotate_formula_operands(
    asm: &str,
    mut operands: Vec<serde_json::Value>,
) -> Vec<serde_json::Value> {
    let Some((kind, amount)) = rhs_shift_modifier(asm) else {
        return operands;
    };
    let Some(rhs) = operands
        .get_mut(1)
        .and_then(|operand| operand.as_object_mut())
    else {
        return operands;
    };
    rhs.insert("shift".to_string(), serde_json::json!(kind));
    rhs.insert(
        "shift_amount".to_string(),
        serde_json::json!(format!("{amount:#x}")),
    );
    if let Some(value) = rhs
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
        .and_then(|value| apply_shift_modifier(value, &kind, amount))
    {
        rhs.insert(
            "effective_value".to_string(),
            serde_json::json!(format!("{value:#x}")),
        );
    }
    operands
}

pub(super) fn shifted_rhs_display(asm: &str, value: &str) -> String {
    let Some((kind, amount)) = rhs_shift_modifier(asm) else {
        return value.to_string();
    };
    let op = match kind.as_str() {
        "lsl" => "<<",
        "lsr" => ">>",
        "asr" => "asr",
        _ => return value.to_string(),
    };
    format!("({value} {op} {amount:#x})")
}

pub(super) fn rhs_shift_modifier(asm: &str) -> Option<(String, u32)> {
    let operands = asm
        .split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .unwrap_or_default();
    let modifier = operands.get(3)?.trim().to_ascii_lowercase();
    let mut parts = modifier.split_whitespace();
    let kind = parts.next()?.to_string();
    if !matches!(kind.as_str(), "lsl" | "lsr" | "asr") {
        return None;
    }
    let amount = parts
        .next()
        .and_then(immediate_operand_value)
        .and_then(|value| parse_u64_str(&value))?;
    (amount < 64).then_some((kind, amount as u32))
}

pub(super) fn apply_shift_modifier(value: u64, kind: &str, amount: u32) -> Option<u64> {
    match kind {
        "lsl" => Some(value.wrapping_shl(amount)),
        "lsr" => Some(value.wrapping_shr(amount)),
        "asr" => Some(((value as i64) >> amount) as u64),
        _ => None,
    }
}

pub(super) fn recognize_alu_semantic(
    asm: &str,
    result: &str,
    values: &[String],
) -> Option<serde_json::Value> {
    let mnemonic = asm.split_whitespace().next()?.to_ascii_lowercase();
    let result = parse_u64_str(result)?;
    match mnemonic.as_str() {
        "add" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            mod255_fold_semantic(lhs, rhs, result)
                .or_else(|| mod255_fold_semantic(rhs, lhs, result))
                .or_else(|| add_known_constant_semantic(lhs, rhs, result))
                .or_else(|| add_known_constant_semantic(rhs, lhs, result))
                .or_else(|| add_small_delta_semantic(lhs, rhs, result))
                .or_else(|| add_small_delta_semantic(rhs, lhs, result))
                .or_else(|| add32_mix_semantic(lhs, rhs, result))
        }
        "sub" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            sub_small_delta_semantic(lhs, rhs, result)
        }
        "and" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            and_identity_semantic(lhs, rhs, result)
                .or_else(|| and_identity_semantic(rhs, lhs, result))
                .or_else(|| align_down_mask_semantic(lhs, rhs, result))
                .or_else(|| align_down_mask_semantic(rhs, lhs, result))
                .or_else(|| bitmask_extract_semantic(lhs, rhs, result))
                .or_else(|| bitmask_extract_semantic(rhs, lhs, result))
        }
        "orr" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            or_identity_semantic(lhs, rhs, result)
                .or_else(|| or_identity_semantic(rhs, lhs, result))
                .or_else(|| bitwise_or_merge_semantic(lhs, rhs, result))
        }
        "eor" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            xor_identity_semantic(lhs, rhs, result).or_else(|| xor_mix_semantic(lhs, rhs, result))
        }
        "lsl" | "lsr" | "asr" => {
            let input = values.first().and_then(|value| parse_u64_str(value))?;
            let shift = shift_amount_from_asm_or_values(asm, values)?;
            shift_extract_semantic(asm, &mnemonic, input, shift, result)
        }
        "ubfx" => {
            let input = values.first().and_then(|value| parse_u64_str(value))?;
            ubfx_semantic(asm, input, result)
        }
        "mul" => {
            let (lhs, rhs) = parse_binary_values(values)?;
            mul_mod64_semantic(lhs, rhs, result)
        }
        _ => None,
    }
}

pub(super) fn parse_binary_values(values: &[String]) -> Option<(u64, u64)> {
    Some((
        parse_u64_str(values.first()?)?,
        parse_u64_str(values.get(1)?)?,
    ))
}

pub(super) fn parse_binary_values_or_immediate(asm: &str, values: &[String]) -> Option<(u64, u64)> {
    if let Some(lhs) = values.first().and_then(|value| parse_u64_str(value)) {
        if let Some(rhs) = values.get(1).and_then(|value| parse_u64_str(value)) {
            let rhs = rhs_shift_modifier(asm)
                .and_then(|(kind, amount)| apply_shift_modifier(rhs, &kind, amount))
                .unwrap_or(rhs);
            return Some((lhs, rhs));
        }
        return Some((lhs, last_immediate_operand_u64(asm)?));
    }
    None
}

pub(super) fn last_immediate_operand_u64(asm: &str) -> Option<u64> {
    asm.split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .into_iter()
        .flatten()
        .skip(1)
        .filter_map(|op| immediate_operand_value(&op))
        .filter_map(|value| parse_u64_str(&value))
        .last()
}

pub(super) fn xor_identity_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    let input = match (lhs, rhs) {
        (lhs, 0) if lhs != 0 && result == lhs => lhs,
        (0, rhs) if rhs != 0 && result == rhs => rhs,
        _ => return None,
    };
    Some(serde_json::json!({
        "kind": "xor_identity",
        "input": format!("{input:#x}"),
        "zero_operand": "0x0",
        "result": format!("{result:#x}"),
        "expression": "result == input ^ 0",
    }))
}

pub(super) fn xor_mix_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if lhs == 0 || rhs == 0 || (lhs ^ rhs) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "xor_mix",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == lhs ^ rhs",
    }))
}

pub(super) fn and_identity_semantic(
    input: u64,
    mask: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if input == 0 || mask <= 0xfff || input & mask != result || result != input {
        return None;
    }
    Some(serde_json::json!({
        "kind": "and_identity",
        "input": format!("{input:#x}"),
        "mask": format!("{mask:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input & mask",
    }))
}

pub(super) fn align_down_mask_semantic(
    input: u64,
    mask: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if input == 0 || mask <= 0xfff || input & mask != result || result == input {
        return None;
    }
    let cleared = !mask;
    let alignment = cleared.checked_add(1)?;
    if alignment <= 1 || !alignment.is_power_of_two() {
        return None;
    }
    Some(serde_json::json!({
        "kind": "align_down_mask",
        "input": format!("{input:#x}"),
        "mask": format!("{mask:#x}"),
        "alignment": format!("{alignment:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input & ~(alignment - 1)",
    }))
}

pub(super) fn or_identity_semantic(
    input: u64,
    zero: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if input == 0 || zero != 0 || result != input {
        return None;
    }
    Some(serde_json::json!({
        "kind": "or_identity",
        "input": format!("{input:#x}"),
        "zero_operand": "0x0",
        "result": format!("{result:#x}"),
        "expression": "result == input | 0",
    }))
}

pub(super) fn mod255_fold_semantic(
    input: u64,
    quotient: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if input <= 0xff || quotient == 0 {
        return None;
    }
    if quotient != input / 0xff {
        return None;
    }
    let output_byte = (result & 0xff) as u8;
    let remainder = (input % 0xff) as u8;
    if output_byte != remainder {
        return None;
    }
    Some(serde_json::json!({
        "kind": "mod255_low_byte",
        "input": format!("{input:#x}"),
        "quotient": format!("{quotient:#x}"),
        "divisor": "0xff",
        "result": format!("{result:#x}"),
        "output_byte": format!("{output_byte:#x}"),
        "expression": "(input + input / 0xff) & 0xff == input % 0xff",
    }))
}

pub(super) fn bitmask_extract_semantic(
    input: u64,
    mask: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if mask == 0 || mask > 0xfff || input & mask != result {
        return None;
    }
    let low_bit = mask.trailing_zeros();
    let contiguous_width = contiguous_mask_width(mask);
    Some(serde_json::json!({
        "kind": "bitmask_extract",
        "input": format!("{input:#x}"),
        "mask": format!("{mask:#x}"),
        "result": format!("{result:#x}"),
        "low_bit": low_bit,
        "width": contiguous_width,
        "expression": "result == input & mask",
    }))
}

pub(super) fn contiguous_mask_width(mask: u64) -> Option<u32> {
    let shifted = mask >> mask.trailing_zeros();
    ((shifted + 1).is_power_of_two()).then_some(shifted.count_ones())
}

pub(super) fn bitwise_or_merge_semantic(
    lhs: u64,
    rhs: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if lhs | rhs != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "bitwise_or_merge",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == lhs | rhs",
    }))
}

pub(super) fn shift_amount_from_asm_or_values(asm: &str, values: &[String]) -> Option<u64> {
    values
        .get(1)
        .and_then(|value| parse_u64_str(value))
        .or_else(|| {
            let operands = asm
                .split_once(char::is_whitespace)
                .map(|(_, operands)| split_operands(operands))
                .unwrap_or_default();
            operands
                .get(2)
                .and_then(|op| immediate_operand_value(op))
                .and_then(|value| parse_u64_str(&value))
        })
}

pub(super) fn shift_extract_semantic(
    asm: &str,
    mnemonic: &str,
    input: u64,
    shift: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if shift >= 64 {
        return None;
    }
    let width = alu_result_width(asm);
    let computed = if width == 32 {
        let input = input as u32;
        if mnemonic == "lsl" {
            input.wrapping_shl(shift as u32) as u64
        } else {
            input.wrapping_shr(shift as u32) as u64
        }
    } else if mnemonic == "lsl" {
        input.wrapping_shl(shift as u32)
    } else {
        input.wrapping_shr(shift as u32)
    };
    if computed != result {
        return None;
    }
    let kind = if mnemonic == "lsl" {
        "shift_left"
    } else {
        "shift_right"
    };
    let op = if mnemonic == "lsl" { "<<" } else { ">>" };
    Some(serde_json::json!({
        "kind": kind,
        "input": format!("{input:#x}"),
        "shift": format!("{shift:#x}"),
        "result": format!("{result:#x}"),
        "width": width,
        "expression": format!("result == input {op} shift"),
    }))
}

pub(super) fn alu_result_width(asm: &str) -> u32 {
    asm.split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .and_then(|operands| operands.first().cloned())
        .and_then(|operand| first_register_token(&operand))
        .filter(|reg| reg.starts_with('w'))
        .map(|_| 32)
        .unwrap_or(64)
}

pub(super) fn ubfx_semantic(asm: &str, input: u64, result: u64) -> Option<serde_json::Value> {
    let operands = asm
        .split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .unwrap_or_default();
    let lsb = operands
        .get(2)
        .and_then(|op| immediate_operand_value(op))
        .and_then(|value| parse_u64_str(&value))?;
    let width = operands
        .get(3)
        .and_then(|op| immediate_operand_value(op))
        .and_then(|value| parse_u64_str(&value))?;
    if lsb >= 64 || width == 0 || width > 64 {
        return None;
    }
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    if ((input >> lsb) & mask) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "ubfx",
        "input": format!("{input:#x}"),
        "lsb": format!("{lsb:#x}"),
        "width": format!("{width:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == (input >> lsb) & ((1 << width) - 1)",
    }))
}

pub(super) fn add_small_delta_semantic(
    input: u64,
    delta: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if delta > 0xfff || input <= 0xfff || input.wrapping_add(delta) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "add_small_delta",
        "input": format!("{input:#x}"),
        "delta": format!("{delta:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input + small_delta",
    }))
}

pub(super) fn sub_small_delta_semantic(
    input: u64,
    delta: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if delta == 0 || delta > 0xfff || input <= 0xfff || input.wrapping_sub(delta) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "sub_small_delta",
        "input": format!("{input:#x}"),
        "delta": format!("{delta:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input - small_delta",
    }))
}

pub(super) fn add_known_constant_semantic(
    input: u64,
    constant: u64,
    result: u64,
) -> Option<serde_json::Value> {
    let constant_name = known_algorithm_constant_name(constant)?;
    if input.wrapping_add(constant) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "add_known_constant",
        "input": format!("{input:#x}"),
        "constant": format!("{constant:#x}"),
        "constant_name": constant_name,
        "result": format!("{result:#x}"),
        "expression": "result == input + known_constant",
    }))
}

pub(super) fn add32_mix_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if !is_plausible_u32_mix_value(lhs)
        || !is_plausible_u32_mix_value(rhs)
        || !is_plausible_u32_mix_value(result)
    {
        return None;
    }
    if lhs <= 0xff && rhs <= 0xff && result <= 0xff {
        return None;
    }
    if (lhs as u32).wrapping_add(rhs as u32) != result as u32 {
        return None;
    }
    let lhs_low32 = lhs as u32;
    let rhs_low32 = rhs as u32;
    let result_low32 = result as u32;
    Some(serde_json::json!({
        "kind": "add32_mix",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "lhs_low32": format!("{lhs_low32:#x}"),
        "rhs_low32": format!("{rhs_low32:#x}"),
        "result_low32": format!("{result_low32:#x}"),
        "modulus": "2^32",
        "expression": "low32(result) == (low32(lhs) + low32(rhs)) mod 2^32",
    }))
}

pub(super) fn is_plausible_u32_mix_value(value: u64) -> bool {
    value <= 0xf_ffff_ffff
}

pub(super) fn known_algorithm_constant_name(value: u64) -> Option<&'static str> {
    match value {
        0x6745_2301 => Some("md5_iv_a"),
        0xefcd_ab89 => Some("md5_iv_b"),
        0x98ba_dcfe => Some("md5_iv_c"),
        0x1032_5476 => Some("md5_iv_d"),
        _ => None,
    }
}

pub(super) fn mul_mod64_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if lhs.wrapping_mul(rhs) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "mul_mod64",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "modulus": "2^64",
        "lhs_odd": lhs & 1 == 1,
        "rhs_odd": rhs & 1 == 1,
        "expression": "result == (lhs * rhs) mod 2^64",
    }))
}

pub(super) fn immediate_operand_value(op: &str) -> Option<String> {
    let trimmed = op.trim().trim_start_matches('#');
    if trimmed.is_empty() {
        return None;
    }
    parse_u64_str(trimmed)
        .map(|value| format!("{value:#x}"))
        .or_else(|| Some(trimmed.to_string()))
}

pub(super) fn printable_ascii_char(byte: u8) -> Option<String> {
    byte.is_ascii_graphic()
        .then(|| char::from(byte).to_string())
        .or_else(|| (byte == b' ').then(|| " ".to_string()))
}

pub(super) fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| printable_ascii_char(byte).unwrap_or_else(|| ".".to_string()))
        .collect()
}

pub(super) fn classify_vm_asm(asm: &str, profile: &VmProfile) -> &'static str {
    let asm = asm.trim().to_ascii_lowercase();
    let bracket_regs = bracket_registers(&asm).unwrap_or_default();
    let bracket_base = bracket_regs.first().map(String::as_str);
    if asm.starts_with("br ") {
        return "dispatch-branch";
    }
    if asm.starts_with("blr ") {
        return "call-indirect";
    }
    if asm.starts_with("svc ") || asm == "svc" {
        return "syscall";
    }
    if bracket_base == Some(profile.dispatch_reg.as_str()) {
        return "dispatch-table-load";
    }
    if bracket_base == Some(profile.ip_reg.as_str()) {
        return "bytecode-read";
    }
    if bracket_base == Some(profile.state_reg.as_str()) {
        if asm.starts_with("ldr") || asm.starts_with("ldp") || asm.starts_with("ldnp") {
            return "vm-reg-load";
        }
        if asm.starts_with("str") || asm.starts_with("stp") || asm.starts_with("stnp") {
            return "vm-reg-store";
        }
    }
    if asm.starts_with("strb ") {
        return "byte-store";
    }
    if asm.starts_with("ldrb ") {
        return "byte-load";
    }
    if asm.starts_with("str ")
        || asm.starts_with("stur")
        || asm.starts_with("stp ")
        || asm.starts_with("stnp ")
    {
        return "mem-store";
    }
    if asm.starts_with("ldr ")
        || asm.starts_with("ldur")
        || asm.starts_with("ldrsw ")
        || asm.starts_with("ldp ")
        || asm.starts_with("ldnp ")
        || asm.starts_with("ldpsw ")
    {
        return "mem-load";
    }
    if is_alu_mnemonic(asm.split_whitespace().next().unwrap_or("")) {
        return "alu";
    }
    if asm.starts_with("b.") || asm == "ret" {
        return "control";
    }
    "other"
}

pub(super) fn is_alu_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "adc"
            | "adcs"
            | "add"
            | "adds"
            | "adr"
            | "adrp"
            | "and"
            | "ands"
            | "asr"
            | "bic"
            | "bics"
            | "cinc"
            | "cinv"
            | "cneg"
            | "csel"
            | "cset"
            | "csetm"
            | "csinc"
            | "csinv"
            | "csneg"
            | "eon"
            | "eor"
            | "extr"
            | "lsl"
            | "lsr"
            | "madd"
            | "mov"
            | "movk"
            | "movn"
            | "movz"
            | "msub"
            | "mul"
            | "mvn"
            | "neg"
            | "negs"
            | "orn"
            | "orr"
            | "ror"
            | "sbc"
            | "sbcs"
            | "sbfiz"
            | "sbfx"
            | "sdiv"
            | "smaddl"
            | "smull"
            | "smsubl"
            | "sub"
            | "subs"
            | "sxtb"
            | "sxth"
            | "sxtw"
            | "ubfiz"
            | "ubfx"
            | "udiv"
            | "umaddl"
            | "umull"
            | "umsubl"
            | "uxtb"
            | "uxth"
            | "uxtw"
    )
}

pub(super) fn record_reg_u64(record: &serde_json::Value, reg: &str) -> Option<u64> {
    record_reg_value(record, reg)
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
}

pub(super) fn record_reg_value<'a>(
    record: &'a serde_json::Value,
    reg: &str,
) -> Option<&'a serde_json::Value> {
    let regs = record.get("regs")?;
    regs.get(reg)
        .or_else(|| regs.get(register_value_key(reg).as_str()))
}

pub(super) fn def_reg_from_asm(asm: &str) -> Option<String> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    if mnemonic.starts_with('b')
        || matches!(
            mnemonic.as_str(),
            "ret" | "cmp" | "cmn" | "tst" | "ccmp" | "ccmn" | "cbz" | "cbnz" | "tbz" | "tbnz"
        )
        || !store_source_regs_from_asm(asm).is_empty()
    {
        return None;
    }
    let operands = parts.next()?;
    split_operands(operands)
        .first()
        .and_then(|op| first_register_token(op))
}

pub(super) fn pair_load_dest_regs_from_asm(asm: &str) -> Option<Vec<String>> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    if !matches!(mnemonic.as_str(), "ldp" | "ldnp" | "ldpsw") {
        return None;
    }
    let regs = split_operands(parts.next()?)
        .into_iter()
        .take(2)
        .filter_map(|op| first_register_token(&op))
        .collect::<Vec<_>>();
    (regs.len() == 2).then_some(regs)
}

pub(super) fn def_source_regs_from_asm(asm: &str) -> Vec<String> {
    let asm = asm.trim();
    if pair_load_dest_regs_from_asm(asm).is_some() {
        return memory_source_regs_from_asm(asm);
    }
    let Some((_, operands)) = asm.split_once(char::is_whitespace) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    split_operands(operands)
        .into_iter()
        .skip(1)
        .flat_map(|op| register_tokens(&op))
        .filter(|reg| seen.insert(register_value_key(reg)))
        .collect()
}

pub(super) fn memory_source_regs_from_asm(asm: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    bracket_registers(&asm.to_ascii_lowercase())
        .unwrap_or_default()
        .into_iter()
        .filter(|reg| seen.insert(register_value_key(reg)))
        .collect()
}

pub(super) fn register_tokens(op: &str) -> Vec<String> {
    op.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let token = token.trim_end_matches('!').to_ascii_lowercase();
            is_gp_register_token(&token).then_some(token)
        })
        .collect()
}

pub(super) fn is_gp_register_token(token: &str) -> bool {
    token == "sp"
        || token == "wsp"
        || token == "fp"
        || token == "lr"
        || token == "xzr"
        || token == "wzr"
        || token
            .strip_prefix('x')
            .is_some_and(|rest| rest.parse::<u8>().is_ok())
        || token
            .strip_prefix('w')
            .is_some_and(|rest| rest.parse::<u8>().is_ok())
}

pub(super) fn memory_access_width(asm: &str) -> u64 {
    let mnemonic = asm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(mnemonic.as_str(), "ldp" | "ldnp" | "ldpsw") {
        pair_load_dest_regs_from_asm(asm)
            .and_then(|regs| regs.first().map(|reg| register_load_width(reg)))
            .unwrap_or(8)
    } else if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('h') {
        2
    } else if mnemonic == "ldrsw" {
        4
    } else {
        let reg = def_reg_from_asm(asm).unwrap_or_default();
        if reg.starts_with('w') {
            4
        } else {
            8
        }
    }
}

pub(super) fn register_load_width(reg: &str) -> u64 {
    if reg.starts_with('w') {
        4
    } else {
        8
    }
}

pub(super) fn vm_slot_from_asm(
    asm: &str,
    record: &serde_json::Value,
    profile: &VmProfile,
) -> Option<serde_json::Value> {
    let lower = asm.to_ascii_lowercase();
    let regs = bracket_registers(&lower)?;
    if regs.first().map(String::as_str) != Some(profile.state_reg.as_str()) {
        return None;
    }
    if let Some(idx_reg) = regs.get(1) {
        let idx_val = record_reg_u64(record, idx_reg)?;
        let slot = if lower.contains("lsl #3") {
            idx_val
        } else {
            idx_val / 8
        };
        return Some(serde_json::json!({
            "index_reg": idx_reg,
            "index_value": format!("{idx_val:#x}"),
            "slot": slot,
        }));
    }
    let state_base = record_reg_u64(record, &profile.state_reg)?;
    let mem_addr = mem_addr_from_asm(asm, record)?;
    let offset = mem_addr.checked_sub(state_base)?;
    let slot = if offset % 8 == 0 {
        offset / 8
    } else {
        return None;
    };
    Some(serde_json::json!({
        "index_reg": serde_json::Value::Null,
        "index_value": serde_json::Value::Null,
        "offset": format!("{offset:#x}"),
        "slot": slot,
    }))
}

pub(super) fn mem_addr_from_asm(asm: &str, record: &serde_json::Value) -> Option<u64> {
    let lower = asm.to_ascii_lowercase();
    let regs = bracket_registers(&lower)?;
    let base = regs.first().and_then(|reg| record_reg_u64(record, reg))?;
    let index = regs
        .get(1)
        .and_then(|reg| record_reg_u64(record, reg))
        .unwrap_or(0);
    let index = index.checked_shl(bracket_index_shift(&lower).unwrap_or(0))?;
    let imm = bracket_immediate(&lower).unwrap_or(0);
    Some(base.wrapping_add(index).wrapping_add(imm))
}

pub(super) fn bracket_registers(asm: &str) -> Option<Vec<String>> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    let regs = split_operands(inside)
        .into_iter()
        .filter_map(|part| first_register_token(&part))
        .collect::<Vec<_>>();
    (!regs.is_empty()).then_some(regs)
}

pub(super) fn bracket_immediate(asm: &str) -> Option<u64> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    split_operands(inside).into_iter().find_map(|part| {
        let trimmed = part.trim().trim_start_matches('#');
        parse_wrapping_i64_str(trimmed)
    })
}

pub(super) fn parse_wrapping_i64_str(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let negative = s.starts_with('-');
    let unsigned = s.strip_prefix(['-', '+']).unwrap_or(s);
    let magnitude = parse_u64_str(unsigned)?;
    if negative {
        Some(0u64.wrapping_sub(magnitude))
    } else {
        Some(magnitude)
    }
}

pub(super) fn bracket_index_shift(asm: &str) -> Option<u32> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    split_operands(inside).into_iter().find_map(|part| {
        let part = part.trim();
        let rest = part.strip_prefix("lsl")?.trim();
        let shift = rest.trim_start_matches('#');
        shift.parse::<u32>().ok().filter(|bits| *bits < 64)
    })
}
