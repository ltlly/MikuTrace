use super::*;

pub fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn list_runs(base: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let top = read_json_opt(&p.join("meta.json"));
        let calls_dir = p.join("calls");
        if calls_dir.is_dir() {
            let calls = list_calls(&p)?;
            let records = calls
                .iter()
                .filter_map(|c| c.get("records").and_then(|v| v.as_u64()))
                .sum::<u64>();
            let max_records = calls
                .iter()
                .filter_map(|c| c.get("records").and_then(|v| v.as_u64()))
                .max()
                .unwrap_or(0);
            rows.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "method": top.get("method").cloned().unwrap_or(serde_json::Value::Null),
                "cmd": top.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
                "calls": calls.len(),
                "records": records,
                "max_records": max_records,
                "kind": "per-call",
            }));
        }
    }
    rows.sort_by_key(|r| {
        r.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    });
    Ok(rows)
}

pub fn list_calls(run_dir: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let calls_dir = run_dir.join("calls");
    let mut rows = Vec::new();
    if !calls_dir.is_dir() {
        return Ok(rows);
    }
    for entry in std::fs::read_dir(calls_dir)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let meta_path = p.join("meta.json");
        if !meta_path.exists() {
            continue;
        }
        let mut row = read_json_opt(&meta_path);
        row["dir"] = serde_json::Value::String(entry.file_name().to_string_lossy().to_string());
        rows.push(row);
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.get("records").and_then(|v| v.as_u64()).unwrap_or(0)));
    Ok(rows)
}

pub fn resolve_map_addr(maps_file: PathBuf, addr: String) -> anyhow::Result<serde_json::Value> {
    let addr = parse_addr_str(&addr).with_context(|| format!("invalid address: {addr}"))?;
    let text = std::fs::read_to_string(&maps_file)
        .with_context(|| format!("failed to read maps file: {}", maps_file.display()))?;
    let out = resolve_addr_in_maps_text(&text, addr).unwrap_or_else(|| {
        serde_json::json!({
            "status": "miss",
            "addr": format!("{addr:#x}"),
            "maps_file": maps_file.display().to_string(),
        })
    });
    Ok(out)
}

pub(super) fn resolve_addr_in_maps_text(text: &str, addr: u64) -> Option<serde_json::Value> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next().unwrap_or("");
        let offset_raw = parts.next().unwrap_or("0");
        let dev = parts.next().unwrap_or("");
        let inode = parts.next().unwrap_or("");
        let path = parts.collect::<Vec<_>>().join(" ");
        let (lo_raw, hi_raw) = range.split_once('-')?;
        let lo = u64::from_str_radix(lo_raw, 16).ok()?;
        let hi = u64::from_str_radix(hi_raw, 16).ok()?;
        if !(lo <= addr && addr < hi) {
            continue;
        }
        let map_file_offset = u64::from_str_radix(offset_raw, 16).unwrap_or(0);
        let map_offset = addr.saturating_sub(lo);
        let file_offset = map_file_offset.saturating_add(map_offset);
        return Some(serde_json::json!({
            "status": "hit",
            "addr": format!("{addr:#x}"),
            "map_start": format!("{lo:#x}"),
            "map_end": format!("{hi:#x}"),
            "perms": perms,
            "map_file_offset": format!("{map_file_offset:#x}"),
            "map_offset": format!("{map_offset:#x}"),
            "file_offset": format!("{file_offset:#x}"),
            "dev": dev,
            "inode": inode,
            "path": if path.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(path) },
            "line": line,
        }));
    }
    None
}

pub(super) fn info_call(path: &Path) -> anyhow::Result<serde_json::Value> {
    let meta = enriched_trace_meta(path);
    let trace = crate::prelude::Trace::load(path)?;
    let n = trace.len();
    let trace_meta = crate::prelude::TraceMeta::load(path)?;
    let mut first_pc = None;
    let mut last_pc = None;
    let mut last_asm = None;
    let mut last_insn_is_ret = None;
    if n > 0 {
        let first = trace.record(0);
        let last = trace.record(n - 1);
        let d = crate::prelude::decode(last.pc, last.inst);
        first_pc = Some(format!("{:#x}", first.pc));
        last_pc = Some(format!("{:#x}", last.pc));
        last_asm = Some(format!("{} {}", d.mnemonic, d.op_str).trim().to_string());
        last_insn_is_ret = Some(d.is_ret);
    }
    let truncated = meta
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let complete = !truncated && last_insn_is_ret.unwrap_or(false);
    let ms = meta.get("ms").and_then(|v| v.as_f64());
    let rec_per_sec = ms
        .filter(|ms| *ms > 0.0)
        .map(|ms| (n as f64 / (ms / 1000.0)) as u64);
    Ok(serde_json::json!({
        "path": path.display().to_string(),
        "callIdx": meta.get("callIdx").cloned().unwrap_or(serde_json::Value::Null),
        "tid": meta.get("tid").cloned().unwrap_or(serde_json::Value::Null),
        "records": n,
        "ms": meta.get("ms").cloned().unwrap_or(serde_json::Value::Null),
        "retval": meta.get("retval").cloned().unwrap_or(serde_json::Value::Null),
        "module": meta.get("module").cloned().unwrap_or(serde_json::Value::Null),
        "modules_count": meta.get("modules").and_then(|v| v.as_array()).map(|items| items.len()).unwrap_or(0),
        "truncated": truncated,
        "last_insn_is_ret": last_insn_is_ret,
        "first_pc": first_pc,
        "last_pc": last_pc,
        "last_asm": last_asm,
        "is_complete": complete,
        "rec_per_sec": rec_per_sec,
        "record_size": 272,
        "format_version": trace_meta.format_version,
        "metadata": trace_meta,
    }))
}

pub(super) fn enriched_trace_meta(path: &Path) -> serde_json::Value {
    let mut meta = read_json_opt(&path.join("meta.json"));
    if path.join("trace.bin").is_file() {
        if let Some(run_dir) = path.parent().and_then(|calls_dir| calls_dir.parent()) {
            let parent = read_json_opt(&run_dir.join("meta.json"));
            merge_missing_meta_field(&mut meta, &parent, "module");
            merge_missing_meta_field(&mut meta, &parent, "modules");
            merge_missing_meta_field(&mut meta, &parent, "pkg");
            merge_missing_meta_field(&mut meta, &parent, "so");
            merge_missing_meta_field(&mut meta, &parent, "method");
            merge_missing_meta_field(&mut meta, &parent, "cmd");
        }
    }
    meta
}

pub(super) fn merge_missing_meta_field(
    meta: &mut serde_json::Value,
    parent: &serde_json::Value,
    key: &str,
) {
    let should_fill = meta
        .get(key)
        .map(|value| value.is_null() || value.as_array().is_some_and(|items| items.is_empty()))
        .unwrap_or(true);
    if should_fill {
        if let Some(value) = parent.get(key) {
            meta[key] = value.clone();
        }
    }
}

pub(super) fn read_json_opt(path: &Path) -> serde_json::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

pub(super) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_bytes_cli(raw: &str) -> anyhow::Result<Vec<u8>> {
    let mut s = raw.trim().to_string();
    if s.starts_with("0x") || s.starts_with("0X") {
        s = s[2..].to_string();
    }
    s.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    if s.is_empty() {
        bail!("empty hex byte string");
    }
    if !s.len().is_multiple_of(2) {
        bail!("hex byte string must contain an even number of nybbles");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte {:?}", &s[i..i + 2]))?,
        );
    }
    Ok(out)
}

pub(super) fn parse_u64_str(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// JSON 值转 u64 的唯一实现：数字直接取值，字符串经 parse_u64_str
/// 解析（0x 前缀十六进制 / 十进制）。vm_* 模块里的 value_as_u64、
/// node_value_u64 等都是本函数之上的薄包装，不要再新增平行实现。
pub(super) fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_str))
}

/// Parse an ADDRESS/OFFSET/PC the way a reverse engineer writes one: HEX by
/// default (disassembler convention — `7fc108c568` is hex, not decimal), `0x`
/// also hex, `d`-prefix forces decimal (`d16` = 16). Matches the P0/P1 commands'
/// `parse_u64` so the same `--addr`/`--off` means the same thing everywhere.
/// Use ONLY for address-typed args; size/count/idx keep `parse_u64_str`
/// (decimal-default, so `--size 256` stays 256).
pub(super) fn parse_addr_str(raw: &str) -> Option<u64> {
    crate::address_parse::parse_address(raw).ok()
}

pub(super) fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_nybble(input[i + 1]), hex_nybble(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

pub(super) fn hex_nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(super) fn utf8_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::from_utf8_lossy(&bytes[..take]).into_owned();
    if bytes.len() > take {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_csv_trims_and_drops_empty() {
        assert_eq!(split_csv("a, b ,c"), vec!["a", "b", "c"]);
        assert_eq!(split_csv(""), Vec::<String>::new());
        assert_eq!(split_csv(" , , "), Vec::<String>::new());
    }

    #[test]
    fn resolve_addr_in_maps_text_hit_and_miss() {
        let text = "1000-2000 r-xp 00000000 08:01 1234 /system/lib64/libc.so\n";
        let hit = resolve_addr_in_maps_text(text, 0x1500).unwrap();
        assert_eq!(hit["path"], "/system/lib64/libc.so");
        assert_eq!(hit["map_offset"], "0x500");
        assert_eq!(hit["file_offset"], "0x500");
        assert!(
            resolve_addr_in_maps_text(text, 0x9999).is_none(),
            "outside range"
        );
        assert!(
            resolve_addr_in_maps_text("zz-1000 r-xp 0 0 0 x\n", 0x500).is_none(),
            "bad hex lo"
        );
    }

    #[test]
    fn resolve_addr_in_maps_text_handles_anon_maps() {
        let text = "1000-2000 ---p 00000000 00:00 0 \n";
        let hit = resolve_addr_in_maps_text(text, 0x1000).unwrap();
        assert_eq!(hit["path"], serde_json::Value::Null);
    }
}

pub fn info(path: PathBuf) -> anyhow::Result<serde_json::Value> {
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    let out = if path.join("trace.bin").is_file() {
        info_call(&path)?
    } else if path.join("calls").is_dir() {
        let top = read_json_opt(&path.join("meta.json"));
        let calls = list_calls(&path)?;
        serde_json::json!({
            "path": path.display().to_string(),
            "pkg": top.get("pkg").cloned().unwrap_or(serde_json::Value::Null),
            "so": top.get("so").cloned().unwrap_or(serde_json::Value::Null),
            "method": top.get("method").cloned().unwrap_or(serde_json::Value::Null),
            "cmd": top.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
            "fn_offset": top.get("fn_offset").cloned().unwrap_or(serde_json::Value::Null),
            "fn_addr": top.get("fn_addr").cloned().unwrap_or(serde_json::Value::Null),
            "module": top.get("module").cloned().unwrap_or(serde_json::Value::Null),
            "calls_count": calls.len(),
            "total_records": calls.iter().filter_map(|c| c.get("records").and_then(|v| v.as_u64())).sum::<u64>(),
            "max_records": calls.iter().filter_map(|c| c.get("records").and_then(|v| v.as_u64())).max().unwrap_or(0),
            "calls": calls,
        })
    } else {
        bail!("unsupported info path: {}", path.display());
    };
    Ok(out)
}
