use super::*;

pub(super) fn normalize_api_path(path: &str) -> anyhow::Result<String> {
    let path = path.trim();
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.starts_with("/api/") || path == "/openapi.json" {
        Ok(path)
    } else {
        bail!("api path must start with /api/ or be /openapi.json: {path}")
    }
}

pub(super) fn parse_key_values(raw: Vec<String>) -> anyhow::Result<Vec<(&'static str, String)>> {
    let mut out = Vec::new();
    for item in raw {
        let Some((k, v)) = item.split_once('=') else {
            bail!("--param must be key=value, got {item:?}");
        };
        let key = k.trim();
        if key.is_empty() {
            bail!("--param key must not be empty");
        }
        let key: &'static str = Box::leak(key.to_string().into_boxed_str());
        out.push((key, v.to_string()));
    }
    Ok(out)
}

pub(super) fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn split_csv_allow_empty(s: &str) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    split_csv(s)
}

/// Decode the `hex` field of a /api/mem-export response and write the raw
/// decrypted bytes to `out`. Prints a JSON summary (with completeness +
/// provenance histogram) so the caller still sees how trustworthy the dump is.
/// `??` frontier bytes are written as 0x00 — surfaced via completeness < 1.0.
pub(super) fn cmd_mem_export_write(value: &serde_json::Value, out: &Path) -> anyhow::Result<()> {
    let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "ready" {
        // Pass the route's miss/ambiguous/error JSON straight through.
        return print_pretty(value);
    }
    let hex = value
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("mem-export response missing hex field"))?;
    if !hex.len().is_multiple_of(2) {
        bail!("mem-export hex length is odd ({} chars)", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16)
            .with_context(|| format!("bad hex byte at {i}"))?;
        bytes.push(b);
    }
    std::fs::write(out, &bytes).with_context(|| format!("failed to write {}", out.display()))?;
    let mut summary = value.as_object().cloned().unwrap_or_default();
    summary.remove("hex"); // raw bytes are now on disk; don't echo the blob
    summary.insert(
        "out_file".to_string(),
        serde_json::Value::String(out.display().to_string()),
    );
    summary.insert(
        "bytes_written".to_string(),
        serde_json::Value::from(bytes.len()),
    );
    print_pretty(&serde_json::Value::Object(summary))
}

pub(super) fn cmd_list(path: Option<PathBuf>, dir: PathBuf, json: bool) -> anyhow::Result<()> {
    let target = path.unwrap_or(dir);
    if !target.exists() {
        bail!("path does not exist: {}", target.display());
    }
    let rows = if target.join("calls").is_dir() {
        list_calls(&target)?
    } else {
        list_runs(&target)?
    };
    if json {
        print_pretty(&serde_json::Value::Array(rows))
    } else {
        for row in rows {
            println!(
                "{}",
                serde_json::to_string(&row).context("serialize list row")?
            );
        }
        Ok(())
    }
}

pub(super) fn list_runs(base: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
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

pub(super) fn list_calls(run_dir: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
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

pub(super) fn cmd_info(path: PathBuf, json: bool) -> anyhow::Result<()> {
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
    if json {
        print_pretty(&out)
    } else {
        println!("{}", serde_json::to_string_pretty(&out)?);
        Ok(())
    }
}

pub(super) fn cmd_resolve_map_addr(maps_file: PathBuf, addr: String) -> anyhow::Result<()> {
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
    print_pretty(&out)
}

pub(super) fn cmd_resolve_trace_addr(trace_dir: PathBuf, addr: String) -> anyhow::Result<()> {
    let addr = parse_addr_str(&addr).with_context(|| format!("invalid address: {addr}"))?;
    let meta = enriched_trace_meta(&trace_dir);
    let module = module_for_addr(&meta, addr);
    if module.is_null() {
        print_pretty(&serde_json::json!({
            "status": "miss",
            "addr": format!("{addr:#x}"),
            "trace_dir": trace_dir.display().to_string(),
            "modules": meta.get("modules").and_then(|v| v.as_array()).map(|m| m.len()).unwrap_or(0),
        }))
    } else {
        print_pretty(&serde_json::json!({
            "status": "hit",
            "addr": format!("{addr:#x}"),
            "trace_dir": trace_dir.display().to_string(),
            "module": module,
            "primary_module": meta.get("module").cloned().unwrap_or(serde_json::Value::Null),
        }))
    }
}

pub(super) fn cmd_resolve_elf_symbol(elf_file: PathBuf, offset: String) -> anyhow::Result<()> {
    let offset = parse_addr_str(&offset).with_context(|| format!("invalid offset: {offset}"))?;
    let (tool, symbols) = elf_symbols_from_nm(&elf_file)
        .with_context(|| format!("failed to read ELF symbols: {}", elf_file.display()))?;
    let out = resolve_elf_symbol_json(&symbols, offset).unwrap_or_else(|| {
        serde_json::json!({
            "status": "miss",
            "elf_file": elf_file.display().to_string(),
            "offset": format!("{offset:#x}"),
            "symbol_count": symbols.len(),
            "source_tool": tool,
        })
    });
    let mut obj = out.as_object().cloned().unwrap_or_default();
    obj.insert(
        "elf_file".to_string(),
        serde_json::Value::String(elf_file.display().to_string()),
    );
    obj.insert("source_tool".to_string(), serde_json::Value::String(tool));
    print_pretty(&serde_json::Value::Object(obj))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ElfSymbol {
    pub(super) addr: u64,
    pub(super) size: Option<u64>,
    pub(super) kind: String,
    pub(super) name: String,
}

pub(super) fn elf_symbols_from_nm(elf_file: &Path) -> anyhow::Result<(String, Vec<ElfSymbol>)> {
    let attempts: &[(&str, &[&str])] = &[
        ("llvm-nm", &["-D", "--defined-only", "--print-size"]),
        ("llvm-nm", &["--defined-only", "--print-size"]),
        ("nm", &["-D", "--defined-only", "--print-size"]),
        ("nm", &["--defined-only", "--print-size"]),
    ];
    let mut errors = Vec::new();
    for (tool, args) in attempts {
        match run_nm_command(tool, args, elf_file) {
            Ok(text) => {
                let mut symbols = parse_nm_symbols(&text);
                if !symbols.is_empty() {
                    symbols.sort_by_key(|sym| sym.addr);
                    return Ok((format!("{} {}", tool, args.join(" ")), symbols));
                }
                errors.push(format!(
                    "{} {} returned no defined symbols",
                    tool,
                    args.join(" ")
                ));
            }
            Err(err) => errors.push(format!("{} {}: {err}", tool, args.join(" "))),
        }
    }
    bail!("{}", errors.join("; "))
}

pub(super) fn run_nm_command(tool: &str, args: &[&str], elf_file: &Path) -> anyhow::Result<String> {
    let output = Command::new(tool)
        .args(args)
        .arg(elf_file)
        .output()
        .with_context(|| format!("failed to execute {tool}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "exit status {}{}",
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(super) fn parse_nm_symbols(text: &str) -> Vec<ElfSymbol> {
    text.lines()
        .filter_map(parse_nm_symbol_line)
        .collect::<Vec<_>>()
}

pub(super) fn parse_nm_symbol_line(line: &str) -> Option<ElfSymbol> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    let addr = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
    let (size, kind_idx, name_idx) = if parts.len() >= 4 && is_nm_kind(parts[2]) {
        (
            u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok(),
            2usize,
            3usize,
        )
    } else if is_nm_kind(parts[1]) {
        (None, 1usize, 2usize)
    } else {
        return None;
    };
    let kind = parts[kind_idx].to_string();
    if kind.eq_ignore_ascii_case("U") {
        return None;
    }
    let name = parts[name_idx..].join(" ");
    (!name.is_empty()).then_some(ElfSymbol {
        addr,
        size,
        kind,
        name,
    })
}

pub(super) fn is_nm_kind(s: &str) -> bool {
    s.len() == 1 && s.as_bytes()[0].is_ascii_alphabetic()
}

pub(super) fn resolve_elf_symbol_json(
    symbols: &[ElfSymbol],
    offset: u64,
) -> Option<serde_json::Value> {
    let sym = symbols.iter().rev().find(|sym| sym.addr <= offset)?;
    let delta = offset.saturating_sub(sym.addr);
    let next = symbols.iter().find(|next| next.addr > sym.addr);
    let in_size = sym
        .size
        .map(|size| delta < size)
        .or_else(|| next.map(|next| offset < next.addr));
    Some(serde_json::json!({
        "status": if delta == 0 { "exact" } else { "nearest" },
        "offset": format!("{offset:#x}"),
        "symbol_addr": format!("{:#x}", sym.addr),
        "symbol_size": sym.size.map(|size| format!("{size:#x}")),
        "delta": format!("{delta:#x}"),
        "name": sym.name,
        "base_name": elf_symbol_base_name(&sym.name),
        "kind": sym.kind,
        "in_symbol_range": in_size,
        "next_symbol_addr": next.map(|sym| format!("{:#x}", sym.addr)),
        "next_symbol": next.map(|sym| sym.name.clone()),
        "symbol_count": symbols.len(),
    }))
}

pub(super) fn elf_symbol_base_name(name: &str) -> String {
    name.split("@@")
        .next()
        .unwrap_or(name)
        .split('@')
        .next()
        .unwrap_or(name)
        .to_string()
}

pub(super) fn info_call(path: &Path) -> anyhow::Result<serde_json::Value> {
    let meta = enriched_trace_meta(path);
    let trace = tracemiku_core::prelude::Trace::load(path)?;
    let n = trace.len();
    let mut first_pc = None;
    let mut last_pc = None;
    let mut last_asm = None;
    let mut last_insn_is_ret = None;
    if n > 0 {
        let first = trace.record(0);
        let last = trace.record(n - 1);
        let d = tracemiku_core::prelude::decode(last.pc, last.inst);
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

#[allow(clippy::too_many_arguments)]
pub(super) fn taint_params(
    start: usize,
    reg: String,
    max_count: Option<usize>,
    through_mem: bool,
    data_only: bool,
    cross_fn_call: bool,
    scan_limit: Option<usize>,
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("start", start.to_string()),
        ("reg", reg),
        ("through_mem", through_mem.to_string()),
        ("data_only", data_only.to_string()),
        ("cross_fn_call", cross_fn_call.to_string()),
    ];
    if let Some(max) = max_count {
        params.push(("max_count", max.to_string()));
    }
    if let Some(scan) = scan_limit {
        params.push(("scan_limit", scan.to_string()));
    }
    params
}

pub(super) fn route_path(base: &str, params: &[(&str, String)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{qs}")
}

pub(super) fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(super) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn parse_hex_bytes_cli(raw: &str) -> anyhow::Result<Vec<u8>> {
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

pub(super) fn find_hex_byte_offsets(haystack_hex: &str, needle_hex: &str) -> Vec<usize> {
    let mut haystack = haystack_hex.trim().to_ascii_lowercase();
    let mut needle = needle_hex.trim().to_ascii_lowercase();
    haystack.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    needle.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    if needle.is_empty() || !needle.len().is_multiple_of(2) || haystack.len() < needle.len() {
        return Vec::new();
    }
    (0..=haystack.len() - needle.len())
        .step_by(2)
        .filter(|&idx| haystack[idx..idx + needle.len()] == needle)
        .map(|idx| idx / 2)
        .collect()
}

pub(super) fn parse_u64_str(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse an ADDRESS/OFFSET/PC the way a reverse engineer writes one: HEX by
/// default (disassembler convention — `7fc108c568` is hex, not decimal), `0x`
/// also hex, `d`-prefix forces decimal (`d16` = 16). Matches the P0/P1 commands'
/// `parse_u64` so the same `--addr`/`--off` means the same thing everywhere.
/// Use ONLY for address-typed args; size/count/idx keep `parse_u64_str`
/// (decimal-default, so `--size 256` stays 256).
pub(super) fn parse_addr_str(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(dec) = s.strip_prefix('d').or_else(|| s.strip_prefix('D')) {
        dec.parse::<u64>().ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
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
    fn normalize_api_path_adds_slash_and_prefix() {
        assert_eq!(normalize_api_path("api/records").unwrap(), "/api/records");
        assert_eq!(normalize_api_path("/api/records").unwrap(), "/api/records");
        assert_eq!(normalize_api_path(" /openapi.json ").unwrap(), "/openapi.json");
        assert!(normalize_api_path("records").is_err(), "missing /api/ prefix");
        assert!(normalize_api_path("/other/path").is_err());
    }

    #[test]
    fn parse_key_values_requires_equals() {
        let ok = parse_key_values(vec!["a=1".into(), "b=2".into()]).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].1, "1");
        assert!(parse_key_values(vec!["noequals".into()]).is_err());
        assert!(parse_key_values(vec!["=x".into()]).is_err(), "empty key");
    }

    #[test]
    fn split_csv_trims_and_drops_empty() {
        assert_eq!(split_csv("a, b ,c"), vec!["a", "b", "c"]);
        assert_eq!(split_csv(""), Vec::<String>::new());
        assert_eq!(split_csv(" , , "), Vec::<String>::new());
        assert_eq!(split_csv_allow_empty(""), vec![String::new()]);
    }

    #[test]
    fn resolve_addr_in_maps_text_hit_and_miss() {
        let text = "1000-2000 r-xp 00000000 08:01 1234 /system/lib64/libc.so\n";
        let hit = resolve_addr_in_maps_text(text, 0x1500).unwrap();
        assert_eq!(hit["path"], "/system/lib64/libc.so");
        assert_eq!(hit["map_offset"], "0x500");
        assert_eq!(hit["file_offset"], "0x500");
        assert!(resolve_addr_in_maps_text(text, 0x9999).is_none(), "outside range");
        assert!(resolve_addr_in_maps_text("zz-1000 r-xp 0 0 0 x\n", 0x500).is_none(), "bad hex lo");
    }

    #[test]
    fn resolve_addr_in_maps_text_handles_anon_maps() {
        let text = "1000-2000 ---p 00000000 00:00 0 \n";
        let hit = resolve_addr_in_maps_text(text, 0x1000).unwrap();
        assert_eq!(hit["path"], serde_json::Value::Null);
    }
}
