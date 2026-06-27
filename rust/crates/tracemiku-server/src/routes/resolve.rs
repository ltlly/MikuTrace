//! GET /api/resolve?addr= | (so=&off=)
//!
//! The tool-neutral address-interop foundation. Every other traceMiku query is
//! PC/idx centric; this route is the one place that translates between the
//! `(SO, static-offset)` coordinate that every disassembler (IDA / BN / Ghidra,
//! CLI or UI) shows and a human/AI can read+type, and traceMiku's internal
//! absolute PC. It accepts the coordinate in EITHER direction and always echoes
//! the canonical form back PLUS the runtime facts only a trace can give:
//!
//!   * `addr=0x...`            absolute PC  → (module, offset, exec count, ...)
//!   * `so=libfoo&off=0x...`   module+offset → (absolute PC, exec count, ...)
//!
//! `so` is matched tool-neutrally (full path, basename, basename-prefix, or
//! substring) so the stable basename a human typed in IDA resolves to the
//! versioned `.so` actually loaded on device. Ambiguous matches are reported
//! rather than silently picking one.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ResolveQuery {
    /// Absolute PC (hex `0x..` or decimal). Forward direction.
    pub addr: Option<String>,
    /// Module name / basename / prefix / substring. Reverse direction (with `off`).
    pub so: Option<String>,
    /// Module-relative offset (hex or decimal). Reverse direction (with `so`).
    pub off: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Coord {
    /// Loaded module name (full path as seen on device).
    pub module: Option<String>,
    pub module_base: Option<String>,
    pub module_end: Option<String>,
    /// Module-relative static offset — the coordinate shared with disassemblers.
    pub offset: Option<String>,
    /// Absolute PC in this trace's address space.
    pub pc: String,
    /// Times this exact PC was executed in the trace.
    pub exec_count: usize,
    /// First/last record index at this PC (None if never executed).
    pub first_idx: Option<usize>,
    pub last_idx: Option<usize>,
    /// True when `pc` lies inside a loaded module range.
    pub in_module: bool,
    /// True when the trace actually executed this PC at least once.
    pub executed: bool,
}

pub async fn resolve_handler(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
) -> Json<Value> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || resolve_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "resolve worker failed: {err}");
                json!({ "status": "error", "error": "resolve worker panicked" })
            }),
    )
}

/// Parse an address/offset the way a reverse engineer writes one.
///
/// Addresses and offsets are universally hex in IDA/BN/Ghidra, so a bare token
/// is hex (`10` -> `0x10`), NOT decimal — otherwise `--off 10` and `--off 6a30`
/// would silently use different bases. A leading `0x`/`0X` is also accepted.
/// Use `d`/`D` prefix to force decimal when genuinely needed (`d16` -> 16).
fn parse_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(dec) = s.strip_prefix('d').or_else(|| s.strip_prefix('D')) {
        dec.parse::<u64>().ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

fn coord_for_pc(inner: &crate::state::AppStateInner, pc: u64) -> Coord {
    let idxs = inner.index.pc_to_idxs.get(&pc);
    let exec_count = idxs.map(Vec::len).unwrap_or(0);
    let first_idx = idxs.and_then(|v| v.first().copied());
    let last_idx = idxs.and_then(|v| v.last().copied());
    let rel = inner.modules.resolve_relative(pc);
    let module_info = inner.modules.resolve(pc);
    Coord {
        module: rel.as_ref().map(|(name, _)| name.clone()),
        module_base: module_info.as_ref().map(|m| m.base.clone()),
        module_end: module_info.as_ref().map(|m| m.end.clone()),
        offset: rel.as_ref().map(|(_, off)| format!("{off:#x}")),
        pc: format!("{pc:#x}"),
        exec_count,
        first_idx,
        last_idx,
        in_module: rel.is_some(),
        executed: exec_count > 0,
    }
}

fn resolve_response(inner: &crate::state::AppStateInner, q: ResolveQuery) -> Value {
    // Reverse direction: (so, off) → PC. Takes precedence when both provided.
    if let (Some(so), Some(off_raw)) = (q.so.as_ref(), q.off.as_ref()) {
        let Some(off) = parse_u64(off_raw) else {
            return json!({ "status": "error", "error": format!("invalid off: {off_raw}") });
        };
        let candidates = inner.modules.resolve_offset_candidates(so, off);
        return match candidates.len() {
            0 => json!({
                "status": "miss",
                "query": { "so": so, "off": format!("{off:#x}") },
                "reason": "no loaded module matched",
                "modules_total": inner.modules.len(),
            }),
            1 => {
                let (name, base, end, pc) = &candidates[0];
                // The matched module exists, but the offset may exceed its
                // mapped size — surface that explicitly rather than returning a
                // PC that lands in a neighbouring (or no) module.
                if *pc < *base || *pc >= *end {
                    json!({
                        "status": "out_of_range",
                        "direction": "offset_to_pc",
                        "query": { "so": so, "off": format!("{off:#x}") },
                        "module": name,
                        "module_base": format!("{base:#x}"),
                        "module_end": format!("{end:#x}"),
                        "module_size": format!("{:#x}", end.wrapping_sub(*base)),
                        "pc": format!("{pc:#x}"),
                        "reason": "offset exceeds module mapped size",
                    })
                } else {
                    json!({
                        "status": "hit",
                        "direction": "offset_to_pc",
                        "query": { "so": so, "off": format!("{off:#x}") },
                        "coord": coord_for_pc(inner, *pc),
                    })
                }
            }
            _ => json!({
                "status": "ambiguous",
                "query": { "so": so, "off": format!("{off:#x}") },
                "candidates": candidates
                    .iter()
                    .map(|(name, base, _end, pc)| json!({
                        "module": name,
                        "module_base": format!("{base:#x}"),
                        "pc": format!("{pc:#x}"),
                    }))
                    .collect::<Vec<_>>(),
                "hint": "narrow `so` to a unique module name",
            }),
        };
    }

    // Forward direction: absolute PC → (module, offset).
    if let Some(addr_raw) = q.addr.as_ref() {
        let Some(pc) = parse_u64(addr_raw) else {
            return json!({ "status": "error", "error": format!("invalid addr: {addr_raw}") });
        };
        let coord = coord_for_pc(inner, pc);
        return json!({
            "status": if coord.in_module || coord.executed { "hit" } else { "miss" },
            "direction": "pc_to_offset",
            "query": { "addr": format!("{pc:#x}") },
            "coord": coord,
        });
    }

    json!({
        "status": "error",
        "error": "provide either addr=0x... (PC→offset) or so=<name>&off=0x... (offset→PC)",
    })
}

#[cfg(test)]
mod tests {
    use super::parse_u64;

    #[test]
    fn parse_u64_treats_bare_token_as_hex() {
        // disassembler convention: bare offsets/addrs are hex
        assert_eq!(parse_u64("0x10"), Some(16));
        assert_eq!(parse_u64("0X10"), Some(16));
        assert_eq!(parse_u64("10"), Some(16)); // hex, NOT decimal 10
        assert_eq!(parse_u64("6a30"), Some(0x6a30));
        assert_eq!(parse_u64("ff"), Some(255));
        // explicit decimal escape hatch
        assert_eq!(parse_u64("d16"), Some(16));
        assert_eq!(parse_u64("D255"), Some(255));
        // garbage
        assert_eq!(parse_u64("zz"), None);
        assert_eq!(parse_u64("0xZZ"), None);
    }
}
