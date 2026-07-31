//! Shared helpers for routes that take an `idx | reg | addr | idxs | regs |
//! addrs` seed and emit a graph/slice over the persistent dependency CSR.
//!
//! Originally inlined three times across `dep_graph`, `bfs_slice`, and
//! `forward_dep_tree`. This module centralises:
//!
//! * `parse_u64` — accept hex (`0x…`) or decimal literals.
//! * `split_csv` — `"1, 2,3"` → ["1", "2", "3"], dropping empties.
//! * `ResolvedSeed` — common JSON shape for the seed envelope.
//! * `resolve_*` — fall back to the trace's index for register/address
//!   look-ups, returning a single-seed envelope.
//! * `edge_kind` / `edge_label` / `node_id` — string formatting helpers.
//! * `render_dep_node` — common node payload (PC, asm, func, expression, via)
//!   used by both `dep_graph` and `forward_dep_tree`.

use serde::Serialize;
use tracemiku_core::analysis_index::DepKind;
use tracemiku_core::disasm::decode;

use crate::state::AppState;
use crate::taint_graph::expression_from_asm;

/// JSON shape for a seed envelope. The handler surfaces these so the UI
/// can display "seed kind", "before cursor", and any resolution note.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedSeed {
    pub kind: &'static str,
    pub idx: Option<usize>,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub before: Option<usize>,
    pub note: Option<String>,
}

impl ResolvedSeed {
    pub fn placeholder(note: &str) -> Self {
        Self {
            kind: "none",
            idx: None,
            reg: None,
            addr: None,
            before: None,
            note: Some(note.to_string()),
        }
    }

    pub fn for_idx(idx: usize, reg: Option<String>, before: Option<usize>) -> Self {
        Self {
            kind: "idx",
            idx: Some(idx),
            reg,
            addr: None,
            before,
            note: None,
        }
    }

    pub fn for_idx_token(token: &str, before: Option<usize>) -> Self {
        match token.parse::<usize>() {
            Ok(idx) => Self::for_idx(idx, None, before),
            Err(_) => Self {
                kind: "idx",
                idx: None,
                reg: None,
                addr: None,
                before,
                note: Some(format!("invalid idx literal {token:?}")),
            },
        }
    }
}

/// Parse a hex (`0x…`) or decimal literal into `u64`. Trims whitespace.
pub fn parse_u64(raw: &str) -> Option<u64> {
    crate::routes::parse::parse_dec_u64(raw)
}

/// Split a comma-separated string into trimmed, non-empty tokens.
pub fn split_csv(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty())
}

pub fn resolve_reg(state: &AppState, reg: &str, before: usize) -> ResolvedSeed {
    let idx = state.inner.index.last_def_before(reg, before);
    ResolvedSeed {
        kind: "reg",
        idx,
        reg: Some(reg.to_string()),
        addr: None,
        before: Some(before),
        note: idx
            .is_none()
            .then(|| format!("no definition of {reg} before #{before}")),
    }
}

pub fn resolve_addr(state: &AppState, addr_raw: &str, before: usize) -> ResolvedSeed {
    let Some(addr) = parse_u64(addr_raw) else {
        return ResolvedSeed {
            kind: "addr",
            idx: None,
            reg: None,
            addr: Some(addr_raw.to_string()),
            before: Some(before),
            note: Some(format!("invalid address literal {addr_raw:?}")),
        };
    };
    let idx = state
        .inner
        .index
        .mem_addr_to_writes
        .get(&addr)
        .and_then(|idxs| {
            let cut = idxs.partition_point(|idx| *idx < before);
            (cut > 0).then_some(idxs[cut - 1])
        });
    ResolvedSeed {
        kind: "addr",
        idx,
        reg: None,
        addr: Some(format!("{addr:#x}")),
        before: Some(before),
        note: idx
            .is_none()
            .then(|| format!("no write to {addr:#x} before #{before}")),
    }
}

/// Resolution priority shared by `dep_graph` / `forward_dep_tree` (the
/// single-seed routes): explicit `idx` wins, then `reg`, then `addr`. The
/// returned `Option<usize>` is the resolved trace index, if any.
pub fn resolve_one(
    state: &AppState,
    idx: Option<usize>,
    reg: Option<&str>,
    addr: Option<&str>,
    before: usize,
    raw_before: Option<usize>,
) -> (Option<usize>, ResolvedSeed) {
    if let Some(idx) = idx {
        return (
            Some(idx),
            ResolvedSeed::for_idx(idx, reg.map(str::to_string), raw_before),
        );
    }
    if let Some(reg) = reg {
        let seed = resolve_reg(state, reg, before);
        return (seed.idx, seed);
    }
    if let Some(addr) = addr {
        let seed = resolve_addr(state, addr, before);
        return (seed.idx, seed);
    }
    (
        None,
        ResolvedSeed {
            kind: "none",
            idx: None,
            reg: None,
            addr: None,
            before: raw_before,
            note: Some("provide idx, reg, or addr".to_string()),
        },
    )
}

/// Annotate seeds whose idx is past the trace boundary so the UI can show a
/// note rather than silently returning empty.
pub fn annotate_outside_trace<'a, I: IntoIterator<Item = &'a mut ResolvedSeed>>(
    seeds: I,
    trace_len: usize,
) {
    for seed in seeds {
        if let Some(idx) = seed.idx {
            if idx >= trace_len && seed.note.is_none() {
                seed.note = Some(format!("seed idx {idx} is outside trace"));
            }
        }
    }
}

pub fn edge_kind_str(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Reg => "reg",
        DepKind::Address => "addr",
        DepKind::Mem => "mem",
        DepKind::Control => "control",
    }
}

pub fn edge_label_str(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Reg => "reg",
        DepKind::Address => "addr",
        DepKind::Mem => "mem value",
        DepKind::Control => "control",
    }
}

pub fn node_id(idx: usize) -> String {
    format!("idx:{idx}")
}

/// Common per-row payload reused by `/api/dep-graph`, `/api/forward-dep-tree`
/// and the enriched `/api/bfs-slice` rows.
#[derive(Debug, Clone, Serialize)]
pub struct DepNode {
    pub id: String,
    pub idx: usize,
    pub depth: usize,
    pub pc: String,
    pub func: Option<String>,
    pub asm: String,
    pub via: String,
    pub expression: String,
}

/// Build the `DepNode` payload for `idx`. `via_override` is honored when the
/// caller wants to surface a seed register name; otherwise we pick the
/// instruction's first def, then "mem", then mnemonic.
pub fn render_dep_node(
    state: &AppState,
    idx: usize,
    depth: usize,
    via_override: Option<&str>,
) -> DepNode {
    let rec = state.inner.trace.record(idx);
    let decoded = decode(rec.pc, rec.inst);
    let asm = if decoded.op_str.is_empty() {
        decoded.mnemonic.clone()
    } else {
        format!("{} {}", decoded.mnemonic, decoded.op_str)
    };
    let via = via_override.map(ToOwned::to_owned).unwrap_or_else(|| {
        decoded
            .regs_def
            .first()
            .cloned()
            .or_else(|| {
                decoded
                    .mem_op
                    .iter()
                    .any(|op| op.is_write)
                    .then(|| "mem".to_string())
            })
            .unwrap_or_else(|| decoded.mnemonic.clone())
    });
    let func = state
        .inner
        .symbols
        .lookup_entry(rec.pc)
        .map(|entry| entry.name);
    DepNode {
        id: node_id(idx),
        idx,
        depth,
        pc: format!("{:#x}", rec.pc),
        func,
        expression: expression_from_asm(&asm, &via, None),
        asm,
        via,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_u64("0x42"), Some(0x42));
        assert_eq!(parse_u64("66"), Some(66));
        assert_eq!(parse_u64("not-a-number"), None);
    }

    #[test]
    fn parse_u64_handles_uppercase_prefix() {
        assert_eq!(parse_u64("0XAB"), Some(0xab));
    }

    #[test]
    fn split_csv_drops_empties() {
        let tokens: Vec<&str> = split_csv(" 1, ,2,3,").collect();
        assert_eq!(tokens, vec!["1", "2", "3"]);
    }

    #[test]
    fn for_idx_token_round_trips_invalid() {
        let seed = ResolvedSeed::for_idx_token("bogus", None);
        assert_eq!(seed.idx, None);
        assert!(seed.note.unwrap().contains("invalid idx literal"));
    }

    #[test]
    fn for_idx_token_parses_int() {
        let seed = ResolvedSeed::for_idx_token("42", Some(100));
        assert_eq!(seed.idx, Some(42));
        assert_eq!(seed.before, Some(100));
        assert!(seed.note.is_none());
    }

    #[test]
    fn edge_kind_str_round_trips() {
        assert_eq!(edge_kind_str(DepKind::Reg), "reg");
        assert_eq!(edge_kind_str(DepKind::Address), "addr");
        assert_eq!(edge_kind_str(DepKind::Mem), "mem");
        assert_eq!(edge_kind_str(DepKind::Control), "control");
    }
}
