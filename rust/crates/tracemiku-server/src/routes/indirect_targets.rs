//! GET /api/indirect-targets?addr= | (so=&off=)  [&min_count=]
//!
//! Resolves where an indirect branch/call actually went at runtime — the
//! single highest-frequency wall in static RE of obfuscated/optimized code.
//! A disassembler shows `br x8` / `blr x9` / a jump-table dispatch and stops;
//! it cannot know the target without running the code. traceMiku does: every
//! executed indirect branch's successor PC is right there in the trace.
//!
//! Keyed tool-neutrally on the shared `(SO, offset)` coordinate:
//!
//!   * `addr=0x<PC>`           one indirect-branch source → target distribution
//!   * `so=<name>&off=0x<off>` same, via module-relative offset
//!   * (neither)               list every indirect-branch source in the trace
//!
//! Each source and target is returned as a full `(module, offset, pc, exec…)`
//! coordinate plus the observed hit count and percentage, so the answer drops
//! straight back into IDA/BN/Ghidra at the resolved offset.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::resolve::{coord_for_pc, parse_u64, Coord};
use crate::state::AppState;

/// Cap on distinct sources returned by the list-all form.
const MAX_SOURCES_LISTED: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct IndirectTargetsQuery {
    pub addr: Option<String>,
    pub so: Option<String>,
    pub off: Option<String>,
    /// Drop targets observed fewer than this many times (default 1 = keep all).
    #[serde(default = "default_min_count")]
    pub min_count: u64,
}

fn default_min_count() -> u64 {
    1
}

#[derive(Debug, Serialize)]
pub struct TargetEntry {
    pub coord: Coord,
    pub count: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct SourceEntry {
    pub source: Coord,
    /// "br" / "blr" (indirect call) or null if the source PC was never decoded.
    pub mnemonic: Option<String>,
    pub total_observations: u64,
    pub distinct_targets: usize,
    pub targets: Vec<TargetEntry>,
}

pub async fn indirect_targets_handler(
    State(state): State<AppState>,
    Query(q): Query<IndirectTargetsQuery>,
) -> Json<Value> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || indirect_targets_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "indirect-targets worker failed: {err}");
                json!({ "status": "error", "error": "indirect-targets worker panicked" })
            }),
    )
}

/// Mnemonic at a source PC (first observed execution), if decodable.
fn mnemonic_at(inner: &crate::state::AppStateInner, pc: u64) -> Option<String> {
    let idx = inner.index.pc_to_idxs.get(&pc).and_then(|v| v.first())?;
    let d = tracemiku_core::disasm::decode(pc, inner.trace.inst(*idx));
    Some(d.mnemonic)
}

fn build_source_entry(
    inner: &crate::state::AppStateInner,
    src_pc: u64,
    targets: &[(u64, u64)],
    min_count: u64,
) -> SourceEntry {
    let total: u64 = targets.iter().map(|(_, c)| *c).sum();
    let entries: Vec<TargetEntry> = targets
        .iter()
        .filter(|(_, c)| *c >= min_count)
        .map(|(tpc, count)| TargetEntry {
            coord: coord_for_pc(inner, *tpc),
            count: *count,
            percent: if total > 0 {
                (*count as f64) * 100.0 / (total as f64)
            } else {
                0.0
            },
        })
        .collect();
    SourceEntry {
        source: coord_for_pc(inner, src_pc),
        mnemonic: mnemonic_at(inner, src_pc),
        total_observations: total,
        distinct_targets: entries.len(),
        targets: entries,
    }
}

fn indirect_targets_response(
    inner: &crate::state::AppStateInner,
    q: IndirectTargetsQuery,
) -> Value {
    // Resolve the requested source PC, if any.
    let source_pc: Option<u64> = if let Some(addr) = q.addr.as_ref() {
        match parse_u64(addr) {
            Some(pc) => Some(pc),
            None => return json!({ "status": "error", "error": format!("invalid addr: {addr}") }),
        }
    } else if let (Some(so), Some(off_raw)) = (q.so.as_ref(), q.off.as_ref()) {
        let Some(off) = parse_u64(off_raw) else {
            return json!({ "status": "error", "error": format!("invalid off: {off_raw}") });
        };
        let candidates = inner.modules.resolve_offset_candidates(so, off);
        match candidates.len() {
            0 => {
                return json!({
                    "status": "miss",
                    "query": { "so": so, "off": format!("{off:#x}") },
                    "reason": "no loaded module matched",
                })
            }
            1 => Some(candidates[0].3),
            _ => {
                return json!({
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
                })
            }
        }
    } else {
        None
    };

    let dispatch = tracemiku_core::cfg::resolve_indirect_branch_targets(&inner.trace);

    // Single-source query.
    if let Some(src_pc) = source_pc {
        return match dispatch.get(&src_pc) {
            Some(targets) => {
                let entry = build_source_entry(inner, src_pc, targets, q.min_count);
                json!({
                    "status": "hit",
                    "source": entry.source,
                    "mnemonic": entry.mnemonic,
                    "total_observations": entry.total_observations,
                    "distinct_targets": entry.distinct_targets,
                    "targets": entry.targets,
                })
            }
            None => {
                // Distinguish "not an indirect branch" from "valid but unobserved".
                let coord = coord_for_pc(inner, src_pc);
                let mnem = mnemonic_at(inner, src_pc);
                json!({
                    "status": "no_dispatch",
                    "source": coord,
                    "mnemonic": mnem,
                    "reason": match mnem.as_deref() {
                        Some("br") | Some("blr") => "indirect branch executed but had no recorded successor (trace tail)",
                        Some(_) => "PC is not an indirect branch (br/blr)",
                        None => "PC was never executed in this trace",
                    },
                })
            }
        };
    }

    // List-all form: every indirect-branch source, busiest first.
    let mut sources: Vec<SourceEntry> = dispatch
        .iter()
        .map(|(&src, targets)| build_source_entry(inner, src, targets, q.min_count))
        .collect();
    sources.sort_by(|a, b| b.total_observations.cmp(&a.total_observations));
    let total_sources = sources.len();
    let capped = total_sources > MAX_SOURCES_LISTED;
    sources.truncate(MAX_SOURCES_LISTED);

    json!({
        "status": "ok",
        "total_sources": total_sources,
        "returned": sources.len(),
        "capped": capped,
        "sources": sources,
    })
}
