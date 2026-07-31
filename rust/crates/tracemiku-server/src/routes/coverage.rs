//! GET /api/coverage?addr= | (so=&off=) | fn=
//!
//! Path coverage for the function containing a `(SO, offset)` coordinate: which
//! basic blocks actually executed and — the runtime fact static tools can't give
//! — for every conditional/indirect branch, WHICH WAY it went and how often.
//!
//! A static disassembler shows a branch as "both targets possible". The trace
//! collapses that ambiguity: `b.eq` at +0x40 went taken 14× / fall 0× → the
//! fall path is dead in this run. One-sided branches are flagged explicitly so
//! a reverse engineer (or AI driving IDA/BN/Ghidra) can prune the static CFG to
//! the path that actually ran.
//!
//! Note: the trace CFG contains only executed blocks, so this reports executed
//! coverage + branch bias, NOT a percentage against an unknown static total
//! (which only a static disassembler has). Pair with a disassembler's block
//! count via the shared (SO,offset) coordinate for an absolute ratio.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::resolve::parse_u64;
use crate::state::AppState;
use tracemiku_core::cfg::EdgeKind;

const MAX_BRANCHES_RETURNED: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct CoverageQuery {
    pub addr: Option<String>,
    pub so: Option<String>,
    pub off: Option<String>,
    /// Scope directly by function name (e.g. "sub_7f10") instead of a coordinate.
    #[serde(default, rename = "fn")]
    pub fn_name: String,
}

#[derive(Debug, Serialize)]
pub struct BranchTarget {
    pub coord: crate::routes::resolve::Coord,
    pub kind: String,
    pub count: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct BranchPoint {
    /// Source block end (the branch instruction's block start).
    pub block_start: String,
    pub block_offset: Option<String>,
    /// Terminator mnemonic of the block (e.g. "b.eq", "br", "cbz"), if decoded.
    pub terminator: Option<String>,
    /// True when the terminator is a conditional branch (b.cond/cbz/cbnz/tbz/tbnz).
    pub conditional: bool,
    pub total: u64,
    pub distinct_targets: usize,
    /// True when a conditional branch kept < 2 successors in the trace CFG, i.e.
    /// the not-taken direction never executed (static "both possible" collapsed).
    pub one_sided: bool,
    pub targets: Vec<BranchTarget>,
}

/// Mnemonic of the instruction at `end_pc` (the block terminator), via the
/// first record at that PC. None if the PC was never executed / not decodable.
fn terminator_mnemonic(inner: &crate::state::AppStateInner, end_pc: u64) -> Option<String> {
    let idx = inner
        .index
        .pc_to_idxs
        .get(&end_pc)
        .and_then(|v| v.first())?;
    let d = tracemiku_core::disasm::decode(end_pc, inner.trace.inst(*idx));
    Some(d.mnemonic)
}

fn resolve_fn_name(
    inner: &crate::state::AppStateInner,
    q: &CoverageQuery,
) -> Result<String, Value> {
    if !q.fn_name.is_empty() {
        return Ok(q.fn_name.clone());
    }
    let pc = if let Some(addr) = q.addr.as_ref() {
        parse_u64(addr)
            .ok_or_else(|| json!({ "status": "error", "error": format!("invalid addr: {addr}") }))?
    } else if let (Some(so), Some(off_raw)) = (q.so.as_ref(), q.off.as_ref()) {
        let off = parse_u64(off_raw).ok_or_else(
            || json!({ "status": "error", "error": format!("invalid off: {off_raw}") }),
        )?;
        let candidates = inner.modules.resolve_offset_candidates(so, off);
        match candidates.len() {
            0 => {
                return Err(json!({
                    "status": "miss",
                    "query": { "so": so, "off": format!("{off:#x}") },
                    "reason": "no loaded module matched",
                }))
            }
            1 => candidates[0].3,
            _ => {
                return Err(json!({
                    "status": "ambiguous",
                    "query": { "so": so, "off": format!("{off:#x}") },
                    "candidates": candidates
                        .iter()
                        .map(|(name, base, _e, pc)| json!({
                            "module": name, "module_base": format!("{base:#x}"), "pc": format!("{pc:#x}")
                        }))
                        .collect::<Vec<_>>(),
                }))
            }
        }
    } else {
        return Err(json!({
            "status": "error",
            "error": "provide addr=0x..., so=<name>&off=0x..., or fn=<name>",
        }));
    };
    let (name, _off) = inner.symbols.lookup(pc);
    if name.is_empty() {
        return Err(json!({
            "status": "miss",
            "query": { "pc": format!("{pc:#x}") },
            "reason": "no function contains that PC (try fn= directly)",
        }));
    }
    Ok(name)
}

pub async fn coverage_handler(
    State(state): State<AppState>,
    Query(q): Query<CoverageQuery>,
) -> Json<Value> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || coverage_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "coverage worker failed: {err}");
                json!({ "status": "error", "error": "coverage worker panicked" })
            }),
    )
}

fn coverage_response(inner: &crate::state::AppStateInner, q: CoverageQuery) -> Value {
    let fn_name = match resolve_fn_name(inner, &q) {
        Ok(n) => n,
        Err(v) => return v,
    };
    let cfg = &inner.cfg;

    // Collect this function's executed blocks.
    let mut block_count = 0usize;
    let mut total_block_execs = 0u64;
    let mut branch_points: Vec<BranchPoint> = Vec::new();
    let mut one_sided_count = 0usize;

    for b in cfg.blocks() {
        let (name, _off) = inner.symbols.lookup(b.start_pc);
        if name != fn_name {
            continue;
        }
        block_count += 1;
        total_block_execs += b.executions;

        let edges = cfg.edges_from(b.start_pc);

        // Decode the block terminator (instruction at end_pc) so we can tell a
        // conditional branch apart from a fall-through/return. In a trace CFG
        // every edge present was actually traversed (count >= 1), so the
        // one-sided signal is NOT "an edge with count 0" — it's "a CONDITIONAL
        // branch whose trace CFG has fewer than its 2 static successors", i.e.
        // the not-taken direction never ran in this trace.
        let term_mnem = terminator_mnemonic(inner, b.end_pc);
        let is_conditional = term_mnem
            .as_deref()
            .map(tracemiku_core::disasm::classify::is_conditional_branch_mnem)
            .unwrap_or(false);
        let is_indirect = edges
            .iter()
            .any(|(_, m)| matches!(m.kind, EdgeKind::IndirectDispatch { .. }));

        // Report a branch point when: multiple successors (real fork), an
        // indirect dispatch, or a conditional branch that only kept one
        // successor (the collapse we specifically want to surface).
        let is_branch = edges.len() > 1 || is_indirect || (is_conditional && !edges.is_empty());
        if !is_branch {
            continue;
        }
        let total: u64 = edges.iter().map(|(_, m)| m.count).sum();
        let targets: Vec<BranchTarget> = edges
            .iter()
            .map(|(dst, m)| BranchTarget {
                coord: crate::routes::resolve::coord_for_pc(inner, *dst),
                kind: m.kind.label(),
                count: m.count,
                percent: if total > 0 {
                    (m.count as f64) * 100.0 / (total as f64)
                } else {
                    0.0
                },
            })
            .collect();
        // A conditional branch statically has 2 successors (taken + fall). If
        // the trace kept fewer than 2, the missing direction never executed.
        let one_sided = is_conditional && targets.len() < 2;
        if one_sided {
            one_sided_count += 1;
        }
        let (_n, boff) = inner
            .modules
            .resolve_relative(b.start_pc)
            .map(|(n, o)| (n, Some(format!("{o:#x}"))))
            .unwrap_or_default();
        branch_points.push(BranchPoint {
            block_start: format!("{:#x}", b.start_pc),
            block_offset: boff,
            terminator: term_mnem,
            conditional: is_conditional,
            total,
            distinct_targets: targets.len(),
            one_sided,
            targets,
        });
    }

    if block_count == 0 {
        return json!({
            "status": "miss",
            "function": fn_name,
            "reason": "no executed blocks resolve to this function",
        });
    }

    // Deterministic order: primary = execution count desc, tie-break = block
    // offset asc. Without the tie-break, equal-total branches reorder between
    // runs and break CLI/web parity (both surfaces must agree byte-for-byte).
    branch_points.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.block_offset.cmp(&b.block_offset))
    });
    let total_branches = branch_points.len();
    let capped = total_branches > MAX_BRANCHES_RETURNED;
    branch_points.truncate(MAX_BRANCHES_RETURNED);

    json!({
        "status": "ok",
        "function": fn_name,
        "executed_blocks": block_count,
        "total_block_executions": total_block_execs,
        "branch_points": total_branches,
        "one_sided_branches": one_sided_count,
        "branches_returned": branch_points.len(),
        "branches_capped": capped,
        "branches": branch_points,
        "note": "executed blocks only; trace CFG has no never-run blocks. one_sided=branch with a single real target (static 'both possible' collapsed).",
    })
}
