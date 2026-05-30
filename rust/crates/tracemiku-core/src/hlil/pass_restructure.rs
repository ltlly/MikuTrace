//! HLIL restructure pass.
//!
//! Transforms flat goto-based HLIL into structured control flow with
//! If/Else, While, and DoWhile expressions.
//!
//! Algorithm:
//!   1. Build CFG from flat HLIL (basic blocks with succ/pred edges)
//!   2. Compute dominators for natural loop detection
//!   3. Walk blocks in dominance-frontier order; for each block:
//!      a. If the block is a loop header, emit While/DoWhile
//!      b. Else if the block ends with If and both branches converge,
//!         emit If/Else
//!      c. Else if the block ends with If, emit If-then (no else)
//!      d. Otherwise emit flat (inline Labels/Gotos as needed)

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::hlil::expr::{
    HlilExpr, HlilOp, HlilOperand,
    block as hlil_block, if_else as hlil_if_else,
    while_loop as hlil_while_loop, do_while as hlil_do_while,
    break_ as hlil_break, continue_ as hlil_continue,
};

const MAX_RESTRUCTURE_RECURSION: usize = 256;

thread_local! {
    static RESTRUCTURE_DEPTH: Cell<usize> = const { Cell::new(0) };
}

// ============================================================================
// Block type for internal CFG construction
// ============================================================================

#[derive(Debug, Clone)]
struct Block {
    id: usize,
    /// Effective PC used as key for jump-target lookups.
    start_pc: u64,
    /// Flat HLIL expressions in this block (includes Label at entry).
    exprs: Vec<HlilExpr>,
    /// Predecessor block IDs.
    preds: Vec<usize>,
    /// Successor block IDs.
    succs: Vec<usize>,
}

impl Block {
    fn last(&self) -> Option<&HlilExpr> {
        self.exprs.last()
    }

    fn ends_with_op(&self, op: HlilOp) -> bool {
        self.last().map(|e| e.op == op).unwrap_or(false)
    }

    fn goto_target(&self) -> Option<u64> {
        let last = self.last()?;
        if last.op != HlilOp::Goto {
            return None;
        }
        match last.operands.first() {
            Some(HlilOperand::U64(v)) => Some(*v),
            _ => None,
        }
    }

    /// Extract (cond, true_target_pc, false_target_pc) from an If-ending block.
    fn if_targets(&self) -> Option<(HlilExpr, u64, u64)> {
        let last = self.last()?;
        if last.op != HlilOp::If {
            return None;
        }
        let cond = match &last.operands[0] {
            HlilOperand::Expr(e) => (**e).clone(),
            _ => return None,
        };
        let true_pc = extract_goto_target(&last.operands[1])?;
        let false_pc = extract_goto_target(last.operands.get(2)?)?;
        Some((cond, true_pc, false_pc))
    }
}

fn extract_goto_target(op: &HlilOperand) -> Option<u64> {
    match op {
        HlilOperand::Expr(e) if e.op == HlilOp::Goto => {
            match e.operands.first() {
                Some(HlilOperand::U64(v)) => Some(*v),
                _ => None,
            }
        }
        _ => None,
    }
}

// ============================================================================
// Terminator detection
// ============================================================================

fn is_terminator(op: HlilOp) -> bool {
    matches!(
        op,
        HlilOp::Goto
            | HlilOp::If
            | HlilOp::Ret
            | HlilOp::Jump
            | HlilOp::Tailcall
            | HlilOp::Noret
    )
}

// ============================================================================
// CFG construction
// ============================================================================

fn build_cfg(exprs: &[HlilExpr]) -> Vec<Block> {
    if exprs.is_empty() {
        return vec![];
    }

    let n = exprs.len();

    // Find block start leaders
    let mut leader = vec![false; n];
    leader[0] = true;

    for (i, e) in exprs.iter().enumerate() {
        match e.op {
            HlilOp::Goto | HlilOp::If | HlilOp::Jump | HlilOp::Ret | HlilOp::Tailcall | HlilOp::Noret => {
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            HlilOp::Label => {
                leader[i] = true;
            }
            _ => {}
        }
    }

    // Split into blocks
    let mut blocks = Vec::new();
    let mut start = 0;
    for end in 1..=n {
        if end == n || leader[end] {
            let block_exprs: Vec<HlilExpr> = exprs[start..end].to_vec();
            let start_pc = block_exprs
                .first()
                .map(|e| e.pc)
                .unwrap_or(0);
            blocks.push(Block {
                id: blocks.len(),
                start_pc,
                exprs: block_exprs,
                preds: Vec::new(),
                succs: Vec::new(),
            });
            start = end;
        }
    }

    // Build PC → block map (use first expression's PC, or Label's PC if first is Label)
    let pc_to_block = build_pc_to_block(&blocks);

    // Resolve successors
    for i in 0..blocks.len() {
        let mut succs = Vec::new();
        if let Some(last) = blocks[i].last() {
            match last.op {
                HlilOp::Goto => {
                    if let Some(target) = blocks[i].goto_target() {
                        if let Some(&bid) = pc_to_block.get(&target) {
                            succs.push(bid);
                        }
                    }
                }
                HlilOp::If => {
                    if let Some((_, true_pc, false_pc)) = blocks[i].if_targets() {
                        if let Some(&bid) = pc_to_block.get(&true_pc) {
                            if !succs.contains(&bid) {
                                succs.push(bid);
                            }
                        }
                        if let Some(&bid) = pc_to_block.get(&false_pc) {
                            if !succs.contains(&bid) {
                                succs.push(bid);
                            }
                        }
                    }
                }
                HlilOp::Ret | HlilOp::Tailcall | HlilOp::Noret | HlilOp::Jump => {}
                _ => {
                    // Fallthrough to next sequential block
                    if i + 1 < blocks.len() {
                        succs.push(i + 1);
                    }
                }
            }
        }
        blocks[i].succs = succs;
    }

    // Build predecessor lists
    let mut preds_list: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for i in 0..blocks.len() {
        for &s in &blocks[i].succs {
            if s < blocks.len() {
                preds_list[s].push(i);
            }
        }
    }
    for (i, p) in preds_list.into_iter().enumerate() {
        blocks[i].preds = p;
    }

    blocks
}

/// Build a map from block entry PC to block ID.
/// Uses the Label's PC if the block starts with one.
fn build_pc_to_block(blocks: &[Block]) -> BTreeMap<u64, usize> {
    let mut map = BTreeMap::new();
    for b in blocks {
        if let Some(first) = b.exprs.first() {
            map.insert(first.pc, b.id);
        }
    }
    map
}

// ============================================================================
// Dominator computation (iterative)
// ============================================================================

fn compute_dominators(blocks: &[Block]) -> Vec<BTreeSet<usize>> {
    let n = blocks.len();
    if n == 0 {
        return vec![];
    }
    let entry = 0;
    let mut doms: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    doms[entry].insert(entry);
    for i in 1..n {
        doms[i] = (0..n).collect();
    }

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if i == entry {
                continue;
            }
            let mut new_dom: Option<BTreeSet<usize>> = None;
            for &pred in &blocks[i].preds {
                if pred < n {
                    new_dom = Some(match new_dom {
                        None => doms[pred].clone(),
                        Some(s) => s.intersection(&doms[pred]).copied().collect(),
                    });
                }
            }
            let mut new_dom = new_dom.unwrap_or_default();
            new_dom.insert(i);
            if new_dom != doms[i] {
                doms[i] = new_dom;
                changed = true;
            }
        }
    }
    doms
}

// ============================================================================
// Natural loop detection
// ============================================================================

/// Find back edges: (tail, header) where tail → header and header dominates tail.
fn find_back_edges(blocks: &[Block], doms: &[BTreeSet<usize>]) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        for &succ in &block.succs {
            if succ < doms.len() && doms[i].contains(&succ) {
                edges.push((i, succ));
            }
        }
    }
    edges
}

/// Collect loop body blocks reachable from header without re-entering it.
fn collect_loop_body(blocks: &[Block], header: usize, tail: usize) -> Vec<usize> {
    let mut body = BTreeSet::new();
    body.insert(header);

    // Walk predecessors backwards from tail until hitting header
    let mut stack = vec![tail];
    let mut visited = BTreeSet::new();
    visited.insert(header);
    while let Some(b) = stack.pop() {
        if visited.contains(&b) {
            continue;
        }
        visited.insert(b);
        body.insert(b);
        for &pred in &blocks[b].preds {
            if !visited.contains(&pred) {
                stack.push(pred);
            }
        }
    }

    let mut body_vec: Vec<usize> = body.into_iter().collect();
    body_vec.sort();
    body_vec
}

/// Merge overlapping loops into a single loop group.
fn merge_loop_groups(loops: Vec<(usize, Vec<usize>)>) -> Vec<(usize, Vec<usize>)> {
    let mut merged: Vec<(usize, Vec<usize>)> = Vec::new();
    for (hdr, body) in loops {
        let mut combined = body;
        merged.retain(|(eh, eb)| {
            if combined.contains(eh) || eh == &hdr {
                // Merge this loop into combined
                for &b in eb {
                    if !combined.contains(&b) {
                        combined.push(b);
                    }
                }
                combined.sort();
                false // remove the merged entry
            } else {
                true
            }
        });
        merged.push((hdr, combined));
    }
    merged
}

fn find_loop_groups(blocks: &[Block], back_edges: &[(usize, usize)]) -> Vec<(usize, Vec<usize>)> {
    let raw: Vec<(usize, Vec<usize>)> = back_edges
        .iter()
        .map(|&(tail, header)| {
            let body = collect_loop_body(blocks, header, tail);
            (header, body)
        })
        .collect();
    merge_loop_groups(raw)
}

// ============================================================================
// Loop classification
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopKind {
    While,
    DoWhile,
}

/// Classify a natural loop.
///
/// - While: header block ends with an If, and the body contains a separate
///   latch block that branches back to the header.
/// - DoWhile: the header is a self-loop (body == [header]) and the header
///   ends with an If whose true_target is the header itself; OR the loop
///   has multiple blocks but the header does NOT end with an If, meaning
///   the condition is at the latch (bottom of the loop).
fn classify_loop(blocks: &[Block], header: usize, body: &[usize]) -> LoopKind {
    let header_block = &blocks[header];
    let is_if_header = header_block.ends_with_op(HlilOp::If);
    let is_self_loop = body.len() == 1;

    if is_self_loop && is_if_header {
        // Self-loop with If at bottom → do-while
        LoopKind::DoWhile
    } else if is_if_header {
        // If at top → while
        LoopKind::While
    } else {
        // No If at top → do-while (condition is at the tail/latch block)
        LoopKind::DoWhile
    }
}

// ============================================================================
// Body expression collection helpers
// ============================================================================

/// Collect expressions from a block for use inside a structured body.
/// Skips the leading Label (implicit in structure) and skips a trailing
/// Goto or If (flow is implicit in the structure).
fn collect_block_body(block: &Block) -> Vec<HlilExpr> {
    collect_block_body_with_loop_flow(block, None, None)
}

fn collect_loop_block_body(block: &Block, header_pc: u64, exit_pc: Option<u64>) -> Vec<HlilExpr> {
    collect_block_body_with_loop_flow(block, Some(header_pc), exit_pc)
}

fn collect_block_body_with_loop_flow(
    block: &Block,
    loop_header_pc: Option<u64>,
    loop_exit_pc: Option<u64>,
) -> Vec<HlilExpr> {
    let mut out = Vec::new();
    for (i, e) in block.exprs.iter().enumerate() {
        // Skip leading Label
        if i == 0 && e.op == HlilOp::Label {
            continue;
        }
        // Skip trailing Goto (back edge or branch to merge). A single-edge
        // block produced from an inner branch remains visible as break/continue
        // when it targets the current loop boundary.
        if i == block.exprs.len() - 1 && e.op == HlilOp::Goto {
            let target = match e.operands.first() {
                Some(HlilOperand::U64(v)) => Some(*v),
                _ => None,
            };
            let single_edge_block = block.exprs.len() <= 2;
            if single_edge_block && loop_header_pc.is_some() && target == loop_header_pc {
                out.push(hlil_continue(e.pc));
            } else if single_edge_block && loop_exit_pc.is_some() && target == loop_exit_pc {
                out.push(hlil_break(e.pc));
            }
            continue;
        }
        // Skip trailing If (do-while condition at bottom), unless it is an
        // inner loop-control branch that should become break/continue.
        if i == block.exprs.len() - 1 && e.op == HlilOp::If {
            if let Some(header_pc) = loop_header_pc {
                if let Some(rewritten) = rewrite_loop_control_if(e, header_pc, loop_exit_pc) {
                    out.push(rewritten);
                }
            }
            continue;
        }
        out.push(e.clone());
    }
    out
}

/// Collect expressions from all body blocks, flattening into a single vec.
/// Skips leading Labels and trailing Gotos/Ifs from each block.
#[allow(dead_code)]
fn collect_body_from_blocks(block_ids: &[usize], blocks: &[Block]) -> Vec<HlilExpr> {
    let mut out = Vec::new();
    for &bid in block_ids {
        let b = &blocks[bid];
        let mut body = collect_block_body(b);
        out.append(&mut body);
    }
    out
}

/// Strip the very last trailing Goto from an expression list (if present).
#[allow(dead_code)]
fn strip_trailing_goto(exprs: &mut Vec<HlilExpr>) {
    if exprs.last().map(|e| e.op == HlilOp::Goto).unwrap_or(false) {
        exprs.pop();
    }
}

/// Rewrite explicit loop-edge gotos inside a structured loop body.
///
/// Gotos to the loop header are semantic `continue`; gotos to the loop exit are
/// semantic `break`. Other gotos are preserved as fallback control flow.
fn normalize_loop_body_flow(exprs: &mut [HlilExpr], header_pc: u64, exit_pc: Option<u64>) {
    for e in exprs {
        if e.op == HlilOp::Goto {
            let target = match e.operands.first() {
                Some(HlilOperand::U64(v)) => Some(*v),
                _ => None,
            };
            if target == Some(header_pc) {
                *e = hlil_continue(e.pc);
            } else if target == exit_pc {
                *e = hlil_break(e.pc);
            }
            continue;
        }
        for op in &mut e.operands {
            if let HlilOperand::Expr(child) = op {
                normalize_loop_body_flow(std::slice::from_mut(child.as_mut()), header_pc, exit_pc);
            }
        }
    }
}

fn rewrite_loop_control_if(e: &HlilExpr, header_pc: u64, exit_pc: Option<u64>) -> Option<HlilExpr> {
    if e.op != HlilOp::If {
        return None;
    }
    let cond = match e.operands.first() {
        Some(HlilOperand::Expr(cond)) => (**cond).clone(),
        _ => return None,
    };
    let (then_body, then_changed) = rewrite_loop_branch(e.operands.get(1), header_pc, exit_pc, e.pc);
    let (else_body, else_changed) = rewrite_loop_branch(e.operands.get(2), header_pc, exit_pc, e.pc);
    if !then_changed && !else_changed {
        return None;
    }
    Some(hlil_if_else(
        cond,
        then_body.unwrap_or_else(|| hlil_block(Vec::new(), e.pc)),
        else_body,
        e.pc,
    ))
}

fn rewrite_loop_branch(
    op: Option<&HlilOperand>,
    header_pc: u64,
    exit_pc: Option<u64>,
    pc: u64,
) -> (Option<HlilExpr>, bool) {
    let Some(op) = op else {
        return (None, false);
    };
    if let Some(target) = extract_goto_target(op) {
        if target == header_pc {
            return (Some(hlil_continue(pc)), true);
        }
        if Some(target) == exit_pc {
            return (Some(hlil_break(pc)), true);
        }
        return (None, false);
    }
    if let HlilOperand::Expr(expr) = op {
        let mut out = (**expr).clone();
        normalize_loop_body_flow(std::slice::from_mut(&mut out), header_pc, exit_pc);
        return (Some(out), false);
    }
    (None, false)
}

// ============================================================================
// Main restructuring entry point
// ============================================================================

/// Restructure flat goto-based HLIL into structured HLIL with If/Else,
/// While, and DoWhile expressions.
pub fn restructure_hlil(exprs: &[HlilExpr]) -> Vec<HlilExpr> {
    // Defensive: ensure the recursion counter starts clean for this top-level call.
    RESTRUCTURE_DEPTH.with(|d| d.set(0));
    let blocks = build_cfg(exprs);
    if blocks.len() <= 1 {
        return exprs.to_vec();
    }

    let doms = compute_dominators(&blocks);
    let back_edges = find_back_edges(&blocks, &doms);
    let loops = find_loop_groups(&blocks, &back_edges);

    let loop_header_set: BTreeSet<usize> = loops.iter().map(|(h, _)| *h).collect();
    let pc_to_block = build_pc_to_block(&blocks);

    let mut visited = vec![false; blocks.len()];
    let mut result = Vec::new();

    walk_region(
        0,
        &blocks,
        &loop_header_set,
        &loops,
        &pc_to_block,
        &mut visited,
        &mut result,
    );

    result
}

// ============================================================================
// Region walker — recursive block traversal with pattern detection
// ============================================================================

fn walk_region(
    current: usize,
    blocks: &[Block],
    loop_header_set: &BTreeSet<usize>,
    loops: &[(usize, Vec<usize>)],
    pc_to_block: &BTreeMap<u64, usize>,
    visited: &mut [bool],
    out: &mut Vec<HlilExpr>,
) {
    let depth_ok = RESTRUCTURE_DEPTH.with(|d| {
        let depth = d.get();
        if depth >= MAX_RESTRUCTURE_RECURSION {
            false
        } else {
            d.set(depth + 1);
            true
        }
    });
    if !depth_ok {
        if current < blocks.len() {
            for e in &blocks[current].exprs {
                out.push(e.clone());
            }
            visited[current] = true;
        }
        return;
    }

    struct DepthGuard;
    impl Drop for DepthGuard {
        fn drop(&mut self) {
            RESTRUCTURE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }
    let _guard = DepthGuard;

    if current >= blocks.len() || visited[current] {
        return;
    }

    // ---- 1. Loop handling (check before If-else, since loop headers are If blocks) ----
    if loop_header_set.contains(&current) {
        if let Some((_, body_bids)) = loops.iter().find(|(h, _)| *h == current) {
            // Mark ALL body blocks as visited so they aren't re-emitted later.
            let mut body_set: BTreeSet<usize> = body_bids.iter().copied().collect();
            // Also collect transitively-reachable blocks within the loop body
            // that may not be in body_bids but are still part of the loop.
            for b in body_bids.iter().copied().collect::<Vec<_>>() {
                let mut stack = vec![b];
                while let Some(bid) = stack.pop() {
                    if bid >= blocks.len() || body_set.contains(&bid) {
                        continue;
                    }
                    body_set.insert(bid);
                    for &s in &blocks[bid].succs {
                        if !body_set.contains(&s) {
                            stack.push(s);
                        }
                    }
                }
            }

            let kind = classify_loop(blocks, current, body_bids);
            let header = &blocks[current];

            match kind {
                LoopKind::While => {
                    // While loop: header ends with If(cond, body_pc, exit_pc).
                    // The body blocks execute and branch back to the header.
                    if let Some((cond, body_pc, exit_pc)) = header.if_targets() {
                        // Collect body block IDs
                        let mut body_block_ids = Vec::new();
                        if let Some(&body_bid) = pc_to_block.get(&body_pc) {
                            // Walk forward from body_bid until we hit the header or exit
                            let mut seen = BTreeSet::new();
                            let mut stack = vec![body_bid];
                            while let Some(bid) = stack.pop() {
                                if bid == current || seen.contains(&bid) || bid >= blocks.len() {
                                    continue;
                                }
                                seen.insert(bid);
                                body_block_ids.push(bid);
                                for &s in &blocks[bid].succs {
                                    if body_bids.contains(&s) && s != current && !seen.contains(&s) {
                                        stack.push(s);
                                    }
                                }
                            }
                        }

                        // Collect body expressions from all body blocks.
                        // Back-edges and loop exits stay visible as
                        // continue/break when they occur in nested branches.
                        let mut body_exprs = Vec::new();
                        for &bid in &body_block_ids {
                            let mut blk_exprs =
                                collect_loop_block_body(&blocks[bid], header.start_pc, Some(exit_pc));
                            body_exprs.append(&mut blk_exprs);
                        }
                        normalize_loop_body_flow(&mut body_exprs, header.start_pc, Some(exit_pc));

                        out.push(hlil_while_loop(
                            cond,
                            hlil_block(body_exprs, header.start_pc),
                            header.start_pc,
                        ));

                        // Mark body blocks as visited
                        for &bid in &body_block_ids {
                            if bid < visited.len() {
                                visited[bid] = true;
                            }
                        }
                        visited[current] = true;

                        // Continue with exit block
                        if let Some(&exit_bid) = pc_to_block.get(&exit_pc) {
                            walk_region(
                                exit_bid,
                                blocks,
                                loop_header_set,
                                loops,
                                pc_to_block,
                                visited,
                                out,
                            );
                        }
                        return;
                    }
                }
                LoopKind::DoWhile => {
                    if let Some((cond, back_pc, exit_pc)) = header.if_targets() {
                        if back_pc == header.start_pc {
                            // Self-loop: the header IS the body.
                            // Collect header body (excluding the trailing If).
                            let mut body_exprs =
                                collect_loop_block_body(header, header.start_pc, Some(exit_pc));

                            // Also collect any other body blocks reachable from header
                            // that aren't the header or exit.
                            let mut extra_block_ids = Vec::new();
                            for &bid in body_bids {
                                if bid != current {
                                    extra_block_ids.push(bid);
                                }
                            }
                            for &bid in &extra_block_ids {
                                let mut blk_exprs =
                                    collect_loop_block_body(&blocks[bid], header.start_pc, Some(exit_pc));
                                body_exprs.append(&mut blk_exprs);
                            }
                            normalize_loop_body_flow(&mut body_exprs, header.start_pc, Some(exit_pc));

                            out.push(hlil_do_while(
                                hlil_block(body_exprs, header.start_pc),
                                cond,
                                header.start_pc,
                            ));

                            // Mark body blocks as visited
                            for &bid in body_bids {
                                if bid < visited.len() {
                                    visited[bid] = true;
                                }
                            }

                            // Continue with exit
                            if let Some(&exit_bid) = pc_to_block.get(&exit_pc) {
                                walk_region(
                                    exit_bid,
                                    blocks,
                                    loop_header_set,
                                    loops,
                                    pc_to_block,
                                    visited,
                                    out,
                                );
                            }
                            return;
                        }
                    }

                    // Do-while where the header doesn't end with If:
                    // The body spans multiple blocks, condition is at the latch.
                    // Collect all body blocks and find the latch.
                    let mut body_block_ids: Vec<usize> = body_bids
                        .iter()
                        .copied()
                        .filter(|&b| b != current && b < blocks.len())
                        .collect();
                    body_block_ids.sort();

                    let mut body_exprs = Vec::new();
                    for &bid in &body_block_ids {
                        let mut blk_exprs = collect_loop_block_body(&blocks[bid], header.start_pc, None);
                        body_exprs.append(&mut blk_exprs);
                    }

                    // Try to extract condition from the last body block (latch)
                    if let Some(&latch_bid) = body_block_ids.last() {
                        if let Some((cond, _true_pc, _exit_pc)) = blocks[latch_bid].if_targets() {
                            // Remove the If's condition from collected body (it's the
                            // bottom-of-loop test).
                            // The body already has the latch block content minus the If
                            // (collect_block_body skips trailing If).
                            // Prepend the header's non-If body
                            let mut full_body = collect_loop_block_body(header, header.start_pc, Some(_exit_pc));
                            full_body.append(&mut body_exprs);
                            normalize_loop_body_flow(&mut full_body, header.start_pc, Some(_exit_pc));

                            out.push(hlil_do_while(
                                hlil_block(full_body, header.start_pc),
                                cond,
                                header.start_pc,
                            ));

                            for &bid in body_bids {
                                if bid < visited.len() {
                                    visited[bid] = true;
                                }
                            }

                            // Continue with exit
                            if let Some(&exit_bid) = pc_to_block.get(&_exit_pc) {
                                walk_region(
                                    exit_bid,
                                    blocks,
                                    loop_header_set,
                                    loops,
                                    pc_to_block,
                                    visited,
                                    out,
                                );
                            }
                            return;
                        }
                    }

                    // Fall through if we can't classify the do-while
                }
            }
        }
    }

    // ---- 2. If-else or If-then detection ----
    if blocks[current].ends_with_op(HlilOp::If) {
        if let Some((cond, true_pc, false_pc)) = blocks[current].if_targets() {
            let true_bid = pc_to_block.get(&true_pc).copied();
            let false_bid = pc_to_block.get(&false_pc).copied();

            // Check if both branches converge to a common merge block.
            let convergence = check_convergence(true_bid, false_bid, blocks);

            if let Some(merge_bid) = convergence {
                // If-else with both branches converging to merge.
                let mut then_exprs = Vec::new();
                let mut else_exprs = Vec::new();

                // Collect true branch expressions
                if let Some(tb) = true_bid {
                    collect_region_between(tb, Some(merge_bid), blocks, &mut then_exprs, visited, loop_header_set, loops, pc_to_block);
                }
                // Collect false branch expressions
                if let Some(fb) = false_bid {
                    collect_region_between(fb, Some(merge_bid), blocks, &mut else_exprs, visited, loop_header_set, loops, pc_to_block);
                }

                out.push(hlil_if_else(
                    cond,
                    hlil_block(then_exprs, blocks[current].start_pc),
                    Some(hlil_block(else_exprs, blocks[current].start_pc)),
                    blocks[current].start_pc,
                ));

                // Mark branch blocks as visited
                mark_region_visited(true_bid, Some(merge_bid), blocks, visited);
                mark_region_visited(false_bid, Some(merge_bid), blocks, visited);
                visited[current] = true;

                // Continue from merge
                if !visited[merge_bid] {
                    walk_region(
                        merge_bid,
                        blocks,
                        loop_header_set,
                        loops,
                        pc_to_block,
                        visited,
                        out,
                    );
                }
                return;
            } else {
                // If-then (no else): emit if with a single block body.
                // The false target acts as the merge point, so the then body
                // stops before it.
                let mut then_exprs = Vec::new();
                if let Some(tb) = true_bid {
                    collect_region_between(tb, false_bid, blocks, &mut then_exprs, visited, loop_header_set, loops, pc_to_block);
                }

                out.push(hlil_if_else(
                    cond,
                    hlil_block(then_exprs, blocks[current].start_pc),
                    None,
                    blocks[current].start_pc,
                ));

                if let Some(tb) = true_bid {
                    mark_region_visited(Some(tb), false_bid, blocks, visited);
                }
                visited[current] = true;

                // Continue with false target (the "else" path, flat)
                if let Some(fb) = false_bid {
                    walk_region(
                        fb,
                        blocks,
                        loop_header_set,
                        loops,
                        pc_to_block,
                        visited,
                        out,
                    );
                }
                return;
            }
        }
    }

    // ---- 3. Flat emission (labels + assignments + calls + gotos) ----
    for e in &blocks[current].exprs {
        out.push(e.clone());
    }
    visited[current] = true;

    // Follow fallthrough to successor
    let block = &blocks[current];
    let last_op = block.last().map(|e| e.op).unwrap_or(HlilOp::Nop);
    if !is_terminator(last_op) {
        // Fallthrough to next block
        if current + 1 < blocks.len() && !visited[current + 1] {
            walk_region(
                current + 1,
                blocks,
                loop_header_set,
                loops,
                pc_to_block,
                visited,
                out,
            );
        }
    } else if last_op == HlilOp::Goto {
        // Follow unconditional goto to its target
        if let Some(target_pc) = block.goto_target() {
            if let Some(&target_bid) = pc_to_block.get(&target_pc) {
                if !visited[target_bid] {
                    walk_region(
                        target_bid,
                        blocks,
                        loop_header_set,
                        loops,
                        pc_to_block,
                        visited,
                        out,
                    );
                }
            }
        }
    }
}

// ============================================================================
// Convergence / region helpers
// ============================================================================

/// Check if two blocks converge to a common successor (merge block).
/// Returns Some(merge_bid) if they do, None otherwise.
fn check_convergence(
    true_bid: Option<usize>,
    false_bid: Option<usize>,
    blocks: &[Block],
) -> Option<usize> {
    match (true_bid, false_bid) {
        (Some(tb), Some(fb)) => {
            let true_succs: BTreeSet<usize> = blocks[tb].succs.iter().copied().collect();
            let false_succs: BTreeSet<usize> = blocks[fb].succs.iter().copied().collect();
            true_succs.intersection(&false_succs).next().copied()
        }
        _ => None,
    }
}

/// Collect expressions from a region [start, stop) of blocks, stopping
/// before the stop block. Recursively detects nested structures.
fn collect_region_between(
    start: usize,
    stop: Option<usize>,
    blocks: &[Block],
    out: &mut Vec<HlilExpr>,
    visited: &mut [bool],
    loop_header_set: &BTreeSet<usize>,
    loops: &[(usize, Vec<usize>)],
    pc_to_block: &BTreeMap<u64, usize>,
) {
    let mut bid = start;
    while bid < blocks.len() && Some(bid) != stop && !visited[bid] {
        let block = &blocks[bid];

        // Check for nested structures at this block
        if loop_header_set.contains(&bid) {
            // Nested loop — recurse via walk_region
            let _before = out.len();
            let mut tmp = Vec::new();
            walk_region(bid, blocks, loop_header_set, loops, pc_to_block, visited, &mut tmp);
            out.extend(tmp);
            // After walk_region, bid may have been marked visited. Skip to next.
            // Find the next unvisited block
            bid = find_next_unvisited(bid + 1, visited, blocks.len());
            if bid >= blocks.len() || Some(bid) == stop {
                break;
            }
            continue;
        }

        if block.ends_with_op(HlilOp::If) {
            // Nested if-else — recurse via walk_region
            let _before = out.len();
            let mut tmp = Vec::new();
            walk_region(bid, blocks, loop_header_set, loops, pc_to_block, visited, &mut tmp);
            out.extend(tmp);
            // Find the next unvisited block beyond whatever was consumed
            bid = find_next_unvisited(bid + 1, visited, blocks.len());
            if bid >= blocks.len() || Some(bid) == stop {
                break;
            }
            continue;
        }

        // Emit flat, skipping the leading Label and trailing Goto as needed
        let mut collected = Vec::new();
        for (i, e) in block.exprs.iter().enumerate() {
            if i == 0 && e.op == HlilOp::Label {
                continue; // implicit in structure
            }
            if i == block.exprs.len() - 1 && e.op == HlilOp::Goto {
                // The trailing Goto goes to the stop or merge block; skip it
                continue;
            }
            collected.push(e.clone());
        }
        out.extend(collected);

        visited[bid] = true;

        // Determine the next block to visit
        if is_terminator(block.last().map(|e| e.op).unwrap_or(HlilOp::Nop)) {
            // If this is a Goto targeting the merge/stop, we're done with the region
            if let Some(target) = block.goto_target() {
                if let Some(&target_bid) = pc_to_block.get(&target) {
                    if Some(target_bid) == stop {
                        break;
                    }
                }
            }
            break;
        }

        bid += 1;
        if bid >= blocks.len() || Some(bid) == stop {
            break;
        }
    }
}

/// Find the next unvisited block starting from `start`, stopping before `stop`.
fn find_next_unvisited(
    start: usize,
    visited: &[bool],
    max: usize,
) -> usize {
    let mut bid = start;
    while bid < max && visited[bid] {
        bid += 1;
    }
    bid
}

/// Mark all blocks in the region [start, stop) as visited.
fn mark_region_visited(
    start: Option<usize>,
    stop: Option<usize>,
    blocks: &[Block],
    visited: &mut [bool],
) {
    let Some(start) = start else { return };
    let mut bid = start;
    while bid < blocks.len() && Some(bid) != stop {
        visited[bid] = true;
        let block = &blocks[bid];
        if is_terminator(block.last().map(|e| e.op).unwrap_or(HlilOp::Nop)) {
            break;
        }
        bid += 1;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use crate::hlil::expr::{
        assign, binary, goto, if_else, konst,
        label, ret, var, HlilOp,
    };
    use crate::hlil::render::render_hlil;

    use super::*;

    // -----------------------------------------------------------------------
    // Test: If-else with convergence
    // -----------------------------------------------------------------------
    #[test]
    fn restructures_if_else() {
        // Flat HLIL:
        //   0x1000: if (cond) { goto 0x1010; } else { goto 0x1020; }
        //   0x1010: loc_1010: v1 = 1; goto 0x1030;
        //   0x1020: loc_1020: v2 = 2; goto 0x1030;
        //   0x1030: loc_1030: return;
        let cond = binary(HlilOp::CmpE, var("x"), konst(0));
        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1020, 0x1020)), 0x1000),
            label("loc_1010", 0x1010),
            assign(var("v1"), konst(1), 0x1010),
            goto(0x1030, 0x1018),
            label("loc_1020", 0x1020),
            assign(var("v2"), konst(2), 0x1020),
            goto(0x1030, 0x1028),
            label("loc_1030", 0x1030),
            ret(0x1030),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        // Should have if-else structure
        assert!(rendered.contains("if ("), "expected if in: {rendered}");
        assert!(rendered.contains("v1 = 1;"), "expected v1=1 in: {rendered}");
        assert!(rendered.contains("v2 = 2;"), "expected v2=2 in: {rendered}");
        assert!(rendered.contains("return;"), "expected return in: {rendered}");
        // Should NOT contain gotos (the gotos were merged into structure)
        assert!(
            !rendered.contains("goto loc_1010"),
            "unexpected goto: {rendered}"
        );
        assert!(
            !rendered.contains("goto loc_1020"),
            "unexpected goto: {rendered}"
        );
        assert!(
            !rendered.contains("goto loc_1030"),
            "unexpected goto: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Simple if-then (no else)
    // -----------------------------------------------------------------------
    #[test]
    fn restructures_if_then() {
        // Flat HLIL:
        //   0x1000: if (cond) { goto 0x1010; } else { goto 0x1020; }
        //   0x1010: loc_1010: v1 = 1; goto 0x1020;
        //   0x1020: loc_1020: return;
        let cond = binary(HlilOp::CmpE, var("x"), konst(0));
        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1020, 0x1020)), 0x1000),
            label("loc_1010", 0x1010),
            assign(var("v1"), konst(1), 0x1010),
            goto(0x1020, 0x1018),
            label("loc_1020", 0x1020),
            ret(0x1020),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(rendered.contains("if ("), "expected if in: {rendered}");
        assert!(rendered.contains("v1 = 1;"), "expected v1=1 in: {rendered}");
        assert!(rendered.contains("return;"), "expected return in: {rendered}");
        assert!(
            !rendered.contains("goto loc_1010"),
            "unexpected goto: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: While loop
    // -----------------------------------------------------------------------
    #[test]
    fn restructures_while_loop() {
        // Flat HLIL mimicking a while(i < 10) { ... } pattern:
        //   0x1000: if (i < 10) { goto 0x1010; } else { goto 0x1030; }
        //   0x1010: loc_1010: do_work(i); i = i + 1; goto 0x1000;
        //   0x1030: loc_1030: return;
        let cond = binary(HlilOp::CmpUlt, var("i"), konst(10));
        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1030, 0x1030)), 0x1000),
            label("loc_1010", 0x1010),
            assign(var("tmp"), konst(1), 0x1010),
            assign(
                var("i"),
                binary(HlilOp::Add, var("i"), konst(1)),
                0x1014,
            ),
            goto(0x1000, 0x1018),
            label("loc_1030", 0x1030),
            ret(0x1030),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(
            rendered.contains("while ("),
            "expected while loop in: {rendered}"
        );
        assert!(
            rendered.contains("i = (i + 1);"),
            "expected body in: {rendered}"
        );
        assert!(rendered.contains("return;"), "expected return in: {rendered}");
        assert!(
            !rendered.contains("goto loc_1000"),
            "unexpected back-edge goto: {rendered}"
        );
        // There should be NO gotos in the while loop output
        assert!(
            !rendered.contains("goto"),
            "expected no gotos: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Do-while loop (self-loop)
    // -----------------------------------------------------------------------
    #[test]
    fn restructures_do_while_self_loop() {
        // Flat HLIL mimicking a do { ... } while(cond) pattern:
        //   0x1000: loc_1000: do_work(i); i = i + 1; if (i < 10) { goto 0x1000; } else { goto 0x1020; }
        //   0x1020: loc_1020: return;
        let cond = binary(HlilOp::CmpUlt, var("i"), konst(10));
        let flat: Vec<HlilExpr> = vec![
            label("loc_1000", 0x1000),
            assign(var("tmp"), konst(1), 0x1000),
            assign(
                var("i"),
                binary(HlilOp::Add, var("i"), konst(1)),
                0x1004,
            ),
            if_else(cond.clone(), goto(0x1000, 0x1000), Some(goto(0x1020, 0x1020)), 0x1008),
            label("loc_1020", 0x1020),
            ret(0x1020),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(
            rendered.contains("do"),
            "expected do-while loop in: {rendered}"
        );
        assert!(
            rendered.contains("while ("),
            "expected while condition in: {rendered}"
        );
        assert!(
            rendered.contains("i = (i + 1);"),
            "expected body in: {rendered}"
        );
        assert!(rendered.contains("return;"), "expected return in: {rendered}");
        assert!(
            !rendered.contains("goto loc_1000"),
            "unexpected back-edge goto: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Flat sequence (no control flow) is unchanged
    // -----------------------------------------------------------------------
    #[test]
    fn flat_sequence_unchanged() {
        let flat: Vec<HlilExpr> = vec![
            assign(var("x"), konst(1), 0x1000),
            assign(var("y"), konst(2), 0x1004),
            ret(0x1008),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(rendered.contains("x = 1;"));
        assert!(rendered.contains("y = 2;"));
        assert!(rendered.contains("return;"));
    }

    // -----------------------------------------------------------------------
    // Test: Multiple sequential if-else blocks
    // -----------------------------------------------------------------------
    #[test]
    fn multiple_sequential_if_else() {
        // Two if-else blocks in sequence:
        // First: if (cond1) goto A; else goto B
        // A: v1=1; goto M1;
        // B: v2=2; goto M1;
        // M1: if (cond2) goto C; else goto D
        // C: v3=3; goto M2;
        // D: v4=4; goto M2;
        // M2: return;
        let cond1 = binary(HlilOp::CmpE, var("a"), konst(0));
        let cond2 = binary(HlilOp::CmpNe, var("b"), konst(0));

        let flat: Vec<HlilExpr> = vec![
            if_else(cond1.clone(), goto(0x1010, 0x1010), Some(goto(0x1020, 0x1020)), 0x1000),
            label("loc_1010", 0x1010),
            assign(var("v1"), konst(1), 0x1010),
            goto(0x1030, 0x1018),
            label("loc_1020", 0x1020),
            assign(var("v2"), konst(2), 0x1020),
            goto(0x1030, 0x1028),
            label("loc_1030", 0x1030),
            if_else(cond2.clone(), goto(0x1040, 0x1040), Some(goto(0x1050, 0x1050)), 0x1030),
            label("loc_1040", 0x1040),
            assign(var("v3"), konst(3), 0x1040),
            goto(0x1060, 0x1048),
            label("loc_1050", 0x1050),
            assign(var("v4"), konst(4), 0x1050),
            goto(0x1060, 0x1058),
            label("loc_1060", 0x1060),
            ret(0x1060),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(rendered.contains("v1 = 1;"), "v1=1 in: {rendered}");
        assert!(rendered.contains("v2 = 2;"), "v2=2 in: {rendered}");
        assert!(rendered.contains("v3 = 3;"), "v3=3 in: {rendered}");
        assert!(rendered.contains("v4 = 4;"), "v4=4 in: {rendered}");
        assert!(rendered.contains("return;"), "return in: {rendered}");
        // Count ifs — should be 2
        let if_count = rendered.matches("if (").count();
        assert_eq!(if_count, 2, "expected 2 ifs, got {if_count}: {rendered}");
        // No gotos should remain
        assert!(!rendered.contains("goto loc_"), "unexpected gotos: {rendered}");
    }

    // -----------------------------------------------------------------------
    // Test: While loop with if-else inside (nested)
    // -----------------------------------------------------------------------
    #[test]
    fn nested_while_with_if_inside() {
        // while (cond) {
        //   if (inner_cond) { v1=1; } else { v2=2; }
        // }
        // return;
        //
        // Flat HLIL:
        // 0x1000: if (cond) { goto 0x1010; } else { goto 0x1060; }
        // 0x1010: if (inner_cond) { goto 0x1020; } else { goto 0x1030; }
        // 0x1020: v1=1; goto 0x1040;
        // 0x1030: v2=2; goto 0x1040;
        // 0x1040: goto 0x1000;
        // 0x1060: return;

        let cond = binary(HlilOp::CmpUlt, var("i"), konst(10));
        let inner_cond = binary(HlilOp::CmpE, var("x"), konst(0));

        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1060, 0x1060)), 0x1000),
            label("loc_1010", 0x1010),
            if_else(inner_cond.clone(), goto(0x1020, 0x1020), Some(goto(0x1030, 0x1030)), 0x1010),
            label("loc_1020", 0x1020),
            assign(var("v1"), konst(1), 0x1020),
            goto(0x1040, 0x1028),
            label("loc_1030", 0x1030),
            assign(var("v2"), konst(2), 0x1030),
            goto(0x1040, 0x1038),
            label("loc_1040", 0x1040),
            goto(0x1000, 0x1040),
            label("loc_1060", 0x1060),
            ret(0x1060),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(
            rendered.contains("while ("),
            "expected while in: {rendered}"
        );
        assert!(rendered.contains("v1 = 1;"), "v1=1 in: {rendered}");
        assert!(rendered.contains("v2 = 2;"), "v2=2 in: {rendered}");
        assert!(rendered.contains("return;"), "return in: {rendered}");
        // No gotos
        assert!(
            !rendered.contains("goto loc_"),
            "unexpected gotos: {rendered}"
        );
    }

    #[test]
    fn loop_branch_to_exit_becomes_break() {
        // while (i < 10) {
        //   if (stop) break;
        //   i = i + 1;
        // }
        // return;
        let cond = binary(HlilOp::CmpUlt, var("i"), konst(10));
        let stop = binary(HlilOp::CmpNe, var("stop"), konst(0));

        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1060, 0x1060)), 0x1000),
            label("loc_1010", 0x1010),
            if_else(stop.clone(), goto(0x1060, 0x1060), Some(goto(0x1020, 0x1020)), 0x1010),
            label("loc_1020", 0x1020),
            assign(var("i"), binary(HlilOp::Add, var("i"), konst(1)), 0x1020),
            goto(0x1000, 0x1028),
            label("loc_1060", 0x1060),
            ret(0x1060),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(rendered.contains("while ("), "expected while in: {rendered}");
        assert!(rendered.contains("break;"), "expected break in: {rendered}");
        assert!(
            !rendered.contains("goto loc_1060"),
            "unexpected exit goto: {rendered}"
        );
    }

    #[test]
    fn loop_branch_to_header_becomes_continue() {
        // while (i < 10) {
        //   if (skip) continue;
        //   i = i + 1;
        // }
        // return;
        let cond = binary(HlilOp::CmpUlt, var("i"), konst(10));
        let skip = binary(HlilOp::CmpNe, var("skip"), konst(0));

        let flat: Vec<HlilExpr> = vec![
            if_else(cond.clone(), goto(0x1010, 0x1010), Some(goto(0x1060, 0x1060)), 0x1000),
            label("loc_1010", 0x1010),
            if_else(skip.clone(), goto(0x1000, 0x1000), Some(goto(0x1020, 0x1020)), 0x1010),
            label("loc_1020", 0x1020),
            assign(var("i"), binary(HlilOp::Add, var("i"), konst(1)), 0x1020),
            goto(0x1000, 0x1028),
            label("loc_1060", 0x1060),
            ret(0x1060),
        ];

        let result = restructure_hlil(&flat);
        let rendered = render_hlil(&result);

        assert!(rendered.contains("while ("), "expected while in: {rendered}");
        assert!(
            rendered.contains("continue;"),
            "expected continue in: {rendered}"
        );
        assert!(
            !rendered.contains("goto loc_1000"),
            "unexpected header goto: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Empty input
    // -----------------------------------------------------------------------
    #[test]
    fn empty_input() {
        let result = restructure_hlil(&[]);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: Single block (no jumps) passes through
    // -----------------------------------------------------------------------
    #[test]
    fn single_block_passes_through() {
        let flat: Vec<HlilExpr> = vec![
            assign(var("x"), konst(42), 0x1000),
            ret(0x1004),
        ];
        let result = restructure_hlil(&flat);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].op, HlilOp::Assign);
        assert_eq!(result[1].op, HlilOp::Ret);
    }
}
