//! LLIL restructure pass.
//!
//! M5: full control-flow restructuring — block splitting, if/else merging,
//! natural loop detection (back-edge), and while/do-while classification.
//!
//! Reference: Cifuentes, "Structuring Decompiled Graphs" (1994).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::render::render_stmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StructNode {
    Stmt {
        pc: String,
        text: String,
    },
    If {
        pc: String,
        cond: String,
        true_target: String,
        false_target: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        then_body: Vec<StructNode>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        else_body: Vec<StructNode>,
    },
    While {
        pc: String,
        cond: String,
        body: Vec<StructNode>,
    },
    DoWhile {
        pc: String,
        cond: String,
        body: Vec<StructNode>,
    },
    Goto {
        pc: String,
        target: String,
    },
    Return {
        pc: String,
    },
}

/// A basic block in the restructuring CFG.
#[derive(Debug, Clone)]
struct Block {
    id: usize,
    exprs: Vec<LlilExpr>,
    preds: Vec<usize>,
    succs: Vec<usize>,
}

impl Block {
    fn last_expr(&self) -> Option<&LlilExpr> {
        self.exprs.last()
    }

    fn is_goto(&self) -> bool {
        self.last_expr()
            .map(|e| e.op == LlilOp::Goto)
            .unwrap_or(false)
    }

    fn is_if(&self) -> bool {
        self.last_expr()
            .map(|e| e.op == LlilOp::If)
            .unwrap_or(false)
    }

    fn goto_target(&self) -> Option<u64> {
        match self.last_expr()?.operands.first() {
            Some(LlilOperand::U64(v)) => Some(*v),
            _ => None,
        }
    }

    fn if_targets(&self) -> Option<(u64, u64)> {
        let e = self.last_expr()?;
        if e.op != LlilOp::If {
            return None;
        }
        let t = match e.operands.get(1) {
            Some(LlilOperand::U64(v)) => *v,
            _ => return None,
        };
        let f = match e.operands.get(2) {
            Some(LlilOperand::U64(v)) => *v,
            _ => return None,
        };
        Some((t, f))
    }
}

/// Split a flat LLIL list into basic blocks.
fn build_cfg(exprs: &[LlilExpr]) -> Vec<Block> {
    if exprs.is_empty() {
        return vec![];
    }

    let n = exprs.len();
    let mut leader = vec![false; n];
    leader[0] = true;

    let mut pc_to_idx: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, e) in exprs.iter().enumerate() {
        pc_to_idx.insert(e.pc, i);
    }

    for (i, e) in exprs.iter().enumerate() {
        match e.op {
            LlilOp::Goto => {
                let t = match e.operands.first() {
                    Some(LlilOperand::U64(v)) => Some(*v),
                    _ => None,
                };
                if let Some(t) = t {
                    if let Some(&j) = pc_to_idx.get(&t) {
                        leader[j] = true;
                    }
                }
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            LlilOp::If => {
                let t = match e.operands.get(1) {
                    Some(LlilOperand::U64(v)) => Some(*v),
                    _ => None,
                };
                let f = match e.operands.get(2) {
                    Some(LlilOperand::U64(v)) => Some(*v),
                    _ => None,
                };
                if let Some(t) = t {
                    if let Some(&j) = pc_to_idx.get(&t) {
                        leader[j] = true;
                    }
                }
                if let Some(f) = f {
                    if let Some(&j) = pc_to_idx.get(&f) {
                        leader[j] = true;
                    }
                }
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            LlilOp::Jump => {
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            LlilOp::Ret | LlilOp::Tailcall => {
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            _ => {}
        }
    }

    let mut blocks = Vec::new();
    let mut block_start = 0usize;
    for i in 1..=n {
        if i == n || leader[i] {
            let exprs_block = exprs[block_start..i].to_vec();
            blocks.push(Block {
                id: blocks.len(),
                exprs: exprs_block,
                preds: Vec::new(),
                succs: Vec::new(),
            });
            if i < n {
                block_start = i;
            }
        }
    }

    // Resolve successors via PC → block map
    let mut pc_to_block: BTreeMap<u64, usize> = BTreeMap::new();
    for b in &blocks {
        if let Some(e) = b.exprs.first() {
            pc_to_block.insert(e.pc, b.id);
        }
    }
    // Also add all PCs in a block (e.g., mid-block targets)
    for b in &blocks {
        for e in &b.exprs {
            pc_to_block.entry(e.pc).or_insert(b.id);
        }
    }

    for i in 0..blocks.len() {
        let mut succs = Vec::new();
        if let Some(last) = blocks[i].last_expr() {
            match last.op {
                LlilOp::Goto => {
                    if let Some(t) = blocks[i].goto_target() {
                        if let Some(&bid) = pc_to_block.get(&t) {
                            succs.push(bid);
                        }
                    }
                }
                LlilOp::If => {
                    if let Some((t, f)) = blocks[i].if_targets() {
                        if let Some(&bid) = pc_to_block.get(&t) {
                            succs.push(bid);
                        }
                        if let Some(&bid) = pc_to_block.get(&f) {
                            succs.push(bid);
                        }
                    }
                }
                LlilOp::Ret | LlilOp::Tailcall => {}
                _ => {
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
    for (i, preds) in preds_list.into_iter().enumerate() {
        blocks[i].preds = preds;
    }

    blocks
}

/// Compute dominators for blocks.
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

/// Detect natural loops via back edges (successor that dominates the block).
fn find_back_edges(blocks: &[Block], doms: &[BTreeSet<usize>]) -> Vec<(usize, usize)> {
    let mut back_edges = Vec::new();
    for i in 0..blocks.len() {
        for &succ in &blocks[i].succs {
            if succ < doms.len() && doms[i].contains(&succ) {
                back_edges.push((i, succ));
            }
        }
    }
    back_edges
}

/// Group blocks into loop bodies (header + body blocks).
fn find_loop_groups(blocks: &[Block], back_edges: &[(usize, usize)]) -> Vec<(usize, Vec<usize>)> {
    let mut loops: Vec<(usize, Vec<usize>)> = Vec::new();
    for &(tail, header) in back_edges {
        // Collect body: all blocks reachable from header that can reach the tail
        // without going through header.
        let mut body = BTreeSet::new();
        body.insert(header);
        body.insert(tail);

        // BFS from tail backwards (using predecessors) until we hit header
        let mut queue: Vec<usize> = vec![tail];
        let mut visited = BTreeSet::new();
        visited.insert(header);
        while let Some(b) = queue.pop() {
            if visited.contains(&b) {
                continue;
            }
            visited.insert(b);
            body.insert(b);
            for &pred in &blocks[b].preds {
                if !visited.contains(&pred) {
                    queue.push(pred);
                }
            }
        }

        let mut body_vec: Vec<usize> = body.into_iter().collect();
        body_vec.sort();
        loops.push((header, body_vec));
    }
    loops
}

/// Classify loop type: while (condition at header) or do-while (condition at tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopKind {
    While,
    DoWhile,
}

fn classify_loop(blocks: &[Block], header: usize, body: &[usize]) -> Option<LoopKind> {
    let header_block = blocks.get(header)?;
    let is_if_header = header_block.is_if();

    // Check if tail (last body block) branches back to header
    let _body_set: BTreeSet<usize> = body.iter().copied().collect();
    let has_latch = body.iter().any(|&b| blocks[b].succs.contains(&header));

    if is_if_header && has_latch {
        // Header is an If: typical while loop pattern
        // The If's false target goes to exit, true goes to body
        Some(LoopKind::While)
    } else if has_latch && !is_if_header {
        // Latch branches back to header, header is not an If: do-while pattern
        Some(LoopKind::DoWhile)
    } else {
        None
    }
}

/// Main CFG restructuring entry point.
///
/// Splits flat LLIL into blocks, detects if/else and loop patterns,
/// and produces structured nodes.
pub fn restructure_cfg(exprs: &[LlilExpr]) -> Vec<StructNode> {
    let blocks = build_cfg(exprs);
    if blocks.is_empty() {
        return vec![];
    }

    let doms = compute_dominators(&blocks);
    let back_edges = find_back_edges(&blocks, &doms);
    let loops = find_loop_groups(&blocks, &back_edges);

    // Collect loop body block IDs for quick lookup
    let loop_block_set: BTreeSet<usize> = loops
        .iter()
        .flat_map(|(_, body)| body.iter())
        .copied()
        .collect();
    let loop_header_set: BTreeSet<usize> = loops.iter().map(|(h, _)| *h).collect();

    // Build a topological-like walk: start from block 0, mark visited
    let mut visited = vec![false; blocks.len()];
    let mut nodes = Vec::new();

    struct_region(
        &blocks,
        &doms,
        &loop_block_set,
        &loop_header_set,
        &loops,
        0,
        &mut visited,
        &mut nodes,
    );

    nodes
}

fn build_pc_to_block(blocks: &[Block]) -> BTreeMap<u64, usize> {
    let mut m = BTreeMap::new();
    for b in blocks {
        if let Some(e) = b.exprs.first() {
            m.insert(e.pc, b.id);
        }
    }
    m
}

fn struct_region(
    blocks: &[Block],
    doms: &[BTreeSet<usize>],
    loop_set: &BTreeSet<usize>,
    header_set: &BTreeSet<usize>,
    loops: &[(usize, Vec<usize>)],
    current: usize,
    visited: &mut [bool],
    out: &mut Vec<StructNode>,
) {
    if current >= blocks.len() || visited[current] {
        return;
    }
    visited[current] = true;

    // Check if this is a loop header
    if header_set.contains(&current) {
        if let Some((_, body)) = loops.iter().find(|(h, _)| *h == current) {
            let loop_kind = classify_loop(blocks, current, body);
            let header_block = &blocks[current];
            match loop_kind {
                Some(LoopKind::While) => {
                    // While loop: header is If, false goes to exit
                    let (cond_pc, cond_str) = if let Some(e) = header_block.last_expr() {
                        if e.op == LlilOp::If {
                            let cond = render_operand(e.operands.first());
                            (format!("{:#x}", e.pc), cond)
                        } else {
                            (format!("{:#x}", current), "?".to_string())
                        }
                    } else {
                        (format!("{:#x}", current), "?".to_string())
                    };

                    let mut body_blocks = Vec::new();

                    // Mark all body blocks visited
                    for &b in body {
                        if b != current && !visited[b] {
                            visited[b] = true;
                        }
                    }

                    // Render body blocks
                    for &b in body {
                        if b == current {
                            continue;
                        }
                        let block = &blocks[b];
                        for e in &block.exprs {
                            if e.op != LlilOp::If
                                && e.op != LlilOp::Goto
                                && e.op != LlilOp::Ret
                                && e.op != LlilOp::Jump
                            {
                                body_blocks.push(StructNode::Stmt {
                                    pc: format!("{:#x}", e.pc),
                                    text: render_stmt(e),
                                });
                            }
                        }
                    }

                    out.push(StructNode::While {
                        pc: cond_pc,
                        cond: cond_str,
                        body: body_blocks,
                    });

                    // Continue with the exit block (false target of header If)
                    if let Some((_, false_target)) = header_block.if_targets() {
                        let pc_to_blk = build_pc_to_block(blocks);
                        if let Some(&exit_bid) = pc_to_blk.get(&false_target) {
                            if exit_bid < blocks.len() && !visited[exit_bid] {
                                struct_region(
                                    blocks, doms, loop_set, header_set, loops, exit_bid, visited,
                                    out,
                                );
                            }
                        }
                    }
                    return;
                }
                Some(LoopKind::DoWhile) => {
                    let mut body_nodes = Vec::new();
                    for &b in body {
                        let block = &blocks[b];
                        if b == current {
                            for e in block.exprs.iter().take(block.exprs.len().saturating_sub(1)) {
                                body_nodes.push(StructNode::Stmt {
                                    pc: format!("{:#x}", e.pc),
                                    text: render_stmt(e),
                                });
                            }
                        } else {
                            for e in &block.exprs {
                                body_nodes.push(StructNode::Stmt {
                                    pc: format!("{:#x}", e.pc),
                                    text: render_stmt(e),
                                });
                            }
                            if !visited[b] {
                                visited[b] = true;
                            }
                        }
                    }
                    // Condition is on the latch back edge to header
                    let latch_cond = body.iter().filter(|&&b| b != current).find_map(|&b| {
                        let block = &blocks[b];
                        if block.is_if() {
                            block.last_expr().map(|e| {
                                (format!("{:#x}", e.pc), render_operand(e.operands.first()))
                            })
                        } else {
                            None
                        }
                    });

                    if let Some((pc, cond)) = latch_cond {
                        out.push(StructNode::DoWhile {
                            pc,
                            cond,
                            body: body_nodes,
                        });
                    } else {
                        for node in body_nodes {
                            out.push(node);
                        }
                    }

                    // Continue with the exit block (tail successor that's not the header)
                    for &b in body {
                        if b == current {
                            continue;
                        }
                        for &succ in &blocks[b].succs {
                            if succ != current && succ < blocks.len() && !visited[succ] {
                                struct_region(
                                    blocks, doms, loop_set, header_set, loops, succ, visited, out,
                                );
                            }
                        }
                    }
                    return;
                }
                None => {}
            }
        }
    }

    // Try if/else detection: block ends with If
    if blocks[current].is_if() {
        if let Some((true_target, false_target)) = blocks[current].if_targets() {
            let pc_to_block = build_pc_to_block(blocks);
            let true_bid = pc_to_block.get(&true_target);
            let false_bid = pc_to_block.get(&false_target);

            // Check for if-else pattern: both targets converge to same block
            let has_convergence = match (true_bid, false_bid) {
                (Some(&tb), Some(&fb)) => {
                    let true_succs: BTreeSet<usize> = blocks[tb].succs.iter().copied().collect();
                    let false_succs: BTreeSet<usize> = blocks[fb].succs.iter().copied().collect();
                    true_succs.intersection(&false_succs).next().is_some()
                }
                _ => false,
            };

            let cond_e = blocks[current].last_expr().unwrap();
            let pc_str = format!("{:#x}", cond_e.pc);
            let cond = render_operand(cond_e.operands.first());

            if has_convergence {
                // Build then/else bodies
                let mut then_nodes = Vec::new();
                let mut else_nodes = Vec::new();

                if let Some(&tb) = true_bid {
                    if tb < blocks.len() && tb != current {
                        build_body_nodes(
                            blocks,
                            &doms,
                            loop_set,
                            header_set,
                            loops,
                            tb,
                            visited,
                            then_nodes.as_mut(),
                        );
                    }
                }
                if let Some(&fb) = false_bid {
                    if fb < blocks.len() && fb != current {
                        build_body_nodes(
                            blocks,
                            &doms,
                            loop_set,
                            header_set,
                            loops,
                            fb,
                            visited,
                            else_nodes.as_mut(),
                        );
                    }
                }

                out.push(StructNode::If {
                    pc: pc_str,
                    cond,
                    true_target: format!("{true_target:#x}"),
                    false_target: format!("{false_target:#x}"),
                    then_body: then_nodes,
                    else_body: else_nodes,
                });

                // Continue to the merge block (common successor of then/else)
                let merge_bid = {
                    let tsuccs: BTreeSet<usize> = true_bid
                        .map(|&tb| blocks.get(tb).map(|b| b.succs.clone()).unwrap_or_default())
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                    let fsuccs: BTreeSet<usize> = false_bid
                        .map(|&fb| blocks.get(fb).map(|b| b.succs.clone()).unwrap_or_default())
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                    tsuccs.intersection(&fsuccs).next().copied()
                };
                if let Some(merge_bid) = merge_bid {
                    if merge_bid < blocks.len() && !visited[merge_bid] {
                        struct_region(
                            blocks, doms, loop_set, header_set, loops, merge_bid, visited, out,
                        );
                    }
                }
                return;
            } else {
                // Simple if-then, else is fallthrough
                let mut then_nodes = Vec::new();
                if let Some(&tb) = true_bid {
                    if tb < blocks.len() && tb != current {
                        build_body_nodes(
                            blocks,
                            &doms,
                            loop_set,
                            header_set,
                            loops,
                            tb,
                            visited,
                            then_nodes.as_mut(),
                        );
                    }
                }
                out.push(StructNode::If {
                    pc: pc_str,
                    cond,
                    true_target: format!("{true_target:#x}"),
                    false_target: format!("{false_target:#x}"),
                    then_body: then_nodes,
                    else_body: Vec::new(),
                });
                // Continue to the false target (fallthrough)
                if let Some(&fb) = false_bid {
                    if fb < blocks.len() && !visited[fb] {
                        struct_region(blocks, doms, loop_set, header_set, loops, fb, visited, out);
                    }
                }
                return;
            }
        }
    }

    // Otherwise: render block as flat statements
    let block = &blocks[current];
    for e in &block.exprs {
        if !e.is_control_flow() && e.op != LlilOp::If {
            out.push(StructNode::Stmt {
                pc: format!("{:#x}", e.pc),
                text: render_stmt(e),
            });
        }
    }

    // If the last expr is a Goto that's not a back edge, add it
    if block.is_goto() {
        if let Some(t) = block.goto_target() {
            out.push(StructNode::Goto {
                pc: format!("{:#x}", block.exprs.last().unwrap().pc),
                target: format!("{t:#x}"),
            });
        }
    }
    if block
        .last_expr()
        .map(|e| e.op == LlilOp::Ret)
        .unwrap_or(false)
    {
        out.push(StructNode::Return {
            pc: format!("{:#x}", block.exprs.last().unwrap().pc),
        });
    }

    // Follow successors that are not yet visited
    for &succ in &block.succs {
        if succ < blocks.len() && !visited[succ] && !loop_set.contains(&succ) {
            struct_region(
                blocks, doms, loop_set, header_set, loops, succ, visited, out,
            );
        }
    }
}

fn build_body_nodes(
    blocks: &[Block],
    _doms: &[BTreeSet<usize>],
    loop_set: &BTreeSet<usize>,
    _header_set: &BTreeSet<usize>,
    _loops: &[(usize, Vec<usize>)],
    current: usize,
    visited: &mut [bool],
    out: &mut Vec<StructNode>,
) {
    if current >= blocks.len() || visited[current] || loop_set.contains(&current) {
        return;
    }
    visited[current] = true;

    let block = &blocks[current];
    for e in &block.exprs {
        if e.is_control_flow() || e.op == LlilOp::If {
            match e.op {
                LlilOp::If => {
                    let cond = render_operand(e.operands.first());
                    let t = match e.operands.get(1) {
                        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
                        _ => "?".to_string(),
                    };
                    let f = match e.operands.get(2) {
                        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
                        _ => "?".to_string(),
                    };
                    out.push(StructNode::If {
                        pc: format!("{:#x}", e.pc),
                        cond,
                        true_target: t,
                        false_target: f,
                        then_body: Vec::new(),
                        else_body: Vec::new(),
                    });
                }
                LlilOp::Goto => {
                    let t = match e.operands.first() {
                        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
                        _ => "?".to_string(),
                    };
                    out.push(StructNode::Goto {
                        pc: format!("{:#x}", e.pc),
                        target: t,
                    });
                }
                LlilOp::Ret => {
                    out.push(StructNode::Return {
                        pc: format!("{:#x}", e.pc),
                    });
                }
                _ => {}
            }
            continue;
        }
        out.push(StructNode::Stmt {
            pc: format!("{:#x}", e.pc),
            text: render_stmt(e),
        });
    }

    // Follow successors that are within the body (non-loop, non-visited)
    for &succ in &block.succs {
        if succ < blocks.len() && !visited[succ] && !loop_set.contains(&succ) {
            build_body_nodes(
                blocks,
                _doms,
                loop_set,
                _header_set,
                _loops,
                succ,
                visited,
                out,
            );
        }
    }
}

fn render_operand(op: Option<&LlilOperand>) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => e.short(),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) | Some(LlilOperand::Str(r)) => {
            r.clone()
        }
        Some(LlilOperand::Imm(v)) => v.to_string(),
        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn render_target(op: Option<&LlilOperand>) -> String {
    render_operand(op)
}

/// Backward-compatible flat restructure (one block, no CFG analysis).
pub fn restructure_block(exprs: &[LlilExpr]) -> Vec<StructNode> {
    exprs.iter().map(restructure_stmt).collect()
}

fn restructure_stmt(e: &LlilExpr) -> StructNode {
    match e.op {
        LlilOp::If => StructNode::If {
            pc: format!("{:#x}", e.pc),
            cond: render_operand(e.operands.first()),
            true_target: render_target(e.operands.get(1)),
            false_target: render_target(e.operands.get(2)),
            then_body: Vec::new(),
            else_body: Vec::new(),
        },
        LlilOp::Goto => StructNode::Goto {
            pc: format!("{:#x}", e.pc),
            target: render_target(e.operands.first()),
        },
        LlilOp::Ret => StructNode::Return {
            pc: format!("{:#x}", e.pc),
        },
        _ => StructNode::Stmt {
            pc: format!("{:#x}", e.pc),
            text: render_stmt(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{
        binary, expr, flag_cond, konst, reg, set_reg, LlilExpr, LlilOp, LlilOperand,
    };

    use super::*;

    #[test]
    fn classifies_if_node() {
        let br = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                expr(flag_cond("eq")),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1004,
        );
        let nodes = restructure_block(&[br]);
        assert!(matches!(nodes[0], StructNode::If { .. }));
    }

    #[test]
    fn restructure_cfg_empty() {
        let nodes = restructure_cfg(&[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn restructure_cfg_simple() {
        let exprs = vec![
            set_reg("x0", konst(1), 0x1000),
            set_reg("x1", konst(2), 0x1004),
            LlilExpr::new(LlilOp::Ret, 8, Vec::new(), 0x1008),
        ];
        let nodes = restructure_cfg(&exprs);
        assert!(!nodes.is_empty());
        assert_eq!(nodes.len(), 3); // 2 stmts + 1 return
    }

    #[test]
    fn detects_if_else_pattern() {
        // if (x0 == 0) goto 0x2000 else goto 0x1008
        // 0x1008: x1 = 1; goto 0x2000
        let exprs = vec![
            LlilExpr::new(
                LlilOp::If,
                1,
                vec![
                    expr(binary(LlilOp::CmpE, reg("x0"), konst(0))),
                    LlilOperand::U64(0x2000),
                    LlilOperand::U64(0x1008),
                ],
                0x1000,
            ),
            set_reg("x1", konst(1), 0x1008),
            LlilExpr::new(LlilOp::Goto, 8, vec![LlilOperand::U64(0x2000)], 0x100c),
        ];
        let nodes = restructure_cfg(&exprs);
        assert!(!nodes.is_empty());
        // Should detect if-then pattern
        assert!(matches!(nodes[0], StructNode::If { .. }));
    }
}
