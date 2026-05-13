//! Cross-block SSA construction with φ-node insertion.
//!
//! M5: full dominance-frontier SSA over the LLIL CFG.
//! Builds on `ssa_block` (block-local) and extends to the full function CFG.
//!
//! Algorithm:
//! 1. Split flat LLIL list into basic blocks (leader detection).
//! 2. Build CFG (predecessor/successor maps).
//! 3. Compute dominator tree via iterative dataflow.
//! 4. Compute dominance frontiers.
//! 5. Insert φ nodes at dominance frontiers.
//! 6. Rename variables with version numbers (recursive walk).
//!
//! Reference: Cytron et al., "Efficiently Computing Static Single Assignment Form".

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::llil::expr::{expr, LlilExpr, LlilOp, LlilOperand};

/// One basic block in the phi-SSA structure.
#[derive(Debug, Clone, Serialize)]
pub struct PhiBlock {
    pub id: usize,
    pub start_idx: usize,
    pub end_idx: usize,
    pub exprs: Vec<LlilExpr>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub phi_nodes: Vec<LlilExpr>,
}

/// Result of cross-block phi-SSA construction.
#[derive(Debug, Clone, Serialize)]
pub struct PhiCfg {
    pub blocks: Vec<PhiBlock>,
    pub entry_block: usize,
    pub exit_blocks: Vec<usize>,
    pub phi_count: usize,
}

fn goto_target(e: &LlilExpr) -> Option<u64> {
    match e.operands.first() {
        Some(LlilOperand::U64(v)) => Some(*v),
        _ => None,
    }
}

fn if_true_target(e: &LlilExpr) -> Option<u64> {
    match e.operands.get(1) {
        Some(LlilOperand::U64(v)) => Some(*v),
        _ => None,
    }
}

fn if_false_target(e: &LlilExpr) -> Option<u64> {
    match e.operands.get(2) {
        Some(LlilOperand::U64(v)) => Some(*v),
        _ => None,
    }
}

fn collect_vars(blocks: &[PhiBlock]) -> Vec<String> {
    let mut vars = BTreeSet::new();
    for b in blocks {
        for e in &b.exprs {
            collect_vars_in_expr(e, &mut vars);
        }
    }
    vars.into_iter().collect()
}

fn collect_vars_in_expr(e: &LlilExpr, vars: &mut BTreeSet<String>) {
    for op in &e.operands {
        match op {
            LlilOperand::Reg(r) => {
                vars.insert(r.clone());
            }
            LlilOperand::Expr(child) => collect_vars_in_expr(child, vars),
            _ => {}
        }
    }
}

/// Split a flat LLIL expression list into basic blocks.
///
/// Block leaders are: the first expression, targets of Goto/If/Jump,
/// and expressions immediately after any control-flow transfer.
fn split_blocks(exprs: &[LlilExpr]) -> Vec<PhiBlock> {
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
                if let Some(t) = goto_target(e) {
                    if let Some(&j) = pc_to_idx.get(&t) {
                        leader[j] = true;
                    }
                }
                if i + 1 < n {
                    leader[i + 1] = true;
                }
            }
            LlilOp::If => {
                if let Some(t) = if_true_target(e) {
                    if let Some(&j) = pc_to_idx.get(&t) {
                        leader[j] = true;
                    }
                }
                if let Some(t) = if_false_target(e) {
                    if let Some(&j) = pc_to_idx.get(&t) {
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
            blocks.push(PhiBlock {
                id: blocks.len(),
                start_idx: block_start,
                end_idx: i,
                exprs: exprs_block,
                successors: Vec::new(),
                predecessors: Vec::new(),
                phi_nodes: Vec::new(),
            });
            if i < n {
                block_start = i;
            }
        }
    }

    // Build pc_to_block map for successor resolution
    let mut pc_to_block: BTreeMap<u64, usize> = BTreeMap::new();
    for b in &blocks {
        if let Some(e) = b.exprs.first() {
            pc_to_block.insert(e.pc, b.id);
        }
    }
    for b in &blocks {
        for e in &b.exprs {
            pc_to_block.entry(e.pc).or_insert(b.id);
        }
    }

    // Resolve successors
    for i in 0..blocks.len() {
        let mut succs = Vec::new();
        if let Some(last) = blocks[i].exprs.last() {
            match last.op {
                LlilOp::Goto => {
                    if let Some(t) = goto_target(last) {
                        if let Some(&bid) = pc_to_block.get(&t) {
                            succs.push(bid);
                        }
                    }
                }
                LlilOp::If => {
                    if let Some(t) = if_true_target(last) {
                        if let Some(&bid) = pc_to_block.get(&t) {
                            succs.push(bid);
                        }
                    }
                    if let Some(t) = if_false_target(last) {
                        if let Some(&bid) = pc_to_block.get(&t) {
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
        blocks[i].successors = succs;
    }

    // Build predecessor lists
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (i, block) in blocks.iter().enumerate() {
        for &succ in &block.successors {
            if succ < preds.len() {
                preds[succ].push(i);
            }
        }
    }
    for (i, pred_list) in preds.into_iter().enumerate() {
        blocks[i].predecessors = pred_list;
    }

    blocks
}

/// Compute dominators via iterative dataflow.
///
/// Returns `idom` (immediate dominator) for each block.
/// Entry block's idom is itself.
fn compute_dominators(blocks: &[PhiBlock]) -> Vec<Option<usize>> {
    let n = blocks.len();
    if n == 0 {
        return vec![];
    }
    let entry = 0;
    let mut doms: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    // Initialize: entry dominates only itself; others dominated by all blocks
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
            for &pred in &blocks[i].predecessors {
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

    let mut idom = vec![None; n];
    idom[entry] = None;
    for i in 1..n {
        // Find immediate dominator = the dominator that dominates all others (strict dom)
        idom[i] = doms[i]
            .iter()
            .copied()
            .filter(|&d| d != i)
            .max_by_key(|&d| doms[d].len());
    }
    idom
}

/// Compute children in the dominator tree.
fn dom_children(idom: &[Option<usize>]) -> Vec<Vec<usize>> {
    let n = idom.len();
    let mut children = vec![Vec::new(); n];
    for (i, dom) in idom.iter().enumerate() {
        if let Some(d) = dom {
            if *d < n {
                children[*d].push(i);
            }
        }
    }
    children
}

/// Compute dominance frontiers.
fn compute_dominance_frontiers(
    blocks: &[PhiBlock],
    idom: &[Option<usize>],
) -> Vec<BTreeSet<usize>> {
    let n = blocks.len();
    let mut df = vec![BTreeSet::new(); n];
    for b in 0..n {
        let preds = &blocks[b].predecessors;
        if preds.len() >= 2 {
            for &p in preds {
                if p >= n {
                    continue;
                }
                let mut runner = p;
                while Some(runner) != idom[b] {
                    df[runner].insert(b);
                    if let Some(next) = idom[runner] {
                        runner = next;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    df
}

/// Insert phi nodes for all variables at dominance frontiers.
fn insert_phi_nodes(blocks: &mut [PhiBlock], vars: &[String], df: &[BTreeSet<usize>]) {
    for var in vars {
        // Skip non-register variables
        if var.is_empty() || var == "lr" || var == "sp" || var == "fp" {
            continue;
        }

        // Find blocks that define this var
        let mut def_blocks = BTreeSet::new();
        for b in blocks.iter() {
            for e in &b.exprs {
                if let LlilOp::SetReg = e.op {
                    if let Some(LlilOperand::Reg(dst)) = e.operands.first() {
                        let base = dst.rsplit_once('#').map(|(n, _)| n).unwrap_or(&dst);
                        if base == var {
                            def_blocks.insert(b.id);
                        }
                    }
                }
            }
        }

        if def_blocks.is_empty() {
            continue;
        }

        // Worklist: iterated dominance frontier
        let mut worklist: BTreeSet<usize> = def_blocks.clone();
        let mut phis = BTreeSet::new();
        let mut processed = BTreeSet::new();

        while let Some(b) = worklist.pop_first() {
            if !processed.insert(b) {
                continue;
            }
            for &f in &df[b] {
                if phis.insert(f) {
                    worklist.insert(f);
                }
            }
        }

        // Create phi nodes (start with just destination, fill_phi_arg adds pairs)
        for &b_id in &phis {
            let phi = LlilExpr::new(
                LlilOp::SetReg,
                8,
                vec![LlilOperand::Reg(var.clone())],
                0,
            )
            .with_extra("phi", var.clone())
            .with_extra("phi_block", b_id.to_string());
            blocks[b_id].phi_nodes.push(phi);
        }
    }
}

/// Build the dominance tree and rename variables.
/// Returns exprs with SSA-renamed registers (x0#1, etc.) and phi nodes filled.
fn rename_vars(blocks: &mut [PhiBlock], idom: &[Option<usize>], children: &[Vec<usize>]) {
    let mut stacks: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut counters: BTreeMap<String, u32> = BTreeMap::new();

    rename_block(blocks, 0, idom, children, &mut stacks, &mut counters, None);
}

fn rename_block(
    blocks: &mut [PhiBlock],
    b: usize,
    idom: &[Option<usize>],
    children: &[Vec<usize>],
    stacks: &mut BTreeMap<String, Vec<u32>>,
    counters: &mut BTreeMap<String, u32>,
    _from_pred: Option<usize>,
) {
    if b >= blocks.len() {
        return;
    }

    // Process phi nodes — for each phi, assign a new version number
    let mut phi_versions: Vec<(String, u32)> = Vec::new();
    for phi in &mut blocks[b].phi_nodes {
        if let Some(LlilOperand::Reg(var_name)) = phi.operands.first().cloned() {
            let v = counters.entry(var_name.clone()).or_insert(0);
            *v += 1;
            phi_versions.push((var_name.clone(), *v));
            stacks.entry(var_name.clone()).or_default().push(*v);
        }
    }

    // Rename regular instructions
    let mut new_exprs = Vec::new();
    for e in &blocks[b].exprs {
        let renamed = rename_expr(e, stacks, counters);
        new_exprs.push(renamed);
    }
    blocks[b].exprs = new_exprs;

    // Update successors' phi nodes with this block's versions
    for &succ in &blocks[b].successors {
        if succ >= blocks.len() {
            continue;
        }
        for phi in &mut blocks[succ].phi_nodes {
            if let Some(LlilOperand::Reg(var_name)) = phi.operands.first().cloned() {
                if let Some(stack) = stacks.get(&var_name) {
                    if let Some(&ver) = stack.last() {
                        // Fill the phi operand for predecessor b
                        fill_phi_arg(phi, b, &var_name, ver);
                    }
                }
            }
        }
    }

    // Recursively rename children in dominator tree
    for &child in &children[b] {
        rename_block(blocks, child, idom, children, stacks, counters, Some(b));
    }

    // Pop versions pushed for phi nodes
    for (var_name, _) in phi_versions {
        if let Some(stack) = stacks.get_mut(&var_name) {
            stack.pop();
        }
    }
}

/// Fill a phi node's argument for a given predecessor block.
/// We store phi args as pairs (block_id as Imm, Reg operand).
fn fill_phi_arg(phi: &mut LlilExpr, pred_block: usize, var_name: &str, version: u32) {
    // Phi format: SetReg(var_base, rest are pairs: (Imm(block_id), Reg("var#ver")))
    // We search for the block_id, and if found, update the reg; if not found, append.

    let mut found = false;
    let n = phi.operands.len();
    for i in (1..n).step_by(2) {
        if i + 1 < n {
            if let Some(LlilOperand::Imm(bid)) = phi.operands.get(i) {
                if *bid == pred_block as i64 {
                    phi.operands[i + 1] = LlilOperand::Reg(format!("{}#{}", var_name, version));
                    found = true;
                    break;
                }
            }
        }
    }
    if !found {
        phi.operands.push(LlilOperand::Imm(pred_block as i64));
        phi.operands
            .push(LlilOperand::Reg(format!("{}#{}", var_name, version)));
    }
}

fn rename_expr(
    e: &LlilExpr,
    stacks: &mut BTreeMap<String, Vec<u32>>,
    counters: &mut BTreeMap<String, u32>,
) -> LlilExpr {
    let mut out = e.clone();
    if out.op == LlilOp::SetReg {
        if let Some(LlilOperand::Reg(dst)) = out.operands.first().cloned() {
            let base = dst
                .rsplit_once('#')
                .map(|(n, _)| n)
                .unwrap_or(&dst)
                .to_string();
            if !base.is_empty() {
                let v = counters.entry(base.clone()).or_insert(0);
                *v += 1;
                stacks.entry(base.clone()).or_default().push(*v);
                out.operands[0] = LlilOperand::Reg(format!("{base}#{v}"));

                let renamed_rhs = match out.operands.get(1) {
                    Some(LlilOperand::Expr(rhs)) => expr(rename_sub_expr(rhs, stacks)),
                    _ => out.operands.get(1).cloned().unwrap_or(LlilOperand::Imm(0)),
                };
                out.operands[1] = renamed_rhs;
                return out;
            }
        }
    }
    // Rename register uses in sub-expressions
    out.operands = e
        .operands
        .iter()
        .map(|op| match op {
            LlilOperand::Expr(child) => expr(rename_sub_expr(child, stacks)),
            LlilOperand::Reg(r) => {
                let base = r.rsplit_once('#').map(|(n, _)| n).unwrap_or(r);
                if let Some(stack) = stacks.get(base) {
                    if let Some(&ver) = stack.last() {
                        LlilOperand::Reg(format!("{base}#{ver}"))
                    } else {
                        LlilOperand::Reg(format!("{base}#0"))
                    }
                } else {
                    op.clone()
                }
            }
            _ => op.clone(),
        })
        .collect();
    out
}

fn rename_sub_expr(e: &LlilExpr, stacks: &BTreeMap<String, Vec<u32>>) -> LlilExpr {
    let mut out = e.clone();
    out.operands = e
        .operands
        .iter()
        .map(|op| match op {
            LlilOperand::Expr(child) => expr(rename_sub_expr(child, stacks)),
            LlilOperand::Reg(r) => {
                let base = r.rsplit_once('#').map(|(n, _)| n).unwrap_or(r);
                if let Some(stack) = stacks.get(base) {
                    if let Some(&ver) = stack.last() {
                        LlilOperand::Reg(format!("{base}#{ver}"))
                    } else {
                        LlilOperand::Reg(format!("{base}#0"))
                    }
                } else {
                    op.clone()
                }
            }
            _ => op.clone(),
        })
        .collect();
    out
}

/// Main entry point: construct cross-block SSA with phi nodes.
pub fn phi_cfg(exprs: &[LlilExpr]) -> PhiCfg {
    let mut blocks = split_blocks(exprs);
    if blocks.is_empty() {
        return PhiCfg {
            blocks: vec![],
            entry_block: 0,
            exit_blocks: vec![],
            phi_count: 0,
        };
    }

    let vars = collect_vars(&blocks);
    let idom = compute_dominators(&blocks);
    let children = dom_children(&idom);
    let df = compute_dominance_frontiers(&blocks, &idom);

    insert_phi_nodes(&mut blocks, &vars, &df);
    rename_vars(&mut blocks, &idom, &children);

    let exit_blocks: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.successors.is_empty())
        .map(|(i, _)| i)
        .collect();

    let phi_count: usize = blocks.iter().map(|b| b.phi_nodes.len()).sum();

    PhiCfg {
        blocks,
        entry_block: 0,
        exit_blocks,
        phi_count,
    }
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilExpr, LlilOp, LlilOperand};

    use super::*;

    #[test]
    fn split_flat_into_blocks() {
        let exprs = vec![
            set_reg("x0", konst(1), 0x1000),
            LlilExpr::new(
                LlilOp::If,
                1,
                vec![
                    expr(binary(LlilOp::CmpE, reg("x0"), konst(0))),
                    LlilOperand::U64(0x2000),
                    LlilOperand::U64(0x100c),
                ],
                0x1004,
            ),
            set_reg("x1", konst(2), 0x1008),
            set_reg("x0", konst(3), 0x100c),
            LlilExpr::new(LlilOp::Ret, 8, Vec::new(), 0x1010),
        ];

        let blocks = split_blocks(&exprs);
        assert!(blocks.len() >= 2);
    }

    #[test]
    fn phi_cfg_handles_empty() {
        let cfg = phi_cfg(&[]);
        assert!(cfg.blocks.is_empty());
    }

    #[test]
    fn phi_cfg_single_block_no_phi() {
        let exprs = vec![
            set_reg("x0", konst(1), 0x1000),
            set_reg("x1", binary(LlilOp::Add, reg("x0"), konst(2)), 0x1004),
            LlilExpr::new(LlilOp::Ret, 8, Vec::new(), 0x1008),
        ];
        let cfg = phi_cfg(&exprs);
        assert_eq!(cfg.phi_count, 0);
        assert_eq!(cfg.blocks.len(), 1);
    }
}
