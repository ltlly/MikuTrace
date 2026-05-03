//! Block-level control-flow graph over a Trace. Direct port of
//! `viewer/cfg.py::{Block, CFG, build_cfg}`.
//!
//! Build strategy: walk the trace, split blocks at branch instructions
//! (any insn classified as is_branch by disasm). Each unique start_pc
//! becomes one Block; successor edges come from observed PC transitions
//! (record i+1's PC after a branch at record i).
//!
//! Tarjan SCC marks loop members for the `--scc` UI affordance and feeds
//! into M2-ε's loop detection.

use std::collections::BTreeSet;
use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;

/// A basic block in the trace-derived CFG.
#[derive(Debug, Clone, Serialize)]
pub struct Block {
    pub start_pc: u64,
    /// Inclusive: PC of the LAST instruction in the block (typically the
    /// branch). For fall-through blocks this is the last sequential insn.
    pub end_pc: u64,
    /// Number of times this block was executed in the trace.
    pub executions: u64,
    /// Function name resolved via SymbolMap at start_pc, if available.
    /// `None` for trace-derived blocks where SymbolMap doesn't have an
    /// entry (anonymous block).
    pub fn_name: Option<String>,
    /// Strongly-connected-component id from Tarjan. Same id = same SCC.
    /// Singleton blocks have a unique id; loop-member blocks share an id.
    pub scc_id: u32,
}

/// Block-level CFG. Indexes by start_pc.
#[derive(Debug, Default, Clone)]
pub struct CFG {
    pub graph: DiGraph<Block, ()>,
    /// start_pc → NodeIndex for fast lookup.
    pub by_pc: HashMap<u64, NodeIndex>,
}

impl CFG {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn block(&self, start_pc: u64) -> Option<&Block> {
        let n = *self.by_pc.get(&start_pc)?;
        self.graph.node_weight(n)
    }

    pub fn blocks(&self) -> Vec<&Block> {
        self.graph
            .node_indices()
            .filter_map(|n| self.graph.node_weight(n))
            .collect()
    }

    pub fn successors(&self, start_pc: u64) -> Vec<u64> {
        let Some(&n) = self.by_pc.get(&start_pc) else {
            return Vec::new();
        };
        self.graph
            .neighbors_directed(n, petgraph::Direction::Outgoing)
            .filter_map(|s| self.graph.node_weight(s).map(|b| b.start_pc))
            .collect()
    }
}

/// Build a block-level CFG over the trace.
///
/// Algorithm:
/// 1. First pass: identify "block start PCs" — idx 0's PC, every PC that
///    appears immediately after a branch.
/// 2. Second pass: walk records, partition into blocks. Each record either
///    starts a new block (its PC is in start_pcs) or continues the current
///    one. Branch instructions terminate the current block; the next record's
///    PC starts a new block (already in start_pcs from pass 1).
/// 3. Add edges: for each branch at record i, edge from current-block-start
///    to record (i+1)'s PC.
/// 4. Post-pass: count executions = number of records whose PC equals each
///    block's start_pc (re-entering the block at its head).
pub fn build_cfg(trace: &crate::trace::Trace) -> CFG {
    let n = trace.len();
    if n == 0 {
        return CFG::new();
    }

    // Pass 1: collect block start PCs.
    let mut start_pcs: BTreeSet<u64> = BTreeSet::new();
    start_pcs.insert(trace.pc(0));
    for i in 0..n {
        let pc_i = trace.pc(i);
        let inst_i = trace.inst(i);
        let d = crate::disasm::decode(pc_i, inst_i);
        if d.is_branch && i + 1 < n {
            start_pcs.insert(trace.pc(i + 1));
        }
    }

    // Pass 2: walk records, build block_meta (start_pc → end_pc).
    // Executions are counted in a separate post-pass.
    let mut block_meta: HashMap<u64, u64> = HashMap::new(); // start_pc → end_pc
    let mut edges: Vec<(u64, u64)> = Vec::new();

    let mut current_start: Option<u64> = None;
    let mut current_end: u64 = 0;

    for i in 0..n {
        let pc = trace.pc(i);

        if start_pcs.contains(&pc) {
            // Finalize previous in-flight block (if any).
            if let Some(prev) = current_start {
                block_meta
                    .entry(prev)
                    .and_modify(|e| *e = (*e).max(current_end))
                    .or_insert(current_end);
            }
            current_start = Some(pc);
            current_end = pc;
        } else {
            current_end = pc;
            if let Some(s) = current_start {
                block_meta
                    .entry(s)
                    .and_modify(|e| *e = (*e).max(pc))
                    .or_insert(pc);
            }
        }

        let inst = trace.inst(i);
        let d = crate::disasm::decode(pc, inst);
        if d.is_branch {
            if let Some(s) = current_start {
                if i + 1 < n {
                    edges.push((s, trace.pc(i + 1)));
                }
                // Save end_pc and reset current_start.
                block_meta
                    .entry(s)
                    .and_modify(|e| *e = (*e).max(pc))
                    .or_insert(pc);
            }
            current_start = None;
        }
    }
    // Finalize last in-flight block.
    if let Some(s) = current_start {
        block_meta
            .entry(s)
            .and_modify(|e| *e = (*e).max(current_end))
            .or_insert(current_end);
    }

    // Build CFG nodes.
    let mut cfg = CFG::new();
    for (start, end) in block_meta {
        let block = Block {
            start_pc: start,
            end_pc: end,
            executions: 0,
            fn_name: None,
            scc_id: 0,
        };
        let node = cfg.graph.add_node(block);
        cfg.by_pc.insert(start, node);
    }

    // Add edges (skip if either endpoint isn't a known block start).
    for (from, to) in edges {
        if let (Some(&fn_), Some(&tn)) = (cfg.by_pc.get(&from), cfg.by_pc.get(&to)) {
            if !cfg.graph.contains_edge(fn_, tn) {
                cfg.graph.add_edge(fn_, tn, ());
            }
        }
    }

    // Post-pass: count executions per block (records whose PC == block.start_pc).
    for i in 0..n {
        let pc = trace.pc(i);
        if let Some(&node) = cfg.by_pc.get(&pc) {
            if let Some(b) = cfg.graph.node_weight_mut(node) {
                b.executions += 1;
            }
        }
    }

    // Tarjan SCC: assign scc_id to each block. Same-SCC blocks share an id.
    let sccs = petgraph::algo::tarjan_scc(&cfg.graph);
    for (id, scc) in sccs.iter().enumerate() {
        for &node in scc {
            if let Some(b) = cfg.graph.node_weight_mut(node) {
                b.scc_id = id as u32;
            }
        }
    }

    cfg
}
