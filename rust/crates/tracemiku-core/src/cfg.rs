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
