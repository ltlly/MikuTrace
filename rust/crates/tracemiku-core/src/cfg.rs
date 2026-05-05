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
use std::thread;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::Serialize;

const BRANCH_FLAG: u8 = 0x01;
const CALL_FLAG: u8 = 0x02;
const RET_FLAG: u8 = 0x04;
const CFG_PARALLEL_MIN_RECORDS: usize = 250_000;
const CFG_MIN_CHUNK_RECORDS: usize = 200_000;

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

/// CFG edge metadata. Mirrors Python `viewer/cfg.py::CFG.edges` value
/// dict: `{kind: str, count: int}`.
///
/// `kind` strings (parity with Python):
/// - `"fall"` — sequential fall-through into a block start.
/// - `"call-return"` — bl/blr → ret pair (caller block → post-call PC).
/// - `"b"`, `"bl"`, `"blr"`, `"br"`, `"ret"` — direct branch mnemonic.
/// - `"b.cond"` (or `"b.eq"`, `"b.ne"`, ...) — conditional branch
///   (Python uses the full `d.mnemonic` here, e.g. `"b.eq"`).
/// - `"cbz"`, `"cbnz"`, `"tbz"`, `"tbnz"` — compare-and-branch.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EdgeMeta {
    pub kind: String,
    pub count: u64,
}

/// Block-level CFG. Indexes by start_pc.
#[derive(Debug, Default, Clone)]
pub struct CFG {
    pub graph: DiGraph<Block, EdgeMeta>,
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

    /// Iterate outgoing edges of `start_pc`. Returns `(dst_start_pc, EdgeMeta)`,
    /// sorted by dst pc ascending for stable downstream rendering.
    pub fn edges_from(&self, start_pc: u64) -> Vec<(u64, EdgeMeta)> {
        let Some(&n) = self.by_pc.get(&start_pc) else {
            return Vec::new();
        };
        let mut out: Vec<(u64, EdgeMeta)> = self
            .graph
            .edges_directed(n, petgraph::Direction::Outgoing)
            .filter_map(|e| {
                let dst_pc = self.graph.node_weight(e.target())?.start_pc;
                Some((dst_pc, e.weight().clone()))
            })
            .collect();
        out.sort_by_key(|(pc, _)| *pc);
        out
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
    let branch_info = scan_branch_info(trace);

    // Pass 1: collect block start PCs.
    let mut start_pcs: BTreeSet<u64> = BTreeSet::new();
    start_pcs.insert(trace.pc(0));
    for i in 0..n {
        if branch_info.flags[i] & BRANCH_FLAG != 0 && i + 1 < n {
            start_pcs.insert(trace.pc(i + 1));
        }
    }

    // Pass 2: walk records, build block_meta (start_pc → end_pc).
    // Executions are counted in a separate post-pass.
    let mut block_meta: HashMap<u64, u64> = HashMap::new(); // start_pc → end_pc
    let mut edges: Vec<(u64, u64, EdgeMeta)> = Vec::new();

    let mut current_start: Option<u64> = None;
    let mut current_end: u64 = 0;
    let mut prev_pc: Option<u64> = None;
    let mut prev_was_branch: bool = false;

    // NOTE: M3-ι skeleton — module-boundary re-entry not handled yet
    // (parity with viewer/cfg.py:_add_call_return). Pure in-trace bl/ret
    // pairing: caller block-start pushed on `bl`/`blr`, popped on `ret`.
    let mut call_stack: Vec<u64> = Vec::new();

    for i in 0..n {
        let pc = trace.pc(i);

        if start_pcs.contains(&pc) {
            // Detect fall-through: previous insn was NOT a branch and its PC
            // is exactly 4 bytes before this block-start PC. Push a "fall"
            // edge from the previous block-start to this PC.
            if let (Some(prev), Some(s)) = (prev_pc, current_start) {
                if !prev_was_branch && prev + 4 == pc {
                    edges.push((
                        s,
                        pc,
                        EdgeMeta {
                            kind: "fall".to_string(),
                            count: 1,
                        },
                    ));
                }
            }
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

        let flags = branch_info.flags[i];
        let is_branch = flags & BRANCH_FLAG != 0;
        if is_branch {
            if let Some(s) = current_start {
                // Track call-stack for call-return pairing.
                if flags & CALL_FLAG != 0 {
                    call_stack.push(s);
                } else if flags & RET_FLAG != 0 {
                    if let Some(caller) = call_stack.pop() {
                        if i + 1 < n {
                            edges.push((
                                caller,
                                trace.pc(i + 1),
                                EdgeMeta {
                                    kind: "call-return".to_string(),
                                    count: 1,
                                },
                            ));
                        }
                    }
                }

                if i + 1 < n {
                    edges.push((
                        s,
                        trace.pc(i + 1),
                        EdgeMeta {
                            kind: branch_info
                                .mnemonics
                                .get(&i)
                                .cloned()
                                .unwrap_or_else(|| "b".to_string()),
                            count: 1,
                        },
                    ));
                }
                // Save end_pc and reset current_start.
                block_meta
                    .entry(s)
                    .and_modify(|e| *e = (*e).max(pc))
                    .or_insert(pc);
            }
            current_start = None;
        }

        prev_pc = Some(pc);
        prev_was_branch = is_branch;
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
    // Dedup by (src, dst): increment count on every observation; kind is
    // first-write-wins (matching Python's
    // `setdefault({"kind":k,"count":0})["count"] += 1`).
    let mut edge_index: HashMap<(u64, u64), petgraph::graph::EdgeIndex> = HashMap::new();
    for (from, to, meta) in edges {
        let (Some(&fn_), Some(&tn)) = (cfg.by_pc.get(&from), cfg.by_pc.get(&to)) else {
            continue;
        };
        if let Some(&eidx) = edge_index.get(&(from, to)) {
            if let Some(existing) = cfg.graph.edge_weight_mut(eidx) {
                existing.count += 1;
            }
        } else {
            let eidx = cfg.graph.add_edge(
                fn_,
                tn,
                EdgeMeta {
                    kind: meta.kind,
                    count: meta.count,
                },
            );
            edge_index.insert((from, to), eidx);
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

struct BranchScan {
    flags: Vec<u8>,
    mnemonics: HashMap<usize, String>,
}

struct BranchScanChunk {
    start: usize,
    flags: Vec<u8>,
    mnemonics: HashMap<usize, String>,
}

fn scan_branch_info(trace: &crate::trace::Trace) -> BranchScan {
    let n = trace.len();
    let workers = cfg_worker_count(n);
    if workers <= 1 {
        let chunk = scan_branch_range(trace, 0, n);
        return BranchScan {
            flags: chunk.flags,
            mnemonics: chunk.mnemonics,
        };
    }

    tracing::info!(
        target: "tracemiku-core",
        records = n,
        workers,
        "scanning CFG branch instructions in parallel"
    );

    let chunk_size = n.div_ceil(workers);
    let partials = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(n);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || scan_branch_range(trace, start, end)));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("cfg branch scanner panicked"))
            .collect::<Vec<_>>()
    });

    let mut flags = vec![0u8; n];
    let mut mnemonics = HashMap::new();
    for partial in partials {
        for (offset, flag) in partial.flags.into_iter().enumerate() {
            if flag != 0 {
                flags[partial.start + offset] = flag;
            }
        }
        mnemonics.extend(partial.mnemonics);
    }
    BranchScan { flags, mnemonics }
}

fn scan_branch_range(trace: &crate::trace::Trace, start: usize, end: usize) -> BranchScanChunk {
    let mut flags = vec![0u8; end.saturating_sub(start)];
    let mut mnemonics = HashMap::new();
    for i in start..end {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = crate::disasm::decode(pc, inst);
        if !d.is_branch {
            continue;
        }
        let mut flag = BRANCH_FLAG;
        if d.is_call {
            flag |= CALL_FLAG;
        }
        if d.is_ret {
            flag |= RET_FLAG;
        }
        flags[i - start] = flag;
        mnemonics.insert(i, d.mnemonic);
    }
    BranchScanChunk {
        start,
        flags,
        mnemonics,
    }
}

/// Planned worker count for CFG branch scanning at `n` records.
pub fn cfg_worker_count(n: usize) -> usize {
    crate::parallel::worker_count(
        n,
        "TRACEMIKU_CFG_THREADS",
        CFG_PARALLEL_MIN_RECORDS,
        CFG_MIN_CHUNK_RECORDS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{Trace, REC_SIZE};

    #[test]
    fn build_cfg_classifies_branch_kinds() {
        // Trace: 3 records, ARM64 nop sequence with one bl.
        // 0xd503201f = nop, 0x94000400 = bl +0x1000.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs = [0x1000u64, 0x1004, 0x2000];
        let insts = [0xd503201fu32, 0x94000400, 0xd503201f];
        let mut buf = vec![0u8; REC_SIZE * 3];
        for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":65536}}"#,
        )
        .unwrap();
        let trace = Trace::load(&cd).unwrap();
        let cfg = build_cfg(&trace);
        // At least one edge must have a non-empty kind (the bl edge).
        assert!(
            cfg.graph.edge_weights().any(|m| !m.kind.is_empty()),
            "at least one edge should have a non-empty kind; edges = {:?}",
            cfg.graph.edge_weights().collect::<Vec<_>>()
        );
    }
}
