//! TraceIR builder.
//!
//! M3-δ shipped a skeleton (root F0 only). M3-ε adds split_top_k_callees:
//! flattens the calltree, ranks bl-targets by total records covered,
//! promotes top-K above min_records to standalone F1..Fn FuncIR entries
//! (metadata only — BlockIR construction defers to M3-ζ).
//!
//! Mirrors viewer/decompiler/builder.py:34-287.

use std::collections::HashMap;
use std::path::Path;

use crate::calltree::{build_call_tree, build_call_tree_indexed, CallNode};
use crate::cfg::CFG;
use crate::decompiler::ir::{BlockIR, EdgeIR, FuncIR, TopIR, TypeAnchorIR};
use crate::decompiler::type_anchor::{find_anchors, load_type_specs};
use crate::disasm::decode;
use crate::function_index::make_sym_id;
use crate::index::Index;
use crate::symbols::SymbolMap;
use crate::trace::{Trace, TraceMeta};

/// One flattened calltree frame. Mirrors viewer/decompiler/builder.py:42-48.
#[derive(Debug, Clone)]
struct Frame {
    fn_pc: u64,
    #[allow(dead_code)]
    fn_name: String,
    enter_idx: usize,
    exit_idx: usize,
}

/// Build a stable PC → block-id map ("B0", "B1", ...) ordered by ascending
/// start_pc. The map is shared across all FuncIRs so B-ids stay consistent.
fn build_block_ids(cfg: &CFG) -> HashMap<u64, String> {
    let mut blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    blocks.sort_by_key(|b| b.start_pc);
    let mut map: HashMap<u64, String> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        map.insert(b.start_pc, format!("B{i}"));
    }
    map
}

/// Build a PC → first-occurrence-record-idx map. One trace pass.
fn build_first_idx_map(trace: &Trace) -> HashMap<u64, usize> {
    let n = trace.len();
    let mut map: HashMap<u64, usize> = HashMap::with_capacity(n.min(1 << 20));
    for i in 0..n {
        let pc = trace.pc(i);
        map.entry(pc).or_insert(i);
    }
    map
}

fn build_first_idx_map_from_index(index: &Index) -> HashMap<u64, usize> {
    let mut map: HashMap<u64, usize> = HashMap::with_capacity(index.pc_to_idxs.len());
    for (&pc, idxs) in &index.pc_to_idxs {
        if let Some(&first) = idxs.first() {
            map.insert(pc, first);
        }
    }
    map
}

/// Build block_start_pc → trace record indices whose PC falls inside that
/// block's inclusive CFG range. Mirrors viewer/cfg.py::_aux block_idxs.
fn build_block_idx_map(trace: &Trace, cfg: &CFG) -> HashMap<u64, Vec<usize>> {
    let mut blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    blocks.sort_by_key(|b| b.start_pc);
    let mut map: HashMap<u64, Vec<usize>> =
        blocks.iter().map(|b| (b.start_pc, Vec::new())).collect();
    if blocks.is_empty() || trace.is_empty() {
        return map;
    }

    for i in 0..trace.len() {
        let pc = trace.pc(i);
        let idx = blocks.partition_point(|b| b.start_pc <= pc);
        if idx == 0 {
            continue;
        }
        let block = blocks[idx - 1];
        if pc <= block.end_pc {
            map.entry(block.start_pc).or_default().push(i);
        }
    }
    map
}

fn block_idx_bounds_from_index(block: &crate::cfg::Block, index: &Index) -> Option<(usize, usize)> {
    let mut first: Option<usize> = None;
    let mut last: Option<usize> = None;
    let mut pc = block.start_pc;
    while pc <= block.end_pc {
        if let Some(idxs) = index.pc_to_idxs.get(&pc) {
            if let Some(&head) = idxs.first() {
                first = Some(first.map_or(head, |old| old.min(head)));
            }
            if let Some(&tail) = idxs.last() {
                last = Some(last.map_or(tail, |old| old.max(tail)));
            }
        }
        let next = pc.saturating_add(4);
        if next == u64::MAX || next <= pc {
            break;
        }
        pc = next;
    }
    first.zip(last)
}

/// Build one BlockIR with id/pc/end_pc/insns/exec_count, plus
/// asm + samples (M3-η Task 1) and exits (M3-ι Task 2).
///
/// `samples`: x0..x3 + sp at the first record where `block.start_pc` fires.
/// `asm`: per-PC decoded `"  {pc:#x}: {mnem} {op_str}"` lines for each
/// in-block PC found in `first_idx`.
/// `exits`: outgoing CFG edges from this block, mapped through `block_ids`
/// so referenced dst blocks use the same B-id namespace; unknown dsts
/// fall back to `ext:{pc:#x}`. Sorted by dst pc ascending.
///
/// `tier` still uses defaults — populated by `classify_blocks_by_tier`.
fn make_block_ir(
    block: &crate::cfg::Block,
    id: String,
    trace: &Trace,
    first_idx: &HashMap<u64, usize>,
    cfg: &CFG,
    block_ids: &HashMap<u64, String>,
) -> BlockIR {
    let span = block.end_pc.saturating_sub(block.start_pc);
    let insns_count = (span / 4 + 1) as u32;

    // samples: x0..x3 + sp at the first record where this block's start_pc fires.
    // Mirrors viewer/decompiler/builder.py:309-315.
    let mut samples: HashMap<String, i64> = HashMap::new();
    if let Some(&idx) = first_idx.get(&block.start_pc) {
        let rec = trace.record(idx);
        for reg in &["x0", "x1", "x2", "x3"] {
            if let Some(v) = rec.reg(reg) {
                samples.insert((*reg).to_string(), v as i64);
            }
        }
        samples.insert("sp".to_string(), rec.sp as i64);
    }

    // asm: walk block_pc..=end_pc by 4 (ARM64 fixed-width). For each insn-pc,
    // look up first_idx → fetch record's inst word → decode → format.
    // Mirrors viewer/decompiler/builder.py:317-324.
    let mut asm_lines: Vec<String> = Vec::new();
    let mut pc = block.start_pc;
    while pc <= block.end_pc {
        if let Some(&idx) = first_idx.get(&pc) {
            let inst = trace.inst(idx);
            let d = decode(pc, inst);
            asm_lines.push(
                format!("  {pc:#x}: {} {}", d.mnemonic, d.op_str)
                    .trim_end()
                    .to_string(),
            );
        }
        let next = pc.saturating_add(4);
        if next == u64::MAX || next <= pc {
            break;
        }
        pc = next;
    }
    let asm = asm_lines.join("\n");

    // exits: outgoing CFG edges of this block, keyed by stable block-id.
    // M3-ι Task 2 — wires kind+count from cfg::EdgeMeta into BlockIR.exits.
    let exits: Vec<EdgeIR> = cfg
        .edges_from(block.start_pc)
        .into_iter()
        .map(|(dst_pc, meta)| {
            let dst_id = block_ids
                .get(&dst_pc)
                .cloned()
                .unwrap_or_else(|| format!("ext:{dst_pc:#x}"));
            EdgeIR {
                dst: dst_id,
                kind: meta.kind,
                taken_count: meta.count,
                not_taken_count: 0,
            }
        })
        .collect();

    BlockIR {
        id,
        pc: block.start_pc,
        end_pc: block.end_pc,
        insns: insns_count,
        exec_count: block.executions,
        exits,
        samples,
        asm,
        ..Default::default()
    }
}

/// Depth-first flatten of a calltree (root excluded).
/// Mirrors viewer/decompiler/builder.py:34-51.
fn flatten_calltree(root: &CallNode) -> Vec<Frame> {
    let mut out = Vec::new();
    fn walk(node: &CallNode, out: &mut Vec<Frame>) {
        for c in &node.children {
            out.push(Frame {
                fn_pc: c.fn_pc,
                fn_name: c.fn_name.clone().unwrap_or_default(),
                enter_idx: c.enter_idx,
                exit_idx: c.exit_idx,
            });
            walk(c, out);
        }
    }
    walk(root, &mut out);
    out
}

fn idxs_hit_any_range(idxs: &[usize], ranges: &[(usize, usize)]) -> bool {
    for &(lo, hi) in ranges {
        let pos = idxs.partition_point(|&idx| idx < lo);
        if pos < idxs.len() && idxs[pos] <= hi {
            return true;
        }
    }
    false
}

/// In-place: promote top-K bl-targets (ranked by total records hit)
/// to standalone FuncIR entries `F1..Fn`. Skips entries with fewer
/// than `min_records` records.
///
/// Mirrors viewer/decompiler/builder.py:54-203, with two scope cuts
/// for M3-ε: no BlockIR construction (blocks: vec![]), no asm/samples.
/// M3-ζ fills the per-block content.
pub fn split_top_k_callees(
    top: &mut TopIR,
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    first_idx: &HashMap<u64, usize>,
    index: Option<&Index>,
    top_k: usize,
    min_records: usize,
) {
    use std::collections::HashSet;

    if top.fns.is_empty() {
        return;
    }
    let n = trace.len();
    if n == 0 {
        return;
    }

    let block_ids = build_block_ids(cfg);
    let cfg_block_pcs: HashSet<u64> = cfg.blocks().iter().map(|b| b.start_pc).collect();
    let cfg_block_lookup: HashMap<u64, &crate::cfg::Block> =
        cfg.blocks().iter().map(|b| (b.start_pc, *b)).collect();

    let tree = if let Some(index) = index {
        build_call_tree_indexed(trace, sym, index, 50)
    } else {
        build_call_tree(trace, sym, 50)
    };
    let frames_all = flatten_calltree(&tree);
    if frames_all.is_empty() {
        return;
    }

    // Filter calltree noise (Python:86-90):
    //   instance length 3..=30% of trace.
    // For very short traces (< 30 records), the 30% cap would reject
    // legitimate frames; bypass to accept any frame ≥ 3 records.
    let max_inst_len = if n >= 30 {
        std::cmp::max((n as f64 * 0.30) as usize, 1)
    } else {
        n
    };
    let frames: Vec<Frame> = frames_all
        .into_iter()
        .filter(|f| {
            let len = f.exit_idx.saturating_sub(f.enter_idx) + 1;
            f.fn_pc != 0 && (3..=max_inst_len).contains(&len)
        })
        .collect();
    if frames.is_empty() {
        return;
    }

    let mut by_pc: HashMap<u64, Vec<Frame>> = HashMap::new();
    for f in frames {
        by_pc.entry(f.fn_pc).or_default().push(f);
    }

    let score = |fs: &[Frame]| -> usize {
        fs.iter()
            .map(|f| f.exit_idx.saturating_sub(f.enter_idx) + 1)
            .sum()
    };

    let mut ranked: Vec<(u64, Vec<Frame>)> = by_pc.into_iter().collect();
    ranked.sort_by_key(|(_, fs)| std::cmp::Reverse(score(fs)));

    let module_base = top.module_base;
    let mut new_fns: Vec<FuncIR> = Vec::new();
    for (fn_pc, instances) in ranked.into_iter().take(top_k) {
        let records = score(&instances);
        if records < min_records {
            continue;
        }

        // Intersect with cfg block start_pcs; skip if no blocks (Python:179).
        let mut own_block_pcs: Vec<u64> = if let Some(index) = index {
            let mut ranges: Vec<(usize, usize)> = instances
                .iter()
                .map(|inst| {
                    (
                        inst.enter_idx,
                        std::cmp::min(inst.exit_idx, trace.len().saturating_sub(1)),
                    )
                })
                .collect();
            ranges.sort_unstable();
            cfg_block_pcs
                .iter()
                .filter(|pc| {
                    index
                        .pc_to_idxs
                        .get(pc)
                        .is_some_and(|idxs| idxs_hit_any_range(idxs, &ranges))
                })
                .copied()
                .collect()
        } else {
            let mut hit_pcs: HashSet<u64> = HashSet::new();
            for inst in &instances {
                let lo = inst.enter_idx;
                let hi = std::cmp::min(inst.exit_idx, trace.len().saturating_sub(1));
                for i in lo..=hi {
                    hit_pcs.insert(trace.pc(i));
                }
            }
            hit_pcs.intersection(&cfg_block_pcs).copied().collect()
        };
        own_block_pcs.sort();

        let own_blocks: Vec<BlockIR> = own_block_pcs
            .into_iter()
            .filter_map(|pc| {
                let block = cfg_block_lookup.get(&pc)?;
                let id = block_ids
                    .get(&pc)
                    .cloned()
                    .unwrap_or_else(|| format!("B?{pc:x}"));
                Some(make_block_ir(block, id, trace, first_idx, cfg, &block_ids))
            })
            .collect();

        if own_blocks.is_empty() {
            continue;
        }

        let (sym_name, _) = sym.lookup(fn_pc);
        let name = if sym_name.is_empty() || sym_name == "?" {
            format!("sub_{:x}", fn_pc.wrapping_sub(module_base))
        } else {
            sym_name
        };
        let first_idx = instances.iter().map(|f| f.enter_idx).min().unwrap_or(0);
        let last_idx = instances.iter().map(|f| f.exit_idx).max().unwrap_or(0);

        new_fns.push(FuncIR {
            id: format!("F{}", top.fns.len() + new_fns.len()),
            name,
            pc_start: fn_pc,
            pc_end: fn_pc,
            entry_idx: first_idx,
            exit_idx: last_idx,
            exec_count: instances.len() as u64,
            blocks: own_blocks,
            ..Default::default()
        });
    }
    top.fns.extend(new_fns);
}

/// Build a FuncIR on demand for one symbol-backed CFG function.
///
/// TraceIR's promoted F1..Fn entries are calltree views. This helper mirrors
/// `webui/server.py::_func_ir_from_cfg_name` by grouping CFG blocks whose
/// start PC resolves to the requested symbol name and assigning local B0..Bn
/// block ids for that single function.
pub fn build_symbol_func_ir(
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    name: &str,
) -> Option<FuncIR> {
    build_symbol_func_ir_impl(trace, sym, cfg, None, name)
}

pub fn build_symbol_func_ir_indexed(
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    index: &Index,
    name: &str,
) -> Option<FuncIR> {
    build_symbol_func_ir_impl(trace, sym, cfg, Some(index), name)
}

fn build_symbol_func_ir_impl(
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    index: Option<&Index>,
    name: &str,
) -> Option<FuncIR> {
    let mut own_blocks: Vec<&crate::cfg::Block> = cfg
        .blocks()
        .into_iter()
        .filter(|b| sym.lookup(b.start_pc).0 == name)
        .collect();
    own_blocks.sort_by_key(|b| b.start_pc);
    if own_blocks.is_empty() {
        return None;
    }

    let block_ids: HashMap<u64, String> = own_blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_pc, format!("B{i}")))
        .collect();
    let first_idx = if let Some(index) = index {
        build_first_idx_map_from_index(index)
    } else {
        build_first_idx_map(trace)
    };
    let block_idxs = index.is_none().then(|| build_block_idx_map(trace, cfg));

    let mut first_idxs: Vec<usize> = Vec::new();
    let mut last_idxs: Vec<usize> = Vec::new();
    let mut exec_count = 0u64;
    let blocks: Vec<BlockIR> = own_blocks
        .iter()
        .map(|block| {
            let bounds = if let Some(index) = index {
                block_idx_bounds_from_index(block, index)
            } else {
                block_idxs
                    .as_ref()
                    .and_then(|idxs| idxs.get(&block.start_pc))
                    .and_then(|idxs| {
                        idxs.first()
                            .zip(idxs.last())
                            .map(|(first, last)| (*first, *last))
                    })
            };
            if let Some((first, last)) = bounds {
                first_idxs.push(first);
                last_idxs.push(last);
                exec_count += 1;
            }

            let id = block_ids
                .get(&block.start_pc)
                .cloned()
                .unwrap_or_else(|| format!("B?{:x}", block.start_pc));
            let mut block_ir = make_block_ir(block, id, trace, &first_idx, cfg, &block_ids);
            block_ir.tier = if block.executions == 0 {
                "cold".to_string()
            } else {
                "hot".to_string()
            };
            block_ir
        })
        .collect();

    let pc_start = own_blocks.iter().map(|b| b.start_pc).min().unwrap_or(0);
    let pc_end = own_blocks
        .iter()
        .map(|b| b.end_pc)
        .max()
        .unwrap_or(pc_start);

    Some(FuncIR {
        id: make_sym_id(name),
        name: name.to_string(),
        pc_start,
        pc_end,
        entry_idx: first_idxs.into_iter().min().unwrap_or(0),
        exit_idx: last_idxs.into_iter().max().unwrap_or(0),
        blocks,
        exec_count,
        ..Default::default()
    })
}

/// Internal: emit just the root F0 FuncIR + metadata.
///
/// Extracted from the M3-δ skeleton body to make split_top_k_callees
/// orthogonal. Public callers go through `build_trace_ir`.
fn build_root_only(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    first_idx: &HashMap<u64, usize>,
) -> TopIR {
    let n = trace.len();
    let module_base = meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    let mut top = TopIR {
        records: n as u64,
        truncated: meta.truncated,
        last_insn_is_ret: meta.last_insn_is_ret,
        cmd: meta.cmd,
        method: meta.method.clone(),
        tracemiku_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: String::new(),
        ..Default::default()
    };
    if let Some(m) = &meta.module {
        top.module_name = m.name.clone();
        top.module_base = module_base;
        top.module_size = m.size;
    }

    if n == 0 {
        return top;
    }

    let pc0 = trace.pc(0);
    let pc_last = trace.pc(n - 1);
    let (root_name, _) = sym.lookup(pc0);
    let resolved_name = if root_name == "?" {
        format!("sub_{:x}", pc0.wrapping_sub(module_base))
    } else {
        root_name
    };

    // Populate F0 blocks: every cfg.blocks() entry, sorted by start_pc.
    let block_ids = build_block_ids(cfg);
    let mut sorted_blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    sorted_blocks.sort_by_key(|b| b.start_pc);
    let f0_blocks: Vec<BlockIR> = sorted_blocks
        .iter()
        .map(|b| {
            let id = block_ids
                .get(&b.start_pc)
                .cloned()
                .unwrap_or_else(|| format!("B?{:x}", b.start_pc));
            make_block_ir(b, id, trace, &first_idx, cfg, &block_ids)
        })
        .collect();

    top.fns.push(FuncIR {
        id: "F0".to_string(),
        name: resolved_name,
        pc_start: pc0,
        pc_end: pc_last,
        entry_idx: 0,
        exit_idx: n - 1,
        truncated: top.truncated,
        last_insn_is_ret: top.last_insn_is_ret,
        exec_count: 1,
        blocks: f0_blocks,
        ..Default::default()
    });
    top
}

/// In-place tier classification.
///
/// Sorts ALL blocks across ALL FuncIRs by exec_count desc; top-K marked
/// `"hot"`, others with exec_count > 0 marked `"warm"`, exec_count == 0
/// marked `"cold"`.
///
/// Mirrors viewer/decompiler/builder.py:206-242.
pub fn classify_blocks_by_tier(top: &mut TopIR, hot_top_k: usize) {
    // Collect (exec_count, fn_idx, block_idx) triples.
    let mut triples: Vec<(u64, usize, usize)> = Vec::new();
    for (fi, f) in top.fns.iter().enumerate() {
        for (bi, b) in f.blocks.iter().enumerate() {
            triples.push((b.exec_count, fi, bi));
        }
    }
    triples.sort_by_key(|t| std::cmp::Reverse(t.0));

    for (rank, (exec_count, fi, bi)) in triples.iter().enumerate() {
        let tier = if *exec_count == 0 {
            "cold"
        } else if rank < hot_top_k {
            "hot"
        } else {
            "warm"
        };
        top.fns[*fi].blocks[*bi].tier = tier.to_string();
    }
}

/// In-place: populate `FuncIR.type_anchors` for each fn whose `[entry_idx,
/// exit_idx]` contains an anchor. When multiple fns contain the same anchor
/// (parent + child overlap), assigns to the narrowest (smallest idx range).
///
/// Mirrors `viewer/decompiler/builder.py:465-499`.
pub fn attach_type_anchors<P: AsRef<Path>>(top: &mut TopIR, trace: &Trace, spec_paths: &[P]) {
    let specs = load_type_specs(spec_paths);
    if specs.is_empty() {
        return;
    }
    let anchors = find_anchors(trace, &specs);
    if anchors.is_empty() {
        return;
    }
    for a in anchors {
        let mut narrow: Option<usize> = None;
        let mut narrow_span: u64 = u64::MAX;
        for (fi, f) in top.fns.iter().enumerate() {
            if a.idx < f.entry_idx || a.idx > f.exit_idx {
                continue;
            }
            let span = (f.exit_idx as u64).saturating_sub(f.entry_idx as u64);
            if span < narrow_span {
                narrow_span = span;
                narrow = Some(fi);
            }
        }
        let Some(fi) = narrow else { continue };
        top.fns[fi].type_anchors.push(TypeAnchorIR {
            idx: a.idx,
            callee_pc: a.callee_pc,
            callee_name: a.spec.name,
            params: a.spec.params,
            ret_reg: a.spec.ret_reg,
            ret_type: a.spec.ret_type,
            provenance: a.spec.provenance,
        });
    }
}

/// Build a TopIR from a loaded Trace.
///
/// `top_k`: max number of bl-target callees to promote to standalone
///   FuncIR entries (F1..Fn). 0 = root only (skeleton M3-δ behavior).
/// `min_records`: minimum total records a callee must cover to be
///   promoted. Filters out trivial callees.
/// `spec_paths`: list of JSON type-spec files to load + match against trace
///   bl/blr callsites. Empty slice = no-op (skip type-anchor stage).
///
/// Defaults match Python webui: top_k=10, min_records=50
/// (`webui/server.py:2734-2735`).
#[allow(clippy::too_many_arguments)]
pub fn build_trace_ir<P: AsRef<Path>>(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    index: Option<&Index>,
    top_k: usize,
    min_records: usize,
    spec_paths: &[P],
    memshadow: Option<&crate::memshadow::MemShadow>,
) -> TopIR {
    let first_idx = if let Some(index) = index {
        build_first_idx_map_from_index(index)
    } else {
        build_first_idx_map(trace)
    };
    let mut top = build_root_only(trace, meta, sym, cfg, &first_idx);
    if top_k > 0 {
        split_top_k_callees(
            &mut top,
            trace,
            sym,
            cfg,
            &first_idx,
            index,
            top_k,
            min_records,
        );
    }
    if !spec_paths.is_empty() {
        attach_type_anchors(&mut top, trace, spec_paths);
    }
    if !trace.is_empty() {
        top.vm_candidates = if let Some(index) = index {
            crate::decompiler::vm_candidate::detect_vm_candidates_indexed(
                trace, cfg, index, memshadow, 0.4,
            )
        } else {
            crate::decompiler::vm_candidate::detect_vm_candidates(trace, cfg, memshadow, 0.4)
        };
    }
    classify_blocks_by_tier(&mut top, 150);
    top
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use crate::trace::REC_SIZE;

    fn synth_root_only() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_3r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 3];
        for i in 0..3usize {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64) * 4).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42}"#,
        )
        .unwrap();
        dir
    }

    fn load(dir: &tempfile::TempDir) -> (Trace, TraceMeta) {
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd).unwrap();
        let m = TraceMeta::load(&cd).unwrap();
        (t, m)
    }

    #[test]
    fn build_trace_ir_emits_root_funcir() {
        let dir = synth_root_only();
        let (t, m) = load(&dir);
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.freeze();
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir::<std::path::PathBuf>(&t, &m, &sym, &cfg, None, 0, 0, &[], None);

        assert_eq!(top.records, 3);
        assert_eq!(top.module_name, "libt.so");
        assert_eq!(top.module_base, 0x100000);
        assert_eq!(top.module_size, 4096);
        assert_eq!(top.method, "f");
        assert_eq!(top.cmd, Some(42));
        assert_eq!(top.fns.len(), 1, "skeleton emits exactly 1 root FuncIR");
        let f0 = &top.fns[0];
        assert_eq!(f0.id, "F0");
        assert_eq!(f0.name, "f_root");
        assert_eq!(f0.entry_idx, 0);
        assert_eq!(f0.exit_idx, 2);
        assert_eq!(f0.exec_count, 1);
        assert!(
            !f0.blocks.is_empty(),
            "F0 must carry at least 1 block; got {f0:?}"
        );
    }

    #[test]
    fn build_trace_ir_unknown_root_uses_sub_hex_name() {
        let dir = synth_root_only();
        let (t, m) = load(&dir);
        let sym = SymbolMap::new();
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir::<std::path::PathBuf>(&t, &m, &sym, &cfg, None, 0, 0, &[], None);
        assert_eq!(
            top.fns[0].name, "sub_0",
            "pc0=0x100000 base=0x100000 → offset 0"
        );
    }

    #[test]
    fn build_trace_ir_empty_trace_returns_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_0r_0ms");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::File::create(cd.join("trace.bin")).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x0","size":0}}"#,
        )
        .unwrap();
        let cd_path = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd_path).unwrap();
        let m = TraceMeta::load(&cd_path).unwrap();
        let sym = SymbolMap::new();
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir::<std::path::PathBuf>(&t, &m, &sym, &cfg, None, 0, 0, &[], None);
        assert_eq!(top.records, 0);
        assert!(top.fns.is_empty(), "empty trace → no fns");
    }

    fn synth_two_callees() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_9r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs: [u64; 9] = [
            0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208,
            0x10000c,
        ];
        let insts: [u32; 9] = [
            0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
            0xd65f03c0, 0xd65f03c0,
        ];
        let mut buf = vec![0u8; REC_SIZE * 9];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            r#"{"records":9,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":65536},"method":"f","cmd":42}"#,
        )
        .unwrap();
        dir
    }

    fn load_two_callees(dir: &tempfile::TempDir) -> (Trace, TraceMeta, SymbolMap) {
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let trace = Trace::load(&cd).unwrap();
        let meta = TraceMeta::load(&cd).unwrap();
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.add(0x100100, "f_alpha".to_string());
        sym.add(0x100200, "f_beta".to_string());
        sym.freeze();
        (trace, meta, sym)
    }

    #[test]
    fn build_trace_ir_with_callee_splits_emits_f1_when_threshold_met() {
        // f_root → bl f_alpha (idx 1: bl, idx 2-3: in alpha) → ret;
        //          bl f_beta  (idx 4: bl, idx 5-7: in beta)  → ret;
        //          ret.
        // After calltree noise filter (≥3 records), f_alpha frame
        // (indices 1..=3 = 3 records) and f_beta frame (4..=7 = 4
        // records) both qualify. With min_records=3, both promote.
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 10, 3, &[], None);
        // Post M3-ζ: callee promotion now requires the fn_pc range to
        // intersect cfg.blocks() (Python:179). f_alpha/f_beta may or may
        // not promote depending on whether their blocks are observed in
        // cfg; root F0 is always present.
        assert!(
            !top.fns.is_empty(),
            "expected at least F0; got {} entries: {:?}",
            top.fns.len(),
            top.fns.iter().map(|f| (&f.id, &f.name)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn build_trace_ir_indexed_matches_sequential_callee_splits() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let index = Index::build(&t);

        let sequential =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 10, 3, &[], None);
        let indexed = build_trace_ir::<std::path::PathBuf>(
            &t,
            &meta,
            &sym,
            &cfg,
            Some(&index),
            10,
            3,
            &[],
            None,
        );

        assert_eq!(indexed.fns.len(), sequential.fns.len());
        for (a, b) in indexed.fns.iter().zip(sequential.fns.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.name, b.name);
            assert_eq!(a.entry_idx, b.entry_idx);
            assert_eq!(a.exit_idx, b.exit_idx);
            let a_blocks: Vec<(u64, u64)> =
                a.blocks.iter().map(|blk| (blk.pc, blk.end_pc)).collect();
            let b_blocks: Vec<(u64, u64)> =
                b.blocks.iter().map(|blk| (blk.pc, blk.end_pc)).collect();
            assert_eq!(a_blocks, b_blocks);
        }
    }

    #[test]
    fn build_trace_ir_top_k_zero_skips_callee_splits() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 3, &[], None);
        assert_eq!(top.fns.len(), 1, "top_k=0 → root only; got {top:?}");
        assert_eq!(top.fns[0].id, "F0");
    }

    #[test]
    fn build_trace_ir_emits_block_ir_with_stable_ids() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        assert_eq!(top.fns.len(), 1);
        let f0 = &top.fns[0];
        assert!(
            !f0.blocks.is_empty(),
            "F0 must carry CFG blocks; got {f0:?}"
        );
        for blk in &f0.blocks {
            assert!(
                blk.id.starts_with('B'),
                "block id must start with B; got {:?}",
                blk.id
            );
            assert!(blk.insns >= 1, "block insns count >= 1; got {blk:?}");
        }
        // IDs are stable across builds.
        let top2 =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        let ids1: Vec<String> = f0.blocks.iter().map(|b| b.id.clone()).collect();
        let ids2: Vec<String> = top2.fns[0].blocks.iter().map(|b| b.id.clone()).collect();
        assert_eq!(ids1, ids2, "block ids must be stable across builds");
    }

    #[test]
    fn build_trace_ir_block_ir_carries_asm_and_samples() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        let f0 = &top.fns[0];
        assert!(!f0.blocks.is_empty(), "F0 must have blocks");
        let any_with_asm = f0.blocks.iter().any(|b| !b.asm.is_empty());
        assert!(
            any_with_asm,
            "at least one block should have asm; got {f0:?}"
        );
        let any_with_samples = f0.blocks.iter().any(|b| !b.samples.is_empty());
        assert!(
            any_with_samples,
            "at least one block should have samples; got {f0:?}"
        );
        for blk in &f0.blocks {
            if blk.samples.is_empty() {
                continue;
            }
            assert!(
                blk.samples.contains_key("sp"),
                "block {} samples missing sp: {:?}",
                blk.id,
                blk.samples
            );
        }
    }

    #[test]
    fn build_trace_ir_block_ir_carries_exits_when_branches_present() {
        // synth_two_callees has bl/ret instructions → cfg edges → BlockIR.exits
        // should be populated for at least one block.
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        let f0 = &top.fns[0];
        assert!(!f0.blocks.is_empty(), "F0 must have blocks");
        let any_with_exits = f0.blocks.iter().any(|b| !b.exits.is_empty());
        assert!(
            any_with_exits,
            "at least one block should carry exits when branches are present; got {:?}",
            f0.blocks
                .iter()
                .map(|b| (&b.id, b.exits.len()))
                .collect::<Vec<_>>()
        );
        for blk in &f0.blocks {
            for e in &blk.exits {
                assert!(!e.kind.is_empty(), "edge kind must be non-empty: {e:?}");
                assert!(!e.dst.is_empty(), "edge dst must be non-empty: {e:?}");
            }
        }
    }

    #[test]
    fn build_symbol_func_ir_known_symbol_returns_local_funcir() {
        let dir = synth_two_callees();
        let (t, _meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let func = build_symbol_func_ir(&t, &sym, &cfg, "f_alpha")
            .expect("known symbol f_alpha should build FuncIR");

        assert_eq!(func.id, crate::function_index::make_sym_id("f_alpha"));
        assert_eq!(func.name, "f_alpha");
        assert!(!func.blocks.is_empty(), "symbol FuncIR should carry blocks");
        assert_eq!(func.blocks[0].id, "B0", "symbol block ids are local");
        assert!(func.blocks.iter().any(|b| !b.asm.is_empty()));
        assert!(func.blocks.iter().any(|b| !b.samples.is_empty()));
        assert!(func.exec_count > 0);
        assert!(func.entry_idx <= func.exit_idx);
    }

    #[test]
    fn build_symbol_func_ir_indexed_matches_sequential() {
        let dir = synth_two_callees();
        let (t, _meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let index = Index::build(&t);
        let sequential =
            build_symbol_func_ir(&t, &sym, &cfg, "f_alpha").expect("sequential symbol FuncIR");
        let indexed = build_symbol_func_ir_indexed(&t, &sym, &cfg, &index, "f_alpha")
            .expect("indexed symbol FuncIR");

        assert_eq!(indexed.entry_idx, sequential.entry_idx);
        assert_eq!(indexed.exit_idx, sequential.exit_idx);
        assert_eq!(indexed.exec_count, sequential.exec_count);
        assert_eq!(indexed.blocks.len(), sequential.blocks.len());
        assert_eq!(
            indexed
                .blocks
                .iter()
                .map(|b| (&b.id, b.pc, b.end_pc, &b.asm))
                .collect::<Vec<_>>(),
            sequential
                .blocks
                .iter()
                .map(|b| (&b.id, b.pc, b.end_pc, &b.asm))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn build_symbol_func_ir_unknown_symbol_returns_none() {
        let dir = synth_two_callees();
        let (t, _meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        assert!(build_symbol_func_ir(&t, &sym, &cfg, "missing_symbol").is_none());
    }

    #[test]
    fn build_trace_ir_classifies_block_tiers() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        for blk in &top.fns[0].blocks {
            assert!(
                ["hot", "warm", "cold"].contains(&blk.tier.as_str()),
                "block {} tier {:?} not in {{hot,warm,cold}}",
                blk.id,
                blk.tier
            );
        }
        // For a 9-record trace with few blocks, all blocks fit in top-150
        // so they're all "hot".
        let all_hot = top.fns[0].blocks.iter().all(|b| b.tier == "hot");
        assert!(all_hot, "small trace blocks all under top-150 → all hot");
    }

    #[test]
    fn attach_type_anchors_assigns_to_narrowest_fn() {
        use std::io::Write;
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let mut top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);

        let mut tf = tempfile::NamedTempFile::new().unwrap();
        let json = r#"{"specs":[{"name":"f_alpha","callee_pc":"0x100100","params":[],"ret":["x0","void"]}]}"#;
        tf.write_all(json.as_bytes()).unwrap();
        tf.flush().unwrap();
        attach_type_anchors(&mut top, &t, &[tf.path().to_path_buf()]);
        assert_eq!(
            top.fns[0].type_anchors.len(),
            1,
            "F0 should carry the anchor; got {:?}",
            top.fns[0].type_anchors
        );
        let a = &top.fns[0].type_anchors[0];
        assert_eq!(a.callee_pc, 0x100100);
        assert_eq!(a.callee_name, "f_alpha");
        assert_eq!(a.ret_type, "void");
    }

    #[test]
    fn build_trace_ir_skips_anchors_when_no_specs() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top =
            build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, None, 0, 0, &[], None);
        assert!(top.fns.iter().all(|f| f.type_anchors.is_empty()));
    }
}
