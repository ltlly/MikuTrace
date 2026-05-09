//! Persistent whole-trace analysis index.
//!
//! This is intentionally heavier than [`crate::index::Index`]. The startup
//! index stays focused on hot UI lookups; this module materializes trace-wide
//! dependency rows, final memory definitions, register checkpoints, and compact
//! summaries so later panels/routes can reuse one persisted scan.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::calltree::{build_call_tree_indexed, CallNode};
use crate::disasm::classify::is_conditional_branch_mnem;
use crate::disasm::{addr_of, decode, DecodedInsn};
use crate::index::Index;
use crate::symbols::SymbolMap;
use crate::trace::Trace;

const SIDECAR_MAGIC: &[u8; 8] = b"TMANL1\0\0";
const SIDECAR_VERSION: u32 = 1;
pub const SIDECAR_SUFFIX: &str = ".analysis-full.v1.bin";
pub const CHECKPOINT_INTERVAL: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepKind {
    Reg,
    Address,
    Mem,
    Control,
}

impl DepKind {
    fn to_u8(self) -> u8 {
        match self {
            Self::Reg => 1,
            Self::Address => 2,
            Self::Mem => 3,
            Self::Control => 4,
        }
    }

    fn from_u8(value: u8) -> std::io::Result<Self> {
        match value {
            1 => Ok(Self::Reg),
            2 => Ok(Self::Address),
            3 => Ok(Self::Mem),
            4 => Ok(Self::Control),
            _ => Err(invalid_data("bad analysis edge kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DepEdge {
    pub idx: usize,
    pub kind: DepKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyIndex {
    pub row_offsets: Vec<u64>,
    pub edges: Vec<DepEdge>,
}

impl DependencyIndex {
    pub fn row(&self, idx: usize) -> &[DepEdge] {
        let Some((&start, &end)) = self.row_offsets.get(idx).zip(self.row_offsets.get(idx + 1))
        else {
            return &[];
        };
        let start = start as usize;
        let end = end as usize;
        if start > end || end > self.edges.len() {
            return &[];
        }
        &self.edges[start..end]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemLastDefEntry {
    pub addr: u64,
    pub idx: usize,
    pub value: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegCheckpoint {
    pub idx: usize,
    pub pc: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub record_count: usize,
    pub unique_pc_count: usize,
    pub dependency_edge_count: usize,
    pub reg_dependency_edges: usize,
    pub address_dependency_edges: usize,
    pub mem_dependency_edges: usize,
    pub control_dependency_edges: usize,
    pub mem_read_count: usize,
    pub mem_write_count: usize,
    pub init_mem_loads: usize,
    pub call_count: usize,
    pub ret_count: usize,
    pub conditional_branch_count: usize,
    pub function_count: usize,
    pub call_tree_max_depth: usize,
    pub sidecar_version: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcSummary {
    pub pc: u64,
    pub asm: String,
    pub record_count: usize,
    pub first_idx: usize,
    pub last_idx: usize,
    pub mem_reads: usize,
    pub mem_writes: usize,
    pub calls: usize,
    pub rets: usize,
    pub conditional_branches: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub fn_pc: u64,
    pub fn_name: Option<String>,
    pub call_count: usize,
    pub total_records: usize,
    pub first_enter_idx: usize,
    pub last_exit_idx: usize,
    pub max_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisIndex {
    pub deps: DependencyIndex,
    pub mem_last_def: Vec<MemLastDefEntry>,
    pub reg_checkpoints: Vec<RegCheckpoint>,
    pub call_tree: CallNode,
    pub summary: AnalysisSummary,
    pub pc_summaries: Vec<PcSummary>,
    pub function_summaries: Vec<FunctionSummary>,
}

#[derive(Debug, Clone, Default)]
struct PcAccum {
    asm: String,
    record_count: usize,
    first_idx: usize,
    last_idx: usize,
    mem_reads: usize,
    mem_writes: usize,
    calls: usize,
    rets: usize,
    conditional_branches: usize,
}

#[derive(Debug, Clone, Default)]
struct FunctionAccum {
    fn_name: Option<String>,
    call_count: usize,
    total_records: usize,
    first_enter_idx: usize,
    last_exit_idx: usize,
    max_depth: usize,
}

impl AnalysisIndex {
    /// Sidecar path for this trace:
    /// `<call_dir>/trace.bin.analysis-full.v1.bin`.
    pub fn sidecar_path(trace: &Trace) -> PathBuf {
        trace.call_dir().join(format!("trace.bin{SIDECAR_SUFFIX}"))
    }

    pub fn load_or_build(trace: &Trace, symbols: &SymbolMap, index: &Index) -> Self {
        if let Some(analysis) = Self::try_load_sidecar(trace, symbols) {
            return analysis;
        }
        let analysis = Self::build(trace, symbols, index);
        let _ = analysis.save_sidecar(trace, symbols);
        analysis
    }

    pub fn try_load_sidecar(trace: &Trace, symbols: &SymbolMap) -> Option<Self> {
        Self::read_sidecar(trace, symbols).ok()
    }

    pub fn build(trace: &Trace, symbols: &SymbolMap, index: &Index) -> Self {
        let n = trace.len();
        let mut decode_cache: HashMap<(u64, u32), DecodedInsn> = HashMap::new();
        let mut reg_last: HashMap<String, usize> = HashMap::new();
        let mut mem_last: HashMap<u64, (usize, u8)> = HashMap::new();
        let mut row_offsets = Vec::with_capacity(n + 1);
        let mut edges = Vec::new();
        let mut checkpoints = Vec::new();
        let mut pc_accums: BTreeMap<u64, PcAccum> = BTreeMap::new();
        let mut last_cond: Option<usize> = None;
        let mut summary = AnalysisSummary {
            record_count: n,
            unique_pc_count: index.pc_to_idxs.len(),
            sidecar_version: SIDECAR_VERSION,
            ..AnalysisSummary::default()
        };

        row_offsets.push(0);
        for i in 0..n {
            let rec = trace.record(i);
            let pc = rec.pc;
            let inst = rec.inst;
            let decoded = decode_cache
                .entry((pc, inst))
                .or_insert_with(|| decode(pc, inst));
            let asm = format_asm(decoded);
            let pc_accum = pc_accums.entry(pc).or_insert_with(|| PcAccum {
                asm,
                first_idx: i,
                ..PcAccum::default()
            });
            pc_accum.record_count += 1;
            pc_accum.last_idx = i;

            if i % CHECKPOINT_INTERVAL == 0 || i + 1 == n {
                let duplicate_last = checkpoints
                    .last()
                    .is_some_and(|checkpoint: &RegCheckpoint| checkpoint.idx == i);
                if !duplicate_last {
                    checkpoints.push(RegCheckpoint {
                        idx: i,
                        pc,
                        regs: rec.regs,
                        sp: rec.sp,
                        nzcv: rec.nzcv,
                    });
                }
            }

            let mut row = Vec::new();
            if let Some(cond_idx) = last_cond {
                if cond_idx != i && !decoded.is_call && !decoded.is_ret {
                    push_unique_edge(
                        &mut row,
                        DepEdge {
                            idx: cond_idx,
                            kind: DepKind::Control,
                        },
                    );
                    summary.control_dependency_edges += 1;
                }
            }

            let address_regs = address_regs(decoded);
            let data_regs = store_source_regs(decoded);
            for reg in &decoded.regs_use {
                if let Some(&def_idx) = reg_last.get(reg) {
                    let is_address = address_regs.contains(reg);
                    let is_data = data_regs.contains(reg) || !is_address;
                    if is_address {
                        push_unique_edge(
                            &mut row,
                            DepEdge {
                                idx: def_idx,
                                kind: DepKind::Address,
                            },
                        );
                    }
                    if is_data {
                        push_unique_edge(
                            &mut row,
                            DepEdge {
                                idx: def_idx,
                                kind: DepKind::Reg,
                            },
                        );
                    }
                }
            }

            for op in &decoded.mem_op {
                if op.base.is_empty() {
                    continue;
                }
                let addr = addr_of(&rec, op);
                if op.is_write {
                    summary.mem_write_count += 1;
                    pc_accum.mem_writes += 1;
                } else {
                    summary.mem_read_count += 1;
                    pc_accum.mem_reads += 1;
                    let mut had_def = false;
                    for offset in 0..op.size as u64 {
                        if let Some(&(def_idx, _value)) = mem_last.get(&addr.wrapping_add(offset)) {
                            push_unique_edge(
                                &mut row,
                                DepEdge {
                                    idx: def_idx,
                                    kind: DepKind::Mem,
                                },
                            );
                            had_def = true;
                        }
                    }
                    if !had_def {
                        summary.init_mem_loads += 1;
                    }
                }
            }

            let before_len = edges.len();
            row.sort_unstable_by_key(|edge| (edge.idx, edge.kind.to_u8()));
            row.dedup();
            for edge in &row {
                match edge.kind {
                    DepKind::Reg => summary.reg_dependency_edges += 1,
                    DepKind::Address => summary.address_dependency_edges += 1,
                    DepKind::Mem => summary.mem_dependency_edges += 1,
                    DepKind::Control => {
                        // Counted when the provisional edge is created above.
                    }
                }
            }
            edges.extend(row);
            summary.dependency_edge_count += edges.len() - before_len;
            row_offsets.push(edges.len() as u64);

            for reg in &decoded.regs_def {
                reg_last.insert(reg.clone(), i);
            }
            for op in &decoded.mem_op {
                if op.base.is_empty() || !op.is_write {
                    continue;
                }
                let addr = addr_of(&rec, op);
                let value = store_source_value(&rec, decoded, op.src_reg.as_str());
                for offset in 0..op.size as u64 {
                    let byte = if offset < 8 {
                        ((value >> (offset * 8)) & 0xff) as u8
                    } else {
                        0
                    };
                    mem_last.insert(addr.wrapping_add(offset), (i, byte));
                }
            }

            if decoded.is_call {
                summary.call_count += 1;
                pc_accum.calls += 1;
                last_cond = None;
            } else if decoded.is_ret {
                summary.ret_count += 1;
                pc_accum.rets += 1;
                last_cond = None;
            } else if is_conditional_branch_mnem(&decoded.mnemonic) {
                summary.conditional_branch_count += 1;
                pc_accum.conditional_branches += 1;
                last_cond = Some(i);
            }
        }

        let mut mem_last_def = mem_last
            .into_iter()
            .map(|(addr, (idx, value))| MemLastDefEntry { addr, idx, value })
            .collect::<Vec<_>>();
        mem_last_def.sort_unstable_by_key(|entry| entry.addr);

        let call_tree = build_call_tree_indexed(trace, symbols, index, 50);
        summary.call_tree_max_depth = call_tree_max_depth(&call_tree);
        let function_summaries = function_summaries(&call_tree);
        summary.function_count = function_summaries.len();

        let pc_summaries = pc_accums
            .into_iter()
            .map(|(pc, accum)| PcSummary {
                pc,
                asm: accum.asm,
                record_count: accum.record_count,
                first_idx: accum.first_idx,
                last_idx: accum.last_idx,
                mem_reads: accum.mem_reads,
                mem_writes: accum.mem_writes,
                calls: accum.calls,
                rets: accum.rets,
                conditional_branches: accum.conditional_branches,
            })
            .collect();

        Self {
            deps: DependencyIndex { row_offsets, edges },
            mem_last_def,
            reg_checkpoints: checkpoints,
            call_tree,
            summary,
            pc_summaries,
            function_summaries,
        }
    }

    pub fn save_sidecar(&self, trace: &Trace, symbols: &SymbolMap) -> std::io::Result<()> {
        let path = Self::sidecar_path(trace);
        let tmp_name = format!(
            "{}.tmp.{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("trace.bin.analysis-full.v1.bin"),
            std::process::id()
        );
        let tmp_path = path.with_file_name(tmp_name);
        let write_result = (|| {
            let raw = std::fs::File::create(&tmp_path)?;
            let mut f = BufWriter::with_capacity(1024 * 1024, raw);
            f.write_all(SIDECAR_MAGIC)?;
            write_u32(&mut f, SIDECAR_VERSION)?;
            write_u64(&mut f, trace.raw().len() as u64)?;
            write_u64(&mut f, trace_fingerprint(trace))?;
            write_u64(&mut f, symbols_fingerprint(symbols))?;
            write_dependency_index(&mut f, &self.deps)?;
            write_mem_last_def_vec(&mut f, &self.mem_last_def)?;
            write_reg_checkpoint_vec(&mut f, &self.reg_checkpoints)?;
            write_summary(&mut f, &self.summary)?;
            write_pc_summary_vec(&mut f, &self.pc_summaries)?;
            write_function_summary_vec(&mut f, &self.function_summaries)?;
            let call_tree = serde_json::to_vec(&self.call_tree).map_err(std::io::Error::other)?;
            write_bytes(&mut f, &call_tree)?;
            f.flush()?;
            f.get_ref().sync_all()?;
            std::fs::rename(&tmp_path, &path)
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        write_result
    }

    fn read_sidecar(trace: &Trace, symbols: &SymbolMap) -> std::io::Result<Self> {
        let raw = std::fs::File::open(Self::sidecar_path(trace))?;
        let mut f = BufReader::with_capacity(1024 * 1024, raw);
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)?;
        if &magic != SIDECAR_MAGIC {
            return Err(invalid_data("bad analysis sidecar magic"));
        }
        let version = read_u32(&mut f)?;
        if version != SIDECAR_VERSION {
            return Err(invalid_data("bad analysis sidecar version"));
        }
        let trace_size = read_u64(&mut f)?;
        if trace_size != trace.raw().len() as u64 {
            return Err(invalid_data("stale analysis sidecar trace size"));
        }
        let fingerprint = read_u64(&mut f)?;
        if fingerprint != trace_fingerprint(trace) {
            return Err(invalid_data("stale analysis sidecar trace fingerprint"));
        }
        let symbol_fingerprint = read_u64(&mut f)?;
        if symbol_fingerprint != symbols_fingerprint(symbols) {
            return Err(invalid_data("stale analysis sidecar symbol fingerprint"));
        }
        let deps = read_dependency_index(&mut f)?;
        let mem_last_def = read_mem_last_def_vec(&mut f)?;
        let reg_checkpoints = read_reg_checkpoint_vec(&mut f)?;
        let summary = read_summary(&mut f)?;
        let pc_summaries = read_pc_summary_vec(&mut f)?;
        let function_summaries = read_function_summary_vec(&mut f)?;
        let call_tree_bytes = read_bytes(&mut f)?;
        let call_tree = serde_json::from_slice(&call_tree_bytes)
            .map_err(|_| invalid_data("bad analysis sidecar call tree json"))?;
        Ok(Self {
            deps,
            mem_last_def,
            reg_checkpoints,
            call_tree,
            summary,
            pc_summaries,
            function_summaries,
        })
    }
}

fn push_unique_edge(row: &mut Vec<DepEdge>, edge: DepEdge) {
    if !row.contains(&edge) {
        row.push(edge);
    }
}

fn address_regs(decoded: &DecodedInsn) -> HashSet<String> {
    let mut regs = HashSet::new();
    for op in &decoded.mem_op {
        if !op.base.is_empty() {
            regs.insert(op.base.clone());
        }
        if !op.idx.is_empty() {
            regs.insert(op.idx.clone());
        }
    }
    regs
}

fn store_source_regs(decoded: &DecodedInsn) -> HashSet<String> {
    decoded
        .mem_op
        .iter()
        .filter(|op| op.is_write && !op.src_reg.is_empty())
        .map(|op| op.src_reg.clone())
        .collect()
}

fn store_source_value(rec: &crate::trace::Record, decoded: &DecodedInsn, src_reg: &str) -> u64 {
    if !src_reg.is_empty() {
        return rec.reg_by_name(src_reg).unwrap_or(0);
    }
    let address_regs = address_regs(decoded);
    decoded
        .regs_use
        .iter()
        .find(|reg| !address_regs.contains(*reg))
        .and_then(|reg| rec.reg_by_name(reg))
        .unwrap_or(0)
}

fn format_asm(decoded: &DecodedInsn) -> String {
    if decoded.op_str.is_empty() {
        decoded.mnemonic.clone()
    } else {
        format!("{} {}", decoded.mnemonic, decoded.op_str)
    }
}

fn call_tree_max_depth(node: &CallNode) -> usize {
    node.children
        .iter()
        .map(call_tree_max_depth)
        .max()
        .unwrap_or(node.depth)
        .max(node.depth)
}

fn function_summaries(root: &CallNode) -> Vec<FunctionSummary> {
    let mut accums: BTreeMap<(u64, String), FunctionAccum> = BTreeMap::new();
    collect_function_summaries(root, &mut accums);
    accums
        .into_iter()
        .map(|((fn_pc, key_name), accum)| FunctionSummary {
            fn_pc,
            fn_name: if key_name.is_empty() {
                None
            } else {
                accum.fn_name
            },
            call_count: accum.call_count,
            total_records: accum.total_records,
            first_enter_idx: accum.first_enter_idx,
            last_exit_idx: accum.last_exit_idx,
            max_depth: accum.max_depth,
        })
        .collect()
}

fn collect_function_summaries(
    node: &CallNode,
    accums: &mut BTreeMap<(u64, String), FunctionAccum>,
) {
    if node.depth > 0 {
        let key_name = node.fn_name.clone().unwrap_or_default();
        let entry = accums
            .entry((node.fn_pc, key_name))
            .or_insert_with(|| FunctionAccum {
                fn_name: node.fn_name.clone(),
                first_enter_idx: node.enter_idx,
                last_exit_idx: node.exit_idx,
                ..FunctionAccum::default()
            });
        entry.call_count += 1;
        entry.total_records += node.exit_idx.saturating_sub(node.enter_idx) + 1;
        entry.first_enter_idx = entry.first_enter_idx.min(node.enter_idx);
        entry.last_exit_idx = entry.last_exit_idx.max(node.exit_idx);
        entry.max_depth = entry.max_depth.max(node.depth);
    }
    for child in &node.children {
        collect_function_summaries(child, accums);
    }
}

fn write_dependency_index(w: &mut impl Write, deps: &DependencyIndex) -> std::io::Result<()> {
    write_u64_vec(w, &deps.row_offsets)?;
    write_u64(w, deps.edges.len() as u64)?;
    for edge in &deps.edges {
        write_u64(w, edge.idx as u64)?;
        w.write_all(&[edge.kind.to_u8()])?;
    }
    Ok(())
}

fn read_dependency_index(r: &mut impl Read) -> std::io::Result<DependencyIndex> {
    let row_offsets = read_u64_vec(r)?;
    let len = read_len(r)?;
    let mut edges = Vec::with_capacity(len);
    for _ in 0..len {
        let idx = read_usize_u64(r)?;
        let mut kind = [0u8; 1];
        r.read_exact(&mut kind)?;
        edges.push(DepEdge {
            idx,
            kind: DepKind::from_u8(kind[0])?,
        });
    }
    Ok(DependencyIndex { row_offsets, edges })
}

fn write_mem_last_def_vec(w: &mut impl Write, values: &[MemLastDefEntry]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, value.addr)?;
        write_u64(w, value.idx as u64)?;
        w.write_all(&[value.value])?;
    }
    Ok(())
}

fn read_mem_last_def_vec(r: &mut impl Read) -> std::io::Result<Vec<MemLastDefEntry>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(MemLastDefEntry {
            addr: read_u64(r)?,
            idx: read_usize_u64(r)?,
            value: {
                let mut b = [0u8; 1];
                r.read_exact(&mut b)?;
                b[0]
            },
        });
    }
    Ok(values)
}

fn write_reg_checkpoint_vec(w: &mut impl Write, values: &[RegCheckpoint]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, value.idx as u64)?;
        write_u64(w, value.pc)?;
        for reg in value.regs {
            write_u64(w, reg)?;
        }
        write_u64(w, value.sp)?;
        write_u32(w, value.nzcv)?;
    }
    Ok(())
}

fn read_reg_checkpoint_vec(r: &mut impl Read) -> std::io::Result<Vec<RegCheckpoint>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let idx = read_usize_u64(r)?;
        let pc = read_u64(r)?;
        let mut regs = [0u64; 31];
        for reg in &mut regs {
            *reg = read_u64(r)?;
        }
        values.push(RegCheckpoint {
            idx,
            pc,
            regs,
            sp: read_u64(r)?,
            nzcv: read_u32(r)?,
        });
    }
    Ok(values)
}

fn write_summary(w: &mut impl Write, value: &AnalysisSummary) -> std::io::Result<()> {
    write_u64(w, value.record_count as u64)?;
    write_u64(w, value.unique_pc_count as u64)?;
    write_u64(w, value.dependency_edge_count as u64)?;
    write_u64(w, value.reg_dependency_edges as u64)?;
    write_u64(w, value.address_dependency_edges as u64)?;
    write_u64(w, value.mem_dependency_edges as u64)?;
    write_u64(w, value.control_dependency_edges as u64)?;
    write_u64(w, value.mem_read_count as u64)?;
    write_u64(w, value.mem_write_count as u64)?;
    write_u64(w, value.init_mem_loads as u64)?;
    write_u64(w, value.call_count as u64)?;
    write_u64(w, value.ret_count as u64)?;
    write_u64(w, value.conditional_branch_count as u64)?;
    write_u64(w, value.function_count as u64)?;
    write_u64(w, value.call_tree_max_depth as u64)?;
    write_u32(w, value.sidecar_version)
}

fn read_summary(r: &mut impl Read) -> std::io::Result<AnalysisSummary> {
    Ok(AnalysisSummary {
        record_count: read_usize_u64(r)?,
        unique_pc_count: read_usize_u64(r)?,
        dependency_edge_count: read_usize_u64(r)?,
        reg_dependency_edges: read_usize_u64(r)?,
        address_dependency_edges: read_usize_u64(r)?,
        mem_dependency_edges: read_usize_u64(r)?,
        control_dependency_edges: read_usize_u64(r)?,
        mem_read_count: read_usize_u64(r)?,
        mem_write_count: read_usize_u64(r)?,
        init_mem_loads: read_usize_u64(r)?,
        call_count: read_usize_u64(r)?,
        ret_count: read_usize_u64(r)?,
        conditional_branch_count: read_usize_u64(r)?,
        function_count: read_usize_u64(r)?,
        call_tree_max_depth: read_usize_u64(r)?,
        sidecar_version: read_u32(r)?,
    })
}

fn write_pc_summary_vec(w: &mut impl Write, values: &[PcSummary]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, value.pc)?;
        write_string(w, &value.asm)?;
        write_u64(w, value.record_count as u64)?;
        write_u64(w, value.first_idx as u64)?;
        write_u64(w, value.last_idx as u64)?;
        write_u64(w, value.mem_reads as u64)?;
        write_u64(w, value.mem_writes as u64)?;
        write_u64(w, value.calls as u64)?;
        write_u64(w, value.rets as u64)?;
        write_u64(w, value.conditional_branches as u64)?;
    }
    Ok(())
}

fn read_pc_summary_vec(r: &mut impl Read) -> std::io::Result<Vec<PcSummary>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(PcSummary {
            pc: read_u64(r)?,
            asm: read_string(r)?,
            record_count: read_usize_u64(r)?,
            first_idx: read_usize_u64(r)?,
            last_idx: read_usize_u64(r)?,
            mem_reads: read_usize_u64(r)?,
            mem_writes: read_usize_u64(r)?,
            calls: read_usize_u64(r)?,
            rets: read_usize_u64(r)?,
            conditional_branches: read_usize_u64(r)?,
        });
    }
    Ok(values)
}

fn write_function_summary_vec(
    w: &mut impl Write,
    values: &[FunctionSummary],
) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, value.fn_pc)?;
        write_optional_string(w, value.fn_name.as_deref())?;
        write_u64(w, value.call_count as u64)?;
        write_u64(w, value.total_records as u64)?;
        write_u64(w, value.first_enter_idx as u64)?;
        write_u64(w, value.last_exit_idx as u64)?;
        write_u64(w, value.max_depth as u64)?;
    }
    Ok(())
}

fn read_function_summary_vec(r: &mut impl Read) -> std::io::Result<Vec<FunctionSummary>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(FunctionSummary {
            fn_pc: read_u64(r)?,
            fn_name: read_optional_string(r)?,
            call_count: read_usize_u64(r)?,
            total_records: read_usize_u64(r)?,
            first_enter_idx: read_usize_u64(r)?,
            last_exit_idx: read_usize_u64(r)?,
            max_depth: read_usize_u64(r)?,
        });
    }
    Ok(values)
}

fn trace_fingerprint(trace: &Trace) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    const SAMPLE: usize = 4096;

    fn mix(mut h: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    fn mix_u64(h: u64, value: u64) -> u64 {
        mix(h, &value.to_le_bytes())
    }

    let raw = trace.raw();
    let len = raw.len();
    let mut h = mix_u64(FNV_OFFSET, len as u64);
    if len == 0 {
        return h;
    }
    let mid = len.saturating_sub(SAMPLE) / 2;
    let ranges = [
        (0usize, len.min(SAMPLE)),
        (mid, (mid + SAMPLE).min(len)),
        (len.saturating_sub(SAMPLE), len),
    ];
    for (start, end) in ranges {
        h = mix_u64(h, start as u64);
        h = mix(h, &raw[start..end]);
    }
    h
}

fn symbols_fingerprint(symbols: &SymbolMap) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn mix(mut h: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    fn mix_u64(h: u64, value: u64) -> u64 {
        mix(h, &value.to_le_bytes())
    }

    fn mix_opt_u64(h: u64, value: Option<u64>) -> u64 {
        match value {
            Some(value) => mix_u64(mix(h, &[1]), value),
            None => mix(h, &[0]),
        }
    }

    fn mix_opt_str(h: u64, value: Option<&str>) -> u64 {
        match value {
            Some(value) => mix(mix_u64(mix(h, &[1]), value.len() as u64), value.as_bytes()),
            None => mix(h, &[0]),
        }
    }

    let mut h = mix_u64(FNV_OFFSET, symbols.len() as u64);
    for entry in symbols.iter_entries() {
        h = mix_u64(h, entry.pc);
        h = mix(mix_u64(h, entry.name.len() as u64), entry.name.as_bytes());
        h = mix_opt_str(h, entry.module.as_deref());
        h = mix_opt_u64(h, entry.module_base);
        h = mix_opt_u64(h, entry.module_end);
    }
    h
}

fn write_u64_vec(w: &mut impl Write, values: &[u64]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, *value)?;
    }
    Ok(())
}

fn read_u64_vec(r: &mut impl Read) -> std::io::Result<Vec<u64>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_u64(r)?);
    }
    Ok(values)
}

fn write_bytes(w: &mut impl Write, values: &[u8]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    w.write_all(values)
}

fn read_bytes(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    const MAX_BYTES: usize = 128 * 1024 * 1024;
    let len = read_len(r)?;
    if len > MAX_BYTES {
        return Err(invalid_data("analysis sidecar blob too large"));
    }
    let mut values = vec![0u8; len];
    r.read_exact(&mut values)?;
    Ok(values)
}

fn write_optional_string(w: &mut impl Write, value: Option<&str>) -> std::io::Result<()> {
    match value {
        Some(value) => {
            w.write_all(&[1])?;
            write_string(w, value)
        }
        None => w.write_all(&[0]),
    }
}

fn read_optional_string(r: &mut impl Read) -> std::io::Result<Option<String>> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    match tag[0] {
        0 => Ok(None),
        1 => Ok(Some(read_string(r)?)),
        _ => Err(invalid_data("bad analysis sidecar option tag")),
    }
}

fn write_string(w: &mut impl Write, s: &str) -> std::io::Result<()> {
    write_u64(w, s.len() as u64)?;
    w.write_all(s.as_bytes())
}

fn read_string(r: &mut impl Read) -> std::io::Result<String> {
    const MAX_STRING_BYTES: usize = 16 * 1024;
    let len = read_len(r)?;
    if len > MAX_STRING_BYTES {
        return Err(invalid_data("analysis sidecar string too large"));
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid_data("analysis sidecar string is not utf-8"))
}

fn write_u32(w: &mut impl Write, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u64(w: &mut impl Write, v: u64) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u32(r: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(r: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_len(r: &mut impl Read) -> std::io::Result<usize> {
    read_usize_u64(r)
}

fn read_usize_u64(r: &mut impl Read) -> std::io::Result<usize> {
    let v = read_u64(r)?;
    usize::try_from(v).map_err(|_| invalid_data("analysis sidecar usize overflow"))
}

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}
