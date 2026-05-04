//! TraceIR builder.
//!
//! M3-δ shipped a skeleton (root F0 only). M3-ε adds split_top_k_callees:
//! flattens the calltree, ranks bl-targets by total records covered,
//! promotes top-K above min_records to standalone F1..Fn FuncIR entries
//! (metadata only — BlockIR construction defers to M3-ζ).
//!
//! Mirrors viewer/decompiler/builder.py:34-287.

use crate::calltree::{build_call_tree, CallNode};
use crate::cfg::CFG;
use crate::decompiler::ir::{BlockIR, FuncIR, TopIR};
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
fn build_block_ids(cfg: &CFG) -> std::collections::HashMap<u64, String> {
    use std::collections::HashMap;
    let mut blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    blocks.sort_by_key(|b| b.start_pc);
    let mut map: HashMap<u64, String> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        map.insert(b.start_pc, format!("B{i}"));
    }
    map
}

/// Build one BlockIR with id/pc/end_pc/insns/exec_count.
/// M3-ζ scope: exits / samples / asm / tier use Default values
/// (empty Vec / HashMap / String / "hot"). M3-η fills them.
fn make_block_ir(block: &crate::cfg::Block, id: String) -> BlockIR {
    // ARM64 fixed-width 4-byte instructions. insns = (end_pc - start_pc) / 4 + 1
    // (inclusive end_pc).
    let span = block.end_pc.saturating_sub(block.start_pc);
    let insns = (span / 4 + 1) as u32;
    BlockIR {
        id,
        pc: block.start_pc,
        end_pc: block.end_pc,
        insns,
        exec_count: block.executions,
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
    top_k: usize,
    min_records: usize,
) {
    use std::collections::{HashMap, HashSet};

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

    let tree = build_call_tree(trace, sym, 50);
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

        // Collect unique PCs in any instance range.
        let mut hit_pcs: HashSet<u64> = HashSet::new();
        for inst in &instances {
            let lo = inst.enter_idx;
            let hi = std::cmp::min(inst.exit_idx, trace.len().saturating_sub(1));
            for i in lo..=hi {
                hit_pcs.insert(trace.pc(i));
            }
        }

        // Intersect with cfg block start_pcs; skip if no blocks (Python:179).
        let mut own_block_pcs: Vec<u64> =
            hit_pcs.intersection(&cfg_block_pcs).copied().collect();
        own_block_pcs.sort();

        let own_blocks: Vec<BlockIR> = own_block_pcs
            .into_iter()
            .filter_map(|pc| {
                let block = cfg_block_lookup.get(&pc)?;
                let id = block_ids
                    .get(&pc)
                    .cloned()
                    .unwrap_or_else(|| format!("B?{pc:x}"));
                Some(make_block_ir(block, id))
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

/// Internal: emit just the root F0 FuncIR + metadata.
///
/// Extracted from the M3-δ skeleton body to make split_top_k_callees
/// orthogonal. Public callers go through `build_trace_ir`.
fn build_root_only(trace: &Trace, meta: &TraceMeta, sym: &SymbolMap, cfg: &CFG) -> TopIR {
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
            make_block_ir(b, id)
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

/// Build a TopIR from a loaded Trace.
///
/// `top_k`: max number of bl-target callees to promote to standalone
///   FuncIR entries (F1..Fn). 0 = root only (skeleton M3-δ behavior).
/// `min_records`: minimum total records a callee must cover to be
///   promoted. Filters out trivial callees.
///
/// Defaults match Python webui: top_k=10, min_records=50
/// (`webui/server.py:2734-2735`).
pub fn build_trace_ir(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
) -> TopIR {
    let mut top = build_root_only(trace, meta, sym, cfg);
    if top_k > 0 {
        split_top_k_callees(&mut top, trace, sym, cfg, top_k, min_records);
    }
    top
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let top = build_trace_ir(&t, &m, &sym, &cfg, 0, 0);

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
        let top = build_trace_ir(&t, &m, &sym, &cfg, 0, 0);
        assert_eq!(top.fns[0].name, "sub_0", "pc0=0x100000 base=0x100000 → offset 0");
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
        let top = build_trace_ir(&t, &m, &sym, &cfg, 0, 0);
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
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 10, 3);
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
    fn build_trace_ir_top_k_zero_skips_callee_splits() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 3);
        assert_eq!(top.fns.len(), 1, "top_k=0 → root only; got {top:?}");
        assert_eq!(top.fns[0].id, "F0");
    }

    #[test]
    fn build_trace_ir_emits_block_ir_with_stable_ids() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        assert_eq!(top.fns.len(), 1);
        let f0 = &top.fns[0];
        assert!(!f0.blocks.is_empty(), "F0 must carry CFG blocks; got {f0:?}");
        for blk in &f0.blocks {
            assert!(
                blk.id.starts_with('B'),
                "block id must start with B; got {:?}",
                blk.id
            );
            assert!(blk.insns >= 1, "block insns count >= 1; got {blk:?}");
        }
        // IDs are stable across builds.
        let top2 = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        let ids1: Vec<String> = f0.blocks.iter().map(|b| b.id.clone()).collect();
        let ids2: Vec<String> = top2.fns[0].blocks.iter().map(|b| b.id.clone()).collect();
        assert_eq!(ids1, ids2, "block ids must be stable across builds");
    }
}
