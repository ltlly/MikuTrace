//! OLLVM VM dispatcher detection (heuristic). Direct port of
//! viewer/ollvmdet.py.
//!
//! Looks for the classic obfuscation pattern:
//!   while (1) { op = bytecode[ip++]; handler = table[op]; goto handler; }
//!
//! Scoring:
//!   +0.4 indirect br/blr seen
//!   +0.3 ldr [..,lsl #3] table-load near a br
//!   +0.2 self-update load (ldrh/ldrb/ldr w/ `!` writeback)
//!   +0.1 high-frequency indirect (>= 5× min_entries hits)
//!
//! Output: heuristic candidate list. NEVER decode VM bytecode.

use std::collections::HashMap;

use serde::Serialize;

use crate::disasm::decode;
use crate::index::Index;
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize)]
pub struct OllvmFinding {
    /// First-seen indirect br PC (anchor for the dispatcher).
    pub fn_pc: u64,
    /// Total indirect br/blr hits in the trace.
    pub entry_count: u64,
    /// Confidence in [0.0, 1.0]; rounded to 2 decimals.
    pub confidence: f64,
    /// Human-readable reasons (joined by " + " in Python; we keep as Vec).
    pub reasons: Vec<String>,
    /// User-facing hint string (matches Python "hint" key).
    pub hint: String,
}

/// Detect OLLVM VM dispatcher candidates in the trace.
///
/// `min_entries`: minimum indirect-branch count required before scoring.
/// `conf_threshold`: minimum final confidence to emit a finding.
///
/// Returns a `Vec` (typically 0 or 1 entries; Python returns [] or [{...}]).
pub fn ollvm_detect_vm(
    trace: &Trace,
    min_entries: usize,
    conf_threshold: f64,
) -> Vec<OllvmFinding> {
    let n = trace.len();
    if n < min_entries {
        return Vec::new();
    }

    let mut indirect_total: u64 = 0;
    let mut table_load_total: u64 = 0;
    let mut self_update_total: u64 = 0;
    let mut indirect_pc_first: HashMap<u64, usize> = HashMap::new();

    for i in 0..n {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        let m = d.mnemonic.as_str();
        if m == "br" || m == "blr" {
            indirect_total += 1;
            indirect_pc_first.entry(pc).or_insert(i);
            // Look back ≤ 4 insns for table-load + self-update pattern.
            let lo = i.saturating_sub(4);
            for j in lo..i {
                let pc_j = trace.pc(j);
                let inst_j = trace.inst(j);
                let dj = decode(pc_j, inst_j);
                let op_str = dj.op_str.to_lowercase();
                if dj.mnemonic == "ldr" && op_str.contains("lsl #3") {
                    table_load_total += 1;
                }
                if op_str.contains('!')
                    && (dj.mnemonic == "ldrh" || dj.mnemonic == "ldrb" || dj.mnemonic == "ldr")
                {
                    self_update_total += 1;
                }
            }
        }
    }

    score_ollvm_finding(
        min_entries,
        conf_threshold,
        indirect_total,
        table_load_total,
        self_update_total,
        &indirect_pc_first,
    )
}

/// Same heuristic as [`ollvm_detect_vm`], but uses the startup PC index to
/// decode unique PCs first and only walks records that are actually indirect
/// branch hits. This preserves the observable scoring while avoiding a full
/// trace decode pass on multi-million-record traces.
pub fn ollvm_detect_vm_indexed(
    trace: &Trace,
    index: &Index,
    min_entries: usize,
    conf_threshold: f64,
) -> Vec<OllvmFinding> {
    let n = trace.len();
    if n < min_entries {
        return Vec::new();
    }

    let mut indirect_total: u64 = 0;
    let mut table_load_total: u64 = 0;
    let mut self_update_total: u64 = 0;
    let mut indirect_pc_first: HashMap<u64, usize> = HashMap::new();
    let mut indirect_groups: Vec<&[usize]> = Vec::new();

    for (&pc, idxs) in &index.pc_to_idxs {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let d = decode(pc, trace.inst(first_idx));
        let m = d.mnemonic.as_str();
        if m == "br" || m == "blr" {
            indirect_total += idxs.len() as u64;
            indirect_pc_first.insert(pc, first_idx);
            indirect_groups.push(idxs);
        }
    }

    if indirect_total < min_entries as u64 {
        return Vec::new();
    }

    let mut lookback_cache: HashMap<(u64, u32), (bool, bool)> = HashMap::new();
    for idxs in indirect_groups {
        for &i in idxs {
            let lo = i.saturating_sub(4);
            for j in lo..i {
                let pc_j = trace.pc(j);
                let inst_j = trace.inst(j);
                let key = (pc_j, inst_j);
                let (is_table_load, is_self_update) =
                    if let Some(flags) = lookback_cache.get(&key).copied() {
                        flags
                    } else {
                        let dj = decode(pc_j, inst_j);
                        let op_str = dj.op_str.to_lowercase();
                        let flags = (
                            dj.mnemonic == "ldr" && op_str.contains("lsl #3"),
                            op_str.contains('!')
                                && (dj.mnemonic == "ldrh"
                                    || dj.mnemonic == "ldrb"
                                    || dj.mnemonic == "ldr"),
                        );
                        lookback_cache.insert(key, flags);
                        flags
                    };
                if is_table_load {
                    table_load_total += 1;
                }
                if is_self_update {
                    self_update_total += 1;
                }
            }
        }
    }

    score_ollvm_finding(
        min_entries,
        conf_threshold,
        indirect_total,
        table_load_total,
        self_update_total,
        &indirect_pc_first,
    )
}

fn score_ollvm_finding(
    min_entries: usize,
    conf_threshold: f64,
    indirect_total: u64,
    table_load_total: u64,
    self_update_total: u64,
    indirect_pc_first: &HashMap<u64, usize>,
) -> Vec<OllvmFinding> {
    if indirect_total < min_entries as u64 {
        return Vec::new();
    }

    let mut confidence: f64 = 0.4;
    let mut reasons: Vec<String> = vec!["indirect br/blr".to_string()];
    let half = (min_entries as u64) / 2;
    if table_load_total >= half {
        confidence += 0.3;
        reasons.push(format!(
            "ldr [..,lsl #3] table-load near br ({}×)",
            table_load_total
        ));
    }
    if self_update_total >= half {
        confidence += 0.2;
        reasons.push(format!(
            "self-update ldr[h/b]/[..,#N]! ({}×)",
            self_update_total
        ));
    }
    if indirect_total >= (min_entries as u64) * 5 {
        confidence += 0.1;
        reasons.push(format!("high-frequency indirect ({} hits)", indirect_total));
    }

    if confidence < conf_threshold {
        return Vec::new();
    }

    let anchor_pc = indirect_pc_first
        .iter()
        .min_by_key(|(_, &idx)| idx)
        .map(|(&pc, _)| pc)
        .unwrap_or(0);
    let confidence = (confidence * 100.0).round() / 100.0;

    vec![OllvmFinding {
        fn_pc: anchor_pc,
        entry_count: indirect_total,
        confidence,
        reasons,
        hint: "可能是 OLLVM VM dispatcher / jump-table 派发. 反向追踪建议 skip 内部, 看 VM 调用边界数据流即可.".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use crate::trace::REC_SIZE;

    fn synth_trace(pcs: &[u64], insts: &[u32]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * pcs.len()];
        for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            format!(r#"{{"records":{}}}"#, pcs.len()),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":"0x10000"}}"#,
        )
        .unwrap();
        dir
    }

    fn load(dir: &tempfile::TempDir) -> Trace {
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
        Trace::load(&cd).unwrap()
    }

    #[test]
    fn ollvm_detect_vm_empty_on_short_trace() {
        let dir = synth_trace(&[0x1000], &[0xd503201f]);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert!(findings.is_empty());
    }

    #[test]
    fn ollvm_detect_vm_empty_when_no_indirect_br() {
        // 12 records of nops - no br/blr at all.
        let pcs: Vec<u64> = (0..12u64).map(|i| 0x1000 + i * 4).collect();
        let insts = vec![0xd503201fu32; 12];
        let dir = synth_trace(&pcs, &insts);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert!(findings.is_empty(), "no br → no findings");
    }

    #[test]
    fn ollvm_detect_vm_emits_finding_when_many_indirect_brs() {
        // 20 records all `br x0` (0xd61f0000). Exercises indirect_total >= min_entries.
        let pcs: Vec<u64> = (0..20u64).map(|i| 0x1000 + i * 4).collect();
        let insts = vec![0xd61f0000u32; 20]; // br x0
        let dir = synth_trace(&pcs, &insts);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.confidence >= 0.4, "confidence: {}", f.confidence);
        assert_eq!(f.entry_count, 20);
        assert!(f.reasons.iter().any(|r| r.contains("indirect")));
        assert_eq!(f.fn_pc, 0x1000);
    }

    #[test]
    fn ollvm_detect_vm_indexed_matches_sequential() {
        let pcs: Vec<u64> = (0..20u64).map(|i| 0x1000 + i * 4).collect();
        let insts = vec![0xd61f0000u32; 20]; // br x0
        let dir = synth_trace(&pcs, &insts);
        let trace = load(&dir);
        let index = Index::build(&trace);

        let sequential = ollvm_detect_vm(&trace, 10, 0.3);
        let indexed = ollvm_detect_vm_indexed(&trace, &index, 10, 0.3);

        assert_eq!(indexed.len(), sequential.len());
        assert_eq!(indexed[0].fn_pc, sequential[0].fn_pc);
        assert_eq!(indexed[0].entry_count, sequential[0].entry_count);
        assert_eq!(indexed[0].confidence, sequential[0].confidence);
        assert_eq!(indexed[0].reasons, sequential[0].reasons);
    }
}
