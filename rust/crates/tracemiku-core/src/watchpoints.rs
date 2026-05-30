//! Trace watchpoint scans.

use serde::Serialize;

use crate::disasm::normalize_disasm_reg;
use crate::prelude::Index;
use crate::trace::Trace;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchpointSpec {
    RegChange { reg: String },
    RegEquals { reg: String, value: u64 },
    MemTouch { addr: u64, size: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchpointHit {
    pub idx: usize,
    pub kind: &'static str,
    pub reg: Option<String>,
    pub addr: Option<u64>,
    pub value: Option<u64>,
    pub previous: Option<u64>,
    pub pc: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchpointScan {
    pub status: &'static str,
    pub returned: usize,
    pub total_matches: usize,
    pub truncated: bool,
    pub hits: Vec<WatchpointHit>,
}

pub fn watchpoint_scan(
    trace: &Trace,
    index: &Index,
    spec: &WatchpointSpec,
    cursor: usize,
    limit: usize,
) -> WatchpointScan {
    let limit = limit.max(1);
    match spec {
        WatchpointSpec::RegChange { reg } => scan_reg_change(trace, reg, cursor, limit),
        WatchpointSpec::RegEquals { reg, value } => scan_reg_equals(trace, reg, *value, cursor, limit),
        WatchpointSpec::MemTouch { addr, size } => scan_mem_touch(trace, index, *addr, *size, cursor, limit),
    }
}

fn scan_reg_change(trace: &Trace, reg: &str, cursor: usize, limit: usize) -> WatchpointScan {
    let reg = canonical_reg(reg);
    let mut hits = Vec::new();
    let mut total_matches = 0usize;
    let mut prev = None;
    for idx in 0..trace.len() {
        let value = trace.record(idx).reg_by_name(&reg);
        if idx == 0 {
            prev = value;
            continue;
        }
        if idx < cursor {
            prev = value;
            continue;
        }
        if value != prev {
            if total_matches < limit {
                hits.push(WatchpointHit {
                    idx,
                    kind: "reg_change",
                    reg: Some(reg.clone()),
                    addr: None,
                    value,
                    previous: prev,
                    pc: trace.pc(idx),
                });
            }
            total_matches += 1;
        }
        prev = value;
    }
    watchpoint_response(hits, total_matches, limit)
}

fn scan_reg_equals(trace: &Trace, reg: &str, value: u64, cursor: usize, limit: usize) -> WatchpointScan {
    let reg = canonical_reg(reg);
    let mut hits = Vec::new();
    let mut total_matches = 0usize;
    for idx in cursor..trace.len() {
        let observed = trace.record(idx).reg_by_name(&reg);
        if observed != Some(value) {
            continue;
        }
        if total_matches < limit {
            hits.push(WatchpointHit {
                idx,
                kind: "reg_equals",
                reg: Some(reg.clone()),
                addr: None,
                value: observed,
                previous: None,
                pc: trace.pc(idx),
            });
        }
        total_matches += 1;
    }
    watchpoint_response(hits, total_matches, limit)
}

fn scan_mem_touch(
    trace: &Trace,
    index: &Index,
    addr: u64,
    size: u64,
    cursor: usize,
    limit: usize,
) -> WatchpointScan {
    let size = size.max(1);
    let mut idxs = Vec::new();
    for byte in addr..addr.saturating_add(size) {
        if let Some(writes) = index.mem_addr_to_writes.get(&byte) {
            idxs.extend(writes.iter().copied().filter(|idx| *idx >= cursor));
        }
        if let Some(reads) = index.mem_addr_to_reads.get(&byte) {
            idxs.extend(reads.iter().copied().filter(|idx| *idx >= cursor));
        }
    }
    idxs.sort_unstable();
    idxs.dedup();
    let total_matches = idxs.len();
    let hits = idxs
        .into_iter()
        .take(limit)
        .map(|idx| WatchpointHit {
            idx,
            kind: "mem_touch",
            reg: None,
            addr: Some(addr),
            value: None,
            previous: None,
            pc: trace.pc(idx),
        })
        .collect::<Vec<_>>();
    watchpoint_response(hits, total_matches, limit)
}

fn watchpoint_response(hits: Vec<WatchpointHit>, total_matches: usize, limit: usize) -> WatchpointScan {
    WatchpointScan {
        status: "ready",
        returned: hits.len(),
        total_matches,
        truncated: total_matches > limit,
        hits,
    }
}

fn canonical_reg(reg: &str) -> String {
    let canon = normalize_disasm_reg(reg);
    if canon.is_empty() {
        reg.trim().to_ascii_lowercase()
    } else {
        canon
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::Index;
    use crate::trace::Record;

    #[test]
    fn reg_change_reports_transitions() {
        let mut r1 = Record::zero(0x1004);
        r1.set_gpr(0, 7);
        let dir = tempfile::tempdir().unwrap();
        write_trace(dir.path(), &[Record::zero(0x1000), r1]);
        let trace = Trace::load(dir.path()).unwrap();
        let index = Index::build(&trace);
        let scan = watchpoint_scan(
            &trace,
            &index,
            &WatchpointSpec::RegChange { reg: "x0".into() },
            0,
            10,
        );
        assert!(scan.hits.iter().any(|hit| hit.idx == 1 && hit.value == Some(7)));
    }

    fn write_trace(path: &std::path::Path, records: &[Record]) {
        let mut bytes = Vec::new();
        for rec in records.iter().copied() {
            bytes.extend_from_slice(bytemuck::bytes_of(&rec));
        }
        std::fs::write(path.join("trace.bin"), bytes).unwrap();
    }
}
