//! Hash finalize output-region heuristics.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::memshadow::MemShadow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashFinalizeCandidate {
    pub addr: String,
    pub size: u64,
    pub enter_idx: usize,
    pub exit_idx: usize,
    pub kind: &'static str,
    pub guess: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct WriteRunEntry {
    idx: usize,
    addr: u64,
    size: u64,
}

pub fn hash_finalize_detect(
    memshadow: &MemShadow,
    window: usize,
    min_size: u64,
) -> Vec<HashFinalizeCandidate> {
    let mut writes = memshadow
        .writes
        .iter()
        .map(|w| WriteRunEntry {
            idx: w.idx,
            addr: w.addr,
            size: w.size as u64,
        })
        .collect::<Vec<_>>();
    writes.sort_by_key(|w| w.addr);

    let mut candidates = Vec::new();
    let mut i = 0usize;
    while i < writes.len() {
        let run_start = writes[i].addr;
        let mut run_end = writes[i].addr.saturating_add(writes[i].size);
        let mut run_min_idx = writes[i].idx;
        let mut run_max_idx = writes[i].idx;
        let mut run_sizes = BTreeSet::from([writes[i].size]);
        let mut j = i + 1;
        while j < writes.len() && writes[j].addr == run_end {
            run_end = writes[j].addr.saturating_add(writes[j].size);
            run_min_idx = run_min_idx.min(writes[j].idx);
            run_max_idx = run_max_idx.max(writes[j].idx);
            run_sizes.insert(writes[j].size);
            j += 1;
        }
        let run_size = run_end.saturating_sub(run_start);
        let run_window = run_max_idx.saturating_sub(run_min_idx);
        if run_size >= min_size && run_window <= window {
            let kind = if run_sizes.len() == 1 && run_sizes.contains(&4) && run_size >= 20 {
                "u32x5"
            } else if run_sizes.len() == 1 && run_sizes.contains(&1) {
                "byte_seq"
            } else {
                "mixed"
            };
            candidates.push(HashFinalizeCandidate {
                addr: format!("{run_start:#x}"),
                size: run_size,
                enter_idx: run_min_idx,
                exit_idx: run_max_idx,
                kind,
                guess: digest_size_to_guess(run_size),
            });
        }
        i = j;
    }
    candidates
}

fn digest_size_to_guess(size: u64) -> Option<&'static str> {
    match size {
        16 => Some("md5"),
        20 => Some("sha1"),
        28 => Some("sha224"),
        32 => Some("sha256"),
        64 => Some("sha512"),
        _ => None,
    }
}
