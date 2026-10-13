//! 双向依赖查询共享的种子参数与解析。
use crate::analysis::context::AnalysisContext;
use crate::analysis::seed_resolver::{resolve_addr, resolve_reg, split_csv, ResolvedSeed};
use serde::{Deserialize, Serialize};

const DEFAULT_LIMIT: usize = 5_000;
const MAX_SEEDS: usize = 16;

#[derive(Debug, Deserialize)]
pub struct DependencySeeds {
    pub idx: Option<usize>,
    pub idxs: Option<String>,
    pub reg: Option<String>,
    pub regs: Option<String>,
    pub addr: Option<String>,
    pub addrs: Option<String>,
    pub before: Option<usize>,
    #[serde(default)]
    pub data_only: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub mode: Option<String>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize, Default)]
pub struct EdgeStats {
    pub reg: usize,
    pub address: usize,
    pub mem: usize,
    pub control: usize,
    pub total: usize,
}

pub(crate) fn resolve_all_seeds(
    state: &AnalysisContext,
    q: &DependencySeeds,
    before: usize,
) -> Vec<ResolvedSeed> {
    let mut seeds: Vec<ResolvedSeed> = Vec::new();

    let push = |seeds: &mut Vec<ResolvedSeed>, seed: ResolvedSeed| -> bool {
        if seeds.len() >= MAX_SEEDS {
            return false;
        }
        seeds.push(seed);
        true
    };

    if let Some(idx) = q.idx {
        push(&mut seeds, ResolvedSeed::for_idx(idx, None, q.before));
    }
    if let Some(idxs_raw) = q.idxs.as_deref() {
        for token in split_csv(idxs_raw) {
            if !push(&mut seeds, ResolvedSeed::for_idx_token(token, q.before)) {
                break;
            }
        }
    }
    if let Some(reg) = q.reg.as_deref() {
        push(&mut seeds, resolve_reg(state, reg, before));
    }
    if let Some(regs_raw) = q.regs.as_deref() {
        for token in split_csv(regs_raw) {
            if !push(&mut seeds, resolve_reg(state, token, before)) {
                break;
            }
        }
    }
    if let Some(addr) = q.addr.as_deref() {
        push(&mut seeds, resolve_addr(state, addr, before));
    }
    if let Some(addrs_raw) = q.addrs.as_deref() {
        for token in split_csv(addrs_raw) {
            if !push(&mut seeds, resolve_addr(state, token, before)) {
                break;
            }
        }
    }
    seeds
}

impl Default for DependencySeeds {
    fn default() -> Self {
        Self {
            idx: Default::default(),
            idxs: Default::default(),
            reg: Default::default(),
            regs: Default::default(),
            addr: Default::default(),
            addrs: Default::default(),
            before: Default::default(),
            data_only: Default::default(),
            limit: default_limit(),
            mode: Default::default(),
        }
    }
}
