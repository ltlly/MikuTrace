//! 由运行时证据组合的输出回溯、VM、lineage 与采集目录报告。
use super::{AnalysisContext, Query};
use anyhow::{bail, Context};
use base64::alphabet::STANDARD as BASE64_STANDARD_ALPHABET;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};
mod output_provenance;
use output_provenance::*;
mod output_backtrace;
use output_backtrace::*;
mod backtrace_patterns;
use backtrace_patterns::*;
mod backtrace_step;
use backtrace_step::*;
mod backtrace_rows;
use backtrace_rows::*;
mod backtrace_gaps;
use backtrace_gaps::*;
mod lineage_batch;
mod lineage_chain;
use lineage_chain::*;
mod lineage_tree;
use lineage_tree::*;
mod lineage_bytes;
use lineage_bytes::*;
mod lineage_compact;
use lineage_compact::*;
mod vm_replay;
mod vm_templates;
use vm_templates::*;
mod vm_effects;
use vm_effects::*;
mod writer_sources;
use writer_sources::*;
mod writer_map;
use writer_map::*;
mod evidence_queries;
use evidence_queries::*;
mod catalog;
use catalog::*;
pub mod output_types;
use output_types::*;
pub mod output_vm;
use output_vm::*;
pub mod output_lineage;
pub use catalog::info;
pub use catalog::list_calls;
pub use catalog::list_runs;
pub use catalog::parse_hex_bytes_cli;
pub use catalog::resolve_map_addr;
pub use catalog::split_csv;
pub use evidence_queries::resolve_offset_to_idx;
pub use lineage_batch::byte_lineage;
pub use lineage_batch::vm_backstep;
pub use lineage_chain::vm_backchain;
pub use lineage_chain::vm_backtree;
pub use output_backtrace::output_backtrace;
pub use output_backtrace::OutputBacktraceOpts;
use output_lineage::*;
pub use vm_replay::vm_ops;
pub use vm_replay::vm_slice;

const GAP_SCAN_REGS: &str =
    "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp";
const GAP_SCAN_CHUNK: usize = 500;
const GAP_SCAN_MAX_RECORDS: usize = 5000;
const GAP_SCAN_MAX_CANDIDATES: usize = 12;
const GAP_ARG_STRUCT_SPAN: u64 = 0x400;
const GAP_NEAR_REG_SPAN: u64 = 0x100;
const GAP_SMALL_LEN_MAX: u64 = 0x4000;

#[derive(Clone, Debug)]
pub struct VmProfile {
    ip_reg: String,
    state_reg: String,
    dispatch_reg: String,
    slot_bytes: std::num::NonZeroU64,
    infra_regs: HashSet<String>,
    regfile_range: Option<(u64, u64)>,
}

impl VmProfile {
    pub fn new(
        ip_reg: String,
        state_reg: String,
        dispatch_reg: String,
        slot_bytes: std::num::NonZeroU64,
        infra_regs: String,
    ) -> anyhow::Result<Self> {
        let ip_reg = register_value_key(&ip_reg);
        let state_reg = register_value_key(&state_reg);
        let dispatch_reg = register_value_key(&dispatch_reg);
        let infra_regs: HashSet<String> = split_csv(&infra_regs)
            .into_iter()
            .map(|reg| register_value_key(&reg))
            .chain([
                "sp".to_string(),
                "fp".to_string(),
                "lr".to_string(),
                ip_reg.clone(),
                state_reg.clone(),
                dispatch_reg.clone(),
            ])
            .collect();
        for reg in &infra_regs {
            let valid = matches!(reg.as_str(), "sp" | "fp" | "lr")
                || reg
                    .strip_prefix('x')
                    .and_then(|n| n.parse::<u8>().ok())
                    .is_some_and(|n| n <= 28);
            if !valid {
                bail!("invalid VM register: {reg}");
            }
        }
        if ip_reg == state_reg || ip_reg == dispatch_reg || state_reg == dispatch_reg {
            bail!("VM IP, state and dispatch registers must be distinct");
        }
        Ok(Self {
            ip_reg,
            state_reg,
            dispatch_reg,
            slot_bytes,
            infra_regs,
            regfile_range: None,
        })
    }

    pub fn for_lineage(
        ip_reg: Option<String>,
        state_reg: Option<String>,
        dispatch_reg: Option<String>,
        regfile: Option<String>,
    ) -> anyhow::Result<Self> {
        let ip_reg = ip_reg
            .filter(|s| !s.trim().is_empty())
            .map(|s| register_value_key(&s))
            .unwrap_or_default();
        let state_reg = state_reg
            .filter(|s| !s.trim().is_empty())
            .map(|s| register_value_key(&s))
            .unwrap_or_default();
        let dispatch_reg = dispatch_reg
            .filter(|s| !s.trim().is_empty())
            .map(|s| register_value_key(&s))
            .unwrap_or_default();
        let mut infra_regs: HashSet<String> =
            ["sp".to_string(), "fp".to_string(), "lr".to_string()]
                .into_iter()
                .collect();
        for reg in [&ip_reg, &state_reg, &dispatch_reg] {
            if reg.is_empty() {
                continue;
            }
            let valid = matches!(reg.as_str(), "sp" | "fp" | "lr")
                || reg
                    .strip_prefix('x')
                    .and_then(|n| n.parse::<u8>().ok())
                    .is_some_and(|n| n <= 28);
            if !valid {
                bail!("invalid VM register: {reg}");
            }
            infra_regs.insert(reg.clone());
        }
        let regfile_range = if let Some(raw) = regfile.filter(|s| !s.trim().is_empty()) {
            let (base_raw, size_raw) = raw
                .split_once(':')
                .with_context(|| format!("--vm-regfile must be <BASE_HEX:SIZE_HEX>, got {raw}"))?;
            let base = parse_addr_str(base_raw)
                .with_context(|| format!("invalid --vm-regfile base: {base_raw}"))?;
            let size = parse_addr_str(size_raw)
                .or_else(|| parse_u64_str(size_raw))
                .with_context(|| format!("invalid --vm-regfile size: {size_raw}"))?;
            Some((base, base.saturating_add(size)))
        } else {
            None
        };
        Ok(Self {
            ip_reg,
            state_reg,
            dispatch_reg,
            slot_bytes: std::num::NonZeroU64::new(8).unwrap(),
            infra_regs,
            regfile_range,
        })
    }

    /// Placeholder used when a command runs with every VM-analysis switch off.
    pub fn disabled() -> Self {
        Self {
            ip_reg: String::new(),
            state_reg: String::new(),
            dispatch_reg: String::new(),
            slot_bytes: std::num::NonZeroU64::MIN,
            infra_regs: ["sp".into(), "fp".into(), "lr".into()]
                .into_iter()
                .collect(),
            regfile_range: None,
        }
    }

    pub(super) fn matches_regfile_addr(&self, addr: u64, state_base: Option<u64>) -> Option<u64> {
        if let Some((lo, hi)) = self.regfile_range {
            if addr >= lo && addr < hi {
                return Some(addr - lo);
            }
        }
        if let Some(base) = state_base {
            if addr >= base && addr < base.saturating_add(0x400) {
                return Some(addr - base);
            }
        }
        None
    }

    fn to_json(&self) -> serde_json::Value {
        let mut infra_regs = self.infra_regs.iter().cloned().collect::<Vec<_>>();
        infra_regs.sort();
        serde_json::json!({
            "ip_reg": self.ip_reg,
            "state_reg": self.state_reg,
            "dispatch_reg": self.dispatch_reg,
            "slot_bytes": (!self.state_reg.is_empty()).then_some(self.slot_bytes.get()),
            "infra_regs": infra_regs,
        })
    }

    fn is_infrastructure_reg(&self, reg: &str) -> bool {
        self.infra_regs.contains(&register_value_key(reg))
    }
}

#[cfg(test)]
#[path = "tests/vm_semantics.rs"]
mod vm_semantics_tests;

#[cfg(test)]
#[path = "tests/lineage.rs"]
mod lineage_tests;

#[cfg(test)]
#[path = "tests/output_semantics.rs"]
mod output_semantics_tests;

#[cfg(test)]
#[path = "tests/evidence.rs"]
mod evidence_tests;
