//! Unified FunctionIndex consumed by the SPA Functions panel and CLI.
//!
//! Direct port of viewer/function_index.py. Stable id format:
//!   - `trace:F0` / `trace:F1` / ...
//!   - `symaddr:<hex_addr>` for symbol/module functions
//!   - `bn:<hex_addr>`
//!
//! Legacy aliases the parser still accepts:
//!   - bare `F0` → ("trace", "F0")
//!   - `cfg:<name>` → ("sym", "<name>")

use std::collections::BTreeMap;

use serde::Serialize;

const TRACE_PREFIX: &str = "trace:";
const SYM_PREFIX: &str = "sym:";
const SYMADDR_PREFIX: &str = "symaddr:";
const BN_PREFIX: &str = "bn:";
const LEGACY_CFG_PREFIX: &str = "cfg:";

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("empty fn_id")]
    Empty,
    #[error("empty {0} payload: {1:?}")]
    EmptyPayload(&'static str, String),
    #[error("bn payload is not valid hex: {0:?}")]
    BnNotHex(String),
    #[error("symaddr payload is not valid hex: {0:?}")]
    SymAddrNotHex(String),
    #[error("unrecognized fn_id: {0:?}")]
    Unrecognized(String),
}

pub fn parse_id(fn_id: &str) -> Result<(String, String), ParseError> {
    if fn_id.is_empty() {
        return Err(ParseError::Empty);
    }
    if let Some(payload) = fn_id.strip_prefix(TRACE_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("trace", fn_id.to_string()));
        }
        return Ok(("trace".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(SYM_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("sym", fn_id.to_string()));
        }
        return Ok(("sym".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(SYMADDR_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("symaddr", fn_id.to_string()));
        }
        let hex_part = payload.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex_part, 16)
            .map_err(|_| ParseError::SymAddrNotHex(fn_id.to_string()))?;
        return Ok(("symaddr".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(BN_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("bn", fn_id.to_string()));
        }
        let hex_part = payload.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex_part, 16).map_err(|_| ParseError::BnNotHex(fn_id.to_string()))?;
        return Ok(("bn".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(LEGACY_CFG_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("cfg", fn_id.to_string()));
        }
        return Ok(("sym".to_string(), payload.to_string()));
    }
    if let Some(rest) = fn_id.strip_prefix('F') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Ok(("trace".to_string(), fn_id.to_string()));
        }
    }
    Err(ParseError::Unrecognized(fn_id.to_string()))
}

pub fn make_trace_id(trace_ir_id: &str) -> String {
    format!("{TRACE_PREFIX}{trace_ir_id}")
}

pub fn make_sym_id(name: &str) -> String {
    format!("{SYM_PREFIX}{name}")
}

pub fn make_sym_addr_id(addr: u64) -> String {
    format!("{SYMADDR_PREFIX}{addr:#x}")
}

pub fn make_bn_id(addr: u64) -> String {
    format!("{BN_PREFIX}{addr:#x}")
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionEntry {
    pub id: String,
    pub name: String,
    pub source: String,
    pub entry_pc: Option<u64>,
    pub blocks: u32,
    pub records: u64,
    pub module: Option<String>,
    pub entry_rel: Option<u64>,
    pub trace_ir_id: Option<String>,
    pub bn_start: Option<u64>,
    pub can_llil: bool,
    pub can_bn_hlil: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FunctionIndex {
    pub entries: Vec<FunctionEntry>,
}

impl FunctionIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn by_id(&self, fn_id: &str) -> Option<&FunctionEntry> {
        let (src, payload) = parse_id(fn_id).ok()?;
        match src.as_str() {
            "trace" => self.entries.iter().find(|e| {
                e.source == "trace-ir" && e.trace_ir_id.as_deref() == Some(payload.as_str())
            }),
            "sym" => {
                let mut matches = self
                    .entries
                    .iter()
                    .filter(|e| e.source == "symbol" && e.name == payload);
                let first = matches.next()?;
                matches.next().is_none().then_some(first)
            }
            "symaddr" => {
                let addr = u64::from_str_radix(
                    payload.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()?;
                self.entries
                    .iter()
                    .find(|e| e.source == "symbol" && e.entry_pc == Some(addr))
            }
            "bn" => {
                let addr = u64::from_str_radix(
                    payload.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()?;
                self.entries
                    .iter()
                    .find(|e| e.source == "bn" && e.bn_start == Some(addr))
            }
            _ => None,
        }
    }

    pub fn by_name(&self, name: &str) -> Vec<&FunctionEntry> {
        self.entries.iter().filter(|e| e.name == name).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build a FunctionIndex from SymbolMap + optional CFG.
pub fn build_from_symbols(
    symbols: &crate::symbols::SymbolMap,
    cfg: Option<&crate::cfg::CFG>,
) -> FunctionIndex {
    let mut cfg_counts: BTreeMap<u64, (u32, u64)> = BTreeMap::new();
    if let Some(c) = cfg {
        for block in c.blocks() {
            let Some(lookup) = symbols.lookup_entry(block.start_pc) else {
                continue;
            };
            let entry = cfg_counts.entry(lookup.pc).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(block.executions);
        }
    }

    let mut entries = Vec::new();
    for entry in symbols.iter_entries() {
        let entry_rel = entry.entry_rel();
        let pc = entry.pc;
        let name = entry.name;
        let module = entry.module;
        let (blocks, records) = cfg_counts.get(&pc).copied().unwrap_or((0, 0));
        entries.push(FunctionEntry {
            id: make_sym_addr_id(pc),
            name: name.clone(),
            source: "symbol".to_string(),
            entry_pc: Some(pc),
            blocks,
            records,
            module,
            entry_rel,
            trace_ir_id: None,
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        });
    }
    FunctionIndex { entries }
}
