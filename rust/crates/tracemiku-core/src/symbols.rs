//! Symbol resolution: PC → function name + offset, PC → module.
//!
//! Direct port of `viewer/symbols.py::{SymbolMap, ModuleResolver}`.
//! Both use sorted-Vec + binary-search; sort happens via `freeze()` after
//! all `add()` calls. Lookup is `&self` (no interior mutability).

use std::collections::HashMap;

use crate::disasm::decode;
use crate::trace::{ModuleInfo, Trace};

/// Lookup PC → (function-name, offset-within).
#[derive(Debug, Default, Clone)]
pub struct SymbolMap {
    functions: Vec<(u64, String)>,
    sorted: bool,
}

impl SymbolMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function entry. Caller MUST call `freeze()` before any `lookup`
    /// calls to ensure the binary search sees sorted data.
    pub fn add(&mut self, pc: u64, name: String) {
        self.functions.push((pc, name));
        self.sorted = false;
    }

    /// Sort the function list. Idempotent. Call once after all `add`s.
    pub fn freeze(&mut self) {
        if !self.sorted {
            self.functions.sort_by_key(|(pc, _)| *pc);
            self.sorted = true;
        }
    }

    /// `(name, offset_in_func)`. Returns `("?", 0)` if `pc` is before any
    /// known function or no functions exist. Caller must have called
    /// `freeze()` after all adds.
    pub fn lookup(&self, pc: u64) -> (String, u64) {
        if self.functions.is_empty() {
            return ("?".to_string(), 0);
        }
        let funcs = &self.functions;
        // partition_point: rightmost index where start_pc <= pc.
        let i = funcs.partition_point(|(start, _)| *start <= pc);
        if i == 0 {
            return ("?".to_string(), 0);
        }
        let (start, ref name) = funcs[i - 1];
        (name.clone(), pc.wrapping_sub(start))
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Iterate over `(start_pc, name)` pairs in sorted order.
    /// Caller must have called `freeze()`.
    pub fn iter_functions(&self) -> impl Iterator<Item = (u64, String)> + '_ {
        self.functions.iter().map(|(pc, name)| (*pc, name.clone()))
    }
}

/// Build a SymbolMap from per-call meta.json::known_offsets and run-meta
/// `module` info. `base` is the primary-module base PC; offsets in the
/// known_offsets dict are RELATIVE to that base (per-call meta.json contract).
pub fn build_from_trace(
    trace: &Trace,
    base: u64,
    known_offsets: &HashMap<u64, String>,
) -> SymbolMap {
    let _ = trace; // M2-γ doesn't use the trace bytes; reserved for M2-δ
                   // when auto_known_offsets walks call instructions.
    let mut m = SymbolMap::new();
    for (off, name) in known_offsets {
        m.add(base.wrapping_add(*off), name.clone());
    }
    m.freeze();
    m
}

/// Resolve PC → primary module (or any module) by base+size range.
#[derive(Debug, Default, Clone)]
pub struct ModuleResolver {
    modules: Vec<ModuleResolverEntry>,
}

#[derive(Debug, Clone)]
struct ModuleResolverEntry {
    base: u64,
    end: u64,
    name: String,
    size: u64,
    base_str: String,
    end_str: String,
}

impl ModuleResolver {
    pub fn from_modules(modules: &[ModuleInfo]) -> Self {
        let mut entries: Vec<ModuleResolverEntry> = modules
            .iter()
            .map(|m| {
                let base = u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0);
                ModuleResolverEntry {
                    base,
                    end: base.wrapping_add(m.size),
                    name: m.name.clone(),
                    size: m.size,
                    base_str: m.base.clone(),
                    end_str: m.end.clone(),
                }
            })
            .collect();
        entries.sort_by_key(|e| e.base);
        Self { modules: entries }
    }

    /// PC → ModuleInfo (first module whose [base, end) contains pc).
    pub fn resolve(&self, pc: u64) -> Option<ModuleInfo> {
        self.modules
            .iter()
            .find(|m| m.base <= pc && pc < m.end)
            .map(|m| ModuleInfo {
                name: m.name.clone(),
                base: m.base_str.clone(),
                size: m.size,
                end: m.end_str.clone(),
            })
    }

    /// PC → module name (or None).
    pub fn resolve_name(&self, pc: u64) -> Option<String> {
        self.resolve(pc).map(|m| m.name)
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }
}

/// Walk the trace looking for `bl <target>` instructions; each unique target
/// becomes a synthetic function entry. Names follow IDA/Hex-Rays
/// `sub_<hex>` convention (parity with `viewer/symbols.py:241`).
///
/// Returns map keyed by ABSOLUTE PC. Use [`auto_known_offsets_with_base`]
/// to get module-relative keys.
pub fn auto_known_offsets(trace: &Trace) -> HashMap<u64, String> {
    auto_known_offsets_with_base(trace, 0)
}

/// Same as [`auto_known_offsets`] but keys are relative to `base`. Useful
/// for merging into a static known_offsets dict (which uses module-relative
/// hex keys per the per-call meta.json contract).
pub fn auto_known_offsets_with_base(trace: &Trace, base: u64) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let n = trace.len();
    for i in 0..n {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        if !d.is_call {
            continue;
        }
        let Some(target) = parse_branch_target(&d.op_str) else {
            continue;
        };
        let key = target.wrapping_sub(base);
        out.entry(key).or_insert_with(|| format!("sub_{key:x}"));
    }
    out
}

/// Parse a hex address from capstone's op_str (e.g. "0x100100" or "#0x100100").
/// Returns None for non-hex / indirect targets.
fn parse_branch_target(op_str: &str) -> Option<u64> {
    let s = op_str.trim().trim_start_matches('#');
    let token = s.split([',', ' ']).next()?;
    if !token.starts_with("0x") && !token.starts_with("0X") {
        return None;
    }
    u64::from_str_radix(token.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}
