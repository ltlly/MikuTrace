//! Symbol resolution: PC → function name + offset, PC → module.
//!
//! Direct port of `viewer/symbols.py::{SymbolMap, ModuleResolver}`.
//! Both keep entries in a Vec (sorted by `freeze()` after inserts); lookup is
//! a linear scan. Entries are kept sorted so a future binary-search upgrade is
//! safe, but the current implementation does not binary-search.
//! all `add()` calls. Lookup is `&self` (no interior mutability).

use std::collections::HashMap;
use std::thread;

use crate::disasm::decode;
use crate::parallel;
use crate::trace::{ModuleInfo, Trace};

const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;

/// Symbol kind: function (code) or data (global variable, import stub, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
}

/// One function/symbol entry. `module_*` is optional to preserve the old
/// single-address-space behavior for callers that do not have module metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolEntry {
    pub pc: u64,
    pub name: String,
    pub module: Option<String>,
    pub module_base: Option<u64>,
    pub module_end: Option<u64>,
    pub kind: SymbolKind,
}

impl SymbolEntry {
    fn contains_pc(&self, pc: u64, module_aware: bool) -> bool {
        match (self.module_base, self.module_end) {
            (Some(base), Some(end)) => base <= pc && pc < end,
            _ if module_aware => pc == self.pc,
            _ => true,
        }
    }

    pub fn entry_rel(&self) -> Option<u64> {
        self.module_base.map(|base| self.pc.wrapping_sub(base))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolLookup {
    pub pc: u64,
    pub name: String,
    pub off: u64,
    pub module: Option<String>,
    pub module_base: Option<u64>,
    pub module_end: Option<u64>,
}

/// Lookup PC → (function-name, offset-within).
#[derive(Debug, Default, Clone)]
pub struct SymbolMap {
    functions: Vec<SymbolEntry>,
    sorted: bool,
}

impl SymbolMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function entry. Caller MUST call `freeze()` before any `lookup`
    /// calls to ensure the binary search sees sorted data.
    pub fn add(&mut self, pc: u64, name: String) {
        self.functions.push(SymbolEntry {
            pc,
            name,
            module: None,
            module_base: None,
            module_end: None,
            kind: SymbolKind::Function,
        });
        self.sorted = false;
    }

    pub fn add_with_module(&mut self, pc: u64, name: String, module: &ModuleInfo) {
        let base = parse_hex_u64(&module.base).unwrap_or(0);
        let end = parse_hex_u64(&module.end).unwrap_or_else(|| base.wrapping_add(module.size));
        self.functions.push(SymbolEntry {
            pc,
            name,
            module: Some(module.name.clone()),
            module_base: Some(base),
            module_end: Some(end),
            kind: SymbolKind::Function,
        });
        self.sorted = false;
    }

    /// Add a data symbol (global variable, import stub, etc.).
    pub fn add_data(&mut self, pc: u64, name: String) {
        self.functions.push(SymbolEntry {
            pc,
            name,
            module: None,
            module_base: None,
            module_end: None,
            kind: SymbolKind::Data,
        });
        self.sorted = false;
    }

    pub fn add_resolved(&mut self, pc: u64, name: String, modules: &ModuleResolver) {
        if let Some(module) = modules.resolve(pc) {
            self.add_with_module(pc, name, &module);
        } else {
            self.add(pc, name);
        }
    }

    pub fn has_start_pc(&self, pc: u64) -> bool {
        self.functions.iter().any(|entry| entry.pc == pc)
    }

    pub fn has_start_in_module(&self, pc: u64, module: Option<&str>) -> bool {
        self.functions.iter().any(|entry| {
            entry.pc == pc
                && match module {
                    Some(module) => entry.module.as_deref() == Some(module),
                    None => entry.module.is_none(),
                }
        })
    }

    pub fn add_entry(&mut self, entry: SymbolEntry) {
        self.functions.push(entry);
        self.sorted = false;
    }

    /// Sort the function list. Idempotent. Call once after all `add`s.
    pub fn freeze(&mut self) {
        if !self.sorted {
            self.functions.sort_by_key(|entry| entry.pc);
            self.sorted = true;
        }
    }

    pub fn lookup_entry(&self, pc: u64) -> Option<SymbolLookup> {
        if self.functions.is_empty() {
            return None;
        }
        let funcs = &self.functions;
        let module_aware = funcs.iter().any(|entry| entry.module_base.is_some());
        let mut i = funcs.partition_point(|entry| entry.pc <= pc);
        while i > 0 {
            let entry = &funcs[i - 1];
            if entry.pc <= pc && entry.contains_pc(pc, module_aware) {
                return Some(SymbolLookup {
                    pc: entry.pc,
                    name: entry.name.clone(),
                    off: pc.wrapping_sub(entry.pc),
                    module: entry.module.clone(),
                    module_base: entry.module_base,
                    module_end: entry.module_end,
                });
            }
            if let Some(end) = entry.module_end {
                if pc >= end {
                    return None;
                }
            }
            i -= 1;
        }
        None
    }

    /// `(name, offset_in_func)`. Returns `("", 0)` if `pc` is before any
    /// known function or no functions exist. Caller must have called
    /// `freeze()` after all adds.
    pub fn lookup(&self, pc: u64) -> (String, u64) {
        self.lookup_entry(pc)
            .map(|entry| (entry.name, entry.off))
            .unwrap_or_default()
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
        self.functions
            .iter()
            .map(|entry| (entry.pc, entry.name.clone()))
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = SymbolEntry> + '_ {
        self.functions.iter().cloned()
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

    pub fn resolve_relative(&self, pc: u64) -> Option<(String, u64)> {
        self.modules
            .iter()
            .find(|m| m.base <= pc && pc < m.end)
            .map(|m| (m.name.clone(), pc.wrapping_sub(m.base)))
    }

    pub fn relative_offset(&self, pc: u64) -> Option<u64> {
        self.modules
            .iter()
            .find(|m| m.base <= pc && pc < m.end)
            .map(|m| pc.wrapping_sub(m.base))
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// All module names in base order. Used to surface candidates when a
    /// `(SO, offset)` query matches zero or several loaded modules.
    pub fn module_names(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.name.clone()).collect()
    }

    /// Iterate `(name, base, end, size)` for every loaded module, base order.
    pub fn iter_modules(&self) -> impl Iterator<Item = (String, u64, u64, u64)> + '_ {
        self.modules
            .iter()
            .map(|m| (m.name.clone(), m.base, m.end, m.size))
    }

    /// Resolve a `(module-query, offset)` coordinate to an absolute PC.
    ///
    /// `query` is matched tool-neutrally against loaded module names so that a
    /// human reading `libfoo.so + 0x1234` in IDA/BN/Ghidra, or an AI that only
    /// knows the SO basename, can hand the same coordinate straight to
    /// traceMiku. Matching precedence (first non-empty set wins):
    ///   1. exact `name`            (e.g. "libfoo-1.2.3.so")
    ///   2. exact basename          (path stripped to after last '/')
    ///   3. basename starts-with    (e.g. "libfoo" → versioned ".so")
    ///   4. name contains substring (last-resort fuzzy)
    ///
    /// Returns every candidate so the caller can report ambiguity rather than
    /// silently picking the wrong module. Each tuple is `(name, base, end, pc)`
    /// where `pc = base + offset`.
    pub fn resolve_offset_candidates(
        &self,
        query: &str,
        offset: u64,
    ) -> Vec<(String, u64, u64, u64)> {
        let q = query.trim();

        let pick = |pred: &dyn Fn(&ModuleResolverEntry) -> bool| -> Vec<&ModuleResolverEntry> {
            self.modules.iter().filter(|m| pred(m)).collect()
        };

        let matches = {
            let exact = pick(&|m| m.name == q);
            if !exact.is_empty() {
                exact
            } else {
                let exact_base = pick(&|m| module_basename(&m.name) == q);
                if !exact_base.is_empty() {
                    exact_base
                } else {
                    let prefix = pick(&|m| module_basename(&m.name).starts_with(q));
                    if !prefix.is_empty() {
                        prefix
                    } else {
                        pick(&|m| m.name.contains(q))
                    }
                }
            }
        };

        matches
            .into_iter()
            .map(|m| (m.name.clone(), m.base, m.end, m.base.wrapping_add(offset)))
            .collect()
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

/// Strip a module path down to its final component (`/a/b/libc.so` → `libc.so`).
fn module_basename(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
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
    let n = trace.len();
    let workers = symbol_worker_count(n);
    if workers <= 1 {
        return auto_known_offsets_range(trace, base, 0, n);
    }
    tracing::info!(
        target: "tracemiku-core",
        records = n,
        workers,
        "discovering auto symbols in parallel"
    );

    let chunk_size = n.div_ceil(workers);
    let partials = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(n);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || auto_known_offsets_range(trace, base, start, end)));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("auto symbol worker panicked"))
            .collect::<Vec<_>>()
    });

    merge_auto_known_offset_partials(partials)
}

/// Module-aware call-target discovery. Keys are ABSOLUTE target PCs. Names use
/// the target module's relative offset when the target resolves into a module,
/// so cross-SO calls do not inherit the primary module base.
pub fn auto_known_symbols_with_modules(
    trace: &Trace,
    modules: &ModuleResolver,
) -> HashMap<u64, String> {
    let n = trace.len();
    let workers = symbol_worker_count(n);
    if workers <= 1 {
        return auto_known_symbols_range(trace, modules, 0, n);
    }
    tracing::info!(
        target: "tracemiku-core",
        records = n,
        workers,
        "discovering module-aware auto symbols in parallel"
    );

    let chunk_size = n.div_ceil(workers);
    let partials = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(n);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || auto_known_symbols_range(trace, modules, start, end)));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("auto symbol worker panicked"))
            .collect::<Vec<_>>()
    });

    merge_auto_known_offset_partials(partials)
}

/// Planned worker count for auto symbol discovery at `n` records.
pub fn symbol_worker_count(n: usize) -> usize {
    parallel::worker_count(
        n,
        "TRACEMIKU_SYMBOL_THREADS",
        PARALLEL_MIN_RECORDS,
        MIN_CHUNK_RECORDS,
    )
}

fn auto_known_offsets_range(
    trace: &Trace,
    base: u64,
    start: usize,
    end: usize,
) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for i in start..end {
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

fn merge_auto_known_offset_partials(partials: Vec<HashMap<u64, String>>) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for partial in partials {
        for (key, name) in partial {
            out.entry(key).or_insert(name);
        }
    }
    out
}

fn auto_known_symbols_range(
    trace: &Trace,
    modules: &ModuleResolver,
    start: usize,
    end: usize,
) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for i in start..end {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        if !d.is_call {
            continue;
        }
        let Some(target) = parse_branch_target(&d.op_str) else {
            continue;
        };
        let name = if let Some((_, rel)) = modules.resolve_relative(target) {
            format!("sub_{rel:x}")
        } else {
            format!("sub_{target:x}")
        };
        out.entry(target).or_insert(name);
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

#[cfg(test)]
mod resolve_offset_tests {
    use super::*;

    fn module(name: &str, base: u64, size: u64) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base: format!("{base:#x}"),
            size,
            end: format!("{:#x}", base + size),
        }
    }

    fn sample() -> ModuleResolver {
        ModuleResolver::from_modules(&[
            module("/data/app/libfoo-1.2.3.so", 0x7000_0000, 0x10_0000),
            module("/system/lib64/libc.so", 0x7100_0000, 0x8_0000),
            module("libart.so", 0x7200_0000, 0x20_0000),
        ])
    }

    #[test]
    fn exact_full_name_resolves_to_pc() {
        let r = sample();
        let c = r.resolve_offset_candidates("/data/app/libfoo-1.2.3.so", 0x1234);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].3, 0x7000_0000 + 0x1234);
    }

    #[test]
    fn basename_prefix_resolves_versioned_so() {
        // human/AI types just the stable basename prefix
        let r = sample();
        let c = r.resolve_offset_candidates("libfoo", 0x7890);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, "/data/app/libfoo-1.2.3.so");
        assert_eq!(c[0].3, 0x7000_0000 + 0x7890);
    }

    #[test]
    fn exact_basename_resolves() {
        let r = sample();
        let c = r.resolve_offset_candidates("libc.so", 0x100);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].3, 0x7100_0000 + 0x100);
    }

    #[test]
    fn unknown_module_is_empty() {
        let r = sample();
        assert!(r.resolve_offset_candidates("libdoesnotexist", 0).is_empty());
    }

    #[test]
    fn round_trip_pc_to_offset_to_pc() {
        let r = sample();
        let pc = 0x7000_0000 + 0x1234;
        let (name, off) = r.resolve_relative(pc).unwrap();
        let back = r.resolve_offset_candidates(&name, off);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].3, pc);
    }

    #[test]
    fn iter_modules_lists_all() {
        let r = sample();
        assert_eq!(r.iter_modules().count(), 3);
        assert_eq!(r.module_names().len(), 3);
    }
}
