use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::cfg::build_cfg;
use crate::disasm::decode;
use crate::forward_dep_tree::DependencyUsers;
use crate::prelude::{
    build_call_tree_indexed, build_frame_depth_map, build_function_index, AnalysisIndex, CallNode,
    FunctionIndex, Index, MemShadow, ModuleResolver, SymbolMap, Trace, TraceMeta, CFG,
};
use crate::symbols::auto_known_symbols_with_modules;

use crate::analysis::jni_scan::{scan_jni_calls, JniCallScan};
use crate::analysis::parse::parse_dec_u64;

/// Cached register timelines: reg name → ordered (record_idx, value) pairs.
pub(crate) type RegTimelineCache = HashMap<String, Arc<Vec<(usize, u64)>>>;

#[derive(Clone)]
pub struct AnalysisContext {
    pub inner: Arc<AnalysisData>,
}

pub struct AnalysisData {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
    index: OnceLock<Index>,
    symbols: OnceLock<SymbolMap>,
    pub modules: ModuleResolver,
    cfg: OnceLock<CFG>,
    function_index: OnceLock<FunctionIndex>,
    analysis_index: OnceLock<AnalysisIndex>,
    dep_users: OnceLock<DependencyUsers>,
    memshadow: OnceLock<MemShadow>,
    call_tree: OnceLock<CallNode>,
    call_tree_depth_cache: Mutex<HashMap<usize, CallNode>>,
    frame_depths: OnceLock<Vec<u32>>,
    backtrace_events: OnceLock<Vec<BacktraceEvent>>,
    asm_groups: OnceLock<Vec<AsmSearchGroup>>,
    jni_calls: OnceLock<JniCallScan>,
    pub(crate) crypto_analysis: OnceLock<crate::analysis::crypto_analysis::CryptoAnalysisResponse>,
    pub(crate) reg_timeline_cache: Mutex<RegTimelineCache>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacktraceEvent {
    pub idx: usize,
    pub is_call: bool,
}

#[derive(Debug, Clone)]
pub struct AsmSearchGroup {
    pub pc: u64,
    pub asm: String,
}

impl AnalysisContext {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;

        let modules = ModuleResolver::from_modules(&meta.modules);

        let inner = Arc::new(AnalysisData {
            trace_dir,
            meta,
            trace,
            index: OnceLock::new(),
            symbols: OnceLock::new(),
            modules,
            cfg: OnceLock::new(),
            function_index: OnceLock::new(),
            analysis_index: OnceLock::new(),
            dep_users: OnceLock::new(),
            memshadow: OnceLock::new(),
            call_tree: OnceLock::new(),
            call_tree_depth_cache: Mutex::new(HashMap::new()),
            frame_depths: OnceLock::new(),
            backtrace_events: OnceLock::new(),
            asm_groups: OnceLock::new(),
            jni_calls: OnceLock::new(),
            crypto_analysis: OnceLock::new(),
            reg_timeline_cache: Mutex::new(HashMap::new()),
        });

        Ok(Self { inner })
    }
}

/// 缓存锁统一走中毒恢复：锁中毒不允许让 handler panic。
pub(crate) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl AnalysisData {
    pub fn index(&self) -> &Index {
        self.index.get_or_init(|| Index::load_or_build(&self.trace))
    }

    pub fn symbols(&self) -> &SymbolMap {
        self.symbols.get_or_init(|| {
            let trace_dir = &self.trace_dir;
            let meta = &self.meta;
            let trace = &self.trace;
            let modules = &self.modules;
            // Build SymbolMap from per-call meta.json::known_offsets if present,
            // otherwise empty. Format from per-call meta.json:
            //   { "known_offsets": { "0x0": "f_root", "0x100": "f_alpha", ... } }
            // Offsets are RELATIVE to the primary module base.
            let primary_base: u64 = meta
                .module
                .as_ref()
                .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
                .unwrap_or(0);
            let mut known_offsets = parse_known_offsets(trace_dir).unwrap_or_default();
            // Resolve repo root once for the examples known-offsets overlay.
            let repo_root = find_repo_root(trace_dir);
            // Merge examples/<so>/known_offsets.json overlay if present. Static
            // (per-call meta.json) WIN; examples WIN over auto.
            if let Some(root) = repo_root.as_ref() {
                if let Some(so_name) = meta.module.as_ref().and_then(|m| {
                    m.name
                        .strip_suffix(".so")
                        .map(|s| s.to_string())
                        .or_else(|| Some(m.name.clone()))
                }) {
                    if let Some(examples) = parse_examples_known_offsets(root, &so_name) {
                        for (off, name) in examples {
                            known_offsets.entry(off).or_insert(name);
                        }
                    }
                }
            }
            // Mirror Python's priority: when fn_addr aligns to an offset in known_offsets
            // AND meta.method is non-empty, replace that entry's name with method.
            // (Python: `name = m.method or known_offsets.get(off, "func")` when pc==fn_addr)
            if !meta.method.is_empty() {
                if let Some(fn_addr_str) = &meta.fn_addr {
                    let fn_abs =
                        u64::from_str_radix(fn_addr_str.trim_start_matches("0x"), 16).unwrap_or(0);
                    let fn_off = fn_abs.wrapping_sub(primary_base);
                    if let std::collections::hash_map::Entry::Occupied(mut e) =
                        known_offsets.entry(fn_off)
                    {
                        e.insert(meta.method.clone());
                    }
                }
            }
            let mut symbols = SymbolMap::new();
            for (off, name) in &known_offsets {
                let pc = primary_base.wrapping_add(*off);
                if let Some(module) = meta.module.as_ref() {
                    symbols.add_with_module(pc, name.clone(), module);
                } else {
                    symbols.add(pc, name.clone());
                }
            }
            // Merge auto-discovered bl-target entries; examples + static WIN.
            // These are module-aware, so calls into app-private helper SOs get a
            // name relative to the target SO rather than the primary SO base.
            let auto = auto_known_symbols_with_modules(trace, modules);
            for (pc, name) in auto {
                if symbols.has_start_pc(pc) {
                    continue;
                }
                symbols.add_resolved(pc, name, modules);
            }
            symbols.freeze();
            symbols
        })
    }

    /// 用于断言轻量查询没有隐式构建整份索引。
    pub fn loaded_components(&self) -> [&'static str; 4] {
        [
            if self.index.get().is_some() {
                "ready"
            } else {
                "idle"
            },
            if self.symbols.get().is_some() {
                "ready"
            } else {
                "idle"
            },
            if self.cfg.get().is_some() {
                "ready"
            } else {
                "idle"
            },
            if self.memshadow.get().is_some() {
                "ready"
            } else {
                "idle"
            },
        ]
    }

    pub fn cfg(&self) -> &CFG {
        self.cfg.get_or_init(|| build_cfg(&self.trace))
    }

    pub fn function_index(&self) -> &FunctionIndex {
        self.function_index
            .get_or_init(|| build_function_index(self.symbols(), Some(self.cfg())))
    }

    pub fn memshadow(&self) -> &MemShadow {
        self.memshadow
            .get_or_init(|| MemShadow::load_or_build(&self.trace))
    }

    pub fn memshadow_if_ready(&self) -> Option<&MemShadow> {
        self.memshadow.get()
    }

    pub fn analysis_index(&self) -> &AnalysisIndex {
        self.analysis_index
            .get_or_init(|| AnalysisIndex::load_or_build(&self.trace, self.symbols(), self.index()))
    }

    pub fn analysis_index_status(&self) -> &'static str {
        if self.analysis_index.get().is_some() {
            "ready"
        } else {
            "idle"
        }
    }

    /// Lazily compute the inverted dependency CSR (def→use direction).
    ///
    /// This is what powers `forward-dep-graph`. Cost is O(edges) the first
    /// time and O(1) after; for a 24M-row trace the build is roughly the same
    /// order as one analysis-index sidecar pass over edges.
    pub fn dep_users(&self) -> &DependencyUsers {
        self.dep_users
            .get_or_init(|| DependencyUsers::build(&self.analysis_index().deps, self.trace.len()))
    }

    pub fn call_tree(&self) -> &CallNode {
        self.call_tree
            .get_or_init(|| build_call_tree_indexed(&self.trace, self.symbols(), self.index(), 50))
    }

    pub fn call_tree_for_depth(&self, max_depth: usize) -> CallNode {
        if max_depth == 50 {
            return self.call_tree().clone();
        }
        if let Ok(cache) = self.call_tree_depth_cache.lock() {
            if let Some(tree) = cache.get(&max_depth) {
                return tree.clone();
            }
        }

        let tree = build_call_tree_indexed(&self.trace, self.symbols(), self.index(), max_depth);
        if let Ok(mut cache) = self.call_tree_depth_cache.lock() {
            return cache
                .entry(max_depth)
                .or_insert_with(|| tree.clone())
                .clone();
        }
        tree
    }

    pub fn frame_depths(&self) -> &[u32] {
        self.frame_depths
            .get_or_init(|| build_frame_depth_map(&self.trace))
    }

    pub fn backtrace_events(&self) -> &[BacktraceEvent] {
        self.backtrace_events
            .get_or_init(|| {
                let mut events = Vec::new();
                for (&pc, idxs) in &self.index().pc_to_idxs {
                    let Some(&first_idx) = idxs.first() else {
                        continue;
                    };
                    let d = decode(pc, self.trace.inst(first_idx));
                    if !d.is_call && !d.is_ret {
                        continue;
                    }
                    events.extend(idxs.iter().copied().map(|idx| BacktraceEvent {
                        idx,
                        is_call: d.is_call,
                    }));
                }
                events.sort_unstable_by_key(|event| event.idx);
                events
            })
            .as_slice()
    }

    pub fn asm_groups(&self) -> &[AsmSearchGroup] {
        self.asm_groups
            .get_or_init(|| {
                let mut groups = Vec::with_capacity(self.index().pc_to_idxs.len());
                for (&pc, idxs) in &self.index().pc_to_idxs {
                    let Some(&first_idx) = idxs.first() else {
                        continue;
                    };
                    let record = self.trace.record(first_idx);
                    let decoded = decode(record.pc, record.inst);
                    groups.push(AsmSearchGroup {
                        pc,
                        asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                            .trim()
                            .to_string(),
                    });
                }
                groups
            })
            .as_slice()
    }

    pub fn jni_calls(&self) -> &JniCallScan {
        self.jni_calls.get_or_init(|| {
            scan_jni_calls(
                &self.trace,
                self.index(),
                self.symbols(),
                primary_base(self),
            )
        })
    }
}

fn primary_base(inner: &AnalysisData) -> Option<u64> {
    inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_dec_u64(&m.base))
}

/// Read `<call_dir>/meta.json::known_offsets` and parse into hex-keyed map.
/// Returns None on any parse failure (caller treats as empty).
fn parse_known_offsets(call_dir: &std::path::Path) -> Option<HashMap<u64, String>> {
    let path = call_dir.join("meta.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let ko = v.get("known_offsets")?.as_object()?;
    let mut out = HashMap::new();
    for (k, val) in ko.iter() {
        let off = u64::from_str_radix(k.trim_start_matches("0x"), 16).ok()?;
        let name = val.as_str()?;
        out.insert(off, name.to_string());
    }
    Some(out)
}

/// Read `examples/<so>/known_offsets.json` if present and merge into the
/// known_offsets dict. Static entries from per-call meta.json WIN on
/// collision (don't override curated names with examples ones).
///
/// `so_name` is the module basename without `.so` suffix (e.g., "libtarget"
/// for "libtarget.so").
fn parse_examples_known_offsets(
    repo_root: &std::path::Path,
    so_name: &str,
) -> Option<HashMap<u64, String>> {
    let path = repo_root
        .join("examples")
        .join(so_name)
        .join("known_offsets.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let obj = v.as_object()?;
    let mut out = HashMap::new();
    for (k, val) in obj.iter() {
        let off = u64::from_str_radix(k.trim_start_matches("0x"), 16).ok()?;
        let name = val.as_str()?;
        out.insert(off, name.to_string());
    }
    Some(out)
}

/// Find the repo root by walking up from `call_dir` looking for an `examples/`
/// directory next to a `tracemiku` script.
fn find_repo_root(call_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut cur = call_dir.to_path_buf();
    while let Some(parent) = cur.parent() {
        if parent.join("examples").is_dir() && parent.join("tracemiku").exists() {
            return Some(parent.to_path_buf());
        }
        cur = parent.to_path_buf();
    }
    None
}
