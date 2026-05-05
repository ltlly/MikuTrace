use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::thread;
use std::time::Instant;

use tracemiku_core::cfg::build_cfg;
use tracemiku_core::disasm::decode;
use tracemiku_core::hashfin::{HashFinalizeCandidate, HashFinalizeIndex};
use tracemiku_core::ollvmdet::{ollvm_detect_vm_indexed, OllvmFinding};
use tracemiku_core::prelude::{
    build_call_tree_indexed, build_frame_depth_map, build_from_trace, build_function_index,
    build_trace_ir, CallNode, FunctionIndex, Index, MemShadow, ModuleResolver, SymbolMap, TopIR,
    Trace, TraceMeta, CFG,
};
use tracemiku_core::symbols::auto_known_offsets_with_base;

use crate::bn_sidecar::BnSidecarManager;
use crate::jni_scan::{parse_int, scan_jni_calls, JniCallScan};
use crate::phase_scan::{build_auto_phases, PhaseEntry};

const EAGER_MEMSHADOW_MAX_RECORDS: usize = 1_000_000;
const MEMSHADOW_NOT_STARTED: u8 = 0;
const MEMSHADOW_LOADING: u8 = 1;
const MEMSHADOW_READY: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceIrBuildOptions {
    pub hook_paths: Vec<PathBuf>,
    pub with_memshadow: bool,
    pub split_top_k: usize,
    pub split_min_records: usize,
}

impl Default for TraceIrBuildOptions {
    fn default() -> Self {
        Self {
            hook_paths: Vec::new(),
            with_memshadow: false,
            split_top_k: 10,
            split_min_records: 50,
        }
    }
}

impl TraceIrBuildOptions {
    pub fn uses_cached_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
    pub index: Index,
    pub symbols: SymbolMap,
    pub modules: ModuleResolver,
    pub cfg: CFG,
    pub function_index: FunctionIndex,
    memshadow: OnceLock<MemShadow>,
    memshadow_status: AtomicU8,
    call_tree: OnceLock<CallNode>,
    frame_depths: OnceLock<Vec<u32>>,
    backtrace_events: OnceLock<Vec<BacktraceEvent>>,
    asm_groups: OnceLock<Vec<AsmSearchGroup>>,
    jni_calls: OnceLock<JniCallScan>,
    pub(crate) crypto_scan: OnceLock<crate::crypto_scan::CryptoScanResponse>,
    hash_finalize_index: OnceLock<HashFinalizeIndex>,
    top_ir: OnceLock<TopIR>,
    type_spec_paths: Vec<PathBuf>,
    pub llm_cache: Mutex<HashMap<String, serde_json::Value>>,
    pub cfg_svg_cache: Mutex<HashMap<String, CfgSvgCached>>,
    ollvm_cache: Mutex<HashMap<OllvmCacheKey, Vec<OllvmFinding>>>,
    hash_finalize_cache: Mutex<HashMap<HashFinalizeCacheKey, Vec<HashFinalizeCandidate>>>,
    auto_phase_cache: Mutex<HashMap<bool, Vec<PhaseEntry>>>,
    trace_ir_cache: Mutex<HashMap<TraceIrBuildOptions, Arc<TopIR>>>,
    pub(crate) reg_timeline_cache: Mutex<HashMap<String, Arc<Vec<(usize, u64)>>>>,
    pub bn_sidecar: Mutex<BnSidecarManager>,
}

#[derive(Debug, Clone)]
pub struct CfgSvgCached {
    pub svg: String,
    pub block_count: usize,
    pub total_block_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacktraceEvent {
    pub idx: usize,
    pub is_call: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OllvmCacheKey {
    min_entries: usize,
    threshold_bits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HashFinalizeCacheKey {
    window: usize,
    min_size: u64,
}

#[derive(Debug, Clone)]
pub struct AsmSearchGroup {
    pub pc: u64,
    pub asm: String,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;

        let index = Index::build(&trace);
        let modules = ModuleResolver::from_modules(&meta.modules);

        // Build SymbolMap from per-call meta.json::known_offsets if present,
        // otherwise empty. Format from per-call meta.json:
        //   { "known_offsets": { "0x0": "f_root", "0x100": "f_alpha", ... } }
        // Offsets are RELATIVE to the primary module base.
        let primary_base: u64 = meta
            .module
            .as_ref()
            .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
            .unwrap_or(0);
        let mut known_offsets = parse_known_offsets(&trace_dir).unwrap_or_default();
        // Resolve repo root once; reused below for examples overlay AND for
        // tools/hooks/ type-spec auto-discovery (M3-ι2a Task 3).
        let repo_root = find_repo_root(&trace_dir);
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
        // Merge auto-discovered bl-target entries; examples + static WIN.
        let auto = auto_known_offsets_with_base(&trace, primary_base);
        for (off, name) in auto {
            known_offsets.entry(off).or_insert(name);
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
        let symbols = build_from_trace(&trace, primary_base, &known_offsets);

        let cfg = build_cfg(&trace);
        let function_index = build_function_index(&symbols, Some(&cfg));
        // Auto-discover type-spec JSONs (M3-ι2a Task 3): tools/hooks/*.json
        // with `kind == "type_specs"` plus examples/<so>/type_specs.json.
        let spec_paths: Vec<std::path::PathBuf> = if let Some(root) = repo_root.as_ref() {
            let so_name = meta
                .module
                .as_ref()
                .and_then(|m| m.name.strip_suffix(".so").map(|s| s.to_string()));
            discover_type_spec_paths(root, so_name.as_deref())
        } else {
            Vec::new()
        };
        let memshadow = OnceLock::new();
        let memshadow_status = AtomicU8::new(MEMSHADOW_NOT_STARTED);
        if trace.len() <= EAGER_MEMSHADOW_MAX_RECORDS {
            let start = Instant::now();
            let _ = memshadow.set(MemShadow::load_or_build(&trace));
            memshadow_status.store(MEMSHADOW_READY, Ordering::Release);
            tracing::info!(
                target: "tracemiku-server",
                records = trace.len(),
                elapsed_ms = start.elapsed().as_millis(),
                "loaded eager MemShadow"
            );
        }

        let inner = Arc::new(AppStateInner {
            trace_dir,
            meta,
            trace,
            index,
            symbols,
            modules,
            cfg,
            function_index,
            memshadow,
            memshadow_status,
            call_tree: OnceLock::new(),
            frame_depths: OnceLock::new(),
            backtrace_events: OnceLock::new(),
            asm_groups: OnceLock::new(),
            jni_calls: OnceLock::new(),
            crypto_scan: OnceLock::new(),
            hash_finalize_index: OnceLock::new(),
            top_ir: OnceLock::new(),
            type_spec_paths: spec_paths,
            llm_cache: Mutex::new(HashMap::new()),
            cfg_svg_cache: Mutex::new(HashMap::new()),
            ollvm_cache: Mutex::new(HashMap::new()),
            hash_finalize_cache: Mutex::new(HashMap::new()),
            auto_phase_cache: Mutex::new(HashMap::new()),
            trace_ir_cache: Mutex::new(HashMap::new()),
            reg_timeline_cache: Mutex::new(HashMap::new()),
            bn_sidecar: Mutex::new(BnSidecarManager::from_env()),
        });

        if inner.trace.len() > EAGER_MEMSHADOW_MAX_RECORDS && background_memshadow_enabled() {
            let warm_inner = inner.clone();
            let _ = inner.memshadow_status.compare_exchange(
                MEMSHADOW_NOT_STARTED,
                MEMSHADOW_LOADING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Err(err) = thread::Builder::new()
                .name("tracemiku-mem-warm".to_string())
                .spawn(move || {
                    tracing::info!(
                        target: "tracemiku-server",
                        records = warm_inner.trace.len(),
                        "warming MemShadow in background"
                    );
                    let start = Instant::now();
                    let _ = warm_inner.memshadow();
                    tracing::info!(
                        target: "tracemiku-server",
                        records = warm_inner.trace.len(),
                        elapsed_ms = start.elapsed().as_millis(),
                        "background MemShadow ready"
                    );
                })
            {
                tracing::warn!(
                    target: "tracemiku-server",
                    "failed to spawn MemShadow warmer: {err}"
                );
                inner
                    .memshadow_status
                    .store(MEMSHADOW_NOT_STARTED, Ordering::Release);
            }
        }
        Ok(Self { inner })
    }
}

impl AppStateInner {
    /// Lazily build TraceIR only for decompile endpoints.
    ///
    /// Large traces need Records/Memory/CFG to become interactive before the
    /// heavyweight decompile summary exists. Defaults match Python webui
    /// (webui/server.py:2734-2735).
    pub fn top_ir(&self) -> &TopIR {
        self.top_ir.get_or_init(|| {
            build_trace_ir(
                &self.trace,
                &self.meta,
                &self.symbols,
                &self.cfg,
                Some(&self.index),
                10,
                50,
                &self.type_spec_paths,
                // Keep the decompiler first paint independent from cold
                // MemShadow sidecar loading on multi-GB traces. VM candidates
                // still include hex dumps when another panel has already
                // loaded MemShadow.
                self.memshadow_if_ready(),
            )
        })
    }

    pub fn build_top_ir_with_options(&self, opts: &TraceIrBuildOptions) -> Arc<TopIR> {
        if let Some(cached) = self
            .trace_ir_cache
            .lock()
            .expect("trace-ir cache poisoned")
            .get(opts)
            .cloned()
        {
            return cached;
        }
        let top = Arc::new(self.build_top_ir_uncached(opts));
        self.trace_ir_cache
            .lock()
            .expect("trace-ir cache poisoned")
            .entry(opts.clone())
            .or_insert_with(|| top.clone())
            .clone()
    }

    fn build_top_ir_uncached(&self, opts: &TraceIrBuildOptions) -> TopIR {
        let spec_paths = if opts.hook_paths.is_empty() {
            self.type_spec_paths.as_slice()
        } else {
            opts.hook_paths.as_slice()
        };
        let memshadow = if opts.with_memshadow {
            Some(self.memshadow())
        } else {
            None
        };
        build_trace_ir(
            &self.trace,
            &self.meta,
            &self.symbols,
            &self.cfg,
            Some(&self.index),
            opts.split_top_k,
            opts.split_min_records,
            spec_paths,
            memshadow,
        )
    }

    pub fn memshadow(&self) -> &MemShadow {
        if let Some(mem) = self.memshadow.get() {
            self.memshadow_status
                .store(MEMSHADOW_READY, Ordering::Release);
            return mem;
        }
        let _ = self.memshadow_status.compare_exchange(
            MEMSHADOW_NOT_STARTED,
            MEMSHADOW_LOADING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let mem = self.memshadow.get_or_init(|| {
            let start = Instant::now();
            tracing::info!(
                target: "tracemiku-server",
                records = self.trace.len(),
                "loading MemShadow"
            );
            let mem = MemShadow::load_or_build(&self.trace);
            tracing::info!(
                target: "tracemiku-server",
                records = self.trace.len(),
                elapsed_ms = start.elapsed().as_millis(),
                "loaded MemShadow"
            );
            mem
        });
        self.memshadow_status
            .store(MEMSHADOW_READY, Ordering::Release);
        mem
    }

    pub fn memshadow_if_ready(&self) -> Option<&MemShadow> {
        self.memshadow.get()
    }

    pub fn memshadow_ready_or_block_if_idle(&self) -> Result<&MemShadow, &'static str> {
        match self.memshadow_if_ready() {
            Some(mem) => Ok(mem),
            None => {
                let status = self.memshadow_status();
                if status == "idle" || status == "ready" {
                    Ok(self.memshadow())
                } else {
                    Err(status)
                }
            }
        }
    }

    pub fn memshadow_status(&self) -> &'static str {
        if self.memshadow.get().is_some() {
            return "ready";
        }
        match self.memshadow_status.load(Ordering::Acquire) {
            MEMSHADOW_LOADING => "loading",
            MEMSHADOW_READY => "ready",
            _ => "idle",
        }
    }

    pub fn call_tree(&self) -> &CallNode {
        self.call_tree
            .get_or_init(|| build_call_tree_indexed(&self.trace, &self.symbols, &self.index, 50))
    }

    pub fn frame_depths(&self) -> &[u32] {
        self.frame_depths
            .get_or_init(|| build_frame_depth_map(&self.trace))
    }

    pub fn backtrace_events(&self) -> &[BacktraceEvent] {
        self.backtrace_events
            .get_or_init(|| {
                let mut events = Vec::new();
                for (&pc, idxs) in &self.index.pc_to_idxs {
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
                let mut groups = Vec::with_capacity(self.index.pc_to_idxs.len());
                for (&pc, idxs) in &self.index.pc_to_idxs {
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
            scan_jni_calls(&self.trace, &self.index, &self.symbols, primary_base(self))
        })
    }

    pub fn ollvm_findings(&self, min_entries: usize, threshold: f64) -> Vec<OllvmFinding> {
        let key = OllvmCacheKey {
            min_entries,
            threshold_bits: threshold.to_bits(),
        };
        if let Ok(cache) = self.ollvm_cache.lock() {
            if let Some(findings) = cache.get(&key) {
                return findings.clone();
            }
        }

        let findings = ollvm_detect_vm_indexed(&self.trace, &self.index, min_entries, threshold);
        if let Ok(mut cache) = self.ollvm_cache.lock() {
            cache.entry(key).or_insert_with(|| findings.clone());
        }
        findings
    }

    pub fn hash_finalize_candidates(
        &self,
        mem: &MemShadow,
        window: usize,
        min_size: u64,
    ) -> Vec<HashFinalizeCandidate> {
        let key = HashFinalizeCacheKey { window, min_size };
        if let Ok(cache) = self.hash_finalize_cache.lock() {
            if let Some(candidates) = cache.get(&key) {
                return candidates.clone();
            }
        }

        let candidates = self
            .hash_finalize_index
            .get_or_init(|| HashFinalizeIndex::build(mem))
            .detect(window, min_size);
        if let Ok(mut cache) = self.hash_finalize_cache.lock() {
            cache.entry(key).or_insert_with(|| candidates.clone());
        }
        candidates
    }

    pub fn auto_phases(&self, mem: &MemShadow, detect_byte_streams: bool) -> Vec<PhaseEntry> {
        if let Ok(cache) = self.auto_phase_cache.lock() {
            if let Some(phases) = cache.get(&detect_byte_streams) {
                return phases.clone();
            }
            if !detect_byte_streams {
                if let Some(full_phases) = cache.get(&true) {
                    return full_phases
                        .iter()
                        .filter(|phase| phase.phase != "byte_stream_write")
                        .cloned()
                        .collect();
                }
            }
        }

        let phases = build_auto_phases(&self.trace_dir, mem, detect_byte_streams);
        if let Ok(mut cache) = self.auto_phase_cache.lock() {
            cache
                .entry(detect_byte_streams)
                .or_insert_with(|| phases.clone());
        }
        phases
    }
}

fn primary_base(inner: &AppStateInner) -> Option<u64> {
    inner.meta.module.as_ref().and_then(|m| parse_int(&m.base))
}

fn background_memshadow_enabled() -> bool {
    std::env::var("TRACEMIKU_MEMSHADOW_BACKGROUND")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        })
        .unwrap_or(true)
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
/// `so_name` is the module basename without `.so` suffix (e.g., "libsgmainso"
/// for "libsgmainso.so").
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

/// Walk `<repo_root>/tools/hooks/` collecting `*.json` files where the parsed
/// top-level `kind == "type_specs"`. Sorted alphabetically for stable order.
/// If `so_name_no_ext` is Some, additionally appends
/// `<repo_root>/examples/<so>/type_specs.json` when it exists. Returns
/// absolute paths. (M3-ι2a Task 3 — auto-discovery for build_trace_ir.)
fn discover_type_spec_paths(
    repo_root: &std::path::Path,
    so_name_no_ext: Option<&str>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let hooks_dir = repo_root.join("tools").join("hooks");
    if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
        let mut candidates: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        candidates.sort();
        for path in candidates {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            if v.get("kind").and_then(|k| k.as_str()) == Some("type_specs") {
                out.push(path);
            }
        }
    }
    if let Some(so) = so_name_no_ext {
        let p = repo_root.join("examples").join(so).join("type_specs.json");
        if p.is_file() {
            out.push(p);
        }
    }
    out
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
