use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use tracemiku_core::cfg::build_cfg;
use tracemiku_core::disasm::decode;
use tracemiku_core::forward_dep_tree::DependencyUsers;
use tracemiku_core::hashfin::{HashFinalizeCandidate, HashFinalizeIndex};
use tracemiku_core::ollvmdet::{ollvm_detect_vm_indexed, OllvmFinding};
use tracemiku_core::prelude::{
    build_call_tree_indexed, build_frame_depth_map, build_function_index, AnalysisIndex, CallNode,
    FunctionIndex, Index, MemShadow, ModuleResolver, SymbolMap, Trace, TraceMeta, CFG,
};
use tracemiku_core::symbols::auto_known_symbols_with_modules;

use crate::bn_sidecar::{BnSidecarManager, BnStatusHandle};
use crate::jni_scan::{scan_jni_calls, JniCallScan};
use crate::phase_scan::{build_auto_phases, PhaseEntry};
use crate::routes::parse::parse_dec_u64;

const EAGER_MEMSHADOW_MAX_RECORDS: usize = 1_000_000;
const MEMSHADOW_NOT_STARTED: u8 = 0;
const MEMSHADOW_LOADING: u8 = 1;
const MEMSHADOW_READY: u8 = 2;
const INTERACTIVE_WARM_DELAY_MS: u64 = 250;
const INTERACTIVE_WARM_MAX_RECORDS: usize = 1_500_000;
const BN_RESPONSE_CACHE_VERSION: u64 = 1;
const BN_RESPONSE_CACHE_FILE: &str = "trace.bin.bn-sidecar-cache.v1.json";
/// cfg_svg_cache 写入侧上限：条目数与单条 SVG 字节数。
const CFG_SVG_CACHE_MAX_ENTRIES: usize = 64;
/// ollvm_cache 写入侧上限：不同 (min_entries, threshold) 组合的缓存条数。
const OLLVM_CACHE_MAX_ENTRIES: usize = 16;

/// Cached register timelines: reg name → ordered (record_idx, value) pairs.
pub(crate) type RegTimelineCache = HashMap<String, Arc<Vec<(usize, u64)>>>;

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
    analysis_index: OnceLock<AnalysisIndex>,
    dep_users: OnceLock<DependencyUsers>,
    memshadow: OnceLock<MemShadow>,
    memshadow_status: AtomicU8,
    call_tree: OnceLock<CallNode>,
    call_tree_depth_cache: Mutex<HashMap<usize, CallNode>>,
    frame_depths: OnceLock<Vec<u32>>,
    backtrace_events: OnceLock<Vec<BacktraceEvent>>,
    asm_groups: OnceLock<Vec<AsmSearchGroup>>,
    jni_calls: OnceLock<JniCallScan>,
    pub(crate) crypto_analysis: OnceLock<crate::routes::crypto_analysis::CryptoAnalysisResponse>,
    hash_finalize_index: OnceLock<HashFinalizeIndex>,
    pub cfg_svg_cache: Mutex<CfgSvgCache>,
    ollvm_cache: Mutex<OllvmCache>,
    auto_phase_cache: Mutex<HashMap<bool, Vec<PhaseEntry>>>,
    pub(crate) reg_timeline_cache: Mutex<RegTimelineCache>,
    pub bn_sidecar: Mutex<BnSidecarManager>,
    /// BN sidecar 的无锁 status 快照：async handler 直接读它，
    /// 不与 `bn_sidecar` Mutex（request 持锁可达请求超时）竞争。
    pub bn_sidecar_status: BnStatusHandle,
    pub(crate) bn_response_cache: Mutex<BnResponseCache>,
}

#[derive(Debug, Clone)]
pub struct CfgSvgCached {
    pub svg: String,
    pub block_count: usize,
    pub total_block_count: usize,
}

/// cfg_svg 缓存：写入侧同时执行条目数 FIFO 淘汰与单条 SVG 尺寸上限，
/// 避免无上限缓存随请求组合（fn 过滤 + force）无限增长。
#[derive(Debug, Default)]
pub struct CfgSvgCache {
    entries: HashMap<String, CfgSvgCached>,
    order: VecDeque<String>,
}

impl CfgSvgCache {
    pub fn get(&self, key: &str) -> Option<&CfgSvgCached> {
        self.entries.get(key)
    }

    /// 超过尺寸上限的 SVG 不入缓存（读侧仍可正常返回本次渲染结果）。
    pub fn insert(&mut self, key: String, cached: CfgSvgCached) {
        if cached.svg.len() > crate::routes::cfg_svg::AUTO_CACHED_MAX_SVG_BYTES {
            return;
        }
        if self.entries.insert(key.clone(), cached).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > CFG_SVG_CACHE_MAX_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

/// ollvm 检测结果缓存：threshold 量化入 key + FIFO 条目上限。
#[derive(Debug, Default)]
struct OllvmCache {
    entries: HashMap<OllvmCacheKey, Vec<OllvmFinding>>,
    order: VecDeque<OllvmCacheKey>,
}

impl OllvmCache {
    fn get(&self, key: &OllvmCacheKey) -> Option<&Vec<OllvmFinding>> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: OllvmCacheKey, findings: Vec<OllvmFinding>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key);
        }
        self.entries.insert(key, findings);
        while self.order.len() > OLLVM_CACHE_MAX_ENTRIES {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }
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

#[derive(Debug, Clone)]
pub struct AsmSearchGroup {
    pub pc: u64,
    pub asm: String,
}

/// BN sidecar 响应缓存：容量上限 + 插入序 FIFO 淘汰 + 落盘防抖。
///
/// 成功响应全量序列化写盘较重，因此只在距上次落盘超过
/// `BN_CACHE_PERSIST_DEBOUNCE` 时写一次；退出时（`AppStateInner::drop`）
/// 若仍有未落盘改动则补写一次。
#[derive(Debug)]
pub(crate) struct BnResponseCache {
    entries: HashMap<String, serde_json::Value>,
    order: VecDeque<String>,
    dirty: bool,
    last_persist: Option<Instant>,
}

const BN_CACHE_PERSIST_DEBOUNCE: Duration = Duration::from_secs(30);
const BN_RESPONSE_CACHE_MAX_ENTRIES: usize = 256;

impl BnResponseCache {
    fn from_loaded(entries: HashMap<String, serde_json::Value>) -> Self {
        // 磁盘载入的条目按 map 迭代序作为初始 FIFO 序，保证淘汰有序。
        let order = entries.keys().cloned().collect();
        Self {
            entries,
            order,
            dirty: false,
            last_persist: None,
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.entries.get(key)
    }

    /// 供落盘序列化使用：按 FIFO 序返回条目（serde_json Map 保序即可）。
    fn entries_snapshot(&self) -> &HashMap<String, serde_json::Value> {
        &self.entries
    }

    fn insert(&mut self, key: String, value: serde_json::Value) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value);
        self.dirty = true;
        while self.order.len() > BN_RESPONSE_CACHE_MAX_ENTRIES {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 是否到达防抖落盘时机（脏且距上次落盘超过防抖间隔）。
    fn persist_due(&self) -> bool {
        self.dirty
            && self
                .last_persist
                .is_none_or(|at| at.elapsed() >= BN_CACHE_PERSIST_DEBOUNCE)
    }

    fn mark_persisted(&mut self) {
        self.dirty = false;
        self.last_persist = Some(Instant::now());
    }
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;

        let index = Index::load_or_build(&trace);
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
        // Resolve repo root once for the examples known-offsets overlay.
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
        let auto = auto_known_symbols_with_modules(&trace, &modules);
        for (pc, name) in auto {
            if symbols.has_start_pc(pc) {
                continue;
            }
            symbols.add_resolved(pc, name, &modules);
        }
        symbols.freeze();

        let cfg = build_cfg(&trace);
        let function_index = build_function_index(&symbols, Some(&cfg));
        let bn_response_cache = BnResponseCache::from_loaded(load_bn_response_cache(&trace));
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

        let bn_sidecar = BnSidecarManager::from_env_with_default_base(
            (primary_base != 0).then_some(primary_base),
        );
        let bn_sidecar_status = bn_sidecar.status_handle();

        let inner = Arc::new(AppStateInner {
            trace_dir,
            meta,
            trace,
            index,
            symbols,
            modules,
            cfg,
            function_index,
            analysis_index: OnceLock::new(),
            dep_users: OnceLock::new(),
            memshadow,
            memshadow_status,
            call_tree: OnceLock::new(),
            call_tree_depth_cache: Mutex::new(HashMap::new()),
            frame_depths: OnceLock::new(),
            backtrace_events: OnceLock::new(),
            asm_groups: OnceLock::new(),
            jni_calls: OnceLock::new(),
            crypto_analysis: OnceLock::new(),
            hash_finalize_index: OnceLock::new(),
            cfg_svg_cache: Mutex::new(CfgSvgCache::default()),
            ollvm_cache: Mutex::new(OllvmCache::default()),
            auto_phase_cache: Mutex::new(HashMap::new()),
            reg_timeline_cache: Mutex::new(HashMap::new()),
            bn_sidecar: Mutex::new(bn_sidecar),
            bn_sidecar_status,
            bn_response_cache: Mutex::new(bn_response_cache),
        });

        if background_interactive_warm_enabled() {
            spawn_interactive_cache_warmer(inner.clone());
        }

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
                    let mem = warm_inner.memshadow();
                    tracing::info!(
                        target: "tracemiku-server",
                        records = warm_inner.trace.len(),
                        elapsed_ms = start.elapsed().as_millis(),
                        "background MemShadow ready"
                    );
                    warm_memshadow_caches(&warm_inner, mem);
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

pub(crate) fn bn_response_cache_path(trace: &Trace) -> PathBuf {
    trace.call_dir().join(BN_RESPONSE_CACHE_FILE)
}

fn load_bn_response_cache(trace: &Trace) -> HashMap<String, serde_json::Value> {
    let path = bn_response_cache_path(trace);
    let Ok(raw) = std::fs::read(&path) else {
        return HashMap::new();
    };
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        tracing::warn!(
            target: "tracemiku-server",
            path = %path.display(),
            "ignoring corrupt BN sidecar cache"
        );
        return HashMap::new();
    };
    let version = doc.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let trace_bytes = doc.get("trace_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != BN_RESPONSE_CACHE_VERSION || trace_bytes != trace.raw().len() as u64 {
        return HashMap::new();
    }
    doc.get("entries")
        .and_then(|v| v.as_object())
        .map(|entries| {
            entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// 把当前 BN 响应缓存原子落盘（tmp + rename），并重置防抖状态。
fn persist_bn_response_cache(inner: &AppStateInner) {
    let path = bn_response_cache_path(&inner.trace);
    let tmp_path = path.with_file_name(format!(
        "{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(BN_RESPONSE_CACHE_FILE),
        std::process::id()
    ));
    let doc = {
        let mut cache = lock_or_recover(&inner.bn_response_cache);
        let doc = json!({
            "version": BN_RESPONSE_CACHE_VERSION,
            "trace_bytes": inner.trace.raw().len() as u64,
            "entries": cache.entries_snapshot(),
        });
        cache.mark_persisted();
        doc
    };
    let write_result = (|| -> std::io::Result<()> {
        let raw = serde_json::to_vec(&doc).map_err(std::io::Error::other)?;
        std::fs::write(&tmp_path, raw)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        tracing::warn!(
            target: "tracemiku-server",
            path = %path.display(),
            "failed to persist BN sidecar cache: {err}"
        );
    }
}

/// 缓存锁统一走中毒恢复：锁中毒不允许让 handler panic。
pub(crate) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Drop for AppStateInner {
    fn drop(&mut self) {
        // 退出兜底：防抖窗口内未落盘的缓存改动在这里补写。
        if self
            .bn_response_cache
            .lock()
            .map(|cache| cache.is_dirty())
            .unwrap_or(false)
        {
            persist_bn_response_cache(self);
        }
    }
}

impl AppStateInner {
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

    pub fn memshadow_ready_or_block_if_idle(
        &self,
    ) -> Result<&MemShadow, tracemiku_core::memshadow::MemShadowError> {
        match self.memshadow_if_ready() {
            Some(mem) => Ok(mem),
            None => {
                let status = self.memshadow_status();
                if status == "idle" || status == "ready" {
                    Ok(self.memshadow())
                } else {
                    Err(tracemiku_core::memshadow::MemShadowError::Building)
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

    pub fn analysis_index(&self) -> &AnalysisIndex {
        self.analysis_index
            .get_or_init(|| AnalysisIndex::load_or_build(&self.trace, &self.symbols, &self.index))
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
    /// This is what powers `/api/forward-dep-tree`. Cost is O(edges) the first
    /// time and O(1) after; for a 24M-row trace the build is roughly the same
    /// order as one analysis-index sidecar pass over edges.
    pub fn dep_users(&self) -> &DependencyUsers {
        self.dep_users
            .get_or_init(|| DependencyUsers::build(&self.analysis_index().deps, self.trace.len()))
    }

    pub fn call_tree(&self) -> &CallNode {
        self.call_tree
            .get_or_init(|| build_call_tree_indexed(&self.trace, &self.symbols, &self.index, 50))
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

        let tree = build_call_tree_indexed(&self.trace, &self.symbols, &self.index, max_depth);
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
            threshold_bits: quantize_ollvm_threshold(threshold).to_bits(),
        };
        if let Some(findings) = lock_or_recover(&self.ollvm_cache).get(&key).cloned() {
            return findings;
        }

        let findings = ollvm_detect_vm_indexed(&self.trace, &self.index, min_entries, threshold);
        lock_or_recover(&self.ollvm_cache).insert(key, findings.clone());
        findings
    }

    /// 写入 BN 响应缓存；距上次落盘超过防抖间隔时同步落盘一次。
    pub(crate) fn cache_bn_response(&self, key: String, value: serde_json::Value) {
        let due = {
            let mut cache = lock_or_recover(&self.bn_response_cache);
            cache.insert(key, value);
            cache.persist_due()
        };
        if due {
            persist_bn_response_cache(self);
        }
    }

    pub fn hash_finalize_candidates(
        &self,
        mem: &MemShadow,
        window: usize,
        min_size: u64,
        limit: usize,
    ) -> (usize, Vec<HashFinalizeCandidate>) {
        self.hash_finalize_index
            .get_or_init(|| HashFinalizeIndex::build(mem))
            .detect_limited(window, min_size, limit)
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
    inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_dec_u64(&m.base))
}

/// 连续 threshold 参数直接入 key 会产生无限多个缓存条目；按 1e-9 量化后，
/// 语义上等价的参数共享同一条缓存。
fn quantize_ollvm_threshold(threshold: f64) -> f64 {
    (threshold * 1e9).round() / 1e9
}

fn background_memshadow_enabled() -> bool {
    std::env::var("TRACEMIKU_MEMSHADOW_BACKGROUND")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        })
        .unwrap_or(true)
}

fn background_interactive_warm_enabled() -> bool {
    std::env::var("TRACEMIKU_INTERACTIVE_WARM_BACKGROUND")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        })
        .unwrap_or(true)
}

fn spawn_interactive_cache_warmer(inner: Arc<AppStateInner>) {
    if let Err(err) = thread::Builder::new()
        .name("tracemiku-ui-warm".to_string())
        .spawn(move || {
            thread::sleep(std::time::Duration::from_millis(INTERACTIVE_WARM_DELAY_MS));
            if inner.trace.len() > INTERACTIVE_WARM_MAX_RECORDS {
                tracing::info!(
                    target: "tracemiku-server",
                    records = inner.trace.len(),
                    max_records = INTERACTIVE_WARM_MAX_RECORDS,
                    "skipping full interactive cache warmer for large trace"
                );
                let _ = inner.asm_groups();
                return;
            }
            let start = Instant::now();
            tracing::info!(
                target: "tracemiku-server",
                records = inner.trace.len(),
                "warming interactive caches in background"
            );
            let _ = inner.asm_groups();
            let _ = inner.call_tree();
            let _ = inner.backtrace_events();
            let _ = inner.frame_depths();
            if let Some(mem) = inner.memshadow_if_ready() {
                warm_memshadow_caches(&inner, mem);
            }
            tracing::info!(
                target: "tracemiku-server",
                records = inner.trace.len(),
                elapsed_ms = start.elapsed().as_millis(),
                "background interactive caches ready"
            );
        })
    {
        tracing::warn!(
            target: "tracemiku-server",
            "failed to spawn interactive cache warmer: {err}"
        );
    }
}

fn warm_memshadow_caches(inner: &AppStateInner, mem: &MemShadow) {
    let start = Instant::now();
    let _ = inner.hash_finalize_candidates(mem, 500, 16, 500);
    let _ = inner.auto_phases(mem, true);
    tracing::info!(
        target: "tracemiku-server",
        records = inner.trace.len(),
        elapsed_ms = start.elapsed().as_millis(),
        "background MemShadow-derived caches ready"
    );
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

#[cfg(test)]
mod tests {
    use super::{
        quantize_ollvm_threshold, CfgSvgCache, CfgSvgCached, CFG_SVG_CACHE_MAX_ENTRIES,
        OLLVM_CACHE_MAX_ENTRIES,
    };
    use crate::routes::cfg_svg::AUTO_CACHED_MAX_SVG_BYTES;

    #[test]
    fn ollvm_threshold_quantization_collapses_nearby_values() {
        let a = quantize_ollvm_threshold(0.5);
        let b = quantize_ollvm_threshold(0.5 + 1e-12);
        assert_eq!(a.to_bits(), b.to_bits());
        assert_eq!(
            quantize_ollvm_threshold(0.1234567891).to_bits(),
            quantize_ollvm_threshold(0.1234567894).to_bits()
        );
    }

    #[test]
    fn cfg_svg_cache_evicts_oldest_beyond_entry_cap() {
        let mut cache = CfgSvgCache::default();
        for i in 0..=(CFG_SVG_CACHE_MAX_ENTRIES) {
            cache.insert(
                format!("fn_{i}"),
                CfgSvgCached {
                    svg: "<svg/>".to_string(),
                    block_count: 1,
                    total_block_count: 1,
                },
            );
        }
        assert!(cache.get("fn_0").is_none(), "oldest entry must be evicted");
        assert!(cache
            .get(&format!("fn_{CFG_SVG_CACHE_MAX_ENTRIES}"))
            .is_some());
    }

    #[test]
    fn cfg_svg_cache_rejects_oversized_svg() {
        let mut cache = CfgSvgCache::default();
        cache.insert(
            "huge".to_string(),
            CfgSvgCached {
                svg: "x".repeat(AUTO_CACHED_MAX_SVG_BYTES + 1),
                block_count: 1,
                total_block_count: 1,
            },
        );
        assert!(
            cache.get("huge").is_none(),
            "oversized SVG must not be cached"
        );
    }

    #[test]
    fn cache_caps_are_bounded() {
        assert_eq!(CFG_SVG_CACHE_MAX_ENTRIES, 64);
        assert_eq!(OLLVM_CACHE_MAX_ENTRIES, 16);
    }
}
