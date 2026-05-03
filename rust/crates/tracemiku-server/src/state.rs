use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::cfg::build_cfg;
use tracemiku_core::prelude::{
    build_from_trace, build_function_index, FunctionIndex, Index, MemShadow, ModuleResolver,
    SymbolMap, Trace, TraceMeta, CFG,
};
use tracemiku_core::symbols::auto_known_offsets_with_base;

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
    pub memshadow: MemShadow,
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
        // Merge examples/<so>/known_offsets.json overlay if present. Static
        // (per-call meta.json) WIN; examples WIN over auto.
        if let Some(repo_root) = find_repo_root(&trace_dir) {
            if let Some(so_name) = meta.module.as_ref().and_then(|m| {
                m.name
                    .strip_suffix(".so")
                    .map(|s| s.to_string())
                    .or_else(|| Some(m.name.clone()))
            }) {
                if let Some(examples) = parse_examples_known_offsets(&repo_root, &so_name) {
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
        let memshadow = MemShadow::build_from_trace(&trace);

        Ok(Self {
            inner: Arc::new(AppStateInner {
                trace_dir,
                meta,
                trace,
                index,
                symbols,
                modules,
                cfg,
                function_index,
                memshadow,
            }),
        })
    }
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
