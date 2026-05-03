use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::cfg::build_cfg;
use tracemiku_core::prelude::{
    build_from_trace, Index, ModuleResolver, SymbolMap, Trace, TraceMeta, CFG,
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
        // Merge auto-discovered bl-target entries; static known_offsets WIN
        // on collision (don't override curated names with f_<hex>).
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

        Ok(Self {
            inner: Arc::new(AppStateInner {
                trace_dir,
                meta,
                trace,
                index,
                symbols,
                modules,
                cfg,
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
