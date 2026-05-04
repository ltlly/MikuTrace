# Analysis v2 — M3-ι2a Implementation Plan (type_anchor port)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `viewer/decompiler/type_anchor.py` (130 LOC) to Rust. After this milestone:

1. `tracemiku-core::decompiler::type_anchor` exposes `TypeSpec`, `TypeAnchor`, `load_type_specs(paths)`, `find_anchors(trace, specs)`, `attach_type_anchors(top, trace, spec_paths)`.
2. `AppState::load` auto-discovers JSON spec files under `tools/hooks/*type_specs*.json` and `examples/<so>/type_specs.json`, passes them to `build_trace_ir`.
3. `build_trace_ir` accepts an optional `&[PathBuf]` of spec paths; on non-empty, runs `attach_type_anchors` to populate `FuncIR.type_anchors` (already a field on the IR struct from M3-δ).
4. `render_func_md` emits a `## Type anchors` section per fn (skeleton — group by callee_name, list params/ret/provenance — matches Python `viewer/decompiler/render/markdown.py:207-229`).

**Architecture:**

- **Pure-port module** with no dependencies beyond `serde_json` + `crate::disasm::decode`. Mirrors the Python file 1:1: `TypeSpec` struct + `TypeAnchor` struct + 3 free functions. Use `serde_json::Value` for parsing (lenient — Python's `int(pc, 0)` accepts hex/dec strings, JSON numbers, etc., and we should match: try `as_str` first then int parse, else try `as_u64`).
- **Spec auto-discovery:** `AppState::load` walks `<repo_root>/tools/hooks/` for any file with `kind == "type_specs"` (via JSON header check) and `<repo_root>/examples/<so>/type_specs.json`. Two glob patterns are enough. **No CLI flag** — keep convention-over-config.
- **Builder integration:** new fn `attach_type_anchors(top: &mut TopIR, trace: &Trace, spec_paths: &[PathBuf])` in `decompiler::builder`. Iterates anchors, finds the narrowest fn (smallest `exit_idx - entry_idx`) whose `[entry_idx, exit_idx]` contains `anchor.idx`, appends `TypeAnchorIR` to its `type_anchors`. Public re-export through `prelude`.
- **`build_trace_ir` signature change:** add `spec_paths: &[PathBuf]` as last param. Callers in tests pass `&[]`. Server passes the auto-discovered list.
- **Render section:** Python `render_func_md` already has the `## Type anchors` block (markdown.py:207-229). Port verbatim — group anchors by `callee_name`, render `**name** (callee_pc:#x, ×N)`, params `(reg:type, ...)`, ret `reg:type`, hit-idx samples, provenance.

**Out of scope (deferred to M3-ι2b or later):**
- `vm_candidate.py` port (separate milestone).
- `ollvmdet.py` port (vm_candidate prerequisite).
- Per-call trace JNI events as a spec source (Python supports that as stretch goal; not done yet on Python side either).
- `/api/dec/llm-call` (separate milestone).
- Real-trace parity script (defer until vm_candidate ships so the parity covers both signals together).

**Tech Stack:** Rust 1.95. No new workspace deps (`serde_json` already in tree).

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/decompiler/type_anchor.py:1-131` — full Python reference. 130 LOC.
- `viewer/decompiler/builder.py:465-499` — `attach_type_anchors` reference.
- `viewer/decompiler/render/markdown.py:207-229` — render section reference.
- `tools/hooks/libart_jni.json` (exists; `kind: "jni_vtable"`, NOT a type_specs spec — sample only for format reference).
- `.worktrees/feat-trace-decompiler/tools/hooks/type_specs_example.json` (worktree-only sample of the actual `kind: "type_specs"` schema; format documented in Task 1 below).
- `tracemiku-core::decompiler::ir::TypeAnchorIR` (M3-δ shipped) — Rust IR struct already has `idx, callee_pc, callee_name, params: Vec<(String, String)>, ret_reg, ret_type, provenance` fields ready.
- `tracemiku-core::decompiler::ir::FuncIR.type_anchors: Vec<TypeAnchorIR>` (M3-δ shipped) — field exists, currently always empty.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/type_anchor.rs` (new) | `TypeSpec`, `TypeAnchor`, `load_type_specs(&[PathBuf]) -> Vec<TypeSpec>`, `find_anchors(&Trace, &[TypeSpec]) -> Vec<TypeAnchor>`. |
| `rust/crates/tracemiku-core/src/decompiler/mod.rs` (modify) | `pub mod type_anchor;` |
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (modify) | New `pub fn attach_type_anchors(&mut TopIR, &Trace, &[PathBuf])`. `build_trace_ir` gains a `spec_paths: &[PathBuf]` param; calls `attach_type_anchors` when non-empty. |
| `rust/crates/tracemiku-core/src/decompiler/render.rs` (modify) | `render_func_md` emits `## Type anchors (n)` section when `fn.type_anchors` non-empty. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `TypeSpec`, `TypeAnchor`, `load_type_specs`, `find_anchors`, `attach_type_anchors`. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | Auto-discover type-spec JSON files: `tools/hooks/*` filtered by `kind == "type_specs"`, plus `examples/<so>/type_specs.json` if present. Pass list to `build_trace_ir`. |
| `tools/hooks/type_specs_example.json` (new — copied from worktree sample) | First real type_specs JSON in tree. Uses `callee_pc: "0x0"` placeholders so it's a no-op until users edit. |
| `rust/crates/tracemiku-core/src/decompiler/type_anchor.rs` test mod | Unit tests: load_type_specs (good/bad JSON), find_anchors on synth trace, attach_type_anchors narrowest-fn assignment. |
| `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs` (modify) | Add test: synth trace + bl-target spec → `## Type anchors` appears in markdown. |
| `TODO.md` + spec | Mark `type_anchor.py` complete in spec; note M3-ι2a shipped. |

---

## Task 1: `type_anchor` module

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/type_anchor.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/mod.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

- [ ] **Step 1: Define types + loader + matcher**

```rust
//! Type anchors — JSON-spec-driven (reg, type) injection from trace bl/blr
//! callsites. Direct port of viewer/decompiler/type_anchor.py.
//!
//! Universality (parity with Python §7.0 design checklist):
//!   - No hardcoded SO/fn/offset/reg names; all from external JSON spec.
//!   - User adds any spec file (libssl/libc/custom SDK).
//!   - Detection ≠ decision: we mark anchors, LLM decides usage.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::disasm::decode;
use crate::trace::Trace;

/// One spec entry. Mirrors Python `TypeSpec` dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSpec {
    pub callee_pc: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub params: Vec<(String, String)>,
    #[serde(default = "default_ret_reg")]
    pub ret_reg: String,
    #[serde(default)]
    pub ret_type: String,
    #[serde(default)]
    pub provenance: String,
}

fn default_ret_reg() -> String {
    "x0".to_string()
}

impl Default for TypeSpec {
    fn default() -> Self {
        Self {
            callee_pc: 0,
            name: String::new(),
            params: Vec::new(),
            ret_reg: default_ret_reg(),
            ret_type: String::new(),
            provenance: String::new(),
        }
    }
}

/// One trace bl-callsite hit. Mirrors Python `TypeAnchor`.
#[derive(Debug, Clone)]
pub struct TypeAnchor {
    pub idx: usize,
    pub callee_pc: u64,
    pub spec: TypeSpec,
}

/// Parse a callee_pc value: accept JSON number OR hex/dec string ("0x1234").
fn parse_callee_pc(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        return if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            s.parse::<u64>().ok()
        };
    }
    None
}

/// Parse a params entry: accept ["reg", "type"] OR {"reg":..., "type":...}.
fn parse_params(arr: &serde_json::Value) -> Vec<(String, String)> {
    let Some(items) = arr.as_array() else { return Vec::new() };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if let Some(pair) = it.as_array() {
            if pair.len() >= 2 {
                let r = pair[0].as_str().unwrap_or("").to_string();
                let t = pair[1].as_str().unwrap_or("").to_string();
                out.push((r, t));
            }
        } else if let Some(obj) = it.as_object() {
            let r = obj.get("reg").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let t = obj.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push((r, t));
        }
    }
    out
}

/// Parse ret: accept ["reg", "type"], {"reg":..., "type":...}, or fall back
/// to ret_reg/ret_type top-level fields.
fn parse_ret(entry: &serde_json::Value) -> (String, String) {
    if let Some(ret) = entry.get("ret") {
        if let Some(arr) = ret.as_array() {
            if arr.len() >= 2 {
                return (
                    arr[0].as_str().unwrap_or("x0").to_string(),
                    arr[1].as_str().unwrap_or("").to_string(),
                );
            }
        }
        if let Some(obj) = ret.as_object() {
            return (
                obj.get("reg").and_then(|x| x.as_str()).unwrap_or("x0").to_string(),
                obj.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            );
        }
    }
    (
        entry
            .get("ret_reg")
            .and_then(|x| x.as_str())
            .unwrap_or("x0")
            .to_string(),
        entry
            .get("ret_type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    )
}

/// Load multiple type-spec JSON files. Skips files that don't exist or fail
/// to parse (lenient). Mirrors Python `load_type_specs`.
///
/// Expected JSON schema (matches `tools/hooks/type_specs_example.json`):
/// ```json
/// {
///   "version": 1,
///   "kind": "type_specs",
///   "specs": [
///     {"name": "FindClass", "callee_pc": "0x...",
///      "params": [["x0", "JNIEnv*"], ["x1", "const char*"]],
///      "ret":   ["x0", "jclass"]},
///     ...
///   ]
/// }
/// ```
pub fn load_type_specs<P: AsRef<Path>>(paths: &[P]) -> Vec<TypeSpec> {
    let mut out = Vec::new();
    for p in paths {
        let path = p.as_ref();
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&text) else { continue };
        let Some(specs) = v.get("specs").and_then(|s| s.as_array()) else { continue };
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        for entry in specs {
            let Some(callee_pc) = entry.get("callee_pc").and_then(parse_callee_pc).or_else(|| {
                entry.get("callee_pc").and_then(|v| Some(parse_callee_pc(v)?))
            }) else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let params = entry
                .get("params")
                .map(parse_params)
                .unwrap_or_default();
            let (ret_reg, ret_type) = parse_ret(entry);
            let provenance = if name.is_empty() {
                format!("{fname}#{:#x}", callee_pc)
            } else {
                format!("{fname}#{name}")
            };
            out.push(TypeSpec { callee_pc, name, params, ret_reg, ret_type, provenance });
        }
    }
    out
}

/// Scan trace for bl/blr instructions whose callee_pc (= pc(i+1)) matches
/// any TypeSpec. Mirrors Python `find_anchors`.
pub fn find_anchors(trace: &Trace, specs: &[TypeSpec]) -> Vec<TypeAnchor> {
    if specs.is_empty() {
        return Vec::new();
    }
    let n = trace.len();
    if n == 0 {
        return Vec::new();
    }
    use std::collections::HashMap;
    let pc_to_spec: HashMap<u64, &TypeSpec> = specs.iter().map(|s| (s.callee_pc, s)).collect();
    let mut out = Vec::new();
    for i in 0..(n.saturating_sub(1)) {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        if d.mnemonic != "bl" && d.mnemonic != "blr" {
            continue;
        }
        let target = trace.pc(i + 1);
        if let Some(&spec) = pc_to_spec.get(&target) {
            out.push(TypeAnchor {
                idx: i,
                callee_pc: target,
                spec: spec.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(json: &str) -> tempfile::NamedTempFile {
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(json.as_bytes()).unwrap();
        tf.flush().unwrap();
        tf
    }

    #[test]
    fn load_type_specs_parses_array_form_params_and_ret() {
        let json = r#"{
          "version": 1,
          "kind": "type_specs",
          "specs": [
            {"name": "FindClass", "callee_pc": "0x1234",
             "params": [["x0", "JNIEnv*"], ["x1", "const char*"]],
             "ret":   ["x0", "jclass"]}
          ]
        }"#;
        let tf = write_temp(json);
        let specs = load_type_specs(&[tf.path()]);
        assert_eq!(specs.len(), 1);
        let s = &specs[0];
        assert_eq!(s.callee_pc, 0x1234);
        assert_eq!(s.name, "FindClass");
        assert_eq!(s.params, vec![
            ("x0".into(), "JNIEnv*".into()),
            ("x1".into(), "const char*".into()),
        ]);
        assert_eq!(s.ret_reg, "x0");
        assert_eq!(s.ret_type, "jclass");
        assert!(s.provenance.contains("FindClass"));
    }

    #[test]
    fn load_type_specs_accepts_int_callee_pc() {
        let json = r#"{"specs":[{"name":"f","callee_pc":4660,"params":[],"ret":["x0","int"]}]}"#;
        let tf = write_temp(json);
        let specs = load_type_specs(&[tf.path()]);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].callee_pc, 4660);
    }

    #[test]
    fn load_type_specs_skips_bad_files() {
        let bad = write_temp("not json");
        let nope = std::path::PathBuf::from("/nonexistent/x.json");
        let specs = load_type_specs(&[bad.path().to_path_buf(), nope]);
        assert!(specs.is_empty());
    }

    #[test]
    fn find_anchors_matches_bl_target_pc() {
        // Synth: nop @ 0x1000, bl @ 0x1004 → 0x2000, nop @ 0x2000.
        // 0x9400003f = bl +0x100 ⇒ 0x1004 + 0x400 = 0x1404; doesn't matter
        // because find_anchors uses recorded pc(i+1) not the bl displacement.
        use crate::trace::REC_SIZE;
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs = [0x1000u64, 0x1004, 0x2000];
        let insts = [0xd503201fu32, 0x94000400, 0xd503201f];
        let mut buf = vec![0u8; REC_SIZE * 3];
        for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":0x10000}}"#,
        ).unwrap();
        let trace = crate::trace::Trace::load(&cd).unwrap();
        let specs = vec![TypeSpec {
            callee_pc: 0x2000,
            name: "Target".into(),
            ..Default::default()
        }];
        let anchors = find_anchors(&trace, &specs);
        assert_eq!(anchors.len(), 1, "expected exactly one anchor: {anchors:?}");
        assert_eq!(anchors[0].idx, 1);
        assert_eq!(anchors[0].callee_pc, 0x2000);
        assert_eq!(anchors[0].spec.name, "Target");
    }

    #[test]
    fn find_anchors_returns_empty_when_no_specs() {
        // Don't even need a real trace — empty specs short-circuits.
        // But we do need a valid Trace; reuse synth from above, in a smaller form:
        use crate::trace::REC_SIZE;
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join("trace.bin"), vec![0u8; REC_SIZE]).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x0","size":0x100}}"#,
        ).unwrap();
        let trace = crate::trace::Trace::load(&cd).unwrap();
        assert!(find_anchors(&trace, &[]).is_empty());
    }
}
```

- [ ] **Step 2: Wire module + prelude**

`decompiler/mod.rs`: add `pub mod type_anchor;` (after `pub mod render;`).

`prelude.rs`: extend the decompiler exports —

```rust
pub use crate::decompiler::type_anchor::{
    find_anchors, load_type_specs, TypeAnchor, TypeSpec,
};
```

(Keep `attach_type_anchors` re-export for after Task 2.)

- [ ] **Step 3: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler::type_anchor 2>&1 | tail -10
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/type_anchor.rs \
        rust/crates/tracemiku-core/src/decompiler/mod.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "$(cat <<'EOF'
feat(core): type_anchor port — TypeSpec/TypeAnchor + load_type_specs/find_anchors

Pure 1:1 port of viewer/decompiler/type_anchor.py:
  - TypeSpec / TypeAnchor data carriers (serde-ready).
  - load_type_specs(&[Path]) -> Vec<TypeSpec>: lenient JSON loader,
    accepts hex/dec callee_pc strings + array/object params/ret forms.
  - find_anchors(&Trace, &[TypeSpec]) -> Vec<TypeAnchor>: O(n) bl/blr
    scan, target = recorded pc(i+1).

Universality preserved (no hardcoded SO/fn/reg names; all from spec).

Re-exported via prelude. Tests cover good/bad JSON, int/string callee_pc,
bl-target matching, empty-specs short-circuit.

M3-ι2a Task 1.
EOF
)"
```

---

## Task 2: `attach_type_anchors` + builder integration

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

- [ ] **Step 1: Add `attach_type_anchors` in `builder.rs`**

Mirrors Python `viewer/decompiler/builder.py:465-499`:

```rust
use std::path::Path;

use crate::decompiler::ir::TypeAnchorIR;
use crate::decompiler::type_anchor::{find_anchors, load_type_specs};

/// In-place: populate FuncIR.type_anchors for each fn whose [entry_idx,
/// exit_idx] contains an anchor. When multiple fns contain the same
/// anchor (parent + child overlap), assigns to the narrowest (smallest
/// idx range). Mirrors viewer/decompiler/builder.py:465-499.
pub fn attach_type_anchors<P: AsRef<Path>>(
    top: &mut TopIR,
    trace: &Trace,
    spec_paths: &[P],
) {
    let specs = load_type_specs(spec_paths);
    if specs.is_empty() {
        return;
    }
    let anchors = find_anchors(trace, &specs);
    if anchors.is_empty() {
        return;
    }
    for a in anchors {
        // Pick the narrowest fn whose idx range contains a.idx.
        let mut narrow: Option<usize> = None;
        let mut narrow_span: u64 = u64::MAX;
        for (fi, f) in top.fns.iter().enumerate() {
            if a.idx < f.entry_idx || a.idx > f.exit_idx {
                continue;
            }
            let span = (f.exit_idx as u64).saturating_sub(f.entry_idx as u64);
            if span < narrow_span {
                narrow_span = span;
                narrow = Some(fi);
            }
        }
        let Some(fi) = narrow else { continue };
        top.fns[fi].type_anchors.push(TypeAnchorIR {
            idx: a.idx,
            callee_pc: a.callee_pc,
            callee_name: a.spec.name,
            params: a.spec.params,
            ret_reg: a.spec.ret_reg,
            ret_type: a.spec.ret_type,
            provenance: a.spec.provenance,
        });
    }
}
```

- [ ] **Step 2: Extend `build_trace_ir` signature**

```rust
pub fn build_trace_ir<P: AsRef<Path>>(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
    spec_paths: &[P],
) -> TopIR {
    let mut top = build_root_only(trace, meta, sym, cfg);
    if top_k > 0 {
        split_top_k_callees(&mut top, trace, sym, cfg, top_k, min_records);
    }
    if !spec_paths.is_empty() {
        attach_type_anchors(&mut top, trace, spec_paths);
    }
    classify_blocks_by_tier(&mut top, 150);
    top
}
```

**Update all callers** of `build_trace_ir`:
- `decompiler::builder` tests — pass `&[] as &[std::path::PathBuf]` (or `&[""; 0]`) at the new last arg.
- `tracemiku-server::state::AppState::load` — currently passes `(trace, meta, sym, cfg, 10, 50)`; will be updated in Task 3.
- Any other callers (search with `grep -rn "build_trace_ir" rust/`).

- [ ] **Step 3: Re-export in prelude**

`prelude.rs`: add `attach_type_anchors` to the existing decompiler exports.

- [ ] **Step 4: Tests**

In `decompiler::builder` tests mod:

```rust
#[test]
fn attach_type_anchors_assigns_to_narrowest_fn() {
    use std::io::Write;

    let dir = synth_two_callees();
    let (t, meta, sym) = load_two_callees(&dir);
    let cfg = crate::cfg::build_cfg(&t);
    let mut top = build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, 0, 0, &[]);

    // Add an anchor at callee_pc=0x100100 (= f_alpha entry, called from idx 1
    // in synth_two_callees; trace.pc(1)=0x100004 (bl), trace.pc(2)=0x100100).
    // synth_two_callees fixture: idx 1 has a `bl 0x100100`.
    let mut tf = tempfile::NamedTempFile::new().unwrap();
    let json = r#"{"specs":[{"name":"f_alpha","callee_pc":"0x100100","params":[],"ret":["x0","void"]}]}"#;
    tf.write_all(json.as_bytes()).unwrap();
    tf.flush().unwrap();

    attach_type_anchors(&mut top, &t, &[tf.path().to_path_buf()]);

    // F0 (root) should have 1 anchor (no callees promoted at top_k=0,
    // so root is the only candidate).
    assert_eq!(
        top.fns[0].type_anchors.len(),
        1,
        "F0 should carry the anchor; got {:?}",
        top.fns[0].type_anchors
    );
    let a = &top.fns[0].type_anchors[0];
    assert_eq!(a.callee_pc, 0x100100);
    assert_eq!(a.callee_name, "f_alpha");
    assert_eq!(a.ret_type, "void");
}

#[test]
fn build_trace_ir_skips_anchors_when_no_specs() {
    let dir = synth_two_callees();
    let (t, meta, sym) = load_two_callees(&dir);
    let cfg = crate::cfg::build_cfg(&t);
    let top = build_trace_ir::<std::path::PathBuf>(&t, &meta, &sym, &cfg, 0, 0, &[]);
    assert!(top.fns.iter().all(|f| f.type_anchors.is_empty()));
}
```

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core 2>&1 | tail -5
cargo build -p tracemiku-server 2>&1 | tail -5
# tracemiku-server probably FAILS to compile because state.rs's build_trace_ir call
# needs the new spec_paths arg. Update state.rs in this task or the next? Plan
# does Task 3 next — for now, fix server build by passing &[] in state.rs as a
# minimal patch.
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

If `tracemiku-server` doesn't build because of the changed signature, apply the
**minimal** state.rs patch to call `build_trace_ir(&trace, &meta, &symbols, &cfg, 10, 50, &[] as &[std::path::PathBuf])` — Task 3 will replace `&[]` with the auto-discovered list.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs \
        rust/crates/tracemiku-core/src/prelude.rs \
        rust/crates/tracemiku-server/src/state.rs
git commit -m "$(cat <<'EOF'
feat(core): attach_type_anchors + build_trace_ir spec_paths param

attach_type_anchors(&mut TopIR, &Trace, &[Path]) populates
FuncIR.type_anchors for each fn whose [entry_idx, exit_idx] contains
an anchor. Multi-containing anchors go to the narrowest fn (parent +
child overlap → child wins). Mirrors viewer/decompiler/builder.py:465-499.

build_trace_ir gains a final spec_paths: &[P] param. Empty slice =
no-op (backward-compatible with all existing tests).

state.rs threads &[] for now — Task 3 wires auto-discovery.

Tests:
  - attach_type_anchors_assigns_to_narrowest_fn (core)
  - build_trace_ir_skips_anchors_when_no_specs (core)

M3-ι2a Task 2.
EOF
)"
```

---

## Task 3: Server-side spec auto-discovery + render section

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/render.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs`
- Create: `tools/hooks/type_specs_example.json` (placeholder)

- [ ] **Step 1: Auto-discover type-spec JSONs in `state.rs`**

Add a helper:

```rust
/// Discover type-spec JSON files. Two sources:
///   1. <repo_root>/tools/hooks/*.json — filtered to entries with
///      top-level `"kind": "type_specs"`.
///   2. <repo_root>/examples/<so>/type_specs.json — convention path.
///
/// Returns absolute paths. Order: tools/hooks first (alphabetical),
/// then examples — load_type_specs is order-insensitive but stable
/// ordering helps reproducibility.
fn discover_type_spec_paths(
    repo_root: &std::path::Path,
    so_name_no_ext: Option<&str>,
) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let hooks_dir = repo_root.join("tools").join("hooks");
    if let Ok(rd) = std::fs::read_dir(&hooks_dir) {
        let mut paths: Vec<std::path::PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        paths.sort();
        for p in paths {
            // Header check: top-level "kind" must equal "type_specs".
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&text) else {
                continue;
            };
            if v.get("kind").and_then(|x| x.as_str()) == Some("type_specs") {
                out.push(p);
            }
        }
    }
    if let Some(so) = so_name_no_ext {
        let p = repo_root.join("examples").join(so).join("type_specs.json");
        if p.exists() {
            out.push(p);
        }
    }
    out
}
```

In `AppState::load`, after `find_repo_root` succeeds, build the spec list:

```rust
let spec_paths: Vec<std::path::PathBuf> = if let Some(root) = find_repo_root(&trace_dir) {
    let so_name = meta.module.as_ref().and_then(|m| {
        m.name.strip_suffix(".so").map(|s| s.to_string())
    });
    discover_type_spec_paths(&root, so_name.as_deref())
} else {
    Vec::new()
};
```

Then thread it into the `build_trace_ir` call:

```rust
let top_ir = build_trace_ir(&trace, &meta, &symbols, &cfg, 10, 50, &spec_paths);
```

(Note: `find_repo_root` is called twice. Refactor to call once and reuse — minor cleanup, do it.)

- [ ] **Step 2: Render `## Type anchors` section**

In `decompiler/render.rs::render_func_md`, before the per-block loop (after the metadata block), add:

```rust
if !fn_.type_anchors.is_empty() {
    out.push_str(&format!(
        "## Type anchors ({})\n\n",
        fn_.type_anchors.len()
    ));
    out.push_str("> JSON-spec-driven (DEC3-B). LLM should trust these as ABI ground truth.\n\n");

    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<String, Vec<&crate::decompiler::ir::TypeAnchorIR>> = BTreeMap::new();
    for a in &fn_.type_anchors {
        let key = if a.callee_name.is_empty() {
            format!("sub_{:x}", a.callee_pc)
        } else {
            a.callee_name.clone()
        };
        grouped.entry(key).or_default().push(a);
    }

    for (name, anchors) in &grouped {
        let a0 = anchors[0];
        let params_str: String = a0
            .params
            .iter()
            .map(|(r, t)| format!("{r}:{t}"))
            .collect::<Vec<_>>()
            .join(", ");
        let ret_str = if a0.ret_type.is_empty() {
            a0.ret_reg.clone()
        } else {
            format!("{}:{}", a0.ret_reg, a0.ret_type)
        };
        out.push_str(&format!(
            "- **{name}** ({:#x}, ×{}) `({params_str})` → `{ret_str}`\n",
            a0.callee_pc,
            anchors.len()
        ));
        let mut idxs: Vec<usize> = anchors.iter().map(|a| a.idx).collect();
        idxs.sort_unstable();
        let take_n = idxs.len().min(5);
        let suffix = if anchors.len() > 5 { "..." } else { "" };
        let idx_list: Vec<String> = idxs[..take_n].iter().map(|i| i.to_string()).collect();
        out.push_str(&format!("  - hit idx: [{}]{}\n", idx_list.join(", "), suffix));
        out.push_str(&format!("  - source: `{}`\n", a0.provenance));
    }
    out.push('\n');
}
```

- [ ] **Step 3: Create placeholder spec JSON**

Create `tools/hooks/type_specs_example.json` (copy from
`.worktrees/feat-trace-decompiler/tools/hooks/type_specs_example.json`).
This file uses `"callee_pc": "0x0"` placeholders so it's effectively a
no-op — the auto-discovery will pick it up but find_anchors won't match
any real PC (no in-trace bl jumps to PC 0x0). Users edit this to add
real specs.

- [ ] **Step 4: Render unit test**

In `decompiler/render.rs` tests:

```rust
#[test]
fn render_func_md_emits_type_anchors_section() {
    use crate::decompiler::ir::TypeAnchorIR;
    let f = FuncIR {
        id: "F0".to_string(),
        name: "f".to_string(),
        type_anchors: vec![TypeAnchorIR {
            idx: 5,
            callee_pc: 0x2000,
            callee_name: "FindClass".to_string(),
            params: vec![
                ("x0".to_string(), "JNIEnv*".to_string()),
                ("x1".to_string(), "const char*".to_string()),
            ],
            ret_reg: "x0".to_string(),
            ret_type: "jclass".to_string(),
            provenance: "libart_jni.json#FindClass".to_string(),
        }],
        ..Default::default()
    };
    let md = render_func_md(&f, "all");
    assert!(md.contains("## Type anchors (1)"), "missing section: {md}");
    assert!(md.contains("**FindClass**"));
    assert!(md.contains("(0x2000, ×1)"));
    assert!(md.contains("`(x0:JNIEnv*, x1:const char*)`"));
    assert!(md.contains("→ `x0:jclass`"));
    assert!(md.contains("hit idx: [5]"));
    assert!(md.contains("source: `libart_jni.json#FindClass`"));
}
```

- [ ] **Step 5: Integration test**

In `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs`, add a test
that drops a temp `type_specs.json` next to the `examples/<so>/`
convention path and asserts the rendered markdown contains a
`## Type anchors` section. Since `examples/` lookup happens via
`find_repo_root` which expects `tracemiku` script + `examples/` dir
side-by-side — the existing fixture's tempdir doesn't satisfy that.
**Simpler:** drop the spec JSON inside the `<repo_root>/tools/hooks/`
directory at test-run time? That would pollute the repo. **Instead:**
add a CLI flag or env var override for spec paths? Out of scope.

**Best pragmatic option:** just verify the section *renders* via the
unit test in Step 4. Skip the route-level integration test for type
anchors; the `attach_type_anchors_assigns_to_narrowest_fn` builder
test + render unit test cover the contract, and the route handler is
just `render_func_md(fn, tier)` (no anchor-specific branching).

Document this decision in the commit message.

- [ ] **Step 6: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-server 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-server --test test_dec_fn_route 2>&1 | tail -10
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -10
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-core/src/decompiler/render.rs \
        tools/hooks/type_specs_example.json
git commit -m "$(cat <<'EOF'
feat(core,server): auto-discover type_specs + render type-anchors section

state.rs:
  - discover_type_spec_paths(): walk tools/hooks/ for files with
    top-level "kind": "type_specs"; check examples/<so>/type_specs.json.
  - build_trace_ir now receives the discovered list.

render_func_md: new "## Type anchors (n)" section per fn (skeleton —
groups by callee_name, lists params/ret/provenance, first 5 hit idxs).
Mirrors viewer/decompiler/render/markdown.py:207-229.

tools/hooks/type_specs_example.json: placeholder file with callee_pc=0x0
entries (no-op until users edit). Provides format reference and gives
discover_type_spec_paths something to find on a fresh checkout.

Tests:
  - render_func_md_emits_type_anchors_section (core)
  - (existing builder tests cover attach + populate paths)

M3-ι2a Task 3.
EOF
)"
```

---

## Task 4: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Update spec rows**

Find the `type_anchor.py` row (search "`type_anchor.py`"). If absent
under Python→Rust mapping, add it:

```markdown
| `type_anchor.py` (TypeSpec/TypeAnchor + load + find) | `tracemiku-core::decompiler::type_anchor` + `attach_type_anchors` in builder | ✅ M3-ι2a | 1:1 port; auto-discovers tools/hooks/*.json with kind=="type_specs" plus examples/<so>/type_specs.json. Render markdown section parity with Python markdown.py:207-229. |
```

If a `builder.py` row already exists (M3-ι updated it), append a
`+ type_anchors auto-discovery (M3-ι2a)` to its note.

- [ ] **Step 2: Update TODO.md**

In the progress section, append:

```markdown
- M3-ι2a type_anchor.py port + auto-discovery + render section: ✅ 2026-05-04
```

Also append to the milestone-summary list:

```markdown
- M3-ι2a: type_anchor.py port + tools/hooks/ auto-discovery + render type-anchors section ✅ 2026-05-04
```

Refine the M3-ι2 pointer (replace the multi-item line):

```markdown
- M3-ι2b (next): vm_candidate.py port (depends on ollvmdet.py port), summary VM-candidates hex-dump body, /api/dec/fn/{id} sym:* / bn:* source support (gated on Rust BN backend), /api/dec/llm-call
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-ι2a complete (type_anchor port)"
```

---

## Self-Review

**Spec coverage:**

| Item | Task |
|---|---|
| `TypeSpec` / `TypeAnchor` data carriers | Task 1 |
| `load_type_specs` JSON loader | Task 1 |
| `find_anchors` bl/blr trace scan | Task 1 |
| `attach_type_anchors` narrowest-fn assignment | Task 2 |
| `build_trace_ir` spec_paths plumb-through | Task 2 |
| Server auto-discovery (tools/hooks + examples/<so>) | Task 3 |
| `render_func_md` type-anchors section | Task 3 |
| Placeholder `tools/hooks/type_specs_example.json` | Task 3 |
| Spec/TODO sync | Task 4 |

**Out of scope (deferred to M3-ι2b):**
- `vm_candidate.py` + `ollvmdet.py` ports.
- `summary_md` VM-candidates body fidelity (header-only is shipped).
- `/api/dec/fn/{id}` sym:* / bn:* source support.
- `/api/dec/llm-call`.
- Real-trace parity script (defer to after M3-ι2b so a single script covers both ports).

**Risks:**

1. **Backward-compat break in `build_trace_ir` signature.** Adding a 7th param breaks all callers. Mitigated by updating the only consumer (`state.rs`) and all internal tests in the same Task. Search `grep -rn "build_trace_ir(" rust/` exhaustively before committing Task 2 to make sure no caller is missed.
2. **Spec auto-discovery surprise.** Users might be surprised that `tools/hooks/type_specs_example.json` is auto-loaded with no flag. Mitigated because the placeholder file is a no-op (callee_pc=0x0 won't match any real bl target). Document in commit message.
3. **`generic` parameter friction in `build_trace_ir`.** Using `<P: AsRef<Path>>` works but means callers passing `&[]` need a turbofish (`build_trace_ir::<std::path::PathBuf>(...)`). Acceptable; tests show how.
4. **Render assumes anchors come pre-sorted by idx.** Python uses dict-grouping which preserves insertion order; Rust `BTreeMap<String, _>` sorts by callee_name. That's a slight divergence (callee-name alpha vs first-occurrence order). Acceptable — both are stable.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
