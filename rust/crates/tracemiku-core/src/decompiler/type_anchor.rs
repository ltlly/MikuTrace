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
    let Some(items) = arr.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if let Some(pair) = it.as_array() {
            if pair.len() >= 2 {
                let r = pair[0].as_str().unwrap_or("").to_string();
                let t = pair[1].as_str().unwrap_or("").to_string();
                out.push((r, t));
            }
        } else if let Some(obj) = it.as_object() {
            let r = obj
                .get("reg")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let t = obj
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
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
                obj.get("reg")
                    .and_then(|x| x.as_str())
                    .unwrap_or("x0")
                    .to_string(),
                obj.get("type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
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
///   ]
/// }
/// ```
pub fn load_type_specs<P: AsRef<Path>>(paths: &[P]) -> Vec<TypeSpec> {
    let mut out = Vec::new();
    for p in paths {
        let path = p.as_ref();
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&text) else {
            continue;
        };
        let Some(specs) = v.get("specs").and_then(|s| s.as_array()) else {
            continue;
        };
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        for entry in specs {
            let Some(callee_pc) = entry.get("callee_pc").and_then(parse_callee_pc) else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let params = entry.get("params").map(parse_params).unwrap_or_default();
            let (ret_reg, ret_type) = parse_ret(entry);
            let provenance = if name.is_empty() {
                format!("{fname}#{callee_pc:#x}")
            } else {
                format!("{fname}#{name}")
            };
            out.push(TypeSpec {
                callee_pc,
                name,
                params,
                ret_reg,
                ret_type,
                provenance,
            });
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
    for i in 0..n.saturating_sub(1) {
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
        assert_eq!(
            s.params,
            vec![
                ("x0".into(), "JNIEnv*".into()),
                ("x1".into(), "const char*".into()),
            ]
        );
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
        // find_anchors uses recorded pc(i+1) not the bl displacement, so the
        // exact bl encoding doesn't matter as long as capstone decodes it as bl.
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
            r#"{"module":{"name":"libt.so","base":"0x1000","size":"0x10000"}}"#,
        )
        .unwrap();
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
        // Empty specs short-circuits before any trace walking, but we still
        // need a valid Trace to pass in.
        use crate::trace::REC_SIZE;
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join("trace.bin"), vec![0u8; REC_SIZE]).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x0","size":"0x100"}}"#,
        )
        .unwrap();
        let trace = crate::trace::Trace::load(&cd).unwrap();
        assert!(find_anchors(&trace, &[]).is_empty());
    }
}
