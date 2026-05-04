//! TraceIR builder — M3-δ skeleton.
//!
//! Produces a TopIR with metadata + a single root FuncIR `F0` covering
//! the entire trace. Block/loop/call/type_anchor/vm-candidate
//! construction defer to M3-ε.
//!
//! Mirrors viewer/decompiler/builder.py:244-287.
//!
//! Note: Python's `Trace` carries `meta` as an attribute. Rust's `Trace`
//! and `TraceMeta` are loaded separately, so this builder takes both.

use crate::decompiler::ir::{FuncIR, TopIR};
use crate::symbols::SymbolMap;
use crate::trace::{Trace, TraceMeta};

/// Build a minimal TopIR from a loaded Trace + TraceMeta. Skeleton scope:
///   - top-level metadata (records, module_*, cmd, method, truncated)
///   - one root FuncIR `F0` covering [0, n-1]
///
/// Mirrors `viewer/decompiler/builder.py:244-287`. Block construction,
/// callee splits, type anchors, and VM detection defer to M3-ε.
pub fn build_trace_ir(trace: &Trace, meta: &TraceMeta, sym: &SymbolMap) -> TopIR {
    let n = trace.len();
    let module_base = meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    let mut top = TopIR {
        records: n as u64,
        truncated: meta.truncated,
        last_insn_is_ret: meta.last_insn_is_ret,
        cmd: meta.cmd,
        method: meta.method.clone(),
        tracemiku_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: String::new(),
        ..Default::default()
    };
    if let Some(m) = &meta.module {
        top.module_name = m.name.clone();
        top.module_base = module_base;
        top.module_size = m.size;
    }

    if n == 0 {
        return top;
    }

    let pc0 = trace.pc(0);
    let pc_last = trace.pc(n - 1);
    let (root_name, _) = sym.lookup(pc0);
    let resolved_name = if root_name == "?" {
        format!("sub_{:x}", pc0.wrapping_sub(module_base))
    } else {
        root_name
    };
    top.fns.push(FuncIR {
        id: "F0".to_string(),
        name: resolved_name,
        pc_start: pc0,
        pc_end: pc_last,
        entry_idx: 0,
        exit_idx: n - 1,
        truncated: top.truncated,
        last_insn_is_ret: top.last_insn_is_ret,
        exec_count: 1,
        ..Default::default()
    });
    top
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;

    fn synth_root_only() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_3r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 3];
        for i in 0..3usize {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64) * 4).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42}"#,
        )
        .unwrap();
        dir
    }

    fn load(dir: &tempfile::TempDir) -> (Trace, TraceMeta) {
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd).unwrap();
        let m = TraceMeta::load(&cd).unwrap();
        (t, m)
    }

    #[test]
    fn build_trace_ir_emits_root_funcir() {
        let dir = synth_root_only();
        let (t, m) = load(&dir);
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.freeze();
        let top = build_trace_ir(&t, &m, &sym);

        assert_eq!(top.records, 3);
        assert_eq!(top.module_name, "libt.so");
        assert_eq!(top.module_base, 0x100000);
        assert_eq!(top.module_size, 4096);
        assert_eq!(top.method, "f");
        assert_eq!(top.cmd, Some(42));
        assert_eq!(top.fns.len(), 1, "skeleton emits exactly 1 root FuncIR");
        let f0 = &top.fns[0];
        assert_eq!(f0.id, "F0");
        assert_eq!(f0.name, "f_root");
        assert_eq!(f0.entry_idx, 0);
        assert_eq!(f0.exit_idx, 2);
        assert_eq!(f0.exec_count, 1);
    }

    #[test]
    fn build_trace_ir_unknown_root_uses_sub_hex_name() {
        let dir = synth_root_only();
        let (t, m) = load(&dir);
        let sym = SymbolMap::new();
        let top = build_trace_ir(&t, &m, &sym);
        assert_eq!(top.fns[0].name, "sub_0", "pc0=0x100000 base=0x100000 → offset 0");
    }

    #[test]
    fn build_trace_ir_empty_trace_returns_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_0r_0ms");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::File::create(cd.join("trace.bin")).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x0","size":0}}"#,
        )
        .unwrap();
        let cd_path = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd_path).unwrap();
        let m = TraceMeta::load(&cd_path).unwrap();
        let sym = SymbolMap::new();
        let top = build_trace_ir(&t, &m, &sym);
        assert_eq!(top.records, 0);
        assert!(top.fns.is_empty(), "empty trace → no fns");
    }
}
