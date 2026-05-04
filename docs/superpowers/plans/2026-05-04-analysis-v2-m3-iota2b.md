# Analysis v2 — M3-ι2b Implementation Plan (ollvmdet + vm_candidate port + summary hex-dump)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the OLLVM-VM detection pair to Rust and finish summary-md fidelity. After this milestone:

1. `tracemiku-core::ollvmdet` exposes `ollvm_detect_vm(trace, min_entries, conf_threshold) -> Vec<OllvmFinding>`. Pure 1:1 port of `viewer/ollvmdet.py` (88 LOC). Heuristic that scans trace for indirect br/blr near `ldr [..,lsl #3]` table-loads and `!` self-update loads; emits `{fn_pc, entry_count, confidence, reason, hint}` dict-equivalent.
2. `tracemiku-core::decompiler::vm_candidate` exposes `detect_vm_candidates(trace, cfg, mem) -> Vec<VmCandidateIR>`. Port of `viewer/decompiler/vm_candidate.py` (176 LOC). Two helpers (`_find_self_update_loads`, `_bytecode_range`) + main entry that grabs hex-dump from `MemShadow` for the bytecode region.
3. `build_trace_ir` calls `detect_vm_candidates(trace, cfg, memshadow)` (when memshadow available) and populates `top.vm_candidates`. New optional param `memshadow: Option<&MemShadow>` (8th param).
4. `render_summary_md` fills in the VM-candidates body to match `viewer/decompiler/render/markdown.py:34-72`: per-candidate dispatcher_pc + confidence + reasons + reader_inst + bytecode-range/hex-dump fences. M3-ι already shipped the section header.
5. Server `state.rs` passes `&self.memshadow` to `build_trace_ir` (currently it doesn't — memshadow is built but not used by build_trace_ir).

**Out of scope (deferred):**
- `/api/dec/fn/{id}` `sym:*` / `bn:*` source support — needs Rust BN backend (no Rust BN backend exists yet).
- `/api/dec/llm-call` — LLM client port; separate RFC.
- Real-trace parity script (`scripts/m3_iota_parity.py`) — defer until after this ships so a single script covers both type-anchor + vm-candidate signals end-to-end on the xsign trace.

**Architecture:**

- **`ollvmdet` is a single fn module** with one public function. It walks the trace once, accumulates 4 counters (indirect_total, table_load_total, self_update_total, pc_freq), then computes confidence with the same scoring as Python (0.4 baseline + up to 0.6 across three signals). Returns `Vec<OllvmFinding>` (a Rust struct mirroring the Python dict).
- **`vm_candidate` reuses `ollvm_detect_vm`** and adds three steps: locate the hottest self-update load in the trace, grab its base register's value range across all hits → bytecode addr range, then call `MemShadow::hex_dump` for the LLM-friendly hex view. `VmCandidateIR` is the IR struct that's already in `decompiler::ir` (M3-δ shipped) — reuse it directly, no new type.
- **`build_trace_ir` signature change:** add `memshadow: Option<&MemShadow>` as a new last parameter (8th). When non-None, runs `detect_vm_candidates`. When None, leaves `top.vm_candidates` empty. This matches Python's `detect_vm: bool = True` semantic (memshadow's presence acts as the gate).
- **Render fidelity:** Python `render_summary_md` emits per-candidate sections with `### Candidate #i`, dispatcher_pc, confidence, reasons (as bulleted list), bytecode-reader line (when present), bytecode range OR length-unreliable note (>64KB), and a hex_dump in a triple-backtick fence (first 16 lines). Port exactly.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/ollvmdet.py:1-88` — ollvm_detect_vm reference.
- `viewer/decompiler/vm_candidate.py:1-176` — detect_vm_candidates reference.
- `viewer/decompiler/render/markdown.py:34-72` — VM-candidates body reference.
- `viewer/decompiler/builder.py:447-462` — how Python wires `detect_vm_candidates` (currently in `build_trace_ir` body).
- `tracemiku-core::decompiler::ir::VmCandidateIR` (M3-δ shipped) — `dispatcher_pc, confidence, reasons, reader_pc, reader_inst, reader_hits, reader_base_reg, bytecode_addr, bytecode_len, hex_dump` fields ready.
- `tracemiku-core::memshadow::MemShadow::hex_dump(base, t, rows, cols)` (M2-ζ shipped) — direct API match for Python's `mem.hex_dump`.
- `tracemiku-core::disasm::DecodedInsn::mem_op: Vec<MemOp>` (M2-ζ shipped) — reusable for the self-update load detection.
- `tracemiku-core::disasm::MemOp { base, idx, disp, size, is_write, src_reg }` (M2-ζ shipped).

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/ollvmdet.rs` (new) | `pub fn ollvm_detect_vm(trace, min_entries, conf_threshold) -> Vec<OllvmFinding>` + `OllvmFinding` struct. ~150 LOC including tests. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod ollvmdet;` |
| `rust/crates/tracemiku-core/src/decompiler/vm_candidate.rs` (new) | `pub fn detect_vm_candidates(trace, cfg, mem) -> Vec<VmCandidateIR>` + 2 internal helpers. ~200 LOC including tests. |
| `rust/crates/tracemiku-core/src/decompiler/mod.rs` (modify) | `pub mod vm_candidate;` |
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (modify) | `build_trace_ir` gains `memshadow: Option<&MemShadow>` 8th param; populates `top.vm_candidates`. |
| `rust/crates/tracemiku-core/src/decompiler/render.rs` (modify) | `render_summary_md` VM-candidates body fidelity (per-candidate detail + hex-dump fence). |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `ollvm_detect_vm`, `OllvmFinding`, `detect_vm_candidates`. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | Pass `Some(&memshadow)` to `build_trace_ir`. |
| `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs` (modify) | Add assertion: when synth has no VM patterns, `vm_candidates: []` and `summary_md` doesn't contain `## VM Candidates`. |
| `TODO.md` + spec | Mark `ollvmdet.py` + `vm_candidate.py` complete; `render_summary_md` upgraded to full fidelity. |

---

## Task 1: `ollvmdet` port

**Files:**
- Create: `rust/crates/tracemiku-core/src/ollvmdet.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

- [ ] **Step 1: Define `OllvmFinding` + `ollvm_detect_vm`**

```rust
//! OLLVM VM dispatcher detection (heuristic). Direct port of
//! viewer/ollvmdet.py.
//!
//! Looks for the classic obfuscation pattern:
//!   while (1) { op = bytecode[ip++]; handler = table[op]; goto handler; }
//!
//! Scoring:
//!   +0.4 indirect br/blr seen
//!   +0.3 ldr [..,lsl #3] table-load near a br
//!   +0.2 self-update load (ldrh/ldrb/ldr w/ `!` writeback)
//!   +0.1 high-frequency indirect (>= 5× min_entries hits)
//!
//! Output: heuristic candidate list. NEVER decode VM bytecode.

use std::collections::HashMap;

use serde::Serialize;

use crate::disasm::decode;
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize)]
pub struct OllvmFinding {
    /// First-seen indirect br PC (anchor for the dispatcher).
    pub fn_pc: u64,
    /// Total indirect br/blr hits in the trace.
    pub entry_count: u64,
    /// Confidence in [0.0, 1.0]; rounded to 2 decimals.
    pub confidence: f64,
    /// Human-readable reasons (joined by " + " in Python; we keep as Vec).
    pub reasons: Vec<String>,
    /// User-facing hint string (matches Python "hint" key).
    pub hint: String,
}

/// Detect OLLVM VM dispatcher candidates in the trace.
///
/// `min_entries`: minimum indirect-branch count required before scoring.
/// `conf_threshold`: minimum final confidence to emit a finding.
///
/// Returns a `Vec` (typically 0 or 1 entries; Python returns [] or [{...}]).
pub fn ollvm_detect_vm(
    trace: &Trace,
    min_entries: usize,
    conf_threshold: f64,
) -> Vec<OllvmFinding> {
    let n = trace.len();
    if n < min_entries {
        return Vec::new();
    }

    let mut indirect_total: u64 = 0;
    let mut table_load_total: u64 = 0;
    let mut self_update_total: u64 = 0;
    let mut indirect_pc_first: HashMap<u64, usize> = HashMap::new();

    for i in 0..n {
        let pc = trace.pc(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        let m = d.mnemonic.as_str();
        if m == "br" || m == "blr" {
            indirect_total += 1;
            indirect_pc_first.entry(pc).or_insert(i);
            // Look back ≤ 4 insns for table-load + self-update pattern.
            let lo = i.saturating_sub(4);
            for j in lo..i {
                let pc_j = trace.pc(j);
                let inst_j = trace.inst(j);
                let dj = decode(pc_j, inst_j);
                let op_str = dj.op_str.to_lowercase();
                if dj.mnemonic == "ldr" && op_str.contains("lsl #3") {
                    table_load_total += 1;
                }
                if op_str.contains('!')
                    && (dj.mnemonic == "ldrh" || dj.mnemonic == "ldrb" || dj.mnemonic == "ldr")
                {
                    self_update_total += 1;
                }
            }
        }
    }

    if indirect_total < min_entries as u64 {
        return Vec::new();
    }

    let mut confidence: f64 = 0.4;
    let mut reasons: Vec<String> = vec!["indirect br/blr".to_string()];
    let half = (min_entries as u64) / 2;
    if table_load_total >= half {
        confidence += 0.3;
        reasons.push(format!(
            "ldr [..,lsl #3] table-load near br ({}×)",
            table_load_total
        ));
    }
    if self_update_total >= half {
        confidence += 0.2;
        reasons.push(format!(
            "self-update ldr[h/b]/[..,#N]! ({}×)",
            self_update_total
        ));
    }
    if indirect_total >= (min_entries as u64) * 5 {
        confidence += 0.1;
        reasons.push(format!(
            "high-frequency indirect ({} hits)",
            indirect_total
        ));
    }

    if confidence < conf_threshold {
        return Vec::new();
    }

    // Anchor PC = the indirect-br PC seen earliest.
    let anchor_pc = indirect_pc_first
        .iter()
        .min_by_key(|(_, &idx)| idx)
        .map(|(&pc, _)| pc)
        .unwrap_or(0);

    let confidence = (confidence * 100.0).round() / 100.0;

    vec![OllvmFinding {
        fn_pc: anchor_pc,
        entry_count: indirect_total,
        confidence,
        reasons,
        hint: "可能是 OLLVM VM dispatcher / jump-table 派发. 反向追踪建议 skip 内部, 看 VM 调用边界数据流即可.".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;

    fn synth_trace(pcs: &[u64], insts: &[u32]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * pcs.len()];
        for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            format!(r#"{{"records":{}}}"#, pcs.len()),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":"0x10000"}}"#,
        )
        .unwrap();
        dir
    }

    fn load(dir: &tempfile::TempDir) -> Trace {
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
        Trace::load(&cd).unwrap()
    }

    #[test]
    fn ollvm_detect_vm_empty_on_short_trace() {
        let dir = synth_trace(&[0x1000], &[0xd503201f]);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert!(findings.is_empty());
    }

    #[test]
    fn ollvm_detect_vm_empty_when_no_indirect_br() {
        // 12 records of nops - no br/blr at all.
        let pcs: Vec<u64> = (0..12u64).map(|i| 0x1000 + i * 4).collect();
        let insts = vec![0xd503201fu32; 12];
        let dir = synth_trace(&pcs, &insts);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert!(findings.is_empty(), "no br → no findings");
    }

    #[test]
    fn ollvm_detect_vm_emits_finding_when_many_indirect_brs() {
        // 12 records: alternating nop + br x0 (0xd61f0000). 6 brs ≥ 10? No, 6 < 10.
        // We need ≥ 10 br hits. Use 20 records: 20 brs.
        let pcs: Vec<u64> = (0..20u64).map(|i| 0x1000 + i * 4).collect();
        let insts = vec![0xd61f0000u32; 20]; // br x0
        let dir = synth_trace(&pcs, &insts);
        let trace = load(&dir);
        let findings = ollvm_detect_vm(&trace, 10, 0.3);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.confidence >= 0.4, "confidence: {}", f.confidence);
        assert_eq!(f.entry_count, 20);
        assert!(f.reasons.iter().any(|r| r.contains("indirect")));
        assert_eq!(f.fn_pc, 0x1000);
    }
}
```

- [ ] **Step 2: Module + prelude wiring**

`lib.rs`: add `pub mod ollvmdet;` (alphabetical: between `memshadow` and `prelude`).

`prelude.rs`: append:

```rust
pub use crate::ollvmdet::{ollvm_detect_vm, OllvmFinding};
```

- [ ] **Step 3: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core 2>&1 | tail -5
cargo test -p tracemiku-core --lib ollvmdet 2>&1 | tail -10
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-core/src/ollvmdet.rs \
        rust/crates/tracemiku-core/src/lib.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "$(cat <<'EOF'
feat(core): ollvmdet port — OLLVM VM dispatcher heuristic

ollvm_detect_vm(trace, min_entries, conf_threshold) -> Vec<OllvmFinding>:
  - One trace pass; counts indirect br/blr, ldr [..,lsl #3] table-loads
    near br, and self-update ldr[h/b] writeback patterns.
  - Confidence scoring 0.4 + 0.3 + 0.2 + 0.1 (parity with Python).
  - Anchors finding at the earliest-seen indirect-br PC.

OllvmFinding mirrors Python's dict ({fn_pc, entry_count, confidence,
reasons, hint}) with serde-ready fields.

NEVER decodes VM bytecode (TODO §7.0 + P2-E policy).

Re-exported via prelude. 3 unit tests cover short-trace, no-br, and
many-br paths.

M3-ι2b Task 1.
EOF
)"
```

---

## Task 2: `vm_candidate` port

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/vm_candidate.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/mod.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

- [ ] **Step 1: Implement helpers + `detect_vm_candidates`**

```rust
//! VM bytecode 候选区段检测 (DEC3-D). Direct port of
//! viewer/decompiler/vm_candidate.py.
//!
//! Pipeline:
//!   1. ollvm_detect_vm(trace) → dispatcher candidates
//!   2. Find hottest self-update load (ldrh/ldrb/ldr with `!`) in trace
//!   3. min/max of base-reg values across all reader-PC hits → bytecode range
//!   4. memshadow.hex_dump(min_addr, last_idx, 16, 16) → LLM-readable hex
//!   5. Emit VmCandidateIR; never decode bytecode.

use crate::cfg::CFG;
use crate::decompiler::ir::VmCandidateIR;
use crate::disasm::decode;
use crate::memshadow::MemShadow;
use crate::ollvmdet::ollvm_detect_vm;
use crate::trace::Trace;

/// Find self-update loads in [lo, hi]: returns (pc, hits, mnem_op_str, base_reg).
/// Mirrors Python `_find_self_update_loads`.
fn find_self_update_loads(
    trace: &Trace,
    lo: usize,
    hi: usize,
    min_hits: u64,
    max_step: i64,
) -> Vec<(u64, u64, String, String)> {
    use std::collections::HashMap;

    if hi < lo || trace.len() == 0 {
        return Vec::new();
    }

    // Frequency count over PCs in [lo, hi].
    let mut freq: HashMap<u64, u64> = HashMap::new();
    for i in lo..=hi.min(trace.len() - 1) {
        *freq.entry(trace.pc(i)).or_insert(0) += 1;
    }
    // Sort by hits desc; take top 200 (Python parity).
    let mut sorted: Vec<(u64, u64)> = freq.into_iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    sorted.truncate(200);

    // For each candidate PC, decode its first-seen instance + apply filters.
    let mut hits_seen: Vec<(u64, u64, String, String)> = Vec::new();
    for (pc, cnt) in sorted {
        if cnt < min_hits {
            continue;
        }
        // Find first idx in [lo,hi] with this pc.
        let mut first_idx: Option<usize> = None;
        for i in lo..=hi.min(trace.len() - 1) {
            if trace.pc(i) == pc {
                first_idx = Some(i);
                break;
            }
        }
        let Some(idx) = first_idx else { continue };
        let inst = trace.inst(idx);
        let d = decode(pc, inst);
        let m = d.mnemonic.as_str();
        if m != "ldrh" && m != "ldrb" && m != "ldr" {
            continue;
        }
        if !d.op_str.contains('!') {
            continue;
        }
        let Some(mem_op) = d.mem_op.first() else { continue };
        if mem_op.disp.unsigned_abs() as i64 > max_step {
            continue;
        }
        let mnem_op = format!("{} {}", d.mnemonic, d.op_str);
        hits_seen.push((pc, cnt, mnem_op, mem_op.base.clone()));
    }
    hits_seen.sort_by_key(|(_, c, _, _)| std::cmp::Reverse(*c));
    hits_seen
}

/// Walk all hits of `reader_pc` in [lo, hi]; pull `base_reg` value at each hit;
/// return (min, max). Returns (0, 0) on parse failure / no hits / unknown reg.
/// Mirrors Python `_bytecode_range`.
fn bytecode_range(
    trace: &Trace,
    reader_pc: u64,
    base_reg: &str,
    lo: usize,
    hi: usize,
) -> (u64, u64) {
    if base_reg.is_empty() {
        return (0, 0);
    }
    let n = trace.len();
    if n == 0 || hi < lo {
        return (0, 0);
    }
    let mut vals: Vec<u64> = Vec::new();
    for i in lo..=hi.min(n - 1) {
        if trace.pc(i) != reader_pc {
            continue;
        }
        let rec = trace.record(i);
        let Some(v) = rec.reg(base_reg) else { continue };
        if v != 0 {
            vals.push(v);
        }
        if vals.len() >= 5000 {
            break;
        }
    }
    if vals.is_empty() {
        return (0, 0);
    }
    let mn = *vals.iter().min().unwrap();
    let mx = *vals.iter().max().unwrap();
    (mn, mx)
}

/// Main entry: detect VM dispatcher candidates and grab bytecode hex.
///
/// `mem`: optional MemShadow (built). When `None`, emits candidates without
/// hex_dump (`hex_dump: vec![]`).
/// `confidence_threshold`: passed to ollvm_detect_vm.
pub fn detect_vm_candidates(
    trace: &Trace,
    _cfg: &CFG,
    mem: Option<&MemShadow>,
    confidence_threshold: f64,
) -> Vec<VmCandidateIR> {
    let findings = ollvm_detect_vm(trace, 10, confidence_threshold);
    if findings.is_empty() {
        return Vec::new();
    }
    let n = trace.len();
    if n == 0 {
        return Vec::new();
    }
    let mut out: Vec<VmCandidateIR> = Vec::new();
    for f in findings {
        let mut cand = VmCandidateIR {
            dispatcher_pc: f.fn_pc,
            confidence: f.confidence,
            reasons: f.reasons,
            ..Default::default()
        };
        let readers = find_self_update_loads(trace, 0, n - 1, 8, 16);
        if let Some((pc, hits, ms, base)) = readers.into_iter().next() {
            cand.reader_pc = pc;
            cand.reader_inst = ms;
            cand.reader_hits = hits;
            cand.reader_base_reg = base.clone();
            let (lo, hi) = bytecode_range(trace, pc, &base, 0, n - 1);
            if lo > 0 && hi > lo {
                cand.bytecode_addr = lo;
                cand.bytecode_len = hi - lo + 1;
                if let Some(m) = mem {
                    if m.is_built() {
                        cand.hex_dump = m.hex_dump(lo, (n - 1) as u64, 16, 16);
                    }
                }
            }
        }
        out.push(cand);
    }
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_cfg;
    use crate::trace::REC_SIZE;

    fn synth_no_vm() -> tempfile::TempDir {
        // 12 nops — no indirect br → ollvm_detect_vm returns nothing.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 12];
        for i in 0..12usize {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&(0x1000u64 + (i as u64) * 4).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":12}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":"0x10000"}}"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn detect_vm_candidates_empty_when_no_ollvm_signal() {
        let dir = synth_no_vm();
        let cd = dir.path().join("run").join("calls").read_dir().unwrap()
            .next().unwrap().unwrap().path();
        let t = Trace::load(&cd).unwrap();
        let cfg = build_cfg(&t);
        let cands = detect_vm_candidates(&t, &cfg, None, 0.4);
        assert!(cands.is_empty(), "no ollvm signal → no candidates");
    }

    #[test]
    fn find_self_update_loads_empty_on_no_match() {
        let dir = synth_no_vm();
        let cd = dir.path().join("run").join("calls").read_dir().unwrap()
            .next().unwrap().unwrap().path();
        let t = Trace::load(&cd).unwrap();
        let n = t.len();
        let res = find_self_update_loads(&t, 0, n - 1, 1, 16);
        assert!(res.is_empty(), "no ldrh/ldrb/ldr with `!` in nops");
    }

    #[test]
    fn bytecode_range_zero_when_unknown_reg() {
        let dir = synth_no_vm();
        let cd = dir.path().join("run").join("calls").read_dir().unwrap()
            .next().unwrap().unwrap().path();
        let t = Trace::load(&cd).unwrap();
        let n = t.len();
        let (lo, hi) = bytecode_range(&t, 0x9999, "x0", 0, n - 1);
        assert_eq!((lo, hi), (0, 0));
        let (lo, hi) = bytecode_range(&t, 0x1000, "", 0, n - 1);
        assert_eq!((lo, hi), (0, 0), "empty base_reg → (0,0)");
    }
}
```

**Note:** `MemShadow::is_built` may not exist. Check the public API; if absent, just call `m.hex_dump(...)` unconditionally — the impl can return an empty vec if unbuilt. If `is_built` is private but the equivalent is `built`, use that. **Verify this before committing.**

- [ ] **Step 2: Module + prelude wiring**

`decompiler/mod.rs`: add `pub mod vm_candidate;`.

`prelude.rs`: append:

```rust
pub use crate::decompiler::vm_candidate::detect_vm_candidates;
```

- [ ] **Step 3: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler::vm_candidate 2>&1 | tail -10
cargo test -p tracemiku-core --lib decompiler 2>&1 | grep "test result:" | tail -5
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/vm_candidate.rs \
        rust/crates/tracemiku-core/src/decompiler/mod.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "$(cat <<'EOF'
feat(core): vm_candidate port — VM bytecode reader detection + hex dump

detect_vm_candidates(trace, cfg, mem, threshold) -> Vec<VmCandidateIR>:
  - ollvm_detect_vm() supplies dispatcher anchors.
  - find_self_update_loads(): top-200 hot PCs filtered to ldrh/ldrb/ldr
    with `!` writeback and disp ≤ max_step (16).
  - bytecode_range(): scan all reader_pc hits, pull base_reg values,
    return (min, max).
  - mem.hex_dump(): 16×16 LLM-friendly hex view of the bytecode region.

Reuses existing VmCandidateIR (M3-δ shipped); no new IR type.

Helpers `find_self_update_loads` and `bytecode_range` are private but
unit-tested via pub(crate) re-export in tests.

Tests:
  - detect_vm_candidates_empty_when_no_ollvm_signal
  - find_self_update_loads_empty_on_no_match
  - bytecode_range_zero_when_unknown_reg

M3-ι2b Task 2.
EOF
)"
```

---

## Task 3: Builder integration + render fidelity + server wiring

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/render.rs`
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`

- [ ] **Step 1: Extend `build_trace_ir` with memshadow**

In `decompiler/builder.rs`:

```rust
pub fn build_trace_ir<P: AsRef<Path>>(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
    spec_paths: &[P],
    memshadow: Option<&crate::memshadow::MemShadow>,  // new 8th param
) -> TopIR {
    let mut top = build_root_only(trace, meta, sym, cfg);
    if top_k > 0 {
        split_top_k_callees(&mut top, trace, sym, cfg, top_k, min_records);
    }
    if !spec_paths.is_empty() {
        attach_type_anchors(&mut top, trace, spec_paths);
    }
    if trace.len() > 0 {
        top.vm_candidates =
            crate::decompiler::vm_candidate::detect_vm_candidates(trace, cfg, memshadow, 0.4);
    }
    classify_blocks_by_tier(&mut top, 150);
    top
}
```

**Update all callers of `build_trace_ir`:**
- Tests in `decompiler/builder.rs` — pass `None` as 8th arg.
- `tracemiku-server::state::AppState::load` — pass `Some(&memshadow)`.
- `grep -rn "build_trace_ir(" rust/` to find all call sites.

- [ ] **Step 2: Render full VM-candidates body in `render_summary_md`**

In `decompiler/render.rs`, find the existing M3-ι VM-candidates block. Currently it only emits the header + per-candidate dispatcher_pc + confidence + reasons. Extend to match Python `markdown.py:34-72`:

```rust
if !top.vm_candidates.is_empty() {
    out.push_str(&format!("## VM Candidates ({})\n\n", top.vm_candidates.len()));
    out.push_str("> 来自 ollvmdet + bytecode reader 检测 (DEC3-D). **evidence only — 不解码**, LLM 看 hex dump 自己推编码.\n\n");
    for (i, vc) in top.vm_candidates.iter().enumerate() {
        out.push_str(&format!("### Candidate #{i}\n\n"));
        out.push_str(&format!("- dispatcher_pc: `{:#x}`\n", vc.dispatcher_pc));
        out.push_str(&format!("- confidence: **{:.2}**\n", vc.confidence));
        if !vc.reasons.is_empty() {
            out.push_str("- reasons:\n");
            for r in &vc.reasons {
                out.push_str(&format!("  - {r}\n"));
            }
        }
        if vc.reader_pc != 0 {
            out.push_str(&format!(
                "- bytecode reader: `{}` @ `{:#x}` (×{} hits, base reg = `{}`)\n",
                vc.reader_inst, vc.reader_pc, vc.reader_hits, vc.reader_base_reg
            ));
        }
        if vc.bytecode_addr != 0 {
            if vc.bytecode_len > 65536 {
                out.push_str(&format!(
                    "- bytecode start: `{:#x}` (length unreliable: base reg spans ~{} bytes — likely multiple mmap regions, hex dump shows first 256B)\n",
                    vc.bytecode_addr, vc.bytecode_len
                ));
            } else {
                out.push_str(&format!(
                    "- bytecode range: `{:#x}` + `{}` bytes\n",
                    vc.bytecode_addr, vc.bytecode_len
                ));
            }
        }
        if !vc.hex_dump.is_empty() {
            out.push_str("\n**bytecode hex dump** (memshadow snapshot at trace end):\n\n```\n");
            for ln in vc.hex_dump.iter().take(16) {
                out.push_str(ln);
                if !ln.ends_with('\n') {
                    out.push('\n');
                }
            }
            out.push_str("```\n");
        }
        out.push('\n');
    }
}
```

(This replaces the M3-ι skeleton block that emitted only header + dispatcher_pc + confidence + reasons. Verify the existing block matches; if so, replace verbatim.)

- [ ] **Step 3: Wire `state.rs`**

Change the `build_trace_ir` call to:

```rust
let top_ir = build_trace_ir(
    &trace, &meta, &symbols, &cfg, 10, 50, &spec_paths, Some(&memshadow),
);
```

(`memshadow` is already built earlier in `AppState::load`.)

- [ ] **Step 4: Tests**

In `decompiler/render.rs::mod tests`:

```rust
#[test]
fn render_summary_md_emits_vm_candidates_section_when_present() {
    use crate::decompiler::ir::VmCandidateIR;
    let mut top = TopIR::default();
    top.vm_candidates.push(VmCandidateIR {
        dispatcher_pc: 0x4000,
        confidence: 0.7,
        reasons: vec!["indirect br/blr".into(), "self-update ldrh".into()],
        reader_pc: 0x4100,
        reader_inst: "ldrh w8, [x9, #2]!".into(),
        reader_hits: 200,
        reader_base_reg: "x9".into(),
        bytecode_addr: 0x70000,
        bytecode_len: 1024,
        hex_dump: vec![
            "00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f".into(),
            "10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f".into(),
        ],
        ..Default::default()
    });
    let md = render_summary_md(&top);
    assert!(md.contains("## VM Candidates (1)"));
    assert!(md.contains("### Candidate #0"));
    assert!(md.contains("dispatcher_pc: `0x4000`"));
    assert!(md.contains("confidence: **0.70**"));
    assert!(md.contains("- indirect br/blr"));
    assert!(md.contains("`ldrh w8, [x9, #2]!`"));
    assert!(md.contains("base reg = `x9`"));
    assert!(md.contains("bytecode range: `0x70000` + `1024` bytes"));
    assert!(md.contains("```\n00 01 02 03"));
}

#[test]
fn render_summary_md_marks_bytecode_unreliable_when_oversized() {
    use crate::decompiler::ir::VmCandidateIR;
    let mut top = TopIR::default();
    top.vm_candidates.push(VmCandidateIR {
        dispatcher_pc: 0x4000,
        confidence: 0.5,
        bytecode_addr: 0x70000,
        bytecode_len: 200_000,
        ..Default::default()
    });
    let md = render_summary_md(&top);
    assert!(md.contains("length unreliable"), "missing unreliable note: {md}");
    assert!(md.contains("~200000 bytes") || md.contains("~200,000 bytes"),
        "missing length: {md}");
}
```

In `tests/test_dec_summary_route.rs`:

```rust
#[tokio::test]
async fn dec_summary_no_vm_candidates_on_synth_root_only() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app.oneshot(
        Request::builder().uri("/api/dec/summary").body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cands = v["vm_candidates"].as_array().unwrap();
    assert!(cands.is_empty(), "synth has no OLLVM pattern → no candidates");
    let md = v["summary_md"].as_str().unwrap();
    assert!(!md.contains("## VM Candidates"), "should omit VM section when empty: {md}");
}
```

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
grep -rn "build_trace_ir(" rust/ src/ 2>/dev/null  # confirm all callers updated
cargo build -p tracemiku-server 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -10
cargo test -p tracemiku-server --test test_dec_fn_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -10
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

If `MemShadow.is_built()` doesn't exist publicly, drop the `is_built()` check in vm_candidate.rs — `hex_dump` on an unbuilt MemShadow returning an empty Vec is acceptable behavior (matches the Python check anyway).

The 200,000-byte assertion above accepts either `~200000` or `~200,000` formatting — Rust's default `{}` for u64 doesn't insert commas, so the first form should win. Adjust the assertion if rendering does insert separators.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs \
        rust/crates/tracemiku-core/src/decompiler/render.rs \
        rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/tests/test_dec_summary_route.rs
git commit -m "$(cat <<'EOF'
feat(core,server): vm_candidates wired to build_trace_ir + summary fidelity

build_trace_ir gains 8th param `memshadow: Option<&MemShadow>`. When
provided AND trace non-empty, runs detect_vm_candidates and populates
top.vm_candidates (was always empty before).

render_summary_md VM-candidates body now matches Python markdown.py:34-72:
  - per-candidate dispatcher_pc, confidence, reasons (bullet list)
  - bytecode reader line (when present)
  - bytecode range OR length-unreliable note (>64KB)
  - hex_dump in triple-backtick fence (first 16 lines)

state.rs threads Some(&memshadow) into the builder.

Tests:
  - render_summary_md_emits_vm_candidates_section_when_present (core)
  - render_summary_md_marks_bytecode_unreliable_when_oversized (core)
  - dec_summary_no_vm_candidates_on_synth_root_only (server)

M3-ι2b Task 3.
EOF
)"
```

---

## Task 4: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Spec rows**

Find or add rows for `ollvmdet.py` and `vm_candidate.py`. If absent, add:

```markdown
| `ollvmdet.py` | `tracemiku-core::ollvmdet` | ✅ M3-ι2b | 1:1 port; ollvm_detect_vm + OllvmFinding. Heuristic scoring 0.4+0.3+0.2+0.1. |
| `vm_candidate.py` (DEC3-D) | `tracemiku-core::decompiler::vm_candidate` | ✅ M3-ι2b | 1:1 port; detect_vm_candidates emits VmCandidateIR with hex_dump from MemShadow. |
```

Update the existing `builder.py` row note to append: `+ vm_candidates auto-populated when memshadow provided (M3-ι2b)`.

Update the existing `render_summary_md` row (added in M3-ι) note to append: `+ VM-candidates body fidelity (M3-ι2b)`.

- [ ] **Step 2: TODO.md**

Append to progress section:

```markdown
- M3-ι2b ollvmdet.py + vm_candidate.py port + summary VM-candidates body fidelity: ✅ 2026-05-04
```

Append to milestone-summary list:

```markdown
- M3-ι2b: ollvmdet + vm_candidate port + summary VM-candidates hex-dump body ✅ 2026-05-04
```

Refine the M3-ι2 pointer (replace existing `M3-ι2b (next)` line):

```markdown
- M3-ι2c (next, BN-gated): /api/dec/fn/{id} sym:* / bn:* source support (depends on Rust BN backend port — separate milestone), /api/dec/llm-call (LLM client port), real-trace parity script m3_iota_parity.py covering type_anchor + vm_candidate + summary
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-ι2b complete (ollvmdet + vm_candidate port)"
```

---

## Self-Review

**Spec coverage:**

| Item | Task |
|---|---|
| `OllvmFinding` + `ollvm_detect_vm` | Task 1 |
| `find_self_update_loads` helper | Task 2 |
| `bytecode_range` helper | Task 2 |
| `detect_vm_candidates` main entry | Task 2 |
| `build_trace_ir` 8th param `memshadow` | Task 3 |
| Server passes `Some(&memshadow)` | Task 3 |
| `render_summary_md` VM-candidates body fidelity | Task 3 |
| Spec/TODO sync | Task 4 |

**Out of scope (deferred to M3-ι2c):**
- `/api/dec/fn/{id}` sym:* / bn:* source support — needs Rust BN backend (separate milestone, no Rust BN exists yet).
- `/api/dec/llm-call` — LLM client port (separate RFC).
- Real-trace parity script — defer to M3-ι2c so a single script covers all three M3-ι2{a,b,c} signals on the xsign trace.

**Risks:**

1. **`MemShadow::is_built` may not be public.** Already noted in Task 2 Step 1. Drop the check if the API isn't there — `hex_dump` on a fresh/unbuilt shadow returning an empty Vec is fine.
2. **`build_trace_ir` already has 7 params after M3-ι2a.** Adding an 8th is verbose. If signature pain becomes acute, consider a builder pattern in a future milestone — but for now, just match Python's positional style.
3. **OLLVM heuristic false-positives on real trace.** Confidence 0.4 + 0.3 (table-load) is ≥ threshold 0.4 even from coincidental `lsl #3` patterns. The Python implementation has the same risk; this is the documented "evidence only, LLM decides" trade. Don't fight it.
4. **`hex_dump` cost on huge memshadow.** Real xsign trace has 7.6M records. `MemShadow::hex_dump` walks the per-byte map — should be fast (O(rows*cols)) but worth a smoke check on the live server. M3-ι2b doesn't add a perf gate; if it regresses, deal with it then.
5. **Test PC freedom.** `synth_no_vm` uses 12 nops — `min_entries=10` requires `n >= 10`, so 12 is enough. The "many br" test uses 20 records all `br x0` — that's a stress case that exercises the indirect_total≥min_entries*5 confidence bump.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
