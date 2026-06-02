//! Build nested call tree from trace by walking bl/ret pairs.
//!
//! Direct port of `viewer/calltree.py`. See that file's module docstring
//! for the algorithm + caveats (indirect br x14 tail-calls, b-only tail-calls,
//! Frinet FP-chain not done here).

use serde::{Deserialize, Serialize};

use crate::disasm::decode;
use crate::index::Index;
use crate::symbols::SymbolMap;
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallNode {
    /// Function name. Root node uses "?" (matches Python).
    /// Children with unknown symbol use None (Python: `cf if cf != "?" else None`).
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub fn_name: Option<String>,
    /// Static entry PC of callee (0 for root).
    pub fn_pc: u64,
    pub enter_idx: usize,
    pub exit_idx: usize,
    pub depth: usize,
    pub children: Vec<CallNode>,
    /// Count of children that hit max_depth and were flattened away.
    /// `None` (omitted from JSON) when zero, matching Python which only
    /// sets the key when truncation occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_children: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallEventKind {
    Call,
    Ret,
}

/// Build nested call tree.
///
/// `max_depth` caps nesting; deeper calls are flattened into the deepest
/// permitted frame's `truncated_children` count rather than nested further.
/// Prevents runaway HTML for OLLVM auto-recursive jumpouts (Python parity).
///
/// Algorithm (parity with `viewer/calltree.py`):
/// - Init stack with root frame `{fn: "?", depth: 0, ...}`.
/// - For each record `i`:
///     - `bl`/`blr`: resolve callee name from PC of record `i+1`.
///       If new_depth > max_depth, increment top.truncated_children
///       and a `cap_balance` counter (so the next ret skips popping).
///       Otherwise push a new child frame onto the stack.
///     - `ret`: if `cap_balance > 0`, decrement it (skip pop). Otherwise
///       pop top, set its `exit_idx = i`, and attach to parent's children.
/// - At trace end: close any unclosed frames with `exit_idx = last_idx`.
///
/// Note on cap balance: Python's algorithm `stack.append(top)` pushes the
/// SAME dict reference as the current top. We can't replicate that with
/// `Vec<CallNode>` (unique ownership), so we use a parallel counter that
/// records "skip the next N rets" — produces the same observable tree.
pub fn build_call_tree(trace: &Trace, sym: &SymbolMap, max_depth: usize) -> CallNode {
    let n = trace.len();
    let events = (0..n).filter_map(|i| {
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        match d.mnemonic.as_str() {
            "bl" | "blr" => Some((i, CallEventKind::Call)),
            "ret" => Some((i, CallEventKind::Ret)),
            _ => None,
        }
    });
    build_call_tree_from_events(trace, sym, max_depth, events)
}

/// Same call-tree semantics as [`build_call_tree`], using the startup PC
/// index to decode each unique PC once and walk only call/ret record indices.
pub fn build_call_tree_indexed(
    trace: &Trace,
    sym: &SymbolMap,
    index: &Index,
    max_depth: usize,
) -> CallNode {
    let mut events: Vec<(usize, CallEventKind)> = Vec::new();
    for (&pc, idxs) in &index.pc_to_idxs {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let d = decode(pc, trace.inst(first_idx));
        let kind = match d.mnemonic.as_str() {
            "bl" | "blr" => CallEventKind::Call,
            "ret" => CallEventKind::Ret,
            _ => continue,
        };
        events.extend(idxs.iter().copied().map(|idx| (idx, kind)));
    }
    events.sort_unstable_by_key(|(idx, _)| *idx);
    build_call_tree_from_events(trace, sym, max_depth, events)
}

fn build_call_tree_from_events<I>(
    trace: &Trace,
    sym: &SymbolMap,
    max_depth: usize,
    events: I,
) -> CallNode
where
    I: IntoIterator<Item = (usize, CallEventKind)>,
{
    let n = trace.len();
    let last_idx = n.saturating_sub(1);

    let root = CallNode {
        fn_name: Some("?".to_string()),
        fn_pc: 0,
        enter_idx: 0,
        exit_idx: last_idx,
        depth: 0,
        children: Vec::new(),
        truncated_children: None,
    };
    let mut stack: Vec<CallNode> = vec![root];
    // Number of pending cap-balance rets (each "extra" bl at cap pushes
    // a phantom frame in Python; here we just count them and skip the
    // matching number of rets).
    let mut cap_balance: u32 = 0;

    for (i, kind) in events {
        if kind == CallEventKind::Call {
            // Resolve callee name from PC of the *next* trace record (the
            // first instruction the call lands on).
            let target_pc = if i + 1 < n { trace.pc(i + 1) } else { 0 };
            let (cf, _off) = if target_pc != 0 {
                sym.lookup(target_pc)
            } else {
                (String::new(), 0u64)
            };
            let top_depth = stack.last().expect("stack non-empty").depth;
            let new_depth = top_depth + 1;
            if new_depth > max_depth {
                // Cap reached. Flatten: bump truncated_children on top,
                // and remember to skip one ret.
                let top = stack.last_mut().expect("stack non-empty");
                top.truncated_children = Some(top.truncated_children.unwrap_or(0) + 1);
                cap_balance += 1;
                continue;
            }
            let child = CallNode {
                fn_name: if cf.is_empty() { None } else { Some(cf) },
                fn_pc: target_pc,
                enter_idx: i,
                exit_idx: i,
                depth: new_depth,
                children: Vec::new(),
                truncated_children: None,
            };
            stack.push(child);
        } else {
            if cap_balance > 0 {
                cap_balance -= 1;
                continue;
            }
            if stack.len() > 1 {
                let mut top = stack.pop().expect("stack > 1");
                top.exit_idx = i;
                let parent = stack.last_mut().expect("stack non-empty");
                parent.children.push(top);
            }
        }
    }

    // Close any remaining open frames at last_idx.
    while stack.len() > 1 {
        let mut top = stack.pop().expect("stack > 1");
        top.exit_idx = last_idx;
        let parent = stack.last_mut().expect("stack non-empty");
        parent.children.push(top);
    }
    let mut root = stack.pop().expect("root left");
    root.exit_idx = last_idx;
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use crate::trace::REC_SIZE;

    /// Build a synthetic call_dir with a 9-record trace:
    /// idx | pc        | mnem | comment
    ///   0 | 0x100000  | nop  | f_root entry
    ///   1 | 0x100004  | bl   | call f_alpha @ 0x100100
    ///   2 | 0x100100  | nop  | f_alpha entry
    ///   3 | 0x100104  | ret  | f_alpha return
    ///   4 | 0x100008  | bl   | call f_beta  @ 0x100200
    ///   5 | 0x100200  | nop  | f_beta entry
    ///   6 | 0x100204  | nop
    ///   7 | 0x100208  | ret  | f_beta return
    ///   8 | 0x10000c  | ret  | f_root return
    fn synth_trace_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_9r_1ms");
        std::fs::create_dir_all(&cd).unwrap();

        // ARM64 little-endian opcodes:
        //   nop                      = 0xd503201f
        //   ret                      = 0xd65f03c0
        //   bl #+0xfc  (rel +252)    = 0x9400003f  (from 0x100004 → 0x100100)
        //   bl #+0x1f8 (rel +504)    = 0x9400007e  (from 0x100008 → 0x100200)
        let pcs_and_inst: [(u64, u32); 9] = [
            (0x100000, 0xd503201f),
            (0x100004, 0x9400003f),
            (0x100100, 0xd503201f),
            (0x100104, 0xd65f03c0),
            (0x100008, 0x9400007e),
            (0x100200, 0xd503201f),
            (0x100204, 0xd503201f),
            (0x100208, 0xd65f03c0),
            (0x10000c, 0xd65f03c0),
        ];
        let mut buf = Vec::with_capacity(9 * REC_SIZE);
        for (pc, inst) in pcs_and_inst {
            buf.extend_from_slice(&pc.to_le_bytes());
            for _ in 0..31 {
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
            buf.extend_from_slice(&0x7000u64.to_le_bytes()); // sp
            buf.extend_from_slice(&0u32.to_le_bytes()); // nzcv
            buf.extend_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":9}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
        )
        .unwrap();
        dir
    }

    fn load_trace_and_sym(dir: &tempfile::TempDir) -> (Trace, SymbolMap) {
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
        let trace = Trace::load(&cd).expect("trace loads");
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.add(0x100100, "f_alpha".to_string());
        sym.add(0x100200, "f_beta".to_string());
        sym.freeze();
        (trace, sym)
    }

    #[test]
    fn empty_trace_returns_root_only() {
        // Construct a 0-record trace by writing a 0-length trace.bin.
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
            r#"{"module":{"name":"l.so","base":"0x0","size":0}}"#,
        )
        .unwrap();
        let trace = Trace::load(&cd).unwrap();
        let sym = SymbolMap::new();
        let root = build_call_tree(&trace, &sym, 50);
        assert_eq!(root.fn_name.as_deref(), Some("?"));
        assert_eq!(root.depth, 0);
        assert_eq!(root.enter_idx, 0);
        assert_eq!(root.exit_idx, 0);
        assert!(root.children.is_empty());
        assert!(root.truncated_children.is_none());
    }

    #[test]
    fn root_has_two_callees_with_correct_idx_ranges() {
        let dir = synth_trace_dir();
        let (trace, sym) = load_trace_and_sym(&dir);
        let root = build_call_tree(&trace, &sym, 50);
        assert_eq!(
            root.children.len(),
            2,
            "expected 2 callees of root, got {}: {}",
            root.children.len(),
            serde_json::to_string_pretty(&root).unwrap()
        );
        let alpha = &root.children[0];
        let beta = &root.children[1];
        assert_eq!(alpha.fn_name.as_deref(), Some("f_alpha"));
        assert_eq!(alpha.enter_idx, 1);
        assert_eq!(alpha.exit_idx, 3);
        assert_eq!(alpha.depth, 1);
        assert!(alpha.children.is_empty());
        assert_eq!(beta.fn_name.as_deref(), Some("f_beta"));
        assert_eq!(beta.enter_idx, 4);
        assert_eq!(beta.exit_idx, 7);
    }

    #[test]
    fn indexed_calltree_matches_sequential() {
        let dir = synth_trace_dir();
        let (trace, sym) = load_trace_and_sym(&dir);
        let index = Index::build(&trace);

        let sequential = build_call_tree(&trace, &sym, 50);
        let indexed = build_call_tree_indexed(&trace, &sym, &index, 50);

        assert_eq!(indexed, sequential);
    }

    #[test]
    fn max_depth_cap_flattens_into_truncated_children() {
        let dir = synth_trace_dir();
        let (trace, sym) = load_trace_and_sym(&dir);
        // Cap at depth 0 — every child is flattened into root.truncated_children.
        let root = build_call_tree(&trace, &sym, 0);
        assert!(
            root.children.is_empty(),
            "depth=0 cap means no nested children, got: {}",
            serde_json::to_string_pretty(&root).unwrap()
        );
        assert_eq!(
            root.truncated_children,
            Some(2),
            "two bl-targets flattened into root"
        );
    }
}
