//! Markdown renderer for FuncIR.
//!
//! M3-θ skeleton: emits header + metadata table + per-block sections
//! (B-id, exec_count, tier, asm, samples). Full Python fidelity (LLM
//! summary tokens, type-anchor inlining, sub-fn cross-refs, induction
//! var summaries) defers to later milestones.

use crate::decompiler::ir::{FuncIR, TopIR};

/// Render a FuncIR as a markdown bundle. `tier_filter` is one of
/// `"hot"` / `"warm"` / `"cold"` / `"all"` — only blocks matching the
/// requested tier are rendered (matches Python webui's `tier` param).
pub fn render_func_md(fn_: &FuncIR, tier_filter: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {} — {}\n\n", fn_.id, fn_.name));
    out.push_str(&format!(
        "- **records**: idx [{}..{}]\n",
        fn_.entry_idx, fn_.exit_idx
    ));
    out.push_str(&format!("- **exec_count**: {}\n", fn_.exec_count));
    out.push_str(&format!("- **blocks**: {}\n", fn_.blocks.len()));
    out.push_str(&format!("- **loops**: {}\n", fn_.loops.len()));
    out.push_str(&format!("- **calls**: {}\n", fn_.calls.len()));
    out.push_str(&format!("- **type_anchors**: {}\n", fn_.type_anchors.len()));
    if fn_.truncated {
        out.push_str("- **truncated**: yes\n");
    }
    out.push('\n');

    // Type anchors section (M3-ι2a Task 3) — JSON-spec-driven ABI ground
    // truth, grouped by callee_name (or sub_<pc> when name is empty).
    if !fn_.type_anchors.is_empty() {
        use std::collections::BTreeMap;
        struct Group<'a> {
            count: usize,
            callee_pc: u64,
            params: &'a [(String, String)],
            ret_reg: &'a str,
            ret_type: &'a str,
            provenance: &'a str,
            hits: Vec<usize>,
        }
        let mut groups: BTreeMap<String, Group<'_>> = BTreeMap::new();
        for ta in &fn_.type_anchors {
            let key = if ta.callee_name.is_empty() {
                format!("sub_{:x}", ta.callee_pc)
            } else {
                ta.callee_name.clone()
            };
            groups
                .entry(key)
                .and_modify(|g| {
                    g.count += 1;
                    g.hits.push(ta.idx);
                })
                .or_insert(Group {
                    count: 1,
                    callee_pc: ta.callee_pc,
                    params: &ta.params,
                    ret_reg: &ta.ret_reg,
                    ret_type: &ta.ret_type,
                    provenance: &ta.provenance,
                    hits: vec![ta.idx],
                });
        }
        out.push_str(&format!("## Type anchors ({})\n\n", fn_.type_anchors.len()));
        out.push_str(
            "> JSON-spec-driven (DEC3-B). LLM should trust these as ABI ground truth.\n\n",
        );
        for (name, g) in &groups {
            let params_str = g
                .params
                .iter()
                .map(|(r, t)| format!("{r}:{t}"))
                .collect::<Vec<_>>()
                .join(", ");
            let ret_str = if g.ret_type.is_empty() {
                g.ret_reg.to_string()
            } else {
                format!("{}:{}", g.ret_reg, g.ret_type)
            };
            out.push_str(&format!(
                "- **{}** ({:#x}, ×{}) `({})` → `{}`\n",
                name, g.callee_pc, g.count, params_str, ret_str
            ));
            let shown: Vec<String> = g.hits.iter().take(5).map(|i| i.to_string()).collect();
            let suffix = if g.hits.len() > 5 { ", ..." } else { "" };
            out.push_str(&format!(
                "  - hit idx: [{}{}]\n",
                shown.join(", "),
                suffix
            ));
            out.push_str(&format!("  - source: `{}`\n", g.provenance));
        }
        out.push('\n');
    }

    // Per-block sections.
    let want_all = tier_filter == "all";
    for block in &fn_.blocks {
        if !want_all && block.tier != tier_filter {
            continue;
        }
        out.push_str(&format!(
            "## {} (pc {:#x}, exec {})\n\n",
            block.id, block.pc, block.exec_count
        ));
        out.push_str(&format!("- **tier**: {}\n", block.tier));
        out.push_str(&format!("- **insns**: {}\n", block.insns));
        if !block.samples.is_empty() {
            out.push_str("- **samples**:\n");
            // Sort keys for stable output.
            let mut keys: Vec<&String> = block.samples.keys().collect();
            keys.sort();
            for k in keys {
                let v = block.samples[k];
                // Render as hex when value is non-trivial (>= 16) and not
                // negative; small integers (e.g. counters) render as decimal.
                let v_str = if v.abs() >= 16 {
                    format!("{:#x}", v as u64)
                } else {
                    v.to_string()
                };
                out.push_str(&format!("  - {} = {}\n", k, v_str));
            }
        }
        // exits: outgoing CFG edges (kind + taken_count). Stable order by dst.
        // M3-ι Task 2 — wires BlockIR.exits into per-block markdown.
        if !block.exits.is_empty() {
            out.push_str("- **exits**:\n");
            let mut exits_sorted: Vec<&crate::decompiler::ir::EdgeIR> = block.exits.iter().collect();
            exits_sorted.sort_by(|a, b| a.dst.cmp(&b.dst));
            for e in exits_sorted {
                let cnt = if e.taken_count > 0 {
                    format!(" (×{})", e.taken_count)
                } else {
                    String::new()
                };
                out.push_str(&format!("  - `{}` → **{}**{}\n", e.kind, e.dst, cnt));
            }
        }
        if !block.asm.is_empty() {
            out.push_str("\n```asm\n");
            out.push_str(&block.asm);
            if !block.asm.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n");
        }
        out.push('\n');
    }
    out
}

/// Render TopIR → summary.md text. Mirrors
/// `viewer/decompiler/render/markdown.py::render_summary_md`.
///
/// Skeleton: header, metadata bullet list, optional VM-candidates
/// section (header only — full hex-dump rendering defers until
/// vm_candidate.py is ported), Functions table.
pub fn render_summary_md(top: &TopIR) -> String {
    let mut out = String::new();
    out.push_str("# Trace Summary\n\n");
    out.push_str(&format!("- records: **{}**\n", top.records));
    out.push_str(&format!(
        "- module: `{}` @ {:#x} (size {:#x})\n",
        top.module_name, top.module_base, top.module_size
    ));
    if let Some(cmd) = top.cmd {
        out.push_str(&format!("- cmd: **{cmd}**\n"));
    }
    if !top.method.is_empty() {
        out.push_str(&format!("- method: `{}`\n", top.method));
    }
    out.push_str(&format!("- truncated: {}\n", top.truncated));
    out.push_str(&format!("- last_insn_is_ret: {}\n", top.last_insn_is_ret));
    if !top.tracemiku_version.is_empty() {
        out.push_str(&format!(
            "- generated: {} (tracemiku {})\n",
            top.generated_at, top.tracemiku_version
        ));
    }
    out.push('\n');

    if !top.vm_candidates.is_empty() {
        out.push_str(&format!(
            "## VM Candidates ({})\n\n",
            top.vm_candidates.len()
        ));
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

    out.push_str(&format!("## Functions ({})\n\n", top.fns.len()));
    out.push_str("| id | name | blocks | loops | calls | idx range |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for f in &top.fns {
        out.push_str(&format!(
            "| [{0}](fns/{0}.md) | `{1}` | {2} | {3} | {4} | {5}..{6} |\n",
            f.id,
            f.name,
            f.blocks.len(),
            f.loops.len(),
            f.calls.len(),
            f.entry_idx,
            f.exit_idx
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ir::{BlockIR, FuncIR, TopIR};
    use std::collections::HashMap;

    #[test]
    fn render_func_md_emits_header_metadata_blocks() {
        let mut samples = HashMap::new();
        samples.insert("x0".to_string(), 0xdead_i64);
        samples.insert("sp".to_string(), 0x7000_i64);
        let f = FuncIR {
            id: "F0".to_string(),
            name: "doCommandNative".to_string(),
            entry_idx: 0,
            exit_idx: 100,
            exec_count: 1,
            blocks: vec![BlockIR {
                id: "B0".to_string(),
                pc: 0x1000,
                end_pc: 0x100c,
                insns: 4,
                exec_count: 5,
                samples,
                asm: "  0x1000: nop\n  0x1004: ret".to_string(),
                tier: "hot".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let md = render_func_md(&f, "hot");
        assert!(md.contains("# F0 — doCommandNative"), "missing header in {md}");
        assert!(md.contains("**records**: idx [0..100]"), "missing records line: {md}");
        assert!(md.contains("**blocks**: 1"), "missing blocks count: {md}");
        assert!(md.contains("## B0"), "missing block heading: {md}");
        assert!(md.contains("**tier**: hot"), "missing tier line: {md}");
        assert!(md.contains("```asm"), "missing asm code fence: {md}");
        assert!(md.contains("0x1000: nop"), "missing asm content: {md}");
        assert!(md.contains("x0 = 0xdead"), "missing samples x0: {md}");
        assert!(md.contains("sp = 0x7000"), "missing samples sp: {md}");
    }

    #[test]
    fn render_func_md_emits_exits_section_when_present() {
        use crate::decompiler::ir::EdgeIR;
        let f = FuncIR {
            id: "F0".to_string(),
            name: "f".to_string(),
            blocks: vec![BlockIR {
                id: "B0".to_string(),
                pc: 0x1000,
                tier: "hot".to_string(),
                exits: vec![EdgeIR {
                    dst: "B1".to_string(),
                    kind: "b.eq".to_string(),
                    taken_count: 5,
                    not_taken_count: 0,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let md = render_func_md(&f, "hot");
        assert!(md.contains("**exits**"), "missing exits section: {md}");
        assert!(md.contains("`b.eq`"), "missing edge kind: {md}");
        assert!(md.contains("**B1**"), "missing dst id: {md}");
        assert!(md.contains("(×5)"), "missing taken_count annotation: {md}");
    }

    #[test]
    fn render_func_md_filters_by_tier() {
        let f = FuncIR {
            id: "F0".to_string(),
            name: "f".to_string(),
            blocks: vec![
                BlockIR {
                    id: "B0".to_string(),
                    pc: 0x1000,
                    tier: "hot".to_string(),
                    ..Default::default()
                },
                BlockIR {
                    id: "B1".to_string(),
                    pc: 0x2000,
                    tier: "warm".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let md_hot = render_func_md(&f, "hot");
        assert!(md_hot.contains("## B0"), "B0 (hot) should appear: {md_hot}");
        assert!(!md_hot.contains("## B1"), "B1 (warm) should be filtered: {md_hot}");
        let md_all = render_func_md(&f, "all");
        assert!(md_all.contains("## B0"));
        assert!(md_all.contains("## B1"), "all should include warm: {md_all}");
    }

    #[test]
    fn render_summary_md_emits_header_and_functions_table() {
        let top = TopIR {
            records: 100,
            module_name: "libt.so".to_string(),
            module_base: 0x1000,
            module_size: 0x10000,
            method: "f".to_string(),
            cmd: Some(42),
            fns: vec![FuncIR {
                id: "F0".to_string(),
                name: "doCommandNative".to_string(),
                entry_idx: 0,
                exit_idx: 99,
                blocks: vec![BlockIR::default(), BlockIR::default()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let md = render_summary_md(&top);
        assert!(md.starts_with("# Trace Summary"), "header missing: {md}");
        assert!(md.contains("- records: **100**"));
        assert!(md.contains("`libt.so`"));
        assert!(md.contains("- cmd: **42**"));
        assert!(md.contains("- method: `f`"));
        assert!(md.contains("## Functions (1)"));
        assert!(md.contains("| [F0](fns/F0.md) |"));
        assert!(md.contains("| `doCommandNative` |"));
        assert!(md.contains(" 2 |"), "blocks count missing: {md}");
        assert!(md.contains(" 0..99 |"));
    }

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
        assert!(md.contains("~200000 bytes"), "missing length: {md}");
    }

    #[test]
    fn render_summary_md_omits_optional_fields_when_absent() {
        let top = TopIR {
            records: 0,
            ..Default::default()
        };
        let md = render_summary_md(&top);
        assert!(md.contains("- records: **0**"));
        assert!(!md.contains("- cmd:"), "cmd should be omitted when None: {md}");
        assert!(
            !md.contains("- method:"),
            "method should be omitted when empty: {md}"
        );
        assert!(!md.contains("## VM Candidates"));
        assert!(md.contains("## Functions (0)"));
    }
}
