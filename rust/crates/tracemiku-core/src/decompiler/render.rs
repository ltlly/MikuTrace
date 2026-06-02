//! Markdown renderer for FuncIR.
//!
//! M3-θ skeleton: emits header + metadata table + per-block sections
//! (B-id, exec_count, tier, asm, samples). Full Python fidelity (LLM
//! summary tokens, type-anchor inlining, sub-fn cross-refs, induction
//! var summaries) defers to later milestones.

use crate::decompiler::ir::{FuncIR, TopIR};

/// Render a FuncIR as a markdown bundle. `tier_filter` follows Python:
/// `"hot"` renders hot blocks fully and warm/cold blocks as compact stubs;
/// `"summary"` omits block detail; `"all"`/`"full"` renders every block fully.
pub fn render_func_md(fn_: &FuncIR, tier_filter: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {} `{}`\n\n", fn_.id, fn_.name));
    out.push_str(&format!(
        "- range: {:#x}..{:#x}\n",
        fn_.pc_start, fn_.pc_end
    ));
    out.push_str(&format!(
        "- trace idx: {}..{}\n",
        fn_.entry_idx, fn_.exit_idx
    ));
    out.push_str(&format!("- **exec_count**: {}\n", fn_.exec_count));
    out.push_str(&format!(
        "- truncated: {}, last_insn_is_ret: {}\n",
        fn_.truncated, fn_.last_insn_is_ret
    ));
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
            out.push_str(&format!("  - hit idx: [{}{}]\n", shown.join(", "), suffix));
            out.push_str(&format!("  - source: `{}`\n", g.provenance));
        }
        out.push('\n');
    }

    if !fn_.calls.is_empty() {
        out.push_str(&format!("## Calls ({})\n\n", fn_.calls.len()));
        out.push_str("| idx | src | callee | ret |\n");
        out.push_str("|---|---|---|---|\n");
        for call in &fn_.calls {
            let callee_name = if call.callee_name.is_empty() {
                format!("sub_{:x}", call.callee_pc)
            } else {
                call.callee_name.replace('|', "\\|")
            };
            let callee = if call.callee_pc == 0 {
                format!("`{callee_name}`")
            } else {
                format!("`{callee_name}` @ {:#x}", call.callee_pc)
            };
            let ret = call
                .ret_idx
                .map(|idx| format!("#{idx}"))
                .unwrap_or_else(|| "-".to_string());
            let ret = if let Some(x0) = call.ret_val_x0 {
                format!("{ret} x0={:#x}", x0 as u64)
            } else {
                ret
            };
            out.push_str(&format!(
                "| #{} | `{}` | {} | {} |\n",
                call.idx, call.src_block, callee, ret
            ));
        }
        out.push('\n');
    }

    // Loops section: render detected loops with body blocks, iteration
    // counts, and induction variable summaries.
    if !fn_.loops.is_empty() {
        out.push_str(&format!("## Loops ({})\n\n", fn_.loops.len()));
        for lp in &fn_.loops {
            let body_str = lp.body.join(", ");
            out.push_str(&format!(
                "- **{}** header=`{}` body=[{}] iters={}\n",
                lp.id, lp.header, body_str, lp.iters
            ));
            if !lp.induction_vars.is_empty() {
                out.push_str("  - induction vars:\n");
                for iv in &lp.induction_vars {
                    let step_str = if iv.step == iv.step.round() {
                        format!("{}", iv.step as i64)
                    } else {
                        format!("{:.1}", iv.step)
                    };
                    out.push_str(&format!(
                        "    - `{}`: {} → {} (step={}, n_iters={}, score={:.2}, {})\n",
                        iv.reg,
                        if iv.init >= 0 {
                            format!("{:#x}", iv.init as u64)
                        } else {
                            format!("{}", iv.init)
                        },
                        if iv.final_value >= 0 {
                            format!("{:#x}", iv.final_value as u64)
                        } else {
                            format!("{}", iv.final_value)
                        },
                        step_str,
                        iv.n_iters,
                        iv.linearity_score,
                        iv.classification
                    ));
                    if !iv.samples.is_empty() {
                        let sample_vals: Vec<String> = iv
                            .samples
                            .iter()
                            .take(8)
                            .map(|s| {
                                if *s >= 0 {
                                    format!("{:#x}", *s as u64)
                                } else {
                                    format!("{}", s)
                                }
                            })
                            .collect();
                        out.push_str(&format!("      samples: [{}]\n", sample_vals.join(", ")));
                    }
                }
            }
        }
        out.push('\n');
    }

    if tier_filter == "summary" {
        let hot_count = fn_.blocks.iter().filter(|b| b.tier == "hot").count();
        let warm_count = fn_.blocks.iter().filter(|b| b.tier == "warm").count();
        out.push_str(&format!("## Blocks ({} total)\n\n", fn_.blocks.len()));
        out.push_str(&format!("- hot: {hot_count}, warm: {warm_count}\n"));
        out.push_str("- *block detail omitted (--tier summary). Re-render with --tier hot or --tier full.*\n\n");
        return out;
    }

    let hot_count = fn_.blocks.iter().filter(|b| b.tier == "hot").count();
    let warm_count = fn_.blocks.iter().filter(|b| b.tier == "warm").count();
    if tier_filter == "hot" && warm_count > 0 {
        out.push_str(&format!(
            "## Blocks ({hot_count} hot + {warm_count} warm shown as stub)\n\n"
        ));
    } else {
        out.push_str(&format!("## Blocks ({})\n\n", fn_.blocks.len()));
    }

    for block in &fn_.blocks {
        let stub = tier_filter == "hot" && block.tier != "hot";
        render_block_md(&mut out, block, stub);
    }
    out
}

fn render_block_md(out: &mut String, block: &crate::decompiler::ir::BlockIR, stub: bool) {
    let tier_mark = if block.tier == "hot" {
        String::new()
    } else {
        format!(" ({})", block.tier)
    };
    out.push_str(&format!(
        "### {} @ {:#x} (×{}){}\n",
        block.id, block.pc, block.exec_count, tier_mark
    ));

    if stub {
        let exits_short = if block.exits.is_empty() {
            String::new()
        } else {
            let mut dsts: Vec<String> = block.exits.iter().take(3).map(|e| e.dst.clone()).collect();
            if block.exits.len() > 3 {
                dsts.push("+".to_string());
            }
            format!(" → {}", dsts.join(","))
        };
        out.push_str(&format!("\n- {} insns{}\n\n", block.insns, exits_short));
        return;
    }

    out.push('\n');
    if !block.samples.is_empty() {
        let mut parts = Vec::new();
        for reg in ["x0", "x1", "x2", "x3", "sp"] {
            if let Some(v) = block.samples.get(reg) {
                parts.push(format!("{reg}={:#x}", *v as u64));
            }
        }
        if !parts.is_empty() {
            out.push_str(&format!("- samples (first exec): {}\n", parts.join(", ")));
        }
    }
    out.push_str(&format!(
        "- insns: {}, range: {:#x}..{:#x}\n",
        block.insns, block.pc, block.end_pc
    ));
    if !block.exits.is_empty() {
        out.push_str("- exits:\n");
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
        out.push_str("\n```arm64\n");
        out.push_str(&block.asm);
        if !block.asm.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n");
    }
    out.push('\n');
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
    use crate::decompiler::ir::{BlockIR, CallIR, FuncIR, TopIR};
    use std::collections::HashMap;

    #[test]
    fn render_func_md_emits_header_metadata_blocks() {
        let mut samples = HashMap::new();
        samples.insert("x0".to_string(), 0xdead_i64);
        samples.insert("sp".to_string(), 0x7000_i64);
        let f = FuncIR {
            id: "F0".to_string(),
            name: "nativeEntry".to_string(),
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
        assert!(md.contains("# F0 `nativeEntry`"), "missing header in {md}");
        assert!(
            md.contains("- trace idx: 0..100"),
            "missing trace idx line: {md}"
        );
        assert!(md.contains("## Blocks (1)"), "missing blocks count: {md}");
        assert!(md.contains("### B0"), "missing block heading: {md}");
        assert!(md.contains("```arm64"), "missing asm code fence: {md}");
        assert!(md.contains("0x1000: nop"), "missing asm content: {md}");
        assert!(md.contains("x0=0xdead"), "missing samples x0: {md}");
        assert!(md.contains("sp=0x7000"), "missing samples sp: {md}");
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
        assert!(md.contains("- exits:"), "missing exits section: {md}");
        assert!(md.contains("`b.eq`"), "missing edge kind: {md}");
        assert!(md.contains("**B1**"), "missing dst id: {md}");
        assert!(md.contains("(×5)"), "missing taken_count annotation: {md}");
    }

    #[test]
    fn render_func_md_emits_calls_section() {
        let f = FuncIR {
            id: "F0".to_string(),
            name: "f".to_string(),
            calls: vec![CallIR {
                idx: 7,
                src_block: "B2".to_string(),
                callee_pc: 0x2000,
                callee_fn: Some("callee".to_string()),
                callee_name: "callee".to_string(),
                ret_idx: Some(12),
                ret_val_x0: None,
            }],
            ..Default::default()
        };
        let md = render_func_md(&f, "summary");
        assert!(md.contains("## Calls (1)"), "missing calls section: {md}");
        assert!(md.contains("| #7 | `B2` | `callee` @ 0x2000 | #12 |"));
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
        assert!(
            md_hot.contains("### B0"),
            "B0 (hot) should appear: {md_hot}"
        );
        assert!(
            md_hot.contains("### B1") && md_hot.contains("(warm)") && md_hot.contains("0 insns"),
            "B1 (warm) should appear as a stub: {md_hot}"
        );
        let md_all = render_func_md(&f, "all");
        assert!(md_all.contains("### B0"));
        assert!(
            md_all.contains("### B1"),
            "all should include warm: {md_all}"
        );
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
                name: "nativeEntry".to_string(),
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
        assert!(md.contains("| `nativeEntry` |"));
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
        assert!(
            md.contains("length unreliable"),
            "missing unreliable note: {md}"
        );
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
        assert!(
            !md.contains("- cmd:"),
            "cmd should be omitted when None: {md}"
        );
        assert!(
            !md.contains("- method:"),
            "method should be omitted when empty: {md}"
        );
        assert!(!md.contains("## VM Candidates"));
        assert!(md.contains("## Functions (0)"));
    }
}
