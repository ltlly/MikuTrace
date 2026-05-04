//! Markdown renderer for FuncIR.
//!
//! M3-θ skeleton: emits header + metadata table + per-block sections
//! (B-id, exec_count, tier, asm, samples). Full Python fidelity (LLM
//! summary tokens, type-anchor inlining, sub-fn cross-refs, induction
//! var summaries) defers to later milestones.

use crate::decompiler::ir::FuncIR;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ir::{BlockIR, FuncIR};
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
}
