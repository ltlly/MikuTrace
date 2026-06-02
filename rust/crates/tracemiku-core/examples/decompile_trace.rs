//! Decompile evaluation tool — reads a real trace.bin and decompiles
//! functions, measuring quality and performance.
//!
//! Usage:
//!   cargo run --example decompile_trace -- <call_dir> [--max-fns N] [--min-records M] [--semantic <expected_dir>]
//!
//! Example:
//!   cargo run --example decompile_trace -- \
//!     /home/ltlly/Code/traceMiku/traces/boundary_stat_launch2/calls/call_001_tid11945_8882256r_7389ms \
//!     --max-fns 10 --min-records 50
//!
//! Semantic mode (--semantic <expected_dir>):
//!   Loads fn_N_expected.txt from <expected_dir> for each decompiled function
//!   and computes semantic similarity scores. This is a DIAGNOSTIC TOOL — scores
//!   are informational and not a gating mechanism.
//!
//! Expected output file format: plain text with the reference decompilation
//! in C-like syntax matching the HLIL renderer conventions. Each file is named
//! fn_{idx}_expected.txt where {idx} is the function's index in the trace.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tracemiku_core::decompiler::il_pipeline::decompile_trace;
use tracemiku_core::trace::record::{Record, REC_SIZE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: decompile_trace <call_dir> [--max-fns N] [--min-records M] [--semantic <expected_dir>]"
        );
        std::process::exit(1);
    }

    let call_dir = &args[1];
    let max_fns = parse_flag(&args, "--max-fns", 20);
    let min_records = parse_flag(&args, "--min-records", 30);
    let semantic_dir: Option<PathBuf> = parse_opt_flag_path(&args, "--semantic");

    let trace_path = Path::new(call_dir).join("trace.bin");
    if !trace_path.exists() {
        eprintln!("trace.bin not found at {}", trace_path.display());
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(&trace_path)?.len();
    println!(
        "Reading trace: {} ({:.2} GB)",
        trace_path.display(),
        file_size as f64 / 1e9
    );

    let start_read = Instant::now();
    let (records, unique_pairs) = read_trace_records(&trace_path)?;
    let read_time = start_read.elapsed();
    println!(
        "  {} records, {} unique PCs in {:?}",
        records.len(),
        unique_pairs.len(),
        read_time
    );

    // Group into function segments
    let fns = group_by_function(&records, &unique_pairs);
    println!("  {} function segments detected", fns.len());

    // Find the largest functions
    let mut fn_stats: Vec<_> = fns
        .iter()
        .enumerate()
        .map(|(i, f)| (i, f.len(), f))
        .collect();
    fn_stats.sort_by_key(|(_, len, _)| std::cmp::Reverse(*len));
    fn_stats.truncate(max_fns.min(fns.len()));

    println!(
        "\nDecompiling top {} functions (min {} records each):\n",
        fn_stats.len(),
        min_records
    );

    let mut total_llil = 0usize;
    let mut total_mlil = 0usize;
    let mut total_hlil = 0usize;
    let mut total_insn = 0usize;
    let mut total_time = std::time::Duration::ZERO;
    let mut best_coverage = 0.0f64;
    let mut worst_coverage = 1.0f64;

    // Per-function semantic scores (keyed by fn_idx)
    let mut semantic_scores: BTreeMap<usize, SemanticScore> = BTreeMap::new();

    for (fn_idx, fn_len, fn_insns) in &fn_stats {
        if *fn_len < min_records {
            continue;
        }

        let insns: Vec<(u64, u32)> = fn_insns.iter().map(|(pc, inst)| (*pc, *inst)).collect();

        total_insn += insns.len();

        let start = Instant::now();
        let output = decompile_trace(&insns, &[], &format!("fn_{}", fn_idx));
        let elapsed = start.elapsed();
        total_time += elapsed;

        total_llil += output.llil_count;
        total_mlil += output.mlil_count;
        total_hlil += output.hlil_count;

        best_coverage = best_coverage.max(output.llil_coverage);
        worst_coverage = worst_coverage.min(output.llil_coverage);

        // Sample output
        println!(
            "fn_{:02} | {} insns | LLIL:{} MLIL:{} HLIL:{} | cov:{:.1}% | {:?}",
            fn_idx,
            insns.len(),
            output.llil_count,
            output.mlil_count,
            output.hlil_count,
            output.llil_coverage * 100.0,
            elapsed,
        );

        // --- Semantic comparison (diagnostic tool — not a gate) ---
        if let Some(ref sem_dir) = semantic_dir {
            let expected_path = sem_dir.join(format!("fn_{}_expected.txt", fn_idx));
            match fs::read_to_string(&expected_path) {
                Ok(expected_text) => {
                    let score = compute_semantic_score(&output.hlil_text, &expected_text);
                    println!(
                        "  SEMANTIC | CF:{:.2} VAR:{:.2} STMT:{:.2} KW:{:.2} | OVERALL:{:.2}",
                        score.cf_match,
                        score.var_similarity,
                        score.stmt_ratio,
                        score.keyword_score,
                        score.overall,
                    );
                    // Surface structural details so the developer can
                    // understand *why* a score is low.
                    let actual_cf = count_control_flow(&output.hlil_text);
                    let expected_cf = count_control_flow(&expected_text);
                    println!(
                        "           | CF actual  if:{} while:{} for:{} switch:{}",
                        actual_cf.if_count,
                        actual_cf.while_count,
                        actual_cf.for_count,
                        actual_cf.switch_count,
                    );
                    println!(
                        "           | CF expect  if:{} while:{} for:{} switch:{}",
                        expected_cf.if_count,
                        expected_cf.while_count,
                        expected_cf.for_count,
                        expected_cf.switch_count,
                    );
                    println!(
                        "           | VARS actual:{} expected:{} | STMTS actual:{} expected:{}",
                        count_variables(&output.hlil_text),
                        count_variables(&expected_text),
                        count_statements(&output.hlil_text),
                        count_statements(&expected_text),
                    );
                    println!(
                        "           | KW  load:{} store:{} call:{} return:{} [1=present,0=absent]",
                        if has_memory_load(&output.hlil_text) {
                            1
                        } else {
                            0
                        },
                        if has_memory_store(&output.hlil_text) {
                            1
                        } else {
                            0
                        },
                        if has_fn_call(&output.hlil_text) { 1 } else { 0 },
                        if has_return(&output.hlil_text) { 1 } else { 0 },
                    );
                    semantic_scores.insert(*fn_idx, score);
                }
                Err(_) => {
                    println!(
                        "  SEMANTIC | no expected output at {}",
                        expected_path.display()
                    );
                }
            }
        }

        // Show HLIL for first few functions
        if *fn_idx <= 2 {
            println!("  --- HLIL output ---");
            for line in output.hlil_text.lines().take(25) {
                println!("  | {}", line);
            }
            if output.hlil_text.lines().count() > 25 {
                println!("  | ... ({} lines total)", output.hlil_text.lines().count());
            }
            println!("  -------------------");
        }
        println!();
    }

    // Summary
    println!("═══════════════════════════════════════════");
    println!("DECOMPILER QUALITY REPORT");
    println!("═══════════════════════════════════════════");
    println!("Functions decompiled:    {}", fn_stats.len());
    println!("Total instructions:      {}", total_insn);
    println!("Total decompile time:    {:?}", total_time);
    println!(
        "Avg time/function:       {:?}",
        total_time / fn_stats.len().max(1) as u32
    );
    println!(
        "Avg time/insn:           {:.2} µs",
        total_time.as_micros() as f64 / total_insn.max(1) as f64
    );
    println!();
    println!("LLIL total exprs:        {}", total_llil);
    println!("MLIL total exprs:        {}", total_mlil);
    println!("HLIL total exprs:        {}", total_hlil);
    println!(
        "Expansion LLIL→MLIL:     {:.1}x",
        total_mlil as f64 / total_llil.max(1) as f64
    );
    println!(
        "Expansion MLIL→HLIL:     {:.1}x",
        total_hlil as f64 / total_mlil.max(1) as f64
    );
    println!();
    println!("Best LLIL coverage:      {:.1}%", best_coverage * 100.0);
    println!("Worst LLIL coverage:     {:.1}%", worst_coverage * 100.0);

    // --- Semantic aggregate (diagnostic — not a gate) ---
    if !semantic_scores.is_empty() {
        println!();
        println!("═══════════════════════════════════════════");
        println!("SEMANTIC ACCURACY METRICS (diagnostic tool)");
        println!("═══════════════════════════════════════════");
        println!("Functions with reference: {}", semantic_scores.len());

        let n = semantic_scores.len() as f64;
        let avg_cf: f64 = semantic_scores.values().map(|s| s.cf_match).sum::<f64>() / n;
        let avg_var: f64 = semantic_scores
            .values()
            .map(|s| s.var_similarity)
            .sum::<f64>()
            / n;
        let avg_stmt: f64 = semantic_scores.values().map(|s| s.stmt_ratio).sum::<f64>() / n;
        let avg_kw: f64 = semantic_scores
            .values()
            .map(|s| s.keyword_score)
            .sum::<f64>()
            / n;
        let avg_overall: f64 = semantic_scores.values().map(|s| s.overall).sum::<f64>() / n;

        let mut scores: Vec<_> = semantic_scores.values().map(|s| s.overall).collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let best = scores.last().copied().unwrap_or(0.0);
        let worst = scores.first().copied().unwrap_or(0.0);

        println!();
        println!("Aggregate scores (0.0–1.0, higher is better):");
        println!("  CF match average:       {:.2}", avg_cf);
        println!("  Variable match average: {:.2}", avg_var);
        println!("  Statement ratio average:{:.2}", avg_stmt);
        println!("  Keyword presence avg:   {:.2}", avg_kw);
        println!("  OVERALL average:        {:.2}", avg_overall);
        println!();
        println!("  Best overall score:     {:.2}", best);
        println!("  Worst overall score:    {:.2}", worst);
        println!();
        println!("NOTE: These scores are diagnostic only.");
        println!("      They are NOT gating criteria. Use them to identify");
        println!("      structural gaps between actual and expected decompilation.");
    }

    Ok(())
}

fn read_trace_records(
    path: &Path,
) -> Result<(Vec<Record>, Vec<(u64, u32)>), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = std::io::BufReader::with_capacity(1 << 20, file);
    let mut records = Vec::new();
    let mut unique_pairs: BTreeSet<(u64, u32)> = BTreeSet::new();
    let mut buf = [0u8; REC_SIZE];

    while reader.read_exact(&mut buf).is_ok() {
        let record: &Record = bytemuck::from_bytes(&buf);
        unique_pairs.insert((record.pc, record.inst));
        records.push(*record);
    }

    let pairs: Vec<_> = unique_pairs.into_iter().collect();
    Ok((records, pairs))
}

/// Simple function grouping: split on bl/blr → ret boundaries.
/// This is a heuristic; the full FunctionIndex produces more accurate results.
fn group_by_function(records: &[Record], unique_pairs: &[(u64, u32)]) -> Vec<Vec<(u64, u32)>> {
    // Find return addresses (instruction after bl/blr)
    let mut ret_addrs: BTreeSet<u64> = BTreeSet::new();
    for record in records {
        let inst = record.inst;
        let mnem = decode_mnem(inst);
        if mnem == "bl" || mnem == "blr" {
            ret_addrs.insert(record.pc.wrapping_add(4));
        }
    }

    // Also use ret instructions as split points
    let mut split_addrs: BTreeSet<u64> = BTreeSet::new();
    for (pc, inst) in unique_pairs {
        let mnem = decode_mnem(*inst);
        if mnem == "ret" {
            split_addrs.insert(*pc);
        }
    }

    let mut fns: Vec<Vec<(u64, u32)>> = Vec::new();
    let mut current = Vec::new();

    for (pc, inst) in unique_pairs {
        if ret_addrs.contains(pc) && !current.is_empty() {
            // Potential function entry (after bl)
            fns.push(std::mem::take(&mut current));
        }
        current.push((*pc, *inst));
        if split_addrs.contains(pc) {
            // After ret, start new function on next instruction
            if !current.is_empty() {
                fns.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() {
        fns.push(current);
    }

    // Filter: keep only functions with meaningful size
    fns.retain(|f| f.len() >= 3);
    fns
}

fn decode_mnem(inst: u32) -> String {
    // Simple mnemonic extraction without full disassembly
    // Use the real decoder from the core crate
    use tracemiku_core::disasm::decode;
    let decoded = decode(0, inst);
    decoded
        .mnemonic
        .split('.')
        .next()
        .unwrap_or(&decoded.mnemonic)
        .to_string()
}

fn parse_flag(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_opt_flag_path(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
}

// ============================================================================
// Semantic accuracy metrics — diagnostic tooling, NOT gating criteria
// ============================================================================

/// Counts of structured control flow patterns in HLIL output.
#[derive(Debug, Default, Clone)]
struct CfCounts {
    if_count: usize,
    while_count: usize,
    for_count: usize,
    switch_count: usize,
}

/// Per-function semantic similarity score. All sub-scores are in [0.0, 1.0]
/// where 1.0 is a perfect match.
#[derive(Debug, Clone)]
struct SemanticScore {
    /// How well control-flow structure counts match (Jaccard-like).
    cf_match: f64,
    /// How similar the variable counts are.
    var_similarity: f64,
    /// Ratio of statement counts (min/max, 1.0 = identical).
    stmt_ratio: f64,
    /// Fraction of expected key operations present in actual output.
    keyword_score: f64,
    /// Weighted average of the four sub-scores.
    overall: f64,
}

/// Count `if (`, `while (`, `for (`, `switch (` patterns in text.
fn count_control_flow(text: &str) -> CfCounts {
    CfCounts {
        if_count: text.matches("if (").count(),
        while_count: text.matches("while (").count(),
        for_count: text.matches("for (").count(),
        switch_count: text.matches("switch (").count(),
    }
}

/// Jaccard-like similarity between two CF count vectors.
/// Returns 1.0 when counts are identical, 0.0 when no overlap.
fn cf_similarity(actual: &CfCounts, expected: &CfCounts) -> f64 {
    let pairs: [(usize, usize); 4] = [
        (actual.if_count, expected.if_count),
        (actual.while_count, expected.while_count),
        (actual.for_count, expected.for_count),
        (actual.switch_count, expected.switch_count),
    ];
    let num: f64 = pairs.iter().map(|&(a, e)| a.min(e) as f64).sum();
    let den: f64 = pairs.iter().map(|&(a, e)| a.max(e) as f64).sum();
    if den == 0.0 {
        // Both are empty — structurally equivalent
        1.0
    } else {
        num / den
    }
}

/// Count unique named variables in HLIL output. Matches patterns:
/// `sp_vN`, `arg_N`, `var_N`, `temp_N`, `const_N`.
fn count_variables(text: &str) -> usize {
    let mut seen = BTreeSet::new();
    let mut word = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            if !word.is_empty() {
                check_and_insert_var(&word, &mut seen);
                word.clear();
            }
        }
    }
    if !word.is_empty() {
        check_and_insert_var(&word, &mut seen);
    }
    seen.len()
}

fn check_and_insert_var(word: &str, seen: &mut BTreeSet<String>) {
    if !word.is_empty() {
        let is_var = (word.starts_with("sp_v") && word[4..].bytes().all(|c| c.is_ascii_digit()))
            || (word.starts_with("arg_") && word[4..].bytes().all(|c| c.is_ascii_digit()))
            || (word.starts_with("var_") && word[4..].bytes().all(|c| c.is_ascii_digit()))
            || (word.starts_with("temp_") && word[5..].bytes().all(|c| c.is_ascii_digit()))
            || (word.starts_with("const_") && word[6..].bytes().all(|c| c.is_ascii_digit()));
        if is_var {
            seen.insert(word.to_string());
        }
    }
}

/// Count statement-like lines: lines ending with `;`, `}`, or `{`.
fn count_statements(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            t.ends_with(';') || t.ends_with('}') || t.ends_with('{')
        })
        .count()
}

/// Check if text contains a memory load pattern (`*(` dereference).
fn has_memory_load(text: &str) -> bool {
    text.contains("*(")
}

/// Check if text contains a memory store pattern.
/// Heuristic: `*(` appears with `=` on the left side of the assignment.
fn has_memory_store(text: &str) -> bool {
    // Look for memory-write pattern: *(...) = ...
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            // Found a dereference — check if there's a '=' after it on the same line
            let rest = &text[i..];
            if let Some(eol) = rest.find('\n') {
                if rest[..eol].contains('=') {
                    return true;
                }
            } else if rest.contains('=') {
                return true;
            }
        }
        i += 1;
    }
    // Fallback: general assignment presence + memory deref
    text.contains("*(") && text.contains(" = ")
}

/// Check if text contains a function call pattern:
/// An `(` that is NOT part of `if (`, `while (`, `for (`, `switch (`.
fn has_fn_call(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            // Check what precedes this '(' — if it's `if `, `while `, `for `,
            // `switch `, it's a control flow keyword, not a function call.
            let is_control = if i >= 4 {
                let before = &text[i - 4..i];
                before.ends_with("if ") || before.ends_with("for ")
            } else {
                false
            } || if i >= 6 {
                let before = &text[i - 6..i];
                before.ends_with("while ") || before.ends_with("switch ")
            } else {
                false
            };
            if !is_control && i > 0 && !bytes[i - 1].is_ascii_whitespace() {
                // '(' preceded by a non-whitespace character that is not a
                // control-flow keyword → likely a function call.
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Check if text contains a `return` statement.
fn has_return(text: &str) -> bool {
    text.contains("return")
}

/// Keyword presence score: fraction of the 4 key operations (load, store,
/// call, return) where actual output matches expected presence.
///
/// Scoring:
/// - +1.0 if both have the keyword OR both lack it (agreement)
/// - +0.5 if actual has it but expected doesn't (extra — benign)
/// - +0.0 if expected has it but actual doesn't (missing — significant)
fn keyword_presence_score(actual: &str, expected: &str) -> f64 {
    let checks: [(&str, fn(&str) -> bool); 4] = [
        ("load", has_memory_load),
        ("store", has_memory_store),
        ("call", has_fn_call),
        ("return", has_return),
    ];
    let mut score = 0.0;
    for (_name, check) in &checks {
        let in_actual = check(actual);
        let in_expected = check(expected);
        if in_actual == in_expected {
            score += 1.0; // agreement
        } else if in_actual && !in_expected {
            score += 0.5; // extra (benign — decompiler may have explicit derefs)
        }
        // else: in_expected && !in_actual → score += 0.0 (missing)
    }
    score / checks.len() as f64
}

/// Compute the full semantic similarity score between actual decompiled
/// HLIL text and the expected reference output.
fn compute_semantic_score(actual: &str, expected: &str) -> SemanticScore {
    let actual_cf = count_control_flow(actual);
    let expected_cf = count_control_flow(expected);
    let cf_match = cf_similarity(&actual_cf, &expected_cf);

    let actual_vars = count_variables(actual);
    let expected_vars = count_variables(expected);
    let var_similarity = if actual_vars.max(expected_vars) == 0 {
        1.0 // both have no named variables
    } else {
        actual_vars.min(expected_vars) as f64 / actual_vars.max(expected_vars).max(1) as f64
    };

    let actual_stmts = count_statements(actual);
    let expected_stmts = count_statements(expected);
    let stmt_ratio = if actual_stmts.max(expected_stmts) == 0 {
        1.0
    } else {
        actual_stmts.min(expected_stmts) as f64 / actual_stmts.max(expected_stmts).max(1) as f64
    };

    let keyword_score = keyword_presence_score(actual, expected);

    // Weighted average: CF and keywords carry more weight since they
    // reflect structural correctness; variable/statement counts are
    // more volatile across HLIL renderer versions.
    let overall =
        cf_match * 0.30 + var_similarity * 0.20 + stmt_ratio * 0.15 + keyword_score * 0.35;

    SemanticScore {
        cf_match,
        var_similarity,
        stmt_ratio,
        keyword_score,
        overall,
    }
}
