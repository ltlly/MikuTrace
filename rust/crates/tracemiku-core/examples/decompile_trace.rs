//! Decompile evaluation tool — reads a real trace.bin and decompiles
//! functions, measuring quality and performance.
//!
//! Usage:
//!   cargo run --example decompile_trace -- <call_dir> [--max-fns N] [--min-records M]
//!
//! Example:
//!   cargo run --example decompile_trace -- \
//!     /home/ltlly/Code/traceMiku/traces/boundary_stat_launch2/calls/call_001_tid11945_8882256r_7389ms \
//!     --max-fns 10 --min-records 50

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use tracemiku_core::decompiler::il_pipeline::decompile_trace;
use tracemiku_core::trace::record::{Record, REC_SIZE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: decompile_trace <call_dir> [--max-fns N] [--min-records M]");
        std::process::exit(1);
    }

    let call_dir = &args[1];
    let max_fns = parse_flag(&args, "--max-fns", 20);
    let min_records = parse_flag(&args, "--min-records", 30);

    let trace_path = Path::new(call_dir).join("trace.bin");
    if !trace_path.exists() {
        eprintln!("trace.bin not found at {}", trace_path.display());
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(&trace_path)?.len();
    println!("Reading trace: {} ({:.2} GB)", trace_path.display(), file_size as f64 / 1e9);

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

    println!("\nDecompiling top {} functions (min {} records each):\n", fn_stats.len(), min_records);

    let mut total_llil = 0usize;
    let mut total_mlil = 0usize;
    let mut total_hlil = 0usize;
    let mut total_insn = 0usize;
    let mut total_time = std::time::Duration::ZERO;
    let mut best_coverage = 0.0f64;
    let mut worst_coverage = 1.0f64;

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
    println!("Expansion LLIL→MLIL:     {:.1}x", total_mlil as f64 / total_llil.max(1) as f64);
    println!("Expansion MLIL→HLIL:     {:.1}x", total_hlil as f64 / total_mlil.max(1) as f64);
    println!();
    println!("Best LLIL coverage:      {:.1}%", best_coverage * 100.0);
    println!("Worst LLIL coverage:     {:.1}%", worst_coverage * 100.0);
    println!();

    Ok(())
}

fn read_trace_records(path: &Path) -> Result<(Vec<Record>, Vec<(u64, u32)>), Box<dyn std::error::Error>> {
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
    decoded.mnemonic.split('.').next().unwrap_or(&decoded.mnemonic).to_string()
}

fn parse_flag(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
