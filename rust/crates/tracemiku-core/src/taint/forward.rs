use super::*;

#[allow(clippy::too_many_arguments)]
pub fn forward_taint(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    through_mem: bool,
    mem: Option<&MemShadow>,
    data_only: bool,
) -> (Vec<TaintHit>, bool) {
    let result = forward_taint_ext(
        trace,
        index,
        start_idx,
        taint_reg,
        max_count,
        exclude_regs,
        mem,
        TaintOptions {
            through_mem,
            data_only,
            scan_limit: None,
        },
    );
    (
        result.hits,
        matches!(
            result.stop_reason,
            StopReason::MaxCount | StopReason::ScanLimit
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn forward_taint_ext(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    _mem: Option<&MemShadow>,
    opts: TaintOptions,
) -> TaintWalkResult {
    let through_mem = opts.through_mem;
    let data_only = opts.data_only;
    let scan_limit = opts.scan_limit;
    // _mem is unused on the forward side because tagging is index-only —
    // Python also doesn't use MemShadow on the forward path (only on backward).
    let mut tainted_regs: HashMap<String, TaintProvenance> = HashMap::new();
    tainted_regs.insert(taint_reg.to_string(), TaintProvenance::seed());
    let mut tainted_mem: HashMap<u64, TaintProvenance> = HashMap::new();
    let mut mem_touch = MemTouchTracker::new(index);
    let mut heap: BinaryHeap<Reverse<(usize, u8, String, usize)>> = BinaryHeap::new();
    push_next_reg_events(&mut heap, index, exclude_regs, taint_reg, start_idx);

    let mut out: Vec<TaintHit> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let cap = if max_count == 0 {
        usize::MAX
    } else {
        max_count
    };
    let mut stop_reason = StopReason::Completed;
    let mut since_last_hit: usize = 0;

    while let Some(Reverse((i, event_kind, reg, pos))) = heap.pop() {
        if out.len() >= cap {
            stop_reason = StopReason::MaxCount;
            break;
        }
        if let Some(limit) = scan_limit {
            if since_last_hit >= limit {
                stop_reason = StopReason::ScanLimit;
                break;
            }
        }
        since_last_hit = since_last_hit.saturating_add(1);
        if event_kind != MEM_TOUCH_EVENT {
            let next_entries = if event_kind == REG_DEF_EVENT {
                index.reg_defs.get(&reg)
            } else {
                index.reg_uses.get(&reg)
            };
            if let Some(entries) = next_entries {
                if pos + 1 < entries.len() {
                    heap.push(Reverse((
                        entries[pos + 1],
                        event_kind,
                        reg.clone(),
                        pos + 1,
                    )));
                }
            }
        }
        if seen.contains(&i) {
            continue;
        }
        seen.insert(i);
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        let addr_regs = if data_only {
            addressing_regs(&d.mem_op)
        } else {
            HashSet::new()
        };
        // Tainted regs that this insn READS.
        // In data_only mode, an insn only counts as "used" if the tainted
        // use is NOT purely an addressing reg (Python:155-156).
        let mut used: Vec<String> = Vec::new();
        let mut sources: Vec<TaintProvenance> = Vec::new();
        for u in &d.regs_use {
            if data_only && addr_regs.contains(u) {
                continue;
            }
            if let Some(src) = tainted_regs.get(u) {
                used.push(u.clone());
                sources.push(*src);
            }
        }

        // Check loads against tainted_mem (Python:158-187). For split pair
        // loads, remember which destination half is actually fed by tainted
        // memory so `ldp x4, x5, [sp]` does not taint both halves.
        let mut load_tainted = false;
        let mut load_tainted_regs: Vec<String> = Vec::new();
        for op in &d.mem_op {
            if op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            for o in 0..op.size as u64 {
                if let Some(src) = tainted_mem.get(&(base + o)) {
                    load_tainted = true;
                    sources.push(*src);
                    for dst in load_dest_regs(&d, op) {
                        if !load_tainted_regs.contains(&dst) {
                            load_tainted_regs.push(dst);
                        }
                    }
                    break;
                }
            }
        }

        let defines_tainted = d.regs_def.iter().any(|r| tainted_regs.contains_key(r));
        let mut overwrites_tainted_mem = false;
        for op in &d.mem_op {
            if !op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            if tainted_mem_overlaps(&tainted_mem, base, op.size) {
                overwrites_tainted_mem = true;
                break;
            }
        }

        if used.is_empty() && !load_tainted {
            // Kill semantics: a clean overwrite of a tainted register/memory
            // should stop later false positives. Partial RMW forms such as
            // movk keep the old destination taint when Capstone does not expose
            // the old destination as a use.
            if defines_tainted && !is_partial_modify(&d) {
                for nr in &d.regs_def {
                    tainted_regs.remove(nr);
                }
            }
            if overwrites_tainted_mem {
                for op in &d.mem_op {
                    if !op.is_write {
                        continue;
                    }
                    let base = addr_of(&r, op);
                    let src_tainted = store_source_regs(&d, op)
                        .iter()
                        .any(|src| tainted_regs.contains_key(src));
                    if !src_tainted {
                        mem_touch.clear_span(&mut tainted_mem, base, op.size, through_mem);
                    }
                }
                push_next_mem_touch(&mut heap, &mut mem_touch, &tainted_mem, i);
            }
            continue;
        }
        used.sort();
        used.dedup();
        let mut why_parts: Vec<String> = Vec::new();
        if !used.is_empty() {
            why_parts.push(format!("regs:{}", used.join(",")));
        }
        if load_tainted {
            why_parts.push("mem".to_string());
        }
        let why = why_parts.join(" ");
        let taint_depth = sources
            .iter()
            .filter(|src| src.idx.is_some())
            .map(|src| src.depth.saturating_add(1))
            .max()
            .unwrap_or(0);
        let mut parent_idxs: Vec<usize> = sources.iter().filter_map(|src| src.idx).collect();
        parent_idxs.sort_unstable();
        parent_idxs.dedup();
        out.push(TaintHit {
            idx: i,
            why,
            parent_idxs,
            taint_depth,
            edge_kind: if load_tainted && !used.is_empty() {
                Some("reg+mem".to_string())
            } else if load_tainted {
                Some("mem".to_string())
            } else {
                Some("reg".to_string())
            },
        });
        since_last_hit = 0;
        let next_provenance = TaintProvenance::from_hit(i, taint_depth);

        // Propagate: regs_def → push next-use/def. Loads from tainted memory
        // only taint the loaded destination register(s); tainted register
        // sources still taint all explicit defs as before.
        let mut defs_to_taint: HashSet<String> = HashSet::new();
        if !used.is_empty() {
            for nr in &d.regs_def {
                defs_to_taint.insert(nr.clone());
            }
        }
        if load_tainted {
            if load_tainted_regs.is_empty() {
                for nr in &d.regs_def {
                    defs_to_taint.insert(nr.clone());
                }
            } else {
                for nr in load_tainted_regs {
                    defs_to_taint.insert(nr);
                }
            }
        }
        for nr in &d.regs_def {
            if exclude_regs.contains(nr) {
                continue;
            }
            if defs_to_taint.contains(nr)
                || (is_partial_modify(&d) && tainted_regs.contains_key(nr))
            {
                let was_tainted = tainted_regs.contains_key(nr);
                tainted_regs.insert(nr.clone(), next_provenance);
                if !was_tainted {
                    push_next_reg_events(&mut heap, index, exclude_regs, nr, i);
                }
            } else {
                tainted_regs.remove(nr);
            }
        }
        // Propagate/kill stores per memory half. Pair and exclusive stores use
        // MemOp.src_reg, so stp half2 follows its second data register rather
        // than the first register in the instruction.
        for op in &d.mem_op {
            if !op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            let src_tainted = store_source_regs(&d, op)
                .iter()
                .any(|src| tainted_regs.contains_key(src));
            if src_tainted {
                mem_touch.write_span(
                    &mut tainted_mem,
                    base,
                    op.size,
                    through_mem,
                    next_provenance,
                );
            } else {
                mem_touch.clear_span(&mut tainted_mem, base, op.size, through_mem);
            }
        }
        push_next_mem_touch(&mut heap, &mut mem_touch, &tainted_mem, i);
    }

    TaintWalkResult {
        hits: out,
        stop_reason,
    }
}
