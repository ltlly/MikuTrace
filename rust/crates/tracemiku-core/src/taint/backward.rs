use super::*;

/// Return writer record indices that overlap `[addr, addr+size)` strictly
/// before `before_idx`. Mirrors viewer/taint.py:274-299.
fn mem_writers_overlapping(
    index: &Index,
    mem: Option<&MemShadow>,
    addr: u64,
    size: u32,
    before_idx: usize,
    through_mem: bool,
) -> Vec<usize> {
    if !through_mem || mem.is_none() {
        // Exact-addr mode: ONLY the latest writer < before_idx. The current
        // value at `addr` is defined by the most recent write; older writes
        // are shadowed and must not appear as provenance sources.
        let Some(writers) = index.mem_addr_to_writes.get(&addr) else {
            return Vec::new();
        };
        let pos = writers.partition_point(|&w| w < before_idx);
        if pos == 0 {
            return Vec::new();
        }
        return vec![writers[pos - 1]];
    }
    // Byte-overlap mode: for each byte, take the latest writer < before_idx,
    // then dedupe. Granularity is per-byte; semantics are the same as exact
    // mode — shadowed historical writers are NOT included (see
    // taint_through_mem_contract_tests).
    let mem = mem.unwrap();
    let mut seen: HashSet<usize> = HashSet::new();
    for o in 0..size as u64 {
        if let Some(j) = mem.latest_write_idx_strict_before(addr + o, before_idx) {
            seen.insert(j);
        }
    }
    let mut out: Vec<usize> = seen.into_iter().collect();
    out.sort_unstable();
    out.reverse();
    out
}

#[allow(clippy::too_many_arguments)] // M3-γ Task 4 will add cross_fn_call.
pub fn backward_taint(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    through_mem: bool,
    mem: Option<&MemShadow>,
    data_only: bool,
) -> (Vec<TaintHit>, bool) {
    let result = backward_taint_ext(
        trace,
        index,
        idx,
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
pub fn backward_taint_ext(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    mem: Option<&MemShadow>,
    opts: TaintOptions,
) -> TaintWalkResult {
    let through_mem = opts.through_mem;
    let data_only = opts.data_only;
    let scan_limit = opts.scan_limit;
    let mut pending: VecDeque<BwdItem> = VecDeque::new();
    let mut visited: HashSet<(usize, String)> = HashSet::new();
    let mut raw_out: Vec<RawBwdHit> = Vec::new();
    let cap = if max_count == 0 {
        usize::MAX
    } else {
        max_count
    };
    let mut stop_reason = StopReason::Completed;
    let mut since_last_hit: usize = 0;

    // Initial seed branch (viewer/taint.py:306-318).
    let r0 = trace.record(idx);
    let d0 = decode(r0.pc, r0.inst);
    let starts_with_def = d0.regs_def.iter().any(|r| r == taint_reg);

    if starts_with_def && !exclude_regs.contains(taint_reg) {
        raw_out.push(RawBwdHit {
            idx,
            why: taint_reg.to_string(),
            parent_idxs: Vec::new(),
            taint_depth: 0,
            edge_kind: Some("seed".to_string()),
        });
        if !data_only {
            push_control_dependency(
                trace,
                index,
                &mut raw_out,
                &mut pending,
                idx,
                idx,
                1,
                exclude_regs,
            );
        }
        let addr_regs0 = addressing_regs(&d0.mem_op);
        for u in &d0.regs_use {
            if exclude_regs.contains(u) {
                continue;
            }
            if data_only && addr_regs0.contains(u) {
                continue;
            }
            pending.push_back(BwdItem::Reg {
                cur_idx: idx,
                want_reg: u.clone(),
                parent_idx: Some(idx),
                depth: 1,
                edge_kind: if addr_regs0.contains(u) {
                    "addr"
                } else {
                    "reg"
                },
            });
        }
        for op in &d0.mem_op {
            if !load_op_feeds_reg(&d0, op, taint_reg) {
                continue;
            }
            let addr = addr_of(&r0, op);
            pending.push_back(BwdItem::Mem {
                before_idx: idx,
                addr,
                size: op.size,
                parent_idx: Some(idx),
                depth: 1,
                edge_kind: "mem",
            });
        }
    } else if !exclude_regs.contains(taint_reg) {
        pending.push_back(BwdItem::Reg {
            cur_idx: idx,
            want_reg: taint_reg.to_string(),
            parent_idx: None,
            depth: 0,
            edge_kind: "reg",
        });
    }

    while let Some(item) = pending.pop_front() {
        if raw_out.len() >= cap {
            stop_reason = StopReason::MaxCount;
            break;
        }
        if let Some(limit) = scan_limit {
            if since_last_hit >= limit {
                stop_reason = StopReason::ScanLimit;
                break;
            }
        }
        let before_pop = raw_out.len();
        since_last_hit = since_last_hit.saturating_add(1);
        match item {
            BwdItem::Mem {
                before_idx,
                addr,
                size,
                parent_idx,
                depth,
                edge_kind,
            } => {
                let writers =
                    mem_writers_overlapping(index, mem, addr, size, before_idx, through_mem);
                for j in writers {
                    let r = trace.record(j);
                    let d = decode(r.pc, r.inst);
                    let parent_idxs = parent_idx.into_iter().collect::<Vec<_>>();
                    raw_out.push(RawBwdHit {
                        idx: j,
                        why: "mem".to_string(),
                        parent_idxs: parent_idxs.clone(),
                        taint_depth: depth,
                        edge_kind: Some(edge_kind.to_string()),
                    });
                    if !data_only {
                        push_control_dependency(
                            trace,
                            index,
                            &mut raw_out,
                            &mut pending,
                            j,
                            j,
                            depth.saturating_add(1),
                            exclude_regs,
                        );
                    }
                    let sources = store_source_regs_for_addr(&d, &r, addr, size);
                    for src in sources {
                        if exclude_regs.contains(&src) {
                            continue;
                        }
                        pending.push_back(BwdItem::Reg {
                            cur_idx: j,
                            want_reg: src,
                            parent_idx: Some(j),
                            depth: depth.saturating_add(1),
                            edge_kind: "store-src",
                        });
                    }
                }
            }
            BwdItem::Reg {
                cur_idx,
                want_reg,
                parent_idx,
                depth,
                edge_kind,
            } => {
                if exclude_regs.contains(&want_reg) {
                    continue;
                }
                if visited.contains(&(cur_idx, want_reg.clone())) {
                    continue;
                }
                visited.insert((cur_idx, want_reg.clone()));

                let Some(j) = index.last_def_before(&want_reg, cur_idx) else {
                    continue;
                };
                let parent_idxs = parent_idx.into_iter().collect::<Vec<_>>();
                raw_out.push(RawBwdHit {
                    idx: j,
                    why: want_reg.clone(),
                    parent_idxs,
                    taint_depth: depth,
                    edge_kind: Some(edge_kind.to_string()),
                });
                if !data_only {
                    push_control_dependency(
                        trace,
                        index,
                        &mut raw_out,
                        &mut pending,
                        j,
                        j,
                        depth.saturating_add(1),
                        exclude_regs,
                    );
                }

                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                let addr_regs = addressing_regs(&d.mem_op);
                for u in &d.regs_use {
                    if exclude_regs.contains(u) {
                        continue;
                    }
                    if data_only && addr_regs.contains(u) {
                        continue;
                    }
                    pending.push_back(BwdItem::Reg {
                        cur_idx: j,
                        want_reg: u.clone(),
                        parent_idx: Some(j),
                        depth: depth.saturating_add(1),
                        edge_kind: if addr_regs.contains(u) { "addr" } else { "reg" },
                    });
                }
                for op in &d.mem_op {
                    if !load_op_feeds_reg(&d, op, &want_reg) {
                        continue;
                    }
                    let addr = addr_of(&r, op);
                    pending.push_back(BwdItem::Mem {
                        before_idx: j,
                        addr,
                        size: op.size,
                        parent_idx: Some(j),
                        depth: depth.saturating_add(1),
                        edge_kind: "mem",
                    });
                }
            }
        }
        if raw_out.len() > before_pop {
            since_last_hit = 0;
        }
    }

    // Dedup by sorted idx (Python lines 358-361).
    raw_out.sort_by(|a, b| a.idx.cmp(&b.idx).then_with(|| a.why.cmp(&b.why)));
    let mut seen_idx: HashSet<usize> = HashSet::new();
    let mut out: Vec<TaintHit> = Vec::new();
    for hit in raw_out {
        if seen_idx.contains(&hit.idx) {
            continue;
        }
        seen_idx.insert(hit.idx);
        out.push(TaintHit {
            idx: hit.idx,
            why: hit.why,
            parent_idxs: hit.parent_idxs,
            taint_depth: hit.taint_depth,
            edge_kind: hit.edge_kind,
        });
    }
    TaintWalkResult {
        hits: out,
        stop_reason,
    }
}
