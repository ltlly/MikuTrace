//! External call boundary synthesis (`memcpy` / `memmove` / `memset`) for [`MemShadow`].
//!
//! When Stalker excludes `libc.so` (or another external module), calls such as
//! `memcpy(dst, src, len)`, `memmove(dst, src, len)`, and `memset(dst, c, len)`
//! execute without emitting per-store records in `trace.bin`. At the call
//! boundary record `idx` (`bl` / `blr` / PLT tail `br`), `trace.bin` still
//! captures the pre-call ABI registers (`x0`, `x1`, `x2`, `lr`) and the
//! post-call return state at `idx + 1` (`x0 == dst`, `pc == return_pc`).
//!
//! This module detects verified external copy/fill boundaries, populates
//! synthetic `"x"` byte writes in [`MemShadow`], and records `(dst_addr, idx) -> src_addr`
//! mappings in `copy_sources` so `byte-lineage` can hop across buffer copies.

use std::collections::HashMap;

use crate::disasm::decode;
use crate::memshadow::{ByteEvent, ByteEventKind, ByteEvents, MemRec, MemShadow, MemSnapshot};
use crate::trace::{Record, Trace};

const MAX_SYNTH_COPY_LEN: u64 = 16_384;
const MAX_TOTAL_SYNTH_BYTES: usize = 1024 * 1024;
const MIN_VALID_USER_ADDR: u64 = 0x1000;

/// Detect uninstrumented external `memcpy`/`memmove`/`memset` call boundaries
/// in `trace` and merge their byte writes + `copy_sources` into `mem`.
pub(crate) fn merge_uninstrumented_mem_calls(
    trace: &Trace,
    mem: &mut MemShadow,
    snapshot: Option<&MemSnapshot>,
) {
    let n = trace.len();
    if n < 2 {
        return;
    }

    let mut added = false;
    let mut synth_budget = MAX_TOTAL_SYNTH_BYTES;
    for idx in 0..n - 1 {
        if synth_budget == 0 {
            break;
        }
        let rec = trace.record(idx);
        let next_rec = trace.record(idx + 1);
        if !is_uninstrumented_call_return_boundary(&rec, &next_rec) {
            continue;
        }

        let dst = rec.regs[0];
        let arg1 = rec.regs[1];
        let len = rec.regs[2];

        // Return value of memcpy / memmove / memset in x0 is always `dst`.
        if next_rec.regs[0] != dst {
            continue;
        }
        if dst < MIN_VALID_USER_ADDR || !(1..=MAX_SYNTH_COPY_LEN).contains(&len) {
            continue;
        }
        if (len as usize) > synth_budget {
            continue;
        }
        let Some(dst_end) = dst.checked_add(len) else {
            continue;
        };

        // Case 1: memcpy / memmove(dst, src, len) — must be verified by post-call reads
        if arg1 >= MIN_VALID_USER_ADDR && arg1 != dst {
            if let Some(src_end) = arg1.checked_add(len) {
                let emitted =
                    try_synthesize_mem_copy(idx, dst, dst_end, arg1, src_end, len, mem, snapshot);
                if emitted > 0 {
                    synth_budget = synth_budget.saturating_sub(emitted);
                    added = true;
                    continue;
                }
            }
        }

        // Case 2: memset(dst, c, len) — must be verified by post-call reads
        if arg1 <= 0xff {
            let emitted = try_synthesize_memset(idx, dst, dst_end, arg1 as u8, len, mem, snapshot);
            if emitted > 0 {
                synth_budget = synth_budget.saturating_sub(emitted);
                added = true;
            }
        }
    }

    if added {
        mem.writes.sort_by_key(|rec| (rec.idx, rec.addr));
    }
}

/// True when `rec` is a call or PLT jump into an uninstrumented target and
/// `next_rec` is the immediate return to the caller.
fn is_uninstrumented_call_return_boundary(rec: &Record, next_rec: &Record) -> bool {
    let inst = rec.inst;
    // `bl #imm`: 0x9400_0000..=0x97ff_ffff
    let is_bl = (inst & 0xfc00_0000) == 0x9400_0000;
    // `blr Rn`: 0xd63f_0000
    let is_blr = (inst & 0xffff_fc1f) == 0xd63f_0000;
    // `br Rn`: 0xd61f_0000 (PLT tail jump, e.g. `br x16` / `br x17`)
    let is_br = (inst & 0xffff_fc1f) == 0xd61f_0000;
    // `b #imm`: 0x1400_0000..=0x17ff_ffff (tail call / PLT jump)
    let is_b = (inst & 0xfc00_0000) == 0x1400_0000;

    if is_bl || is_blr {
        let return_pc = rec.pc.wrapping_add(4);
        if next_rec.pc != return_pc {
            return false;
        }
        // If `bl`/`blr` target is `return_pc` itself, it was a traced jump to next insn, not an external call.
        let d = decode(rec.pc, rec.inst);
        if d.mnemonic == "bl" {
            if let Some(target) = parse_branch_target(&d.op_str) {
                if target == return_pc {
                    return false;
                }
            }
        } else if d.mnemonic == "blr" {
            if let Some(target_reg) = d.regs_use.first() {
                if rec.reg_by_name(target_reg) == Some(return_pc) {
                    return false;
                }
            }
        }
        return true;
    }

    if is_br || is_b {
        // In a PLT stub or tail call, LR (`x30`) holds the caller's return address,
        // and the next traced instruction is at `lr` (which differs from the branch target).
        let lr = rec.regs[30];
        if lr < MIN_VALID_USER_ADDR || next_rec.pc != lr || lr == rec.pc.wrapping_add(4) {
            return false;
        }
        if is_br {
            let rn = ((inst >> 5) & 31) as usize;
            if rn < 31 && rec.regs[rn] == lr {
                return false;
            }
        }
        return true;
    }

    false
}

fn parse_branch_target(op_str: &str) -> Option<u64> {
    let tok = op_str
        .split_whitespace()
        .next()?
        .trim_start_matches('#')
        .trim_end_matches(',');
    u64::from_str_radix(tok.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

/// Evaluate known byte at `addr` at or before `idx` using current `mem.bytes` and `snapshot`.
fn known_byte_at_or_before(
    bytes: &ByteEvents,
    snapshot: Option<&MemSnapshot>,
    addr: u64,
    idx: usize,
) -> Option<(u8, &'static str)> {
    if let Some(evs) = bytes.get(&addr) {
        let pos = evs.partition_point(|ev| ev.idx() <= idx);
        if pos > 0 {
            let ev = &evs[pos - 1];
            return Some((ev.byte, ev.kind.as_str()));
        }
    }
    if let Some(snap) = snapshot {
        if let Some(b) = snap.byte_at(addr) {
            return Some((b, "i"));
        }
    }
    None
}

/// Check the first event on `addr` strictly after `idx`. If it is a read (`"r"`),
/// return the read byte value.
fn first_post_call_read_before_write(bytes: &ByteEvents, addr: u64, idx: usize) -> Option<u8> {
    let evs = bytes.get(&addr)?;
    let pos = evs.partition_point(|ev| ev.idx() <= idx);
    let first = evs.get(pos)?;
    (first.kind == "r").then_some(first.byte)
}

/// Insert `ByteEvent` into `evs` while maintaining ascending `idx` order.
/// Returns `true` if inserted, `false` if a write (`"w"` or `"x"`) at `idx` already exists.
fn insert_ordered_write_event(evs: &mut Vec<ByteEvent>, idx: usize, byte: u8) -> bool {
    let lo = evs.partition_point(|ev| ev.idx() < idx);
    let hi = evs.partition_point(|ev| ev.idx() <= idx);
    if evs[lo..hi]
        .iter()
        .any(|ev| ev.kind == "w" || ev.kind == "x")
    {
        return false;
    }
    evs.insert(hi, ByteEvent::new(idx, byte, ByteEventKind::External));
    true
}

#[allow(clippy::too_many_arguments)]
fn try_synthesize_mem_copy(
    idx: usize,
    dst: u64,
    _dst_end: u64,
    src: u64,
    _src_end: u64,
    len: u64,
    mem: &mut MemShadow,
    snapshot: Option<&MemSnapshot>,
) -> usize {
    // Gather pre-call source bytes at `idx` before mutating `mem` (so overlapping
    // `memmove` reads the pre-call snapshot of `src[0..len)`).
    let mut src_bytes: Vec<Option<u8>> = Vec::with_capacity(len as usize);
    let mut known_count = 0usize;
    let mut verified_reads = 0usize;
    let mut changed_vs_prior = 0usize;

    for k in 0..len {
        let s_addr = src.wrapping_add(k);
        let d_addr = dst.wrapping_add(k);
        let src_info = known_byte_at_or_before(&mem.bytes, snapshot, s_addr, idx);
        if let Some((s_byte, _s_kind)) = src_info {
            known_count += 1;
            if let Some(r_byte) = first_post_call_read_before_write(&mem.bytes, d_addr, idx) {
                if r_byte != s_byte {
                    // Post-call read on dst+k before any subsequent write disagrees with src+k!
                    return 0;
                }
                verified_reads += 1;
                let prior = known_byte_at_or_before(&mem.bytes, snapshot, d_addr, idx);
                if prior.map(|(b, _)| b) != Some(s_byte) {
                    changed_vs_prior += 1;
                }
            }
            src_bytes.push(Some(s_byte));
        } else {
            src_bytes.push(None);
        }
    }

    // Never guess a memory copy from pre-call registers alone: require at least one
    // post-call read on `dst` that observed the exact byte from `src` (with a state
    // change on `dst`) and zero contradicting reads across `[dst, dst + len)`.
    if known_count == 0 || verified_reads == 0 || changed_vs_prior == 0 {
        return 0;
    }

    let mut emitted_count = 0usize;
    for (k, maybe_byte) in src_bytes.into_iter().enumerate() {
        let Some(byte) = maybe_byte else {
            continue;
        };
        let d_addr = dst.wrapping_add(k as u64);
        let s_addr = src.wrapping_add(k as u64);
        let evs = mem.bytes.entry(d_addr).or_default();
        if insert_ordered_write_event(evs, idx, byte) {
            mem.writes.push(MemRec {
                idx,
                addr: d_addr,
                size: 1,
                value: byte as u64,
                reserved: 0,
            });
            mem.copy_sources.insert((d_addr, idx), s_addr);
            emitted_count += 1;
        }
    }

    emitted_count
}

fn try_synthesize_memset(
    idx: usize,
    dst: u64,
    _dst_end: u64,
    fill_byte: u8,
    len: u64,
    mem: &mut MemShadow,
    snapshot: Option<&MemSnapshot>,
) -> usize {
    let mut verified_reads = 0usize;
    let mut changed_vs_prior = 0usize;
    for k in 0..len {
        let d_addr = dst.wrapping_add(k);
        if let Some(r_byte) = first_post_call_read_before_write(&mem.bytes, d_addr, idx) {
            if r_byte != fill_byte {
                return 0;
            }
            verified_reads += 1;
            let prior = known_byte_at_or_before(&mem.bytes, snapshot, d_addr, idx);
            if prior.map(|(b, _)| b) != Some(fill_byte) {
                changed_vs_prior += 1;
            }
        }
    }

    if verified_reads == 0 || changed_vs_prior == 0 {
        return 0;
    }

    let mut emitted_count = 0usize;
    for k in 0..len {
        let d_addr = dst.wrapping_add(k);
        let evs = mem.bytes.entry(d_addr).or_default();
        if insert_ordered_write_event(evs, idx, fill_byte) {
            mem.writes.push(MemRec {
                idx,
                addr: d_addr,
                size: 1,
                value: fill_byte as u64,
                reserved: 0,
            });
            emitted_count += 1;
        }
    }
    emitted_count
}

pub(crate) fn load_worker_anchor_windows(
    call_dir: &std::path::Path,
    default_anchor: usize,
) -> HashMap<String, (usize, usize)> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(call_dir.join("meta.json")) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    let Some(items) = json
        .get("workerTraces")
        .or_else(|| json.get("worker_traces"))
        .and_then(|v| v.as_array())
    else {
        return out;
    };
    for item in items {
        let file = item
            .get("file")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                item.get("tid")
                    .and_then(|v| v.as_u64())
                    .map(|tid| format!("worker_trace_tid{tid}.bin"))
            });
        let Some(file) = file else {
            continue;
        };
        let spawned = item
            .get("spawnedAtIdx")
            .or_else(|| item.get("anchorHeadIdx"))
            .and_then(|v| v.as_u64())
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(default_anchor)
            .min(default_anchor);
        let ended = item
            .get("endedAtIdx")
            .and_then(|v| v.as_u64())
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(default_anchor)
            .min(default_anchor)
            .max(spawned);
        out.insert(file.to_string(), (spawned, ended));
    }
    out
}

/// Interpolate a worker record index `i` (out of `n` worker records) into its
/// main-thread causality window `[spawned_at, ended_at]`.
pub(crate) fn worker_record_anchor_idx(
    windows: &HashMap<String, (usize, usize)>,
    file_name: &str,
    worker_idx: usize,
    worker_len: usize,
    default_anchor: usize,
) -> usize {
    let Some(&(spawned, ended)) = windows.get(file_name) else {
        return default_anchor;
    };
    if worker_len <= 1 || ended <= spawned {
        return spawned;
    }
    let span = ended - spawned;
    spawned + (worker_idx.saturating_mul(span)) / (worker_len - 1)
}
