//! 统一内存访问查询；时间区间为 [start,end)，未知读写值仍保留事件。
use super::{AnalysisContext, AnalysisError};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct MemAccessesQuery {
    pub addr: String,
    pub size: usize,
    pub start: usize,
    pub end: Option<usize>,
    pub kind: String,
    pub limit: usize,
    pub cursor: usize,
}
impl Default for MemAccessesQuery {
    fn default() -> Self {
        Self {
            addr: String::new(),
            size: 1,
            start: 0,
            end: None,
            kind: "all".into(),
            limit: 200,
            cursor: 0,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct MemoryAccess {
    pub idx: usize,
    pub kind: &'static str,
    pub source: &'static str,
    pub addr: String,
    pub size: usize,
    pub access_addr: String,
    pub access_size: usize,
    pub bytes: Vec<Option<u8>>,
    pub pc: Option<String>,
    pub asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlogged_write_gap: Option<crate::memshadow::UnloggedWriteGap>,
}
#[derive(Debug, Serialize)]
pub struct MemAccessesResponse {
    pub addr: String,
    pub size: usize,
    pub requested_size: usize,
    pub range_truncated: bool,
    pub start: usize,
    pub end: usize,
    pub kind: String,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub returned: usize,
    pub truncated: bool,
    pub events: Vec<MemoryAccess>,
}
// (idx, kind 0=read 1=write 2=external, address, access size)
type AccessKey = (usize, u8, u64, usize, Option<u8>);

fn trace_accesses<'a>(
    trace: &'a crate::trace::Trace,
    start: usize,
    end: usize,
    addr: u64,
    last: u64,
    kind_filter: String,
) -> impl Iterator<Item = AccessKey> + 'a {
    let mut next = start;
    let mut pending = VecDeque::new();
    std::iter::from_fn(move || {
        loop {
            if let Some(event) = pending.pop_front() {
                return Some(event);
            }
            if next >= end {
                return None;
            }
            let idx = next;
            next += 1;
            let record = trace.record(idx);
            let decoded = crate::disasm::decode(record.pc, record.inst);
            for op in decoded.mem_op.iter().filter(|op| !op.base.is_empty()) {
                let kind = u8::from(op.is_write);
                if (kind == 0 && kind_filter == "write") || (kind == 1 && kind_filter == "read") {
                    continue;
                }
                let access_addr = crate::disasm::addr_of(&record, op);
                if access_addr <= last && access_addr.saturating_add(u64::from(op.size) - 1) >= addr
                {
                    pending.push_back((idx, kind, access_addr, op.size as usize, None));
                }
            }
            // Heap merge requires every input stream to be ordered even for
            // instructions with multiple memory operands.
            if pending.len() > 1 {
                pending.make_contiguous().sort_by_key(|event| *event);
            }
        }
    })
}

pub fn mem_accesses(
    state: &AnalysisContext,
    q: MemAccessesQuery,
) -> Result<MemAccessesResponse, AnalysisError> {
    let addr = crate::address_parse::parse_address(&q.addr)
        .map_err(|e| AnalysisError::invalid(e.to_string()))?;
    if q.size == 0 || q.limit == 0 {
        return Err(AnalysisError::invalid("size and limit must be positive"));
    }
    if !matches!(q.kind.as_str(), "all" | "read" | "write") {
        return Err(AnalysisError::invalid("kind must be all, read or write"));
    }
    let size = q.size.min(4096);
    let last = addr
        .checked_add(size as u64 - 1)
        .ok_or_else(|| AnalysisError::invalid("address range overflows u64"))?;
    let end = q
        .end
        .unwrap_or(state.inner.trace.len())
        .min(state.inner.trace.len());
    if q.start > end {
        return Err(AnalysisError::invalid("start exceeds end"));
    }
    let mem = state.inner.memshadow()?;
    let mut streams: Vec<Box<dyn Iterator<Item = AccessKey> + '_>> = Vec::new();
    streams.push(Box::new(trace_accesses(
        &state.inner.trace,
        q.start,
        end,
        addr,
        last,
        q.kind.clone(),
    )));
    if q.kind != "read" {
        for (&at, events) in mem.bytes.range(addr..=last) {
            let lo = events.partition_point(|e| e.idx() < q.start);
            let hi = events.partition_point(|e| e.idx() < end);
            streams.push(Box::new(
                events[lo..hi]
                    .iter()
                    .filter(|e| e.kind == "x")
                    .map(move |e| (e.idx(), 2, at, 1, Some(e.byte))),
            ));
        }
    }
    let mut heap = BinaryHeap::new();
    for (stream, iter) in streams.iter_mut().enumerate() {
        if let Some(key) = iter.next() {
            heap.push(Reverse((key, stream)));
        }
    }
    let limit = q.limit.min(5000);
    let mut events = Vec::new();
    let mut ordinal = 0usize;
    let mut more = false;
    while let Some(Reverse(((idx, kind, access_addr, access_size, external_byte), stream))) =
        heap.pop()
    {
        if let Some(key) = streams[stream].next() {
            heap.push(Reverse((key, stream)));
        }
        if ordinal < q.cursor {
            ordinal += 1;
            continue;
        }
        if events.len() == limit {
            more = true;
            break;
        }
        ordinal += 1;
        let begin = access_addr.max(addr);
        let finish = access_addr.saturating_add(access_size as u64 - 1).min(last);
        let kind_tag = ["r", "w", "x"][kind as usize];
        let bytes = (begin..=finish)
            .map(|a| {
                if kind == 2 {
                    external_byte
                } else {
                    mem.bytes.get(&a).and_then(|es| {
                        let hi = es.partition_point(|e| e.idx() <= idx);
                        es[..hi]
                            .iter()
                            .rev()
                            .take_while(|e| e.idx() == idx)
                            .find(|e| e.kind == kind_tag)
                            .map(|e| e.byte)
                    })
                }
            })
            .collect();
        let instruction = (kind != 2 && idx < state.inner.trace.len()).then(|| {
            let r = state.inner.trace.record(idx);
            (format!("{:#x}", r.pc), crate::disasm::decode(r.pc, r.inst))
        });
        let unlogged_write_gap = (kind == 0)
            .then(|| {
                (begin..=finish)
                    .find_map(|a| mem.unlogged_write_gap_before(a, idx.saturating_add(1)))
            })
            .flatten();
        events.push(MemoryAccess {
            idx,
            kind: if kind == 0 { "read" } else { "write" },
            source: if kind == 2 { "external" } else { "trace" },
            addr: format!("{begin:#x}"),
            size: (finish - begin + 1) as usize,
            access_addr: format!("{access_addr:#x}"),
            access_size,
            bytes,
            pc: instruction.as_ref().map(|(pc, _)| pc.clone()),
            asm: instruction
                .as_ref()
                .map(|(_, d)| format!("{} {}", d.mnemonic, d.op_str).trim().to_string()),
            unlogged_write_gap,
        });
    }
    Ok(MemAccessesResponse {
        addr: format!("{addr:#x}"),
        size,
        requested_size: q.size,
        range_truncated: q.size > size,
        start: q.start,
        end,
        kind: q.kind,
        cursor: q.cursor,
        next_cursor: more.then_some(ordinal),
        returned: events.len(),
        truncated: more || q.size > size,
        events,
    })
}
