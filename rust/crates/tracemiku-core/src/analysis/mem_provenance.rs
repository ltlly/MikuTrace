//! 逐字节观测来源与最后已观测写入者；按同一时刻查询并合并相邻写入区间。
use super::{AnalysisContext, AnalysisError};
use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize)]
pub struct MemProvenanceQuery {
    pub addr: String,
    pub count: usize,
    pub at: Option<usize>,
}
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Writer {
    pub idx: usize,
    pub source: &'static str,
    pub pc: Option<String>,
    pub asm: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ProvenanceByte {
    pub addr: String,
    pub byte: Option<u8>,
    pub kind: &'static str,
    pub source_idx: Option<usize>,
    pub last_writer: Option<Writer>,
}
#[derive(Debug, Serialize)]
pub struct WriterRun {
    pub offset: usize,
    pub count: usize,
    pub writer: Option<Writer>,
}
#[derive(Debug, Serialize)]
pub struct MemProvenanceResponse {
    pub addr: String,
    pub at: Option<usize>,
    pub count: usize,
    pub requested_count: usize,
    pub truncated: bool,
    pub observed_count: usize,
    pub bytes: Vec<ProvenanceByte>,
    pub writer_runs: Vec<WriterRun>,
}
pub fn mem_provenance(
    state: &AnalysisContext,
    q: MemProvenanceQuery,
) -> Result<MemProvenanceResponse, AnalysisError> {
    let addr = crate::address_parse::parse_address(&q.addr)
        .map_err(|e| AnalysisError::invalid(e.to_string()))?;
    if q.count == 0 {
        return Err(AnalysisError::invalid("count must be positive"));
    }
    if q.at.is_some_and(|at| at >= state.inner.trace.len()) {
        return Err(AnalysisError::invalid("memory time is outside trace"));
    }
    let count = q.count.min(4096);
    addr.checked_add(count as u64 - 1)
        .ok_or_else(|| AnalysisError::invalid("address range overflows u64"))?;
    let at = q.at.unwrap_or(usize::MAX);
    let mem = state.inner.memshadow()?;
    let mut bytes = Vec::with_capacity(count);
    let mut writer_runs: Vec<WriterRun> = Vec::new();
    for offset in 0..count {
        let a = addr + offset as u64;
        let (byte, kind, source_idx) = mem.byte_at(a, at as u64);
        let shadow_writer = mem.bytes.get(&a).and_then(|events| {
            let end = events.partition_point(|e| e.idx() <= at);
            events[..end]
                .iter()
                .rev()
                .find(|e| e.kind == "w" || e.kind == "x")
                .map(|e| (e.idx(), e.kind == "x"))
        });
        let writer = shadow_writer;
        let last_writer = writer.map(|(idx, external)| {
            let insn = (!external && idx < state.inner.trace.len()).then(|| {
                let r = state.inner.trace.record(idx);
                (r.pc, crate::disasm::decode(r.pc, r.inst))
            });
            Writer {
                idx,
                source: if external { "external" } else { "trace" },
                pc: insn.as_ref().map(|(pc, _)| format!("{pc:#x}")),
                asm: insn.map(|(_, d)| format!("{} {}", d.mnemonic, d.op_str).trim().to_string()),
            }
        });
        match writer_runs.last_mut() {
            Some(run) if run.writer == last_writer => run.count += 1,
            _ => writer_runs.push(WriterRun {
                offset,
                count: 1,
                writer: last_writer.clone(),
            }),
        }
        bytes.push(ProvenanceByte {
            addr: format!("{a:#x}"),
            byte,
            kind,
            source_idx,
            last_writer,
        });
    }
    Ok(MemProvenanceResponse {
        addr: format!("{addr:#x}"),
        at: q.at,
        count,
        requested_count: q.count,
        truncated: q.count > count,
        observed_count: bytes.iter().filter(|b| b.byte.is_some()).count(),
        bytes,
        writer_runs,
    })
}
