//! A1 trace-anchored ARM64 architectural checking. Each instruction starts from its captured
//! pre-state. Memory inputs must be independent of the load's captured output.
use crate::disasm::decode;
use crate::memshadow::MemShadow;
use crate::trace::{Record, Trace};
use schemars::JsonSchema;
use serde::Serialize;

mod semantics;

pub const MAX_REPLAY_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayReason {
    RegisterMismatch,
    PcMismatch,
    TraceGap,
    MissingPostState,
    UnknownMemory,
    UnsupportedInstruction,
    SimdStateUnavailable,
    SyscallBoundary,
    ExcludedCall,
    LimitReached,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CaptureRequest {
    pub action: String,
    pub addr: Option<u64>,
    pub size: Option<usize>,
    pub before_idx: usize,
    pub explanation: String,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReplayStop {
    pub reason: ReplayReason,
    pub idx: usize,
    pub pc: u64,
    pub instruction: String,
    pub register: Option<String>,
    pub expected: Option<u64>,
    pub observed: Option<u64>,
    pub next_capture: CaptureRequest,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReplayReport {
    /// matched: requested transitions matched; stopped: unavailable evidence;
    /// diverged: a supported architectural result disagreed with the captured post-state.
    pub status: String,
    pub mode: String,
    pub start: usize,
    pub requested_count: usize,
    pub effective_count: usize,
    pub checked: usize,
    pub register_comparisons: usize,
    pub independent_memory_bytes: usize,
    pub truncated: bool,
    pub stop: Option<ReplayStop>,
    pub dropped_records: u64,
    pub capture_truncated: bool,
    pub metadata_present: bool,
    pub metadata_valid: bool,
    pub limitations: Vec<String>,
}
struct Fault {
    reason: ReplayReason,
    addr: Option<u64>,
    size: Option<usize>,
}
impl Fault {
    fn unsupported() -> Self {
        Self::new(ReplayReason::UnsupportedInstruction)
    }
    fn new(reason: ReplayReason) -> Self {
        Self {
            reason,
            addr: None,
            size: None,
        }
    }
}
fn stop(
    rec: Record,
    idx: usize,
    fault: Fault,
    register: Option<String>,
    expected: Option<u64>,
    observed: Option<u64>,
) -> ReplayStop {
    let decoded = decode(rec.pc, rec.inst);
    let (action, explanation) = match fault.reason {
        ReplayReason::UnknownMemory => (
            "capture_memory_before_instruction",
            "采集读取地址在指令执行前的字节；load 输出不能充当独立输入证据。",
        ),
        ReplayReason::SimdStateUnavailable => (
            "capture_simd_state",
            "需要 SIMD/FP 执行前后状态；272 字节记录不包含这些状态。",
        ),
        ReplayReason::SyscallBoundary => (
            "capture_syscall_boundary",
            "采集系统调用输入、返回值和被写内存的边界差分。",
        ),
        ReplayReason::ExcludedCall | ReplayReason::TraceGap => (
            "expand_trace_scope",
            "扩大采集范围或排查丢记录；无法证明当前指令的直接后状态。",
        ),
        ReplayReason::RegisterMismatch
        | ReplayReason::PcMismatch
        | ReplayReason::UnsupportedInstruction => (
            "inspect_instruction_semantics",
            "检查原始编码、指令语义和真实后状态，停止传播未经验证的结果。",
        ),
        ReplayReason::MissingPostState | ReplayReason::LimitReached => (
            "extend_trace_window",
            "扩大记录窗口或调整有界查询范围，取得下一条执行前状态。",
        ),
    };
    ReplayStop {
        reason: fault.reason,
        idx,
        pc: rec.pc,
        instruction: format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .into(),
        register,
        expected,
        observed,
        next_capture: CaptureRequest {
            action: action.into(),
            addr: fault.addr,
            size: fault.size,
            before_idx: idx,
            explanation: explanation.into(),
        },
    }
}
/// Counts only successfully checked transitions. Range errors never silently
/// select a different window; missing semantics/evidence stop before validation.
pub fn replay_trace(
    trace: &Trace,
    mem: &MemShadow,
    start: usize,
    count: usize,
) -> Result<ReplayReport, String> {
    if count == 0 {
        return Err("count must be positive".into());
    }
    if start >= trace.len() {
        return Err("start is outside trace".into());
    }
    let effective_count = count.min(MAX_REPLAY_RECORDS).min(trace.len() - start);
    let mut report = ReplayReport {
        status: "matched".into(),
        mode: "per_instruction_anchored_arm64".into(),
        start,
        requested_count: count,
        effective_count,
        checked: 0,
        register_comparisons: 0,
        independent_memory_bytes: 0,
        truncated: count > effective_count,
        stop: None,
        dropped_records: trace.quality().dropped,
        capture_truncated: trace.quality().truncated,
        metadata_present: trace.quality().metadata_present,
        metadata_valid: trace.quality().metadata_valid,
        limitations: vec![
            "每条指令重新锚定真实 pre-state；匹配不证明完整函数、未观测路径或高级 IL 正确。".into(),
            "存储只推演有效地址、写回和寄存器后状态；未独立验证实际设备内存写入。".into(),
            "内存 oracle 只采用之前的 store/外部写和初始快照；不包含未采集的其他线程写入。".into(),
        ],
    };
    for idx in start..start + effective_count {
        let rec = trace.record(idx);
        let decoded = decode(rec.pc, rec.inst);
        let early = if decoded.mnemonic == "svc" {
            Some(ReplayReason::SyscallBoundary)
        } else if decoded
            .op_str
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|r| {
                r.len() > 1
                    && matches!(r.as_bytes()[0], b'v' | b'q' | b'd' | b's' | b'h' | b'b')
                    && r.as_bytes()[1].is_ascii_digit()
            })
        {
            Some(ReplayReason::SimdStateUnavailable)
        } else if trace.quality().dropped != 0 || !trace.quality().metadata_valid {
            Some(ReplayReason::TraceGap)
        } else if idx + 1 >= trace.len() {
            Some(ReplayReason::MissingPostState)
        } else if decoded.is_call && trace.pc(idx + 1) == rec.pc.wrapping_add(4) {
            Some(ReplayReason::ExcludedCall)
        } else if crate::trace::evidence::expected_next_pc(&rec).is_none() {
            Some(ReplayReason::UnsupportedInstruction)
        } else if trace.post_record(idx).is_none() {
            Some(ReplayReason::TraceGap)
        } else {
            None
        };
        if let Some(reason) = early {
            report.stop = Some(stop(
                rec,
                idx,
                Fault::new(reason),
                None,
                crate::trace::evidence::expected_next_pc(&rec),
                (idx + 1 < trace.len()).then(|| trace.pc(idx + 1)),
            ));
            break;
        }
        let mut reads = 0;
        let predicted = match semantics::run(rec, mem, idx, &mut reads) {
            Ok(predicted) => predicted,
            Err(fault) => {
                report.stop = Some(stop(rec, idx, fault, None, None, None));
                break;
            }
        };
        let post = trace.record(idx + 1);
        if predicted.pc != post.pc {
            report.stop = Some(stop(
                rec,
                idx,
                Fault::new(ReplayReason::PcMismatch),
                Some("pc".into()),
                Some(predicted.pc),
                Some(post.pc),
            ));
            break;
        }
        let mismatch = (0..31)
            .map(|i| (format!("x{i}"), predicted.regs[i], post.regs[i]))
            .chain([
                ("sp".into(), predicted.sp, post.sp),
                (
                    "nzcv".into(),
                    u64::from(predicted.nzcv),
                    u64::from(post.nzcv),
                ),
            ])
            .find(|(_, a, b)| a != b);
        if let Some((reg, expected, observed)) = mismatch {
            report.stop = Some(stop(
                rec,
                idx,
                Fault::new(ReplayReason::RegisterMismatch),
                Some(reg),
                Some(expected),
                Some(observed),
            ));
            break;
        }
        report.checked += 1;
        report.register_comparisons += 33;
        report.independent_memory_bytes += reads;
    }
    if report.stop.is_none() && count > effective_count {
        let idx = start + effective_count;
        if idx < trace.len() {
            report.stop = Some(stop(
                trace.record(idx),
                idx,
                Fault::new(ReplayReason::LimitReached),
                None,
                None,
                None,
            ));
        }
    }
    if let Some(s) = &report.stop {
        report.status = if matches!(
            s.reason,
            ReplayReason::RegisterMismatch | ReplayReason::PcMismatch
        ) {
            "diverged"
        } else {
            "stopped"
        }
        .into();
    }
    Ok(report)
}
