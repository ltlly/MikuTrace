//! Independent memory evidence is valid only within proven capture continuity.
use super::{semantics, ReplayReason};
use crate::{memshadow::MemShadow, trace::Trace};

pub(super) const MAX_INPUT_LOOKBACK: usize = 10_000;

pub(super) struct MemoryInputs<'a> {
    mem: &'a MemShadow,
    /// First record after a boundary, unsupported instruction or lookback cap.
    /// Zero alone permits using the entry snapshot.
    floor: usize,
}

impl<'a> MemoryInputs<'a> {
    pub(super) fn new(trace: &Trace, mem: &'a MemShadow, start: usize) -> Self {
        let lower = start.saturating_sub(MAX_INPUT_LOOKBACK);
        // The support probe must not scan byte history or consume any evidence.
        let probe = Self {
            mem,
            floor: usize::MAX,
        };
        let mut floor = lower;
        for idx in (lower..start).rev() {
            if trace.post_record(idx).is_none() {
                floor = idx + 1;
                break;
            }
            // Reuse the architectural interpreter's support checks. Only its
            // error category matters here; no replay results are validated or
            // counted. A supported load with unavailable bytes does not itself
            // destroy memory evidence. All unmodelled effects fail closed.
            let mut reads = 0;
            if let Err(fault) = semantics::run(trace.record(idx), &probe, idx, &mut reads) {
                if fault.reason != ReplayReason::UnknownMemory {
                    floor = idx + 1;
                    break;
                }
            }
        }
        Self { mem, floor }
    }

    pub(super) fn byte(&self, addr: u64, before_idx: usize) -> Option<u8> {
        if self.floor > before_idx {
            return None;
        }
        self.mem.input_byte(addr, before_idx, self.floor).0
    }
}
