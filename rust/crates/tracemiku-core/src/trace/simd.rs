//! Optional SIMD sidecar (`simd_trace.bin`) reader.
//!
//! Each record is 520 bytes little-endian: `[trace_idx: u64, v0..v31: [u8; 16] × 32]`.
//! Records are ordered by ascending `trace_idx`. When `simd_sample_stride == 1`,
//! record `i` corresponds directly to `trace_idx == i` when no records are dropped,
//! and binary search handles arbitrary strides or sparse captures.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

/// Bytes per SIMD sidecar record: `8 (trace_idx) + 32 * 16 (q0..q31) = 520`.
pub const SIMD_REC_SIZE: usize = 520;

/// Number of 128-bit vector registers captured per SIMD record (`v0..v31`).
pub const SIMD_NUM_REGS: usize = 32;

/// Memory-mapped `simd_trace.bin` reader.
#[derive(Debug)]
pub struct SimdTrace {
    mmap: Option<Mmap>,
    n: usize,
}

impl SimdTrace {
    /// Open `<call_dir>/simd_trace.bin` if present. Incomplete trailing bytes are
    /// ignored so complete records before them remain valid.
    pub fn load_opt(call_dir: &Path) -> Option<Self> {
        let path = call_dir.join("simd_trace.bin");
        let f = File::open(&path).ok()?;
        let len = f.metadata().ok()?.len() as usize;
        let n = len / SIMD_REC_SIZE;
        if n == 0 {
            return Some(Self { mmap: None, n: 0 });
        }
        // SAFETY: read-only mapping owned by SimdTrace.
        let mmap = unsafe { Mmap::map(&f) }.ok()?;
        Some(Self {
            mmap: Some(mmap),
            n,
        })
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    fn raw(&self) -> &[u8] {
        let bytes = self.mmap.as_deref().unwrap_or(&[]);
        &bytes[..self.n * SIMD_REC_SIZE]
    }

    fn entry_at(&self, pos: usize) -> (u64, &[u8; 512]) {
        let off = pos * SIMD_REC_SIZE;
        let slice = &self.raw()[off..off + SIMD_REC_SIZE];
        let idx = u64::from_le_bytes(slice[0..8].try_into().unwrap());
        let regs: &[u8; 512] = slice[8..520].try_into().unwrap();
        (idx, regs)
    }

    /// Look up the 512-byte vector register block (`v0..v31`, 16 bytes each)
    /// for trace record index `trace_idx`.
    pub fn regs_at_trace_idx(&self, trace_idx: usize) -> Option<&[u8; 512]> {
        if self.n == 0 {
            return None;
        }
        let target = trace_idx as u64;
        // Fast path for stride=1 dense sidecars where position equals trace_idx.
        if trace_idx < self.n {
            let (idx, regs) = self.entry_at(trace_idx);
            if idx == target {
                return Some(regs);
            }
        }
        // Binary search by ascending trace_idx.
        let mut lo = 0usize;
        let mut hi = self.n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (idx, regs) = self.entry_at(mid);
            match idx.cmp(&target) {
                std::cmp::Ordering::Equal => return Some(regs),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Look up the 16-byte raw value of vector register `reg_idx` (`0..32`) at
    /// `trace_idx`.
    pub fn q_bytes(&self, trace_idx: usize, reg_idx: usize) -> Option<[u8; 16]> {
        if reg_idx >= SIMD_NUM_REGS {
            return None;
        }
        let regs = self.regs_at_trace_idx(trace_idx)?;
        let off = reg_idx * 16;
        Some(regs[off..off + 16].try_into().unwrap())
    }

    /// Look up a named SIMD/FP register at `trace_idx`, returning its raw
    /// little-endian bytes (`1`, `2`, `4`, `8`, or `16` bytes depending on
    /// `b`/`h`/`s`/`d`/`q`/`v` prefix or element width).
    pub fn reg_bytes_by_name(&self, trace_idx: usize, name: &str) -> Option<Vec<u8>> {
        let (reg_idx, size) = parse_simd_reg_name(name)?;
        let q = self.q_bytes(trace_idx, reg_idx)?;
        Some(q[..size].to_vec())
    }
}

/// Parse a SIMD/FP register name (`q0..q31`, `v0..v31`, `d0..d31`, `s0..s31`,
/// `h0..h31`, `b0..b31`, including arrangement suffixes like `v0.16b` or `v0.2d`)
/// into `(reg_index 0..31, byte_width 1..=16)`.
pub fn parse_simd_reg_name(name: &str) -> Option<(usize, usize)> {
    let trimmed = name
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let (head, suffix) = match trimmed.split_once('.') {
        Some((h, s)) => (h, Some(s)),
        None => (trimmed.as_str(), None),
    };
    let prefix = head.as_bytes()[0];
    let idx: usize = head[1..].parse().ok()?;
    if idx >= SIMD_NUM_REGS {
        return None;
    }
    let width = match prefix {
        b'q' => 16,
        b'd' => 8,
        b's' => 4,
        b'h' => 2,
        b'b' => 1,
        b'v' => match suffix {
            Some("8b" | "4h" | "2s" | "1d") => 8,
            Some("b") => 1,
            Some("h") => 2,
            Some("s") => 4,
            Some("d") => 8,
            Some("q" | "16b" | "8h" | "4s" | "2d" | "1q") | None => 16,
            Some(other) => {
                // Element index form like `v0.b[0]` or `v0.s[2]` -> size from lane type
                let lane_type = other.split('[').next().unwrap_or("");
                match lane_type {
                    "b" | "16b" | "8b" => 16,
                    "h" | "8h" | "4h" => 16,
                    "s" | "4s" | "2s" => 16,
                    "d" | "2d" | "1d" => 16,
                    _ => 16,
                }
            }
        },
        _ => return None,
    };
    Some((idx, width))
}
