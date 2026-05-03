//! 272-byte fixed-layout trace record.
//!
//! On-disk layout matches the Frida agent's emit: `[pc, x0..x28, fp, lr, sp,
//! nzcv, inst]` where every register slot is u64 little-endian and `nzcv` /
//! `inst` are u32. Total 272 bytes (33 × 8 + 2 × 4). Layout is a committed
//! contract — see `docs/PER_CALL_TRACE_DESIGN.md`.

use bytemuck::{Pod, Zeroable};

/// Bytes per record. Stable across all trace.bin files this codebase reads.
pub const REC_SIZE: usize = 272;

/// Number of u64 register slots stored per record (x0..x28 + fp + lr).
pub const REC_NUM_REGS: usize = 31;

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct Record {
    pub pc: u64,
    pub regs: [u64; REC_NUM_REGS],
    pub sp: u64,
    pub nzcv: u32,
    pub inst: u32,
}

impl Record {
    /// Read register by canonical name. Returns `None` if name is not one of
    /// `x0..x28`, `fp`, `lr`, `sp`, `pc`, `nzcv`. Mirrors Python `Record.reg`.
    pub fn reg(&self, name: &str) -> Option<u64> {
        match name {
            "pc" => Some(self.pc),
            "sp" => Some(self.sp),
            "nzcv" => Some(self.nzcv as u64),
            "fp" => Some(self.regs[29]),
            "lr" => Some(self.regs[30]),
            _ => {
                if let Some(rest) = name.strip_prefix('x') {
                    if let Ok(i) = rest.parse::<usize>() {
                        if i <= 28 {
                            return Some(self.regs[i]);
                        }
                    }
                }
                None
            }
        }
    }

    /// Symbolic register lookup tolerant of `xzr`/`wzr`/`w*` aliases. Used by
    /// `addr_of` so MemOp consumers don't have to pre-normalize. Returns
    /// `None` for unknown names, `Some(0)` for the zero registers, and the
    /// 32-bit-masked value for `w0..w30`. Mirrors the lenient lookup the
    /// Python `addr_of` does via `rec.reg(...) if reg in ALL_REGS else 0`.
    pub fn reg_by_name(&self, name: &str) -> Option<u64> {
        if name.is_empty() {
            return None;
        }
        if name == "xzr" || name == "wzr" {
            return Some(0);
        }
        if name == "sp" {
            return Some(self.sp);
        }
        if name == "pc" {
            return Some(self.pc);
        }
        if name == "fp" {
            return Some(self.regs[29]);
        }
        if name == "lr" {
            return Some(self.regs[30]);
        }
        // Handle x0..x30 and w0..w30 (with 32-bit mask for w-prefix).
        let (rest, is_w) = if let Some(r) = name.strip_prefix('x') {
            (r, false)
        } else if let Some(r) = name.strip_prefix('w') {
            (r, true)
        } else {
            return None;
        };
        let idx: usize = rest.parse().ok()?;
        if idx > 30 {
            return None;
        }
        let v = if idx == 31 {
            // x31/w31 is sp on ARM64; not stored in `regs`. Defensive.
            self.sp
        } else {
            self.regs[idx]
        };
        Some(if is_w { v & 0xffff_ffff } else { v })
    }
}

impl Record {
    /// Test/fixture helper: build an all-zero record with the given PC. Used
    /// by mem_op addr_of tests to synthesize tiny fixtures without touching
    /// disk. Public so integration tests under `tests/` can call it.
    pub fn zero(pc: u64) -> Self {
        let mut r = Self::zeroed();
        r.pc = pc;
        r
    }

    /// Test/fixture helper: set GPR slot `idx` (0..30 inclusive). Out-of-range
    /// is silently ignored. Index mapping: 29 → fp, 30 → lr, anything else
    /// → x{idx}.
    pub fn set_gpr(&mut self, idx: usize, val: u64) {
        if idx < REC_NUM_REGS {
            self.regs[idx] = val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn record_size_is_272() {
        assert_eq!(
            size_of::<Record>(),
            REC_SIZE,
            "Record must be exactly 272 bytes — on-disk contract"
        );
    }

    #[test]
    fn record_alignment_is_8() {
        assert_eq!(
            align_of::<Record>(),
            8,
            "Record must be 8-byte aligned for bytemuck::cast_slice from u8 mmap slice"
        );
    }

    #[test]
    fn record_field_offsets() {
        let r = Record::zeroed();
        let base = &r as *const Record as usize;
        assert_eq!(&r.pc as *const _ as usize - base, 0);
        assert_eq!(&r.regs as *const _ as usize - base, 8);
        assert_eq!(&r.sp as *const _ as usize - base, 8 + 31 * 8); // 256
        assert_eq!(&r.nzcv as *const _ as usize - base, 264);
        assert_eq!(&r.inst as *const _ as usize - base, 268);
    }

    #[test]
    fn reg_lookup_by_name() {
        let mut r = Record::zeroed();
        r.pc = 0x100200;
        r.regs[0] = 0xdead; // x0
        r.regs[28] = 0xbeef; // x28
        r.regs[29] = 0xcafe; // fp
        r.regs[30] = 0xbabe; // lr
        r.sp = 0xfffe;
        r.nzcv = 0b1010;

        assert_eq!(r.reg("pc"), Some(0x100200));
        assert_eq!(r.reg("x0"), Some(0xdead));
        assert_eq!(r.reg("x28"), Some(0xbeef));
        assert_eq!(r.reg("fp"), Some(0xcafe));
        assert_eq!(r.reg("lr"), Some(0xbabe));
        assert_eq!(r.reg("sp"), Some(0xfffe));
        assert_eq!(r.reg("nzcv"), Some(0b1010));
        assert_eq!(r.reg("x29"), None, "x29 (fp alias) not supported by name");
        assert_eq!(r.reg("xx"), None);
        assert_eq!(r.reg(""), None);
    }
}
