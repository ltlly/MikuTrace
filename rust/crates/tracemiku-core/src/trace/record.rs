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
