//! Deliberately bounded architectural checking, independent of decompilers.
//! Unsupported encodings fail closed instead of preserving registers as a NOP.
use super::memory::MemoryInputs;
use super::{Fault, ReplayReason};
use crate::trace::Record;

fn reg(rec: &Record, n: u32, sp: bool) -> u64 {
    if n == 31 {
        if sp {
            rec.sp
        } else {
            0
        }
    } else {
        rec.regs[n as usize]
    }
}
fn put(rec: &mut Record, n: u32, value: u64, wide: bool, sp: bool) {
    let value = if wide { value } else { value & u32::MAX as u64 };
    if n < 31 {
        rec.regs[n as usize] = value;
    } else if sp {
        rec.sp = value;
    }
}
fn flags(a: u64, b: u64, result: u64, wide: bool, subtract: bool) -> u32 {
    let bits = if wide { 64 } else { 32 };
    let sign = 1u64 << (bits - 1);
    let carry = if subtract {
        a >= b
    } else {
        (a as u128 + b as u128) >> bits != 0
    };
    let overflow = if subtract {
        (a ^ b) & (a ^ result)
    } else {
        !(a ^ b) & (a ^ result)
    } & sign
        != 0;
    (u32::from(result & sign != 0) << 31)
        | (u32::from(result == 0) << 30)
        | (u32::from(carry) << 29)
        | (u32::from(overflow) << 28)
}
fn shifted(value: u64, kind: u32, amount: u32, wide: bool) -> u64 {
    let value = if wide { value } else { value & u32::MAX as u64 };
    match kind {
        0 => value << amount,
        1 => value >> amount,
        2 => {
            if wide {
                ((value as i64) >> amount) as u64
            } else {
                ((value as u32 as i32) >> amount) as u32 as u64
            }
        }
        3 => {
            if wide {
                value.rotate_right(amount)
            } else {
                (value as u32).rotate_right(amount) as u64
            }
        }
        _ => unreachable!(),
    }
}
fn load(
    mem: &MemoryInputs<'_>,
    idx: usize,
    addr: u64,
    size: usize,
    reads: &mut usize,
) -> Result<u64, Fault> {
    let mut bytes = [0; 8];
    for (offset, byte) in bytes.iter_mut().enumerate().take(size) {
        let address = addr
            .checked_add(offset as u64)
            .ok_or_else(Fault::unsupported)?;
        *byte = mem.byte(address, idx).ok_or(Fault {
            reason: ReplayReason::UnknownMemory,
            addr: Some(addr),
            size: Some(size),
        })?;
    }
    *reads += size;
    Ok(u64::from_le_bytes(bytes))
}
pub(super) fn run(
    rec: Record,
    mem: &MemoryInputs<'_>,
    idx: usize,
    reads: &mut usize,
) -> Result<Record, Fault> {
    let i = rec.inst;
    let wide = i >> 31 != 0;
    let width_mask = if wide { u64::MAX } else { u32::MAX as u64 };
    let rd = i & 31;
    let rn = (i >> 5) & 31;
    let mut out = rec;
    out.pc = rec.pc.wrapping_add(4);
    // NOP alone: hints such as PAC/AUT must not silently pass as NOPs.
    if i == 0xd503201f {
        return Ok(out);
    }
    if i & 0x7c000000 == 0x14000000
        || crate::trace::evidence::branch_taken(&rec).is_some()
        || matches!(i & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000)
    {
        out.pc = crate::trace::evidence::expected_next_pc(&rec).ok_or_else(Fault::unsupported)?;
        if i & 0xfc000000 == 0x94000000 || i & 0xfffffc1f == 0xd63f0000 {
            out.regs[30] = rec.pc.wrapping_add(4);
        }
        return Ok(out);
    }
    // MOVN/MOVZ/MOVK, including 32-bit zero extension.
    if i & 0x1f800000 == 0x12800000 {
        let shift = ((i >> 21) & 3) * 16;
        if !wide && shift >= 32 {
            return Err(Fault::unsupported());
        }
        let imm = u64::from((i >> 5) & 0xffff) << shift;
        let value = match (i >> 29) & 3 {
            0 => !imm,
            2 => imm,
            3 => (reg(&rec, rd, false) & !(0xffffu64 << shift)) | imm,
            _ => return Err(Fault::unsupported()),
        };
        put(&mut out, rd, value, wide, false);
        return Ok(out);
    }
    // ADD/SUB immediate and shifted register. Extended-register forms are excluded.
    let immediate = i & 0x1f800000 == 0x11000000;
    let shifted_reg = i & 0x1f200000 == 0x0b000000;
    if immediate || shifted_reg {
        let set_flags = i & (1 << 29) != 0;
        let subtract = i & (1 << 30) != 0;
        let a = reg(&rec, rn, immediate) & width_mask;
        let b = if immediate {
            u64::from((i >> 10) & 0xfff) << (if i & (1 << 22) != 0 { 12 } else { 0 })
        } else {
            let kind = (i >> 22) & 3;
            let amount = (i >> 10) & 63;
            if kind == 3 || (!wide && amount >= 32) {
                return Err(Fault::unsupported());
            }
            shifted(reg(&rec, (i >> 16) & 31, false), kind, amount, wide) & width_mask
        };
        let value = if subtract {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        } & width_mask;
        put(&mut out, rd, value, wide, immediate && !set_flags);
        if set_flags {
            out.nzcv = flags(a, b, value, wide, subtract);
        }
        return Ok(out);
    }
    // AND/BIC/ORR/ORN/EOR/EON/ANDS/BICS with immediate shift.
    if i & 0x1f000000 == 0x0a000000 {
        let amount = (i >> 10) & 63;
        if !wide && amount >= 32 {
            return Err(Fault::unsupported());
        }
        let a = reg(&rec, rn, false) & width_mask;
        let mut b = shifted(
            reg(&rec, (i >> 16) & 31, false),
            (i >> 22) & 3,
            amount,
            wide,
        );
        if i & (1 << 21) != 0 {
            b = !b;
        }
        let op = (i >> 29) & 3;
        let value = match op {
            0 | 3 => a & b,
            1 => a | b,
            2 => a ^ b,
            _ => unreachable!(),
        } & width_mask;
        put(&mut out, rd, value, wide, false);
        if op == 3 {
            out.nzcv = (u32::from(value >> (if wide { 63 } else { 31 }) != 0) << 31)
                | (u32::from(value == 0) << 30);
        }
        return Ok(out);
    }
    // ADR/ADRP, with signed 21-bit offset.
    if i & 0x1f000000 == 0x10000000 {
        let imm = (((i >> 5) & 0x7ffff) << 2) | ((i >> 29) & 3);
        let delta = ((imm as i64) << 43) >> 43;
        let value = if wide {
            (rec.pc & !0xfff).wrapping_add_signed(delta << 12)
        } else {
            rec.pc.wrapping_add_signed(delta)
        };
        put(&mut out, rd, value, true, false);
        return Ok(out);
    }
    // Integer STR/LDR unsigned-offset and unscaled/pre/post-index encodings.
    let unsigned_offset = i & 0x3f000000 == 0x39000000;
    let unscaled = i & 0x3f200000 == 0x38000000;
    if unsigned_offset || unscaled {
        let size = 1usize << (i >> 30);
        let opc = (i >> 22) & 3;
        if opc >= 2 {
            return Err(Fault::unsupported());
        } // signed loads/prefetch
        let mode = if unsigned_offset { 0 } else { (i >> 10) & 3 };
        if mode == 2 {
            return Err(Fault::unsupported());
        } // unprivileged form
        if mode != 0 && rn == rd && rn != 31 {
            return Err(Fault::unsupported());
        }
        let delta = if unsigned_offset {
            i64::from((i >> 10) & 0xfff) * size as i64
        } else {
            (i64::from((i >> 12) & 0x1ff) << 55) >> 55
        };
        let base = reg(&rec, rn, true);
        let addr = if mode == 1 {
            base
        } else {
            base.wrapping_add_signed(delta)
        };
        if opc == 1 {
            put(
                &mut out,
                rd,
                load(mem, idx, addr, size, reads)?,
                size == 8,
                false,
            );
        }
        if mode == 1 || mode == 3 {
            put(&mut out, rn, base.wrapping_add_signed(delta), true, true);
        }
        return Ok(out);
    }
    Err(Fault::unsupported())
}
