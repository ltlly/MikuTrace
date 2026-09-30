//! Boundaries between captured pre-states. A following record is not always
//! the post-state: excluded calls, buffer loss and exceptions can intervene.

use super::Record;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CaptureQuality {
    #[serde(default)]
    pub dropped: u64,
    #[serde(default)]
    pub truncated: bool,
    #[serde(skip)]
    pub metadata_valid: bool,
    #[serde(skip)]
    pub metadata_present: bool,
}

/// Evaluate a recorded conditional branch from its pre-state, without
/// confusing an observed successor with a branch outcome.
pub fn branch_taken(rec: &Record) -> Option<bool> {
    let inst = rec.inst;
    if inst & 0xff00_0010 == 0x5400_0000 {
        let n = rec.nzcv & (1 << 31) != 0;
        let z = rec.nzcv & (1 << 30) != 0;
        let c = rec.nzcv & (1 << 29) != 0;
        let v = rec.nzcv & (1 << 28) != 0;
        let cond = inst & 15;
        let base = match cond >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => c && !z,
            5 => n == v,
            6 => !z && n == v,
            _ => true,
        };
        return Some(if cond < 14 && cond & 1 != 0 {
            !base
        } else {
            base
        });
    }
    if inst & 0x7e00_0000 == 0x3400_0000 {
        let mut value = rec.reg_by_name(&register_name(inst & 31))?;
        if inst >> 31 == 0 {
            value &= u32::MAX as u64;
        }
        return Some((value != 0) == (inst & (1 << 24) != 0));
    }
    if inst & 0x7e00_0000 == 0x3600_0000 {
        let value = rec.reg_by_name(&register_name(inst & 31))?;
        let bit = ((inst >> 26) & 32) | ((inst >> 19) & 31);
        return Some(((value >> bit) & 1 != 0) == (inst & (1 << 24) != 0));
    }
    None
}

fn offset(inst: u32, shift: u32, bits: u32) -> i64 {
    let value = ((inst >> shift) & ((1 << bits) - 1)) as i64;
    ((value << (64 - bits)) >> (64 - bits)) << 2
}

/// Expected immediate successor, derived from the instruction and captured
/// register/flag state. Authenticated branches and exceptions are unknown.
pub fn expected_next_pc(rec: &Record) -> Option<u64> {
    let inst = rec.inst;
    let sequential = rec.pc.wrapping_add(4);
    if inst & 0x7c00_0000 == 0x1400_0000 {
        return Some(rec.pc.wrapping_add_signed(offset(inst, 0, 26)));
    }
    if inst & 0xfe00_0000 == 0xd600_0000 {
        if matches!(inst & 0xffff_fc1f, 0xd61f_0000 | 0xd63f_0000 | 0xd65f_0000) {
            return rec.reg_by_name(&register_name((inst >> 5) & 31));
        }
        return None;
    }
    if inst & 0xff00_0000 == 0xd400_0000 {
        return None;
    }
    if let Some(taken) = branch_taken(rec) {
        let bits = if inst & 0x7e00_0000 == 0x3600_0000 {
            14
        } else {
            19
        };
        return Some(if taken {
            rec.pc.wrapping_add_signed(offset(inst, 5, bits))
        } else {
            sequential
        });
    }
    Some(sequential)
}

fn register_name(n: u32) -> String {
    if n == 31 {
        "xzr".into()
    } else {
        format!("x{n}")
    }
}
