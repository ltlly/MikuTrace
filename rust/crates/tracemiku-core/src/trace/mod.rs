//! Trace-side data structures.
//!
//! - [`meta`] — meta.json parser (M1)
//! - [`record`] — 272-byte on-disk record layout (M2-α)
//! - `trace` — mmap'd record stream (M2-α, added by Task 3)

pub mod meta;
pub mod record;

pub use meta::{CallInfo, MetaError, ModuleInfo, TraceMeta};
pub use record::{Record, REC_NUM_REGS, REC_SIZE};
