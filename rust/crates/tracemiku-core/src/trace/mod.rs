//! Trace-side data structures.
//!
//! - [`meta`] — meta.json parser (M1)
//! - [`record`] — 272-byte on-disk record layout (M2-α)
//! - [`trace`] — mmap'd record stream (M2-α)

pub mod meta;
pub mod record;
#[allow(clippy::module_inception)]
pub mod trace;

pub use meta::{CallInfo, MetaError, ModuleInfo, TraceMeta};
pub use record::{Record, FORMAT_VERSION, REC_NUM_REGS, REC_SIZE};
pub use trace::Trace;
