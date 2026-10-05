//! Trace-side data structures.
//!
//! - [`meta`] — meta.json parser (M1)
//! - [`finalize`] — call/run 元数据恢复与目录名统一
//! - [`record`] — 272-byte on-disk record layout (M2-α)
//! - [`trace`] — mmap'd record stream (M2-α)

pub mod evidence;
pub mod finalize;
pub mod meta;
pub mod record;
#[allow(clippy::module_inception)]
pub mod trace;

pub use finalize::{finalize_run, CallRepair, FinalizeError, RunRepair};
pub use meta::{CallInfo, MetaError, ModuleInfo, TraceMeta};
pub use record::{Record, FORMAT_VERSION, REC_NUM_REGS, REC_SIZE};
pub use trace::Trace;
