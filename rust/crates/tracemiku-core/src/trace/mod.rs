//! Trace-side data structures. M1 has only metadata; M2 adds the
//! actual `Trace` (mmap'd record stream).

pub mod meta;

pub use meta::{CallInfo, MetaError, ModuleInfo, TraceMeta};
