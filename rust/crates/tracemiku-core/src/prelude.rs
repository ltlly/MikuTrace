//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::trace::{CallInfo, MetaError, ModuleInfo, TraceMeta};
