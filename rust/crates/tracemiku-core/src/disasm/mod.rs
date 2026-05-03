//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`] (added in Task 4). Cold path: [`raw_decode`] — uncached.

pub mod classify;
pub mod decoder;

pub use decoder::raw_decode;
pub use decoder::DecodedInsn;
