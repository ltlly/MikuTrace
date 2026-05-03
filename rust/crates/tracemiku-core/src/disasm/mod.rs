//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`] (added in Task 4). Cold path: [`decoder::raw_decode`] —
//! uncached, allocates a Capstone handle on first call per thread.

pub mod decoder;

pub use decoder::DecodedInsn;
