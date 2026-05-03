//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`]. Cold path: [`raw_decode`] — uncached.

pub mod cache;
pub mod classify;
pub mod decoder;

pub use cache::decode;
pub use decoder::{raw_decode, DecodedInsn};
