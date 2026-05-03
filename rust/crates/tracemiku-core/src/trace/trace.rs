//! Memory-mapped trace.bin reader.
//!
//! Opens `<call_dir>/trace.bin`, mmaps it, validates that the file size is a
//! multiple of [`REC_SIZE`], and exposes record access by index. Zero-copy:
//! `record(idx)` returns a `Record` value bytemuck-cast from the mmap slice
//! without any allocation.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use memmap2::Mmap;

use crate::trace::record::REC_SIZE;

/// Memory-mapped per-call trace.
#[derive(Debug)]
pub struct Trace {
    call_dir: PathBuf,
    /// Owned mmap; lives as long as `Trace`. Drop closes the underlying fd.
    /// `None` represents an empty (0-byte) trace.bin since memmap2 cannot
    /// mmap a zero-length file.
    mmap: Option<Mmap>,
    /// `mmap.len() / REC_SIZE`. Cached at construction.
    n: usize,
}

impl Trace {
    /// Open `<call_dir>/trace.bin` and mmap it. Validates that the file size
    /// is a multiple of [`REC_SIZE`].
    pub fn load(call_dir: &Path) -> Result<Self> {
        let bin = call_dir.join("trace.bin");
        let f = File::open(&bin).with_context(|| format!("open trace.bin at {}", bin.display()))?;
        let len = f
            .metadata()
            .with_context(|| format!("stat trace.bin at {}", bin.display()))?
            .len() as usize;

        if len == 0 {
            return Ok(Self {
                call_dir: call_dir.to_path_buf(),
                mmap: None,
                n: 0,
            });
        }

        if !len.is_multiple_of(REC_SIZE) {
            return Err(anyhow!(
                "trace.bin size {} is not a multiple of {} (REC_SIZE) — \
                 corrupted trace or truncated write",
                len,
                REC_SIZE,
            ));
        }

        // SAFETY: we own the file, the mmap is read-only, and Mmap will keep
        // the underlying fd alive via its internal handle.
        let mmap = unsafe { Mmap::map(&f) }
            .with_context(|| format!("mmap trace.bin at {}", bin.display()))?;

        Ok(Self {
            call_dir: call_dir.to_path_buf(),
            n: len / REC_SIZE,
            mmap: Some(mmap),
        })
    }

    /// Number of records in the trace.
    pub fn len(&self) -> usize {
        self.n
    }

    /// True iff `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Per-call directory this trace was loaded from.
    pub fn call_dir(&self) -> &Path {
        &self.call_dir
    }

    /// Raw mmap bytes (read-only), or `&[]` for empty trace. Exposed for
    /// tests / Task 4 record accessor; production code prefers `record(i)`.
    #[doc(hidden)]
    pub fn raw(&self) -> &[u8] {
        self.mmap.as_deref().unwrap_or(&[])
    }
}
