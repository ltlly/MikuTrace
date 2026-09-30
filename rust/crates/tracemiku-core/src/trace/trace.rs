//! Memory-mapped trace.bin reader.
//!
//! Opens `<call_dir>/trace.bin`, mmaps it, and exposes complete records by
//! index. If an abnormal teardown leaves a partial trailing record, the reader
//! ignores only that incomplete tail so the rest of the trace stays usable.
//! Zero-copy: `record(idx)` returns a `Record` value bytemuck-cast from the
//! mmap slice without any allocation.

use super::evidence::{expected_next_pc, CaptureQuality};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
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
    /// Number of complete records. Cached at construction.
    n: usize,
    quality: CaptureQuality,
    digest: OnceLock<[u8; 32]>,
}

impl Trace {
    /// Open `<call_dir>/trace.bin` and mmap it. Incomplete trailing bytes are
    /// ignored; complete records before them remain valid.
    pub fn load(call_dir: &Path) -> Result<Self> {
        let bin = call_dir.join("trace.bin");
        let f = File::open(&bin).with_context(|| format!("open trace.bin at {}", bin.display()))?;
        let len = f
            .metadata()
            .with_context(|| format!("stat trace.bin at {}", bin.display()))?
            .len() as usize;
        let meta = call_dir.join("meta.json");
        let metadata_present = meta.exists();
        let parsed = File::open(&meta).ok().and_then(|file| {
            // Bound metadata parsing even for untrusted/offline captures.
            use std::io::Read;
            serde_json::from_reader::<_, CaptureQuality>(file.take(8 * 1024 * 1024)).ok()
        });
        let mut quality = parsed.clone().unwrap_or_default();
        quality.metadata_present = metadata_present;
        quality.metadata_valid = !metadata_present || parsed.is_some();
        quality.truncated |= !len.is_multiple_of(REC_SIZE);

        if len == 0 {
            return Ok(Self {
                call_dir: call_dir.to_path_buf(),
                mmap: None,
                n: 0,
                quality,
                digest: OnceLock::new(),
            });
        }

        let n = len / REC_SIZE;

        // SAFETY: we own the file, the mmap is read-only, and Mmap will keep
        // the underlying fd alive via its internal handle.
        let mmap = unsafe { Mmap::map(&f) }
            .with_context(|| format!("mmap trace.bin at {}", bin.display()))?;

        Ok(Self {
            call_dir: call_dir.to_path_buf(),
            n,
            mmap: Some(mmap),
            quality,
            digest: OnceLock::new(),
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

    pub fn quality(&self) -> &CaptureQuality {
        &self.quality
    }

    /// Full-content identity, computed once per mapped trace.
    pub fn digest(&self) -> [u8; 32] {
        *self
            .digest
            .get_or_init(|| Sha256::digest(self.raw()).into())
    }

    /// Only expose the next captured state as a post-state when immediate
    /// execution continuity is supported. Unlocated dropped records make
    /// every transition uncertain; matching PCs alone cannot repair that.
    pub fn post_record(&self, idx: usize) -> Option<super::Record> {
        if idx >= self.n
            || idx + 1 >= self.n
            || self.quality.dropped != 0
            || !self.quality.metadata_valid
        {
            return None;
        }
        let next = self.record(idx + 1);
        (expected_next_pc(&self.record(idx)) == Some(next.pc)).then_some(next)
    }

    /// Raw mmap bytes (read-only), or `&[]` for empty trace. Exposed for
    /// tests / Task 4 record accessor; production code prefers `record(i)`.
    #[doc(hidden)]
    pub fn raw(&self) -> &[u8] {
        let bytes = self.mmap.as_deref().unwrap_or(&[]);
        &bytes[..self.n * REC_SIZE]
    }

    /// Read record at index `i`. Panics if `i >= len()`.
    ///
    /// Zero-copy: bytemuck-casts the relevant 272-byte slice directly. The
    /// returned `Record` is a stack-allocated value; mutating it does not
    /// affect the mmap.
    pub fn record(&self, i: usize) -> crate::trace::record::Record {
        let off = i.checked_mul(REC_SIZE).expect("record index overflow");
        let end = off
            .checked_add(REC_SIZE)
            .expect("record offset+size overflow");
        let slice = &self.raw()[off..end];
        // bytemuck::from_bytes verifies size + alignment at runtime.
        *bytemuck::from_bytes::<crate::trace::record::Record>(slice)
    }

    /// Fast PC-only path. Avoids constructing a full `Record`. Useful for
    /// scans where only PC matters (e.g. `idxs-for-pc`).
    pub fn pc(&self, i: usize) -> u64 {
        let off = i * REC_SIZE;
        u64::from_le_bytes(self.raw()[off..off + 8].try_into().unwrap())
    }

    /// Fast inst-only path. Returns the raw 4-byte ARM64 little-endian
    /// instruction word. Capstone will decode this in M2-β.
    pub fn inst(&self, i: usize) -> u32 {
        let off = i * REC_SIZE + 268;
        u32::from_le_bytes(self.raw()[off..off + 4].try_into().unwrap())
    }

    /// Sequential iterator over records. No allocation.
    pub fn iter(&self) -> RecordIter<'_> {
        RecordIter {
            trace: self,
            idx: 0,
        }
    }
}

pub struct RecordIter<'t> {
    trace: &'t Trace,
    idx: usize,
}

impl<'t> Iterator for RecordIter<'t> {
    type Item = crate::trace::record::Record;
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.trace.len() {
            return None;
        }
        let r = self.trace.record(self.idx);
        self.idx += 1;
        Some(r)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.trace.len() - self.idx;
        (rem, Some(rem))
    }
}

impl<'t> ExactSizeIterator for RecordIter<'t> {}
