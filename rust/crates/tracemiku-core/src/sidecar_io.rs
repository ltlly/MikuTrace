//! Shared binary sidecar I/O primitives.
//!
//! Three index/sidecar formats (index, analysis-index, memshadow) were
//! reading/writing u64/len/string primitives with three copies of the same
//! code. This module is the single implementation. The on-disk byte layout
//! is a committed contract (see `SIDECAR_VERSION`); primitives here are bare
//! little-endian u64/len-prefixed-string, so unifying the copies does not
//! change any sidecar's bytes.

use std::io::{self, Read, Write};

pub(crate) fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub(crate) fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub(crate) fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn write_len(w: &mut impl Write, v: usize) -> io::Result<()> {
    write_u64(w, v as u64)
}

pub(crate) fn read_len(r: &mut impl Read) -> io::Result<usize> {
    let v = read_u64(r)?;
    usize::try_from(v).map_err(|_| invalid_data("sidecar usize overflow"))
}

pub(crate) fn write_string(w: &mut impl Write, s: &str) -> io::Result<()> {
    write_len(w, s.len())?;
    w.write_all(s.as_bytes())
}

pub(crate) fn read_string(r: &mut impl Read) -> io::Result<String> {
    let len = read_len(r)?;
    if len > (1 << 24) {
        return Err(invalid_data("sidecar string too large"));
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid_data("sidecar string is not utf-8"))
}
