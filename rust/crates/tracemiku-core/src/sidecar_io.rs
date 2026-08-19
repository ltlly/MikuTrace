//! Shared binary sidecar I/O primitives.
//!
//! Three index/sidecar formats (index, analysis-index, memshadow) were
//! reading/writing u64/len/string primitives with three copies of the same
//! code. This module is the single implementation. The on-disk byte layout
//! is a committed contract (see `SIDECAR_VERSION`); primitives here are bare
//! little-endian u64/len-prefixed-string, so unifying the copies does not
//! change any sidecar's bytes.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;

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

pub(crate) fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub(crate) fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

pub(crate) fn write_len(w: &mut impl Write, v: usize) -> io::Result<()> {
    write_u64(w, v as u64)
}

/// 读取一个不做分配的值字段（记录下标、计数等）。仅用于不驱动 `Vec`
/// 分配的字段；所有决定分配大小的长度字段必须用 [`read_len_capped`]。
pub(crate) fn read_len(r: &mut impl Read) -> io::Result<usize> {
    let v = read_u64(r)?;
    usize::try_from(v).map_err(|_| invalid_data("sidecar usize overflow"))
}

/// 读取一个长度字段并强制 `len <= cap`。损坏或被篡改的 sidecar 可能携带
/// 任意超大长度；未设上限时 `Vec::with_capacity(len)` 会在读到 EOF 之前就
/// 触发超大分配（甚至分配失败 abort）。超限统一返回 InvalidData。
pub(crate) fn read_len_capped(r: &mut impl Read, cap: usize) -> io::Result<usize> {
    let v = read_u64(r)?;
    let v = usize::try_from(v).map_err(|_| invalid_data("sidecar usize overflow"))?;
    if v > cap {
        return Err(invalid_data("sidecar length exceeds size limit"));
    }
    Ok(v)
}

/// 以 sidecar 文件自身的字节数推导元素数上限。
///
/// 磁盘上每个序列化元素至少占 `min_elem_bytes` 字节（由写入端原语决定，
/// 如 `write_u64` 固定 8 字节），因此合法数据的元素数必然满足
/// `len * min_elem_bytes <= file_len`；文件头（magic/版本/指纹等）只让该
/// 上限略微偏松，不会拒绝任何合法 sidecar。
pub(crate) fn elem_cap(file_len: usize, min_elem_bytes: usize) -> usize {
    file_len / min_elem_bytes.max(1)
}

/// read_string 的字节上限（16 MiB），与既有契约保持一致。
const MAX_STRING_BYTES: usize = 1 << 24;

pub(crate) fn write_string(w: &mut impl Write, s: &str) -> io::Result<()> {
    write_len(w, s.len())?;
    w.write_all(s.as_bytes())
}

pub(crate) fn read_string(r: &mut impl Read) -> io::Result<String> {
    let len = read_len_capped(r, MAX_STRING_BYTES)?;
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid_data("sidecar string is not utf-8"))
}

/// 将 `body` 的输出原子写入 `path`：先写 `<name>.tmp.<pid>` 临时文件，
/// flush+fsync 成功后 rename 覆盖目标；任一步失败则清理临时文件并返回
/// 错误。`fallback_tmp_name` 用于 `path` 文件名非 UTF-8 时的临时文件命名。
pub(crate) fn write_atomic<F>(path: &Path, fallback_tmp_name: &str, body: F) -> io::Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> io::Result<()>,
{
    let tmp_name = format!(
        "{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(fallback_tmp_name),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    let write_result = (|| {
        let raw = std::fs::File::create(&tmp_path)?;
        let mut f = BufWriter::with_capacity(1024 * 1024, raw);
        body(&mut f)?;
        f.flush()?;
        f.get_ref().sync_all()?;
        std::fs::rename(&tmp_path, path)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}
