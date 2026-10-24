use super::*;

pub(super) fn source_byte_offset_for_write_at(
    write: &serde_json::Value,
    byte_addr: u64,
) -> Option<u64> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    (offset < 16).then_some(offset)
}

pub(super) fn source_byte_for_write_at(write: &serde_json::Value, byte_addr: u64) -> Option<u8> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    let shift = offset.checked_mul(8)?;
    if shift >= 64 {
        return None;
    }
    let value = write
        .get("src_value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    Some(((value >> shift) & 0xff) as u8)
}
