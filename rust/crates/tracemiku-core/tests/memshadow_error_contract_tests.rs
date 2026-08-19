//! Contract tests for MemShadow readiness error typing.
//!
//! `memshadow_ready_or_block_if_idle` previously returned `Result<&MemShadow,
//! &'static str>`; routes matched raw strings ("building"/"error"). The
//! typed contract: the error is a `MemShadowError` enum whose string form is
//! stable (routes serialize it into the response `status` field unchanged),
//! so AI consumers see identical JSON while the server side gets real
//! exhaustiveness checking.
//!
//! 另含 sidecar 读入长度上限契约：损坏/被篡改的 sidecar 携带超大长度时，
//! 必须在分配前返回结构化错误（`try_load_sidecar` 降级为 `None`），
//! 而不是触发超大 `Vec::with_capacity` 分配。

mod common;

use tracemiku_core::index::Index;
use tracemiku_core::memshadow::MemShadow;
use tracemiku_core::memshadow::MemShadowError;
use tracemiku_core::prelude::Trace;

#[test]
fn memshadow_error_kind_matches_legacy_status_strings() {
    // These strings are the committed wire contract (routes put them in the
    // `status` field of their responses). The typed enum must round-trip to
    // exactly these values.
    for (kind, expected) in [
        (MemShadowError::Building, "loading"),
        (MemShadowError::Failed, "error"),
    ] {
        assert_eq!(kind.status_str(), expected);
    }
}

#[test]
fn memshadow_error_is_exhaustive() {
    // Compile-time check: constructing both variants proves the enum exists
    // with the intended shape; a match without _ is exhaustive by the
    // compiler when this compiles.
    match MemShadowError::Building {
        MemShadowError::Building => (),
        MemShadowError::Failed => (),
    }
}

/// 构造一个头部合法、但 `writes_len` 字段为超大值的 memshadow sidecar。
/// 头布局：magic 8 + version u32 + trace_size u64 + writes_len u64。
fn craft_memshadow_sidecar_with_huge_len(call_dir: &std::path::Path, trace: &Trace) {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"TMMSV5\0\0");
    blob.extend_from_slice(&5u32.to_le_bytes());
    blob.extend_from_slice(&(trace.raw().len() as u64).to_le_bytes());
    // 超大长度：远超该文件物理大小能容纳的元素数。
    blob.extend_from_slice(&0x7FFF_FFFF_FFFFu64.to_le_bytes());
    std::fs::write(call_dir.join("trace.bin.memshadow.v5.bin"), blob).unwrap();
}

#[test]
fn memshadow_sidecar_rejects_over_limit_length() {
    // writes_len = 0x7FFF_FFFF_FFFF：旧实现会直接
    // `Vec::with_capacity(len)`（~8 EiB 量级）触发分配失败 abort；
    // 上限以 sidecar 文件自身大小推导，必须在分配前拒绝。
    let fix = common::synth_trace_dir(9);
    let trace = Trace::load(&fix.call_dir).unwrap();
    craft_memshadow_sidecar_with_huge_len(&fix.call_dir, &trace);
    assert!(
        MemShadow::try_load_sidecar(&trace).is_none(),
        "over-limit writes_len must be rejected, not allocated"
    );
    // 合法 sidecar 不受上限影响：重新冷建并保存后必须能加载。
    let _ = MemShadow::load_or_build(&trace);
    assert!(
        MemShadow::try_load_sidecar(&trace).is_some(),
        "legit sidecar must still load under the size-derived caps"
    );
}

#[test]
fn index_sidecar_rejects_over_limit_length() {
    // index sidecar 头布局：magic 8 + version u32 + trace_size u64 +
    // fingerprint u64 = 28 字节，随后第一个字段是 reg_defs 映射长度。
    // 先让 core 写出一份合法 sidecar，再把第一个长度字段改成超大值。
    let fix = common::synth_trace_dir(9);
    let trace = Trace::load(&fix.call_dir).unwrap();
    let _ = Index::load_or_build(&trace);
    let sidecar = Index::sidecar_path(&trace);
    assert!(sidecar.exists(), "index sidecar should exist");

    let mut blob = std::fs::read(&sidecar).unwrap();
    blob[28..36].copy_from_slice(&0x7FFF_FFFF_FFFFu64.to_le_bytes());
    std::fs::write(&sidecar, blob).unwrap();
    assert!(
        Index::try_load_sidecar(&trace).is_none(),
        "over-limit map length must be rejected, not allocated"
    );

    // 恢复合法内容后应可正常加载（上限不拒绝合法数据）。
    let _ = Index::load_or_build(&trace);
    assert!(Index::try_load_sidecar(&trace).is_some());
}
