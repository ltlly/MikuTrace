//! meta 三值语义 + finalize 恢复的唯一验证点。
//!
//! 覆盖 2026-10 真机上确认的阻塞点：拉取失败写出的 `last_insn_is_ret: null`
//! 曾让所有 AppState 消费方报 `invalid type: null, expected a boolean`，
//! 数据在盘上却整条分析链不可用。

use std::fs;
use std::path::{Path, PathBuf};

use tracemiku_core::trace::finalize::{finalize_run, FinalizeError};
use tracemiku_core::trace::meta::{MetaError, TraceMeta};
use tracemiku_core::trace::record::REC_SIZE;

fn tmpdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "tracemiku-finalize-test-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base
}

fn write_call(run: &Path, dir: &str, meta: serde_json::Value, recs: usize) -> PathBuf {
    let d = run.join("calls").join(dir);
    fs::create_dir_all(&d).unwrap();
    if recs > 0 {
        let mut bin = vec![0u8; recs * REC_SIZE];
        for i in 0..recs {
            let off = i * REC_SIZE;
            // pc 放在记录尾部区域, 由 Trace 的解码路径读取; 这里只需非零。
            bin[off + REC_SIZE - 8..off + REC_SIZE]
                .copy_from_slice(&(0x1000u64 + i as u64).to_le_bytes());
        }
        fs::write(d.join("trace.bin"), bin).unwrap();
    }
    fs::write(
        d.join("meta.json"),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    d
}

fn base_meta(idx: u64, tid: i64, ms: i64) -> serde_json::Value {
    serde_json::json!({
        "callIdx": idx, "pid": 1, "tid": tid, "ms": ms,
        "records": 0, "bytes": 0, "truncated": false,
        "last_insn_is_ret": null, "devicePath": null,
        "known_offsets": {"0x1000": "sub_1000"},
    })
}

// ── meta 三值语义 ────────────────────────────────────────────────────────

#[test]
fn null_last_insn_is_ret_is_unknown_not_error() {
    let run = tmpdir("null-ret");
    let d = write_call(
        &run,
        "call_001_tid1_9r_2ms",
        serde_json::json!({"callIdx":1,"tid":1,"records":9,"ms":2,
                          "truncated":false,"last_insn_is_ret":null}),
        9,
    );
    fs::write(
        run.join("meta.json"),
        serde_json::to_vec_pretty(&serde_json::json!({"method":"m","calls":[]})).unwrap(),
    )
    .unwrap();
    let meta = TraceMeta::load(&d).expect("null 布尔不得导致加载失败");
    assert_eq!(meta.last_insn_is_ret, None, "显式 null 必须归一为未知");
    assert_eq!(meta.records, 9);
}

#[test]
fn missing_last_insn_is_ret_is_unknown() {
    let run = tmpdir("missing-ret");
    let d = write_call(
        &run,
        "call_001_tid1_9r_2ms",
        // 旧 fixture: 只有 records, 不带布尔字段
        serde_json::json!({"callIdx":1,"tid":1,"records":9,"ms":2,"truncated":false}),
        9,
    );
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let meta = TraceMeta::load(&d).expect("缺失可选布尔不得报错");
    assert_eq!(meta.last_insn_is_ret, None);
}

#[test]
fn missing_records_gives_recoverable_error() {
    let run = tmpdir("missing-records");
    let d = write_call(
        &run,
        "_pending_call_001",
        serde_json::json!({"callIdx":1,"tid":1,"ms":2,"truncated":true}),
        0,
    );
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    match TraceMeta::load(&d) {
        Err(MetaError::RecordsUnresolved { path }) => {
            assert!(path.ends_with("meta.json"));
        }
        other => panic!("期望 RecordsUnresolved, 实际 {:?}", other.map(|_| "ok")),
    }
}

// ── finalize 回填 ────────────────────────────────────────────────────────

#[test]
fn finalize_backfills_derived_fields_and_preserves_rest() {
    let run = tmpdir("backfill");
    write_call(&run, "_pending_call_001", base_meta(1, 4242, 583), 25);
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"pkg":"p","calls":[]}).to_string(),
    )
    .unwrap();

    let report = finalize_run(&run).unwrap();
    assert_eq!(report.repaired, 1);
    assert_eq!(report.pending, 0);
    let c = &report.calls[0];
    assert_eq!(c.records, 25);
    assert_eq!(c.bytes, (25 * REC_SIZE) as u64);
    assert!(c.renamed);
    assert_eq!(c.to, "call_001_tid4242_25r_583ms");

    let final_dir = run.join("calls").join(&c.to);
    let md: serde_json::Value =
        serde_json::from_slice(&fs::read(final_dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(md["records"], 25);
    assert_eq!(md["bytes"], (25 * REC_SIZE) as u64);
    // 非派生字段必须保留
    assert_eq!(md["known_offsets"]["0x1000"], "sub_1000");
    assert_eq!(md["tid"], 4242);
    assert!(md["last_insn_is_ret"].is_boolean() || md["last_insn_is_ret"].is_null());
}

#[test]
fn finalize_unifies_truncated_dir_name() {
    let run = tmpdir("truncated-name");
    write_call(
        &run,
        "_truncated_call_003_tid7_8r_9ms",
        base_meta(3, 7, 9),
        8,
    );
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let report = finalize_run(&run).unwrap();
    assert_eq!(report.renamed, 1);
    assert_eq!(report.calls[0].to, "call_003_tid7_8r_9ms");
    assert!(run.join("calls/call_003_tid7_8r_9ms/meta.json").exists());
    assert!(!run.join("calls/_truncated_call_003_tid7_8r_9ms").exists());
}

#[test]
fn finalize_keeps_call_without_bin_pending() {
    let run = tmpdir("pending");
    write_call(&run, "_pending_call_002", base_meta(2, 8, 12), 0);
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let report = finalize_run(&run).unwrap();
    assert_eq!(report.pending, 1);
    assert_eq!(report.repaired, 0);
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("meta.json")).unwrap()).unwrap();
    let call = &summary["calls"][0];
    assert_eq!(call["pending"], true);
    assert!(call["records"].is_null(), "pending 不得用 0 冒充已完成");
}

#[test]
fn finalize_is_idempotent() {
    let run = tmpdir("idempotent");
    write_call(&run, "_pending_call_001", base_meta(1, 5, 6), 12);
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let first = finalize_run(&run).unwrap();
    let second = finalize_run(&run).unwrap();
    assert_eq!(first.calls[0].to, second.calls[0].to);
    assert_eq!(second.calls[0].records, 12);
    assert!(!second.calls[0].renamed, "第二次不应再改名");
}

#[test]
fn finalize_flags_device_record_mismatch() {
    let run = tmpdir("mismatch");
    let mut md = base_meta(1, 5, 6);
    md["device_records"] = serde_json::json!(99);
    write_call(&run, "_pending_call_001", md, 12);
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let report = finalize_run(&run).unwrap();
    assert_eq!(report.calls[0].records, 12, "以本地 bin 为准");
    assert!(report.calls[0].warnings.iter().any(|w| w.contains("99")));
}

#[test]
fn finalize_keeps_partial_tail_record() {
    let run = tmpdir("partial");
    let d = run.join("calls").join("_pending_call_001");
    fs::create_dir_all(&d).unwrap();
    // 3.5 条记录: 尾部残缺仍应保留完整记录
    fs::write(d.join("trace.bin"), vec![0u8; 3 * REC_SIZE + 100]).unwrap();
    fs::write(
        d.join("meta.json"),
        serde_json::to_vec_pretty(&base_meta(1, 5, 6)).unwrap(),
    )
    .unwrap();
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();
    let report = finalize_run(&run).unwrap();
    assert_eq!(report.calls[0].records, 3);
    assert!(report.calls[0]
        .warnings
        .iter()
        .any(|w| w.contains("整数倍")));
}

#[test]
fn finalize_missing_run_is_error() {
    assert!(matches!(
        finalize_run(Path::new("/nonexistent/run/xyz")),
        Err(FinalizeError::RunMissing(_))
    ));
}

#[test]
fn finalize_refuses_conflict_instead_of_deleting_source() {
    // P0: 目标目录已存在时必须报冲突, 绝不能按 records 相同删掉源目录。
    // 两个 records 相同的 trace 内容可以完全不同。
    let run = tmpdir("conflict");
    write_call(&run, "_pending_call_001", base_meta(1, 42, 58), 16);
    // 预先放一个同名目标目录, 记录数相同但内容不同
    let clash = write_call(&run, "call_001_tid42_16r_58ms", base_meta(1, 42, 58), 16);
    fs::write(clash.join("marker"), b"other-run-data").unwrap();
    fs::write(
        run.join("meta.json"),
        serde_json::json!({"calls":[]}).to_string(),
    )
    .unwrap();

    let before_src = fs::read(run.join("calls/_pending_call_001/trace.bin")).unwrap();
    let err = finalize_run(&run).expect_err("同名目标必须报冲突");
    assert!(
        matches!(err, FinalizeError::TargetConflict(_)),
        "实际: {err:?}"
    );

    // 源目录与冲突目录都必须完好
    assert!(
        run.join("calls/_pending_call_001/trace.bin").exists(),
        "源目录不得被删除"
    );
    assert_eq!(
        fs::read(run.join("calls/_pending_call_001/trace.bin")).unwrap(),
        before_src
    );
    assert_eq!(fs::read(clash.join("marker")).unwrap(), b"other-run-data");
}
