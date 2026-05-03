//! Shared test fixtures.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

pub struct SynthFixture {
    pub _tmp: TempDir, // RAII guard, kept alive
    pub call_dir: PathBuf,
}

/// Build a synthetic per-call trace dir with the trace_root_two_callees shape:
/// 9 records, 1 module (libt.so @ 0x100000, size 0x10000), 3 known fns.
/// trace.bin is empty for now (Task 7 only parses meta.json).
pub fn synth_meta_only_dir() -> SynthFixture {
    let tmp = tempfile::tempdir().expect("mkdtemp");
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_9r_2ms");
    fs::create_dir(&cd).unwrap();

    // Empty trace.bin — meta parser doesn't read it.
    fs::write(cd.join("trace.bin"), []).unwrap();

    let per_call = serde_json::json!({
        "callIdx": 1, "tid": 100, "records": 9, "ms": 2,
        "retval": "0x0", "truncated": false,
        "last_insn_is_ret": true,
        "known_offsets": {"0x0": "f_root", "0x100": "f_alpha", "0x200": "f_beta"}
    });
    fs::write(
        cd.join("meta.json"),
        serde_json::to_string_pretty(&per_call).unwrap(),
    )
    .unwrap();

    let run_meta = serde_json::json!({
        "pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
        "module": {"name": "libt.so", "base": "0x100000", "size": 0x10000},
        "fn_addr": "0x100000"
    });
    fs::write(
        run.join("meta.json"),
        serde_json::to_string_pretty(&run_meta).unwrap(),
    )
    .unwrap();

    SynthFixture {
        _tmp: tmp,
        call_dir: cd,
    }
}
