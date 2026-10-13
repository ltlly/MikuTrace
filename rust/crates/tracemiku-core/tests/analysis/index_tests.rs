use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tracemiku_core::analysis_index::{AnalysisIndex, DepEdge, DepKind};
use tracemiku_core::index::Index;
use tracemiku_core::symbols::SymbolMap;
use tracemiku_core::trace::Trace;

fn synth_call_dir(records: &[(u64, [u64; 31], u64, u32)]) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    let cd = run
        .join("calls")
        .join(format!("call_001_tid100_{}r_2ms", records.len()));
    fs::create_dir_all(&cd).unwrap();

    let mut trace_file = fs::File::create(cd.join("trace.bin")).unwrap();
    for (pc, regs, sp, inst) in records {
        let mut buf = [0u8; 272];
        buf[0..8].copy_from_slice(&pc.to_le_bytes());
        for (i, value) in regs.iter().enumerate() {
            let start = 8 + i * 8;
            buf[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        buf[256..264].copy_from_slice(&sp.to_le_bytes());
        buf[268..272].copy_from_slice(&inst.to_le_bytes());
        trace_file.write_all(&buf).unwrap();
    }

    fs::write(
        cd.join("meta.json"),
        format!(
            r#"{{"callIdx":1,"tid":100,"records":{},"ms":2}}"#,
            records.len()
        ),
    )
    .unwrap();
    fs::write(
        run.join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[test]
fn analysis_index_builds_dependencies_and_mem_last_defs() {
    let mut regs0 = [0u64; 31];
    regs0[2] = 0x1122_3344_5566_7788;
    let mut regs1 = [0u64; 31];
    regs1[0] = 0x1122_3344_5566_7788;
    let regs2 = [0u64; 31];
    let (_tmp, call_dir) = synth_call_dir(&[
        // mov x0, x2
        (0x100000, regs0, 0x7000, 0xaa0203e0),
        // str x0, [sp]
        (0x100004, regs1, 0x7000, 0xf90003e0),
        // ldr x1, [sp]
        (0x100008, regs2, 0x7000, 0xf94003e1),
    ]);

    let trace = Trace::load(&call_dir).unwrap();
    let index = Index::build(&trace);
    let mut symbols = SymbolMap::new();
    symbols.freeze();
    let analysis = AnalysisIndex::build(&trace, &symbols, &index);

    assert_eq!(analysis.summary.record_count, 3);
    assert_eq!(analysis.summary.mem_write_count, 1);
    assert_eq!(analysis.summary.mem_read_count, 1);
    assert_eq!(analysis.summary.mem_dependency_edges, 1);
    assert!(analysis.deps.row(1).contains(&DepEdge {
        idx: 0,
        kind: DepKind::Reg,
    }));
    assert!(analysis.deps.row(2).contains(&DepEdge {
        idx: 1,
        kind: DepKind::Mem,
    }));
    assert_eq!(analysis.reg_checkpoints.len(), 2);
    assert_eq!(analysis.reg_checkpoints[0].idx, 0);
    assert_eq!(analysis.reg_checkpoints[1].idx, 2);

    let first_byte = analysis
        .mem_last_def
        .iter()
        .find(|entry| entry.addr == 0x7000)
        .unwrap();
    assert_eq!(first_byte.idx, 1);
    assert_eq!(first_byte.value, 0x88);
}

#[test]
fn analysis_index_sidecar_roundtrips_and_rejects_stale_trace() {
    let mut regs0 = [0u64; 31];
    regs0[2] = 0x41;
    let mut regs1 = [0u64; 31];
    regs1[0] = 0x41;
    let (_tmp, call_dir) = synth_call_dir(&[
        (0x100000, regs0, 0x7000, 0xaa0203e0),
        (0x100004, regs1, 0x7000, 0xf90003e0),
    ]);

    let trace = Trace::load(&call_dir).unwrap();
    let index = Index::build(&trace);
    let mut symbols = SymbolMap::new();
    symbols.freeze();
    let analysis = AnalysisIndex::build(&trace, &symbols, &index);
    analysis.save_sidecar(&trace, &symbols).unwrap();

    let loaded = AnalysisIndex::try_load_sidecar(&trace, &symbols).unwrap();
    assert_eq!(loaded.summary, analysis.summary);
    assert_eq!(loaded.deps.row(1), analysis.deps.row(1));
    assert_eq!(loaded.mem_last_def, analysis.mem_last_def);

    let mut renamed_symbols = SymbolMap::new();
    renamed_symbols.add(0x100000, "renamed_entry".to_string());
    renamed_symbols.freeze();
    assert!(AnalysisIndex::try_load_sidecar(&trace, &renamed_symbols).is_none());

    let trace_path = call_dir.join("trace.bin");
    let mut raw = fs::read(&trace_path).unwrap();
    raw[0] ^= 0x10;
    fs::write(trace_path, raw).unwrap();
    let stale_trace = Trace::load(&call_dir).unwrap();
    assert!(AnalysisIndex::try_load_sidecar(&stale_trace, &symbols).is_none());
}
