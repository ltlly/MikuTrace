//! 采集默认边界、恢复入口与失败 JSON 契约；不要求测试机器连接设备。
mod common;

use std::path::PathBuf;
use std::process::Command;

use common::assert_valid;
use serde_json::{json, Value};

fn capture_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "status", "out", "calls", "pending", "error"],
        "properties": {
            "schema_version": {"const": 1}, "status": {"enum": ["ok", "incomplete", "pending", "error"]},
            "out": {"type": "string"},
            "calls": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["call_idx", "tid", "records", "bytes", "truncated", "is_complete", "artifacts", "path"],
                "properties": {
                    "call_idx": {"type": "integer", "minimum": 1},
                    "tid": {"type": "integer", "minimum": 1},
                    "records": {"type": "integer", "minimum": 0},
                    "bytes": {"type": "integer", "minimum": 0},
                    "truncated": {"type": "boolean"}, "is_complete": {"type": "boolean"}, "path": {"type": "string"},
                    "artifacts": {"type": "array", "items": {
                        "type": "object", "additionalProperties": false,
                        "required": ["name", "bytes", "sha256", "gzip_bytes", "transferred_chunks", "reused_chunks"],
                        "properties": {
                            "name": {"type": "string"}, "bytes": {"type": "integer", "minimum": 0},
                            "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                            "gzip_bytes": {"type": "integer", "minimum": 0},
                            "transferred_chunks": {"type": "integer", "minimum": 0},
                            "reused_chunks": {"type": "integer", "minimum": 0}
                        }
                    }}
                }
            }},
            "pending": {"type": "array", "items": {
                "type": "object", "required": ["state"], "properties": {
                    "state": {"type": "string"}, "manifest": {"type": "string"},
                    "session_id": {"type": "string"}, "error": {"type": "string"}
                }
            }},
            "error": {"type": ["object", "null"], "required": ["code", "message"],
                "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}
        }
    })
}

fn entry(args: &[&str]) -> std::process::Output {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    Command::new("python3")
        .arg(root.join("tracemiku"))
        .args(args)
        .env("TRACEMIKU_CLI_BIN", env!("CARGO_BIN_EXE_tracemiku-cli"))
        .current_dir(root)
        .output()
        .unwrap()
}

#[test]
fn trace_defaults_to_one_complete_call_without_record_or_time_caps() {
    let out = entry(&["capabilities", "--command", "trace"]);
    assert!(out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    let args = result["commands"][0]["args"].as_array().unwrap();
    let calls = args.iter().find(|a| a["id"] == "max_calls").unwrap();
    assert_eq!(calls["default_values"], json!(["1"]));
    for removed in [
        "max_records",
        "duration",
        "ext_write_cap",
        "snapshot_max_mb",
    ] {
        assert!(!args.iter().any(|a| a["id"] == removed), "{removed}");
    }
    assert!(args.iter().any(|a| a["id"] == "device_dir"));
}

#[test]
fn recover_is_discoverable_and_missing_descriptor_is_structured_failure() {
    let out = entry(&["capabilities", "--command", "recover"]);
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["commands"][0]["implementation"], "host");
    let dir = tempfile::tempdir().unwrap();
    let out = entry(&["recover", dir.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_valid(capture_schema(), &result);
    assert_valid(
        json!({
            "type": "object", "required": ["schema_version", "status", "out", "calls", "pending", "error"],
            "properties": {
                "schema_version": {"const": 1}, "status": {"const": "error"},
                "out": {"type": "string"}, "calls": {"type": "array"}, "pending": {"type": "array"},
                "error": {"type": "object", "required": ["code", "message"], "properties": {
                    "code": {"type": "string"}, "message": {"type": "string"}
                }}
            }
        }),
        &result,
    );
}

#[test]
fn capture_parameter_error_uses_same_failure_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let out = entry(&["trace", "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_valid(capture_schema(), &result);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["status"], "error");
    assert_eq!(result["error"]["code"], "capture_failed");
}

#[test]
fn recovery_entrypoint_pending_commit_and_repeated_success_have_stable_schema() {
    let (tmp, source) = common::synth_call_dir();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    // 设备读写适配为本机 fixture；统一入口、恢复编排、core finalize 均执行真实代码。
    let script = r#"
import contextlib, gzip, hashlib, io, json, pathlib, runpy, sys
from types import SimpleNamespace
import tracemiku_spool
source, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out.mkdir(); (out / 'calls').mkdir()
device = out.parent / 'device'; device.mkdir()
session_id = 'a' * 32
session = {'schema_version':1, 'session_id':session_id, 'state':'CAPTURING', 'calls':[str(device/'call_1.json')]}
meta = json.loads((source/'meta.json').read_text())
meta.update(bytes=9*272, device_records=9)
manifest = {'schema_version':1, 'session_id':session_id, 'state':'SEALED', 'meta':meta,
            'files':[{'name':'trace.bin', 'device_path':str(device/'trace.bin'), 'bytes':9*272, 'records':9, 'record_size':272}]}
data = bytearray((source/'trace.bin').read_bytes()); data[-4:] = (0xd65f03c0).to_bytes(4,'little')
(device/'trace.bin').write_bytes(data)
(out/'meta.json').write_text('{}')
(out/'recovery.json').write_text(json.dumps({'schema_version':1,'serial':None,'sessions':[{
    'sessionId':session_id,'deviceDir':str(device),'manifestPath':str(device/'session.json'),'pid':100}]}))
acks = []
class Device:
    def __init__(self, *args): pass
    def read_json(self, path): return session if path.endswith('session.json') else manifest
    def export_file(self, artifact, destination, *args):
        data = (device/artifact['name']).read_bytes()
        (destination/artifact['name']).write_bytes(data)
        return {'name':artifact['name'],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                'gzip_bytes':len(gzip.compress(data)),'transferred_chunks':1,'reused_chunks':0}
    def shell(self, command, **kwargs): acks.append(command); return ''
tracemiku_spool.AdbSpool = Device
entry = runpy.run_path('tracemiku')['_capture_result']
def recover():
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout): code = entry(SimpleNamespace(run=str(out)), recover=True)
    return {'code':code, 'result':json.loads(stdout.getvalue())}
pending = recover()
assert acks == [] and list((out/'calls').iterdir()) == []
session['state'] = 'SEALED'
complete = recover()
assert len(acks) == 1 and (device/'trace.bin').exists()
again = recover()
uncertain = out.parent/'uncertain'; uncertain.mkdir(); (uncertain/'calls').mkdir()
(uncertain/'meta.json').write_text('{}')
(uncertain/'recovery.json').write_bytes((out/'recovery.json').read_bytes())
out = uncertain
manifest['meta']['truncated'] = True
incomplete = recover()
print(json.dumps([pending,complete,again,incomplete]))
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(source)
        .arg(tmp.path().join("recovered"))
        .env("TRACEMIKU_CLI_BIN", env!("CARGO_BIN_EXE_tracemiku-cli"))
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Value = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases.as_array().unwrap() {
        assert_valid(capture_schema(), &case["result"]);
    }
    assert_eq!(cases[0]["code"], 2);
    assert_eq!(cases[0]["result"]["status"], "pending");
    for case in &cases.as_array().unwrap()[1..3] {
        assert_eq!(case["code"], 0);
        assert_eq!(case["result"]["status"], "ok");
        assert_eq!(case["result"]["calls"][0]["records"], 9);
        assert_eq!(case["result"]["calls"][0]["is_complete"], true);
        assert!(case["result"]["calls"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("call_001_tid100_9r_2ms"));
        assert_eq!(case["result"]["pending"], json!([]));
    }
    assert_eq!(cases[3]["code"], 2);
    assert_eq!(cases[3]["result"]["status"], "incomplete");
    assert_eq!(cases[3]["result"]["calls"][0]["is_complete"], false);
}

#[test]
fn info_never_marks_an_unverified_transfer_complete() {
    let (_tmp, call) = common::synth_call_dir();
    let path = call.join("meta.json");
    let mut meta: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    meta["transfer_state"] = "PENDING".into();
    std::fs::write(&path, meta.to_string()).unwrap();
    let value = common::run_json(&["info", call.to_str().unwrap()]);
    assert_eq!(value["is_complete"], false);
    meta["transfer_state"] = "VERIFIED".into();
    meta["required_artifacts"] = json!(["trace.bin", "simd_trace.bin"]);
    meta["artifact_checksums"] =
        json!([{"name":"trace.bin", "bytes":9*272}, {"name":"simd_trace.bin", "bytes":9*520}]);
    std::fs::write(&path, meta.to_string()).unwrap();
    assert_eq!(
        common::run_json(&["info", call.to_str().unwrap()])["is_complete"],
        false
    );
}

#[test]
fn persisted_fork_jsonl_uses_bounded_cursor_and_preserves_legacy_meta_support() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("fork_events.jsonl"),
        "{\"trace_idx\":1,\"child_pid\":4}\n{\"trace_idx\":2,\"child_pid\":5}\n",
    )
    .unwrap();
    let args = [
        "events",
        dir.path().to_str().unwrap(),
        "--source",
        "fork",
        "--limit",
        "1",
    ];
    let first = common::run_json(&args);
    assert_eq!(first["events"][0]["event"]["child_pid"], 4);
    assert_eq!(first["truncated"], true);
    let cursor = first["next_cursor"].as_str().unwrap();
    let mut next = args.to_vec();
    next.extend(["--cursor", cursor]);
    let second = common::run_json(&next);
    assert_eq!(second["events"][0]["event"]["child_pid"], 5);
    assert_eq!(second["truncated"], false);
}
