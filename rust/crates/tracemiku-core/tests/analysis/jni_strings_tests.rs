use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_6r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [
        0x100000u64,
        0x100004,
        0x100008,
        0x100000,
        0x100004,
        0x100008,
    ];
    let insts = [
        0xf9000043u32,
        0xf942a809,
        0xd63f0120,
        0xf9000043,
        0xf942a809,
        0xd63f0120,
    ];
    let strings = [
        u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]),
        u64::from_le_bytes([b'w', b'o', b'r', b'l', b'd', 0, 0, 0]),
    ];
    let addrs = [0x7000u64, 0x7010];
    let mut buf = vec![0u8; 272 * 6];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        let group = i / 3;
        for (reg_i, value) in [0x1111u64, 0x2222, addrs[group], strings[group], 0x4444]
            .into_iter()
            .enumerate()
        {
            let roff = off + 8 + reg_i * 8;
            buf[roff..roff + 8].copy_from_slice(&value.to_le_bytes());
        }
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":6,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[test]
fn jni_strings_recovers_observed_input_buffer() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "jni-strings?max=5&max_len=16");
    assert_eq!(status, None);
    assert_eq!(v["count"], 2);
    assert_eq!(v["returned"], 2);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["with_observed_string"], 2);
    assert_eq!(v["without_observed_string"], 0);
    assert_eq!(v["hits"][0]["idx"], 2);
    assert_eq!(v["hits"][0]["jni_fn"], "ReleaseStringUTFChars");
    assert_eq!(v["hits"][0]["arg_name"], "x2");
    assert_eq!(v["hits"][0]["direction"], "in");
    assert_eq!(v["hits"][0]["buffer_addr"], "0x7000");
    assert_eq!(v["hits"][0]["observed_bytes"], 6);
    assert_eq!(v["hits"][0]["string"], "hello");
}

#[test]
fn jni_strings_max_zero_returns_all_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "jni-strings?max=0");
    assert_eq!(status, None);
    assert_eq!(v["count"], 2);
    assert_eq!(v["returned"], 2);
    assert_eq!(v["truncated"], false);
}

#[test]
fn jni_strings_reports_total_and_truncation() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "jni-strings?max=1");
    assert_eq!(status, None);
    assert_eq!(v["count"], 2);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["hits"].as_array().unwrap().len(), 1);
}

fn utf_buffer_call(slot: u32, bytes: [u8; 8], returned: bool) -> (tempfile::TempDir, PathBuf) {
    let (tmp, cd) = synth_call_dir();
    let mut trace = vec![0u8; 272 * 4];
    let insts = [
        0xf9000043,
        0xf9400009 | (slot << 10),
        0xd63f0120,
        0xd503201f,
    ];
    for (idx, inst) in insts.into_iter().enumerate() {
        let row = &mut trace[idx * 272..(idx + 1) * 272];
        let pc = if idx == 3 && !returned {
            0x100100
        } else {
            0x100000 + idx as u64 * 4
        };
        row[..8].copy_from_slice(&pc.to_le_bytes());
        let x0 = if idx == 3 && slot == 169 {
            0x7000u64
        } else {
            0xdead
        };
        row[8..16].copy_from_slice(&x0.to_le_bytes());
        row[16..24].copy_from_slice(&0x7000u64.to_le_bytes());
        row[24..32].copy_from_slice(&0x7000u64.to_le_bytes());
        row[32..40].copy_from_slice(&bytes);
        row[268..272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), trace).unwrap();
    (tmp, cd)
}

#[test]
fn new_string_utf_reads_input_instead_of_jobject_and_keeps_raw_encoding() {
    let (_tmp, cd) = utf_buffer_call(167, [0xc0, 0x80, b'a', 0, 0, 0, 0, 0], true);
    let (status, value) = get(cd, "jni-strings");
    assert_eq!(status, None);
    assert_eq!(value["hits"][0]["direction"], "in");
    assert_eq!(value["hits"][0]["buffer_addr"], "0x7000");
    assert_eq!(value["hits"][0]["bytes_hex"], "c08061");
    assert_eq!(value["hits"][0]["read_stop"], "nul");
    assert_eq!(value["encoding"], "modified_utf8");
    assert_eq!(value["display_encoding"], "utf8_lossy");
}

#[test]
fn get_utf_chars_requires_an_observed_return_to_the_caller() {
    for returned in [true, false] {
        let (_tmp, cd) = utf_buffer_call(169, *b"hello\0\0\0", returned);
        let (_, value) = get(cd, "jni-strings");
        assert_eq!(value["count"], 1);
        let hit = &value["hits"][0];
        if returned {
            assert_eq!(hit["arg_name"], "x0");
            assert_eq!(hit["string"], "hello");
            assert_eq!(hit["read_stop"], "nul");
        } else {
            assert!(hit["buffer_addr"].is_null());
            assert!(hit["string"].is_null());
            assert_eq!(hit["read_stop"], "return_unobserved");
        }
    }
}

#[test]
fn jni_preview_reports_empty_missing_and_capped_bytes() {
    for (bytes, max_len, expected, stop) in [
        ([0; 8], 16, "", "nul"),
        (*b"abcdefgh", 16, "abcdefgh", "missing"),
        (*b"abcdefgh", 3, "abc", "limit"),
    ] {
        let (_tmp, cd) = utf_buffer_call(167, bytes, true);
        let (_, value) = get(cd, &format!("jni-strings?max_len={max_len}"));
        assert_eq!(value["hits"][0]["string"], expected);
        assert_eq!(value["hits"][0]["read_stop"], stop);
    }
}

#[test]
fn jni_preview_does_not_treat_utf16_or_string_handles_as_utf8() {
    for slot in [163, 164, 165, 166, 168] {
        let (_tmp, cd) = utf_buffer_call(slot, *b"hello\0\0\0", true);
        let (_, value) = get(cd, "jni-strings");
        assert_eq!(value["count"], 0, "JNI table slot {slot}");
    }
}
