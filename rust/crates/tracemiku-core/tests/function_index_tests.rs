//! TDD for tracemiku-core::function_index.

use tracemiku_core::function_index::*;

#[test]
fn parse_id_trace_prefix() {
    let (src, payload) = parse_id("trace:F0").expect("parse trace:F0");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F0");
}

#[test]
fn parse_id_sym_prefix() {
    let (src, payload) = parse_id("sym:doCommandNative").expect("parse sym:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "doCommandNative");
}

#[test]
fn parse_id_bn_prefix_validates_hex() {
    let (src, payload) = parse_id("bn:0x12345").expect("parse bn:hex");
    assert_eq!(src, "bn");
    assert_eq!(payload, "0x12345");

    assert!(parse_id("bn:notahex").is_err(), "bn payload must be hex");
}

#[test]
#[allow(non_snake_case)]
fn parse_id_legacy_F_prefix() {
    let (src, payload) = parse_id("F0").expect("parse legacy F0");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F0");

    let (src, payload) = parse_id("F12").expect("parse F12");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F12");
}

#[test]
fn parse_id_legacy_cfg_prefix() {
    let (src, payload) = parse_id("cfg:doCommandNative").expect("parse cfg:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "doCommandNative");
}

#[test]
fn parse_id_rejects_empty_and_garbage() {
    assert!(parse_id("").is_err());
    assert!(parse_id("trace:").is_err(), "empty trace payload");
    assert!(parse_id("sym:").is_err(), "empty sym payload");
    assert!(parse_id("bn:").is_err(), "empty bn payload");
    assert!(parse_id("cfg:").is_err(), "empty cfg payload");
    assert!(parse_id("Foo").is_err(), "F prefix needs digits");
    assert!(parse_id("Fa").is_err(), "F prefix needs digits");
    assert!(parse_id("garbage").is_err());
}

#[test]
fn make_id_constructors() {
    assert_eq!(make_trace_id("F0"), "trace:F0");
    assert_eq!(make_sym_id("foo"), "sym:foo");
    assert_eq!(make_bn_id(0x12345), "bn:0x12345");
}

#[test]
fn function_index_by_id_lookup() {
    let entries = vec![
        FunctionEntry {
            id: "trace:F0".to_string(),
            name: "f_root".to_string(),
            source: "trace-ir".to_string(),
            entry_pc: Some(0x100000),
            blocks: 1,
            records: 9,
            trace_ir_id: Some("F0".to_string()),
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        },
        FunctionEntry {
            id: "sym:f_alpha".to_string(),
            name: "f_alpha".to_string(),
            source: "symbol".to_string(),
            entry_pc: Some(0x100100),
            blocks: 1,
            records: 0,
            trace_ir_id: None,
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        },
    ];
    let idx = FunctionIndex { entries };

    let f0 = idx.by_id("trace:F0").expect("trace:F0 lookup");
    assert_eq!(f0.name, "f_root");

    let alpha = idx.by_id("sym:f_alpha").expect("sym:f_alpha lookup");
    assert_eq!(alpha.entry_pc, Some(0x100100));

    let f0_alias = idx.by_id("F0").expect("F0 legacy alias");
    assert_eq!(f0_alias.name, "f_root");

    assert!(idx.by_id("trace:F99").is_none());
    assert!(idx.by_id("garbage").is_none());
}
