//! TDD for tracemiku-core::function_index.

use tracemiku_core::function_index::*;
use tracemiku_core::prelude::{ModuleInfo, SymbolMap};

#[test]
fn parse_id_sym_prefix() {
    let (src, payload) = parse_id("sym:signCompute").expect("parse sym:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "signCompute");
}

#[test]
fn parse_id_symaddr_prefix_validates_hex() {
    let (src, payload) = parse_id("symaddr:0x12345").expect("parse symaddr:");
    assert_eq!(src, "symaddr");
    assert_eq!(payload, "0x12345");

    assert!(
        parse_id("symaddr:nothex").is_err(),
        "symaddr payload must be hex"
    );
}

#[test]
fn parse_id_bn_prefix_validates_hex() {
    let (src, payload) = parse_id("bn:0x12345").expect("parse bn:hex");
    assert_eq!(src, "bn");
    assert_eq!(payload, "0x12345");

    assert!(parse_id("bn:notahex").is_err(), "bn payload must be hex");
}

#[test]
fn parse_id_legacy_cfg_prefix() {
    let (src, payload) = parse_id("cfg:signCompute").expect("parse cfg:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "signCompute");
}

#[test]
fn parse_id_rejects_empty_and_garbage() {
    assert!(parse_id("").is_err());
    assert!(parse_id("sym:").is_err(), "empty sym payload");
    assert!(parse_id("symaddr:").is_err(), "empty symaddr payload");
    assert!(parse_id("bn:").is_err(), "empty bn payload");
    assert!(parse_id("cfg:").is_err(), "empty cfg payload");
    assert!(parse_id("garbage").is_err());
}

#[test]
fn make_id_constructors() {
    assert_eq!(make_sym_id("foo"), "sym:foo");
    assert_eq!(make_sym_addr_id(0x12345), "symaddr:0x12345");
    assert_eq!(make_bn_id(0x12345), "bn:0x12345");
}

#[test]
fn function_index_by_id_lookup() {
    let entries = vec![FunctionEntry {
        id: "sym:f_alpha".to_string(),
        name: "f_alpha".to_string(),
        source: "symbol".to_string(),
        entry_pc: Some(0x100100),
        blocks: 1,
        records: 0,
        module: None,
        entry_rel: None,
        bn_start: None,
        can_bn_hlil: false,
    }];
    let idx = FunctionIndex { entries };

    let alpha = idx.by_id("sym:f_alpha").expect("sym:f_alpha lookup");
    assert_eq!(alpha.entry_pc, Some(0x100100));

    let alpha_by_addr = idx
        .by_id("symaddr:0x100100")
        .expect("symaddr:0x100100 lookup");
    assert_eq!(alpha_by_addr.name, "f_alpha");

    assert!(idx.by_id("trace:F0").is_none(), "trace ids are gone");
    assert!(idx.by_id("garbage").is_none());
}

#[test]
fn function_index_uses_address_ids_for_duplicate_symbol_names() {
    let mod_a = ModuleInfo {
        name: "liba.so".to_string(),
        base: "0x100000".to_string(),
        size: 0x1000,
        end: "0x101000".to_string(),
    };
    let mod_b = ModuleInfo {
        name: "libb.so".to_string(),
        base: "0x200000".to_string(),
        size: 0x1000,
        end: "0x201000".to_string(),
    };
    let mut symbols = SymbolMap::new();
    symbols.add_with_module(0x100100, "JNI_OnLoad".to_string(), &mod_a);
    symbols.add_with_module(0x200100, "JNI_OnLoad".to_string(), &mod_b);
    symbols.freeze();

    let idx = build_from_symbols(&symbols, None);
    assert_eq!(idx.entries.len(), 2);
    assert!(idx.by_id("symaddr:0x100100").is_some());
    assert!(idx.by_id("symaddr:0x200100").is_some());
    assert_eq!(idx.entries[0].module.as_deref(), Some("liba.so"));
    assert_eq!(idx.entries[0].entry_rel, Some(0x100));
    assert_eq!(idx.entries[1].module.as_deref(), Some("libb.so"));
    assert_eq!(idx.entries[1].entry_rel, Some(0x100));
    assert!(
        idx.by_id("sym:JNI_OnLoad").is_none(),
        "legacy sym:<name> is ambiguous when multiple modules define the same symbol"
    );
}
