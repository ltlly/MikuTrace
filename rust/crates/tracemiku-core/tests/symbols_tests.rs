//! TDD for SymbolMap.

use tracemiku_core::prelude::*;

#[test]
fn symbol_map_lookup_returns_unknown_for_empty() {
    let m = SymbolMap::new();
    let (name, off) = m.lookup(0x100000);
    assert_eq!(name, "?");
    assert_eq!(off, 0);
}

#[test]
fn symbol_map_lookup_finds_function() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    m.add(0x100200, "f_beta".to_string());
    m.freeze();

    let (n, o) = m.lookup(0x100000);
    assert_eq!(n, "f_root");
    assert_eq!(o, 0);

    let (n, o) = m.lookup(0x100050);
    assert_eq!(n, "f_root");
    assert_eq!(o, 0x50);

    let (n, o) = m.lookup(0x100100);
    assert_eq!(n, "f_alpha");
    assert_eq!(o, 0);

    let (n, o) = m.lookup(0x100105);
    assert_eq!(n, "f_alpha");
    assert_eq!(o, 0x5);
}

#[test]
fn symbol_map_lookup_before_first_returns_unknown() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f".to_string());
    m.freeze();
    let (n, o) = m.lookup(0x0fffff);
    assert_eq!(n, "?");
    assert_eq!(o, 0);
}

#[test]
fn symbol_map_unsorted_input_handled() {
    let mut m = SymbolMap::new();
    m.add(0x100200, "f_beta".to_string());
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    m.freeze();
    let (n, _) = m.lookup(0x100050);
    assert_eq!(n, "f_root");
    let (n, _) = m.lookup(0x100150);
    assert_eq!(n, "f_alpha");
    let (n, _) = m.lookup(0x100250);
    assert_eq!(n, "f_beta");
}
