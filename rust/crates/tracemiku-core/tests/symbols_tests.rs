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

#[test]
fn symbol_map_respects_module_boundaries() {
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
    let mut m = SymbolMap::new();
    m.add_with_module(0x100100, "same_name".to_string(), &mod_a);
    m.add_with_module(0x200100, "same_name".to_string(), &mod_b);
    m.freeze();

    let (name, off) = m.lookup(0x100108);
    assert_eq!(name, "same_name");
    assert_eq!(off, 0x8);

    let (name, off) = m.lookup(0x180000);
    assert_eq!(name, "?");
    assert_eq!(off, 0);

    let hit = m.lookup_entry(0x200108).expect("libb symbol lookup");
    assert_eq!(hit.name, "same_name");
    assert_eq!(hit.off, 0x8);
    assert_eq!(hit.module.as_deref(), Some("libb.so"));
    assert_eq!(hit.module_base, Some(0x200000));
}

#[test]
fn symbol_map_unbounded_entries_do_not_bleed_into_module_aware_maps() {
    let mod_b = ModuleInfo {
        name: "libb.so".to_string(),
        base: "0x200000".to_string(),
        size: 0x1000,
        end: "0x201000".to_string(),
    };
    let mut m = SymbolMap::new();
    m.add(0x100000, "unmapped_stub".to_string());
    m.add_with_module(0x200100, "libb_func".to_string(), &mod_b);
    m.freeze();

    let (name, off) = m.lookup(0x150000);
    assert_eq!(name, "?");
    assert_eq!(off, 0);

    let (name, off) = m.lookup(0x200050);
    assert_eq!(name, "?");
    assert_eq!(off, 0);

    let (name, off) = m.lookup(0x100000);
    assert_eq!(name, "unmapped_stub");
    assert_eq!(off, 0);
}
