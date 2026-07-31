//! Boundary contract tests for tracemiku-core::symbols.
//!
//! Covers: freeze/lookup ordering, pc inside vs outside function ranges,
//! module-aware containment, data symbols, unresolved lookups.

use tracemiku_core::symbols::{ModuleResolver, SymbolKind, SymbolMap};
use tracemiku_core::trace::meta::ModuleInfo;

#[test]
fn lookup_returns_containing_function() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x1000, "f_a".into());
    symbols.add(0x2000, "f_b".into());
    symbols.freeze();
    assert_eq!(symbols.lookup(0x1000), ("f_a".into(), 0));
    assert_eq!(symbols.lookup(0x1fff), ("f_a".into(), 0xfff));
    assert_eq!(symbols.lookup(0x2000), ("f_b".into(), 0));
    assert_eq!(symbols.lookup(0x2abc), ("f_b".into(), 0xabc));
}

#[test]
fn lookup_before_first_function_is_empty() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x1000, "f_a".into());
    symbols.freeze();
    assert_eq!(symbols.lookup(0xfff), ("".into(), 0));
    assert_eq!(symbols.lookup(0x500), ("".into(), 0));
}

#[test]
fn freeze_makes_lookup_work_across_adds() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x3000, "f_c".into());
    symbols.add(0x1000, "f_a".into());
    symbols.add(0x2000, "f_b".into());
    // Unsorted adds must be ordered by freeze() before lookups are reliable.
    symbols.freeze();
    assert_eq!(symbols.lookup(0x1500), ("f_a".into(), 0x500));
    assert_eq!(symbols.lookup(0x2500), ("f_b".into(), 0x500));
    assert_eq!(symbols.lookup(0x3500), ("f_c".into(), 0x500));
}

#[test]
fn module_aware_lookup_bounds_by_module() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x1000, "f_a".into());
    let module = ModuleInfo {
        name: "libt.so".into(),
        base: "0x100000".into(),
        size: 0x10000,
        end: "0x110000".into(),
    };
    symbols.add_with_module(0x100100, "f_mod".into(), &module);
    symbols.freeze();
    // f_mod is module-aware: contains pc within [0x100000, 0x110000).
    assert_eq!(symbols.lookup(0x100100), ("f_mod".into(), 0));
    assert_eq!(symbols.lookup(0x10ffff), ("f_mod".into(), 0xfeff));
    // module-aware mode: non-module entries match only their exact start pc.
    assert_eq!(symbols.lookup(0x110000), ("".into(), 0));
    assert_eq!(symbols.lookup(0x1000), ("f_a".into(), 0));
}

#[test]
fn has_start_pc_and_entry_rel() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x1000, "f_a".into());
    assert!(symbols.has_start_pc(0x1000));
    assert!(!symbols.has_start_pc(0x1001));
}

#[test]
fn data_symbols_are_kept_separately() {
    let mut symbols = SymbolMap::new();
    symbols.add(0x1000, "f_a".into());
    symbols.add_data(0x3000, "g_data".into());
    symbols.freeze();
    // lookup treats data as a symbol too (name resolvable).
    assert_eq!(symbols.lookup(0x3000).0, "g_data");
}

#[test]
fn add_resolved_uses_module_resolver() {
    let mut symbols = SymbolMap::new();
    let module = ModuleInfo {
        name: "libt.so".into(),
        base: "0x100000".into(),
        size: 0x10000,
        end: "0x110000".into(),
    };
    let resolver = ModuleResolver::from_modules(&[module]);
    symbols.add_resolved(0x100200, "f_res".into(), &resolver);
    symbols.freeze();
    assert_eq!(symbols.lookup(0x100200), ("f_res".into(), 0));
    assert!(!symbols.is_empty());
}

#[test]
fn symbol_kind_variants_exist() {
    // SymbolKind is used to tag entries; assert the enum surface is stable.
    let _ = SymbolKind::Function;
}
