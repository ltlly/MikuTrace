//! Union field detection pass (ScoreUnionFields).
//!
//! Detects memory locations accessed as different types through different
//! fields or at overlapping offsets. When the same base address is loaded
//! or stored with incompatible type/size patterns, it suggests a C union.
//!
//! Algorithm (mirrors Ghidra's union field recovery):
//!   1. Parse all Load/Store address operands into (base, offset, size) records.
//!   2. Within each base register group, scan for overlapping access patterns:
//!      - Same offset, different sizes → union candidate
//!      - Same offset, same size but different inferred types → union candidate
//!      - Offset 0 accessed as int64 AND also as two int32s at 0,4 → union/struct
//!   3. Score each candidate with ScoreUnionFields:
//!      - +1 per distinct type at the same offset
//!      - +2 per overlapping access (different sizes, same start offset)
//!      - +3 if accessed through different struct field names
//!      - -1 if accesses are temporally separated (union less likely)
//!   4. Emit union type definitions as extra annotations on relevant expressions.

use std::collections::{BTreeMap, BTreeSet};

use super::pass::{Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult};

// ============================================================================
// Access tracking
// ============================================================================

/// A single memory access record extracted from a Load/Store expression.
#[derive(Debug, Clone)]
struct AccessRecord {
    /// Base register (e.g., x0, sp, fp).
    base_reg: String,
    /// Byte offset from the base.
    offset: i64,
    /// Size of the access in bytes.
    size: u8,
    /// Index into the expression list.
    expr_index: usize,
    /// PC of the instruction that produced this access.
    pc: u64,
    /// Inferred C type name from the access size.
    type_name: String,
    /// "load" or "store".
    kind: String,
}

impl AccessRecord {
    fn type_from_size(size: u8) -> &'static str {
        match size {
            1 => "uint8_t",
            2 => "uint16_t",
            4 => "uint32_t",
            8 => "uint64_t",
            _ => "uint8_t",
        }
    }
}

/// Sorted unique types observed at a single (base, offset) location.
#[derive(Debug, Clone, Default)]
struct OffsetTypes {
    types: BTreeSet<String>,
    sizes: BTreeSet<u8>,
    /// Indices into the original access records.
    access_indices: Vec<usize>,
}

/// A scored union candidate: multiple accesses at the same (base, offset)
/// that use different types or sizes.
#[derive(Debug, Clone)]
struct UnionCandidate {
    base_reg: String,
    offset: i64,
    accesses: Vec<usize>,
    /// Score from ScoreUnionFields.
    score: i32,
    /// The distinct type names observed.
    type_names: Vec<String>,
    /// The distinct sizes observed.
    sizes: Vec<u8>,
    /// Reasons for the score (for annotation).
    reasons: Vec<String>,
}

// ============================================================================
// ScoreUnionFields
// ============================================================================

/// Score a set of accesses that target the same (base, offset) as a potential
/// union field.
///
/// Scoring rules:
///   +1 per distinct type at the same offset
///   +2 per overlapping access (different sizes, same start offset)
///   +3 if accessed through different struct field names
///   -1 if accesses are temporally separated (union less likely)
fn score_union_fields(
    _base_reg: &str,
    offset: i64,
    records: &[&AccessRecord],
    access_to_field_name: &BTreeMap<usize, String>,
) -> (i32, Vec<String>) {
    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // Collect distinct types
    let mut distinct_types: BTreeSet<&str> = BTreeSet::new();
    let mut distinct_sizes: BTreeSet<u8> = BTreeSet::new();
    for r in records {
        distinct_types.insert(&r.type_name);
        distinct_sizes.insert(r.size);
    }

    // +1 per distinct type at the same offset (beyond the first)
    if distinct_types.len() > 1 {
        let bonus = (distinct_types.len() - 1) as i32;
        score += bonus;
        reasons.push(format!(
            "+{} distinct types at offset {:#x}: {:?}",
            bonus,
            offset,
            distinct_types.iter().collect::<Vec<_>>()
        ));
    }

    // +2 per overlapping access (different sizes, same start)
    if distinct_sizes.len() > 1 {
        score += 2;
        reasons.push(format!(
            "+2 overlapping access at {:#x} (sizes: {:?})",
            offset,
            distinct_sizes.iter().collect::<Vec<_>>()
        ));
    }

    // Check for same-size but different type names (e.g., int32 vs float32)
    let same_size_types: BTreeMap<u8, BTreeSet<&str>> = {
        let mut m: BTreeMap<u8, BTreeSet<&str>> = BTreeMap::new();
        for r in records {
            m.entry(r.size).or_default().insert(&r.type_name);
        }
        m
    };
    for (_size, types) in &same_size_types {
        if types.len() > 1 {
            let bonus = types.len() as i32 - 1;
            if bonus > 0 {
                score += bonus;
                reasons.push(format!(
                    "+{} same-size different-type at {:#x}: {:?}",
                    bonus,
                    offset,
                    types.iter().collect::<Vec<_>>()
                ));
            }
        }
    }

    // +3 if accessed through different struct field names
    let distinct_fields: BTreeSet<&str> = records
        .iter()
        .filter_map(|r| access_to_field_name.get(&r.expr_index).map(|s| s.as_str()))
        .collect();
    if distinct_fields.len() > 1 {
        score += 3;
        reasons.push(format!(
            "+3 different field names at {:#x}: {:?}",
            offset,
            distinct_fields.iter().collect::<Vec<_>>()
        ));
    }

    // -1 if accesses are temporally separated (large PC gap)
    let pcs: Vec<u64> = records.iter().map(|r| r.pc).collect();
    if pcs.len() >= 2 {
        let min_pc = pcs.iter().min().copied().unwrap_or(0);
        let max_pc = pcs.iter().max().copied().unwrap_or(0);
        let span = max_pc.saturating_sub(min_pc);
        // If PC span > 4096 (different regions), penalize
        if span > 4096 {
            score -= 1;
            reasons.push(format!(
                "-1 temporal separation ({:#x}..{:#x}, span={})",
                min_pc, max_pc, span
            ));
        }
    }

    (score, reasons)
}

// ============================================================================
// Address parsing (reuse from struct recovery for consistency)
// ============================================================================

/// Parse a base+offset pattern from an address operand.
fn parse_base_offset(addr_op: &PassIlOperand) -> Option<(String, i64)> {
    match addr_op {
        PassIlOperand::Var(base) => Some((base.clone(), 0)),
        PassIlOperand::Expr(e) => {
            if (e.op == "LLIL_Add" || e.op == "MLIL_Add" || e.op == "HLIL_Add")
                && e.operands.len() == 2
            {
                if let PassIlOperand::Var(base) = &e.operands[0] {
                    if let PassIlOperand::Imm(off) = e.operands[1] {
                        return Some((base.clone(), off));
                    }
                }
                if let PassIlOperand::Var(base) = &e.operands[1] {
                    if let PassIlOperand::Imm(off) = e.operands[0] {
                        return Some((base.clone(), off));
                    }
                }
            }
            if (e.op == "LLIL_Sub" || e.op == "MLIL_Sub" || e.op == "HLIL_Sub")
                && e.operands.len() == 2
            {
                if let PassIlOperand::Var(base) = &e.operands[0] {
                    if let PassIlOperand::Imm(off) = e.operands[1] {
                        return Some((base.clone(), -off));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract the field name from an expression's extra annotations.
fn field_name_from_extra(extra: &[(String, String)]) -> Option<String> {
    extra
        .iter()
        .find(|(k, _)| k == "struct_field")
        .map(|(_, v)| v.clone())
}

/// Resolve the actual type name for an access, preferring extra annotations.
///
/// If `struct_field_type` is present in extra, use that. Otherwise fall back to
/// the size-derived default. This allows the union detector to see
/// semantic type differences like uint32_t vs float at the same offset.
fn resolve_type_name(extra: &[(String, String)], size: u8) -> String {
    for (k, v) in extra {
        if k == "struct_field_type" {
            return v.clone();
        }
    }
    AccessRecord::type_from_size(size).to_string()
}

// ============================================================================
// UnionFieldDetectionPass
// ============================================================================

/// Detects union fields by finding memory locations accessed through
/// multiple types or sizes, then scoring each candidate.
#[derive(Debug)]
pub struct UnionFieldDetectionPass;

impl UnionFieldDetectionPass {
    /// Scan all expressions for Load/Store memory accesses and build
    /// access records grouped by (base_reg, offset).
    fn collect_access_records(exprs: &[PassIlExpr]) -> Vec<AccessRecord> {
        let mut records = Vec::new();
        for (idx, e) in exprs.iter().enumerate() {
            match e.op.as_str() {
                "LLIL_Load" | "MLIL_Load" | "HLIL_Load" => {
                    if let Some(addr_op) = e.operands.first() {
                        if let Some((base, offset)) = parse_base_offset(addr_op) {
                            records.push(AccessRecord {
                                base_reg: base,
                                offset,
                                size: e.size,
                                expr_index: idx,
                                pc: e.pc,
                                type_name: resolve_type_name(&e.extra, e.size),
                                kind: "load".to_string(),
                            });
                        }
                    }
                }
                "LLIL_Store" | "MLIL_Store" | "HLIL_Store" => {
                    if e.operands.len() >= 2 {
                        if let Some((base, offset)) = parse_base_offset(&e.operands[0]) {
                            records.push(AccessRecord {
                                base_reg: base,
                                offset,
                                size: e.size,
                                expr_index: idx,
                                pc: e.pc,
                                type_name: resolve_type_name(&e.extra, e.size),
                                kind: "store".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        records
    }

    /// Group records by (base_reg, offset) and filter to only those with
    /// multiple accesses or type conflicts.
    fn find_union_candidates(
        records: &[AccessRecord],
        exprs: &[PassIlExpr],
    ) -> Vec<UnionCandidate> {
        // Group by (base_reg, offset)
        let mut groups: BTreeMap<(String, i64), Vec<&AccessRecord>> = BTreeMap::new();
        for r in records {
            groups
                .entry((r.base_reg.clone(), r.offset))
                .or_default()
                .push(r);
        }

        // Build field name lookup from existing struct annotations
        let mut access_to_field: BTreeMap<usize, String> = BTreeMap::new();
        for (idx, e) in exprs.iter().enumerate() {
            if let Some(name) = field_name_from_extra(&e.extra) {
                access_to_field.insert(idx, name);
            }
        }

        let mut candidates: Vec<UnionCandidate> = Vec::new();

        for ((base_reg, offset), group_records) in &groups {
            if group_records.len() < 2 {
                continue;
            }

            // Check if there's a real type conflict
            let types_observed: BTreeSet<&str> =
                group_records.iter().map(|r| r.type_name.as_str()).collect();
            let sizes_observed: BTreeSet<u8> =
                group_records.iter().map(|r| r.size).collect();

            // Need either different sizes or different types to be a candidate
            if sizes_observed.len() < 2 && types_observed.len() < 2 {
                continue;
            }

            // Overlap detection: also include accesses from overlapping ranges
            // e.g., offset 0 size 8 overlaps with offset 0 size 4 AND offset 4 size 4
            let mut all_access_indices: Vec<usize> =
                group_records.iter().map(|r| r.expr_index).collect();

            // Look for accesses at nearby offsets that overlap with this one
            for ((other_base, other_offset), other_records) in &groups {
                if other_base != base_reg || *other_offset == *offset {
                    continue;
                }
                for rec in other_records {
                    // Check overlap: [offset, offset+size) overlaps [other_offset, other_offset+size)
                    let rec_end = offset + rec.size as i64;
                    let other_end = other_offset + rec.size as i64;
                    let overlaps = *offset < other_end && *other_offset < rec_end;
                    if overlaps {
                        all_access_indices.push(rec.expr_index);
                    }
                }
            }
            all_access_indices.sort();
            all_access_indices.dedup();

            // Collect all relevant records for scoring (including overlapping ones)
            let mut all_records: Vec<&AccessRecord> = group_records.to_vec();
            for idx in &all_access_indices {
                if let Some(rec) = records.iter().find(|r| r.expr_index == *idx) {
                    if !all_records.iter().any(|r| r.expr_index == *idx) {
                        all_records.push(rec);
                    }
                }
            }

            let (score, reasons) =
                score_union_fields(base_reg, *offset, &all_records, &access_to_field);

            if score <= 0 {
                continue;
            }

            let type_names: Vec<String> = types_observed.iter().map(|s| s.to_string()).collect();
            let sizes: Vec<u8> = sizes_observed.iter().copied().collect();

            candidates.push(UnionCandidate {
                base_reg: base_reg.clone(),
                offset: *offset,
                accesses: all_access_indices,
                score,
                type_names,
                sizes,
                reasons,
            });
        }

        // Sort by score descending (highest confidence first)
        candidates.sort_by_key(|c| -c.score);
        candidates
    }

    /// Emit union type annotations on the expressions involved in each candidate.
    fn annotate_union_fields(
        exprs: &mut [PassIlExpr],
        candidates: &[UnionCandidate],
    ) -> bool {
        let mut changed = false;

        for candidate in candidates {
            // Build a union type name
            let union_name = format!(
                "union_{}_{:x}",
                candidate.base_reg,
                candidate.offset.unsigned_abs()
            );

            // Build the union type definition string
            let mut members: Vec<String> = Vec::new();
            {
                let mut seen_types: BTreeSet<String> = BTreeSet::new();
                for idx in &candidate.accesses {
                    if let Some(e) = exprs.get(*idx) {
                        let fname = field_name_from_extra(&e.extra)
                            .unwrap_or_else(|| format!("field_{:x}", candidate.offset));
                        let ftype = match e.size {
                            1 => "uint8_t",
                            2 => "uint16_t",
                            4 => "uint32_t",
                            8 => "uint64_t",
                            _ => "uint8_t",
                        };
                        let key = format!("{}:{}", fname, ftype);
                        if seen_types.insert(key.clone()) {
                            members.push(format!("    {} {};", ftype, fname));
                        }
                    }
                }
            }
            let union_def = format!(
                "typedef union {{\n{}\n}} {};",
                members.join("\n"),
                union_name
            );

            // Annotate each expression involved in this union candidate
            for idx in &candidate.accesses {
                if let Some(e) = exprs.get_mut(*idx) {
                    // Remove old union annotations if present
                    e.extra
                        .retain(|(k, _)| k != "union_base" && k != "union_score" && k != "union_type");
                    e.extra.push((
                        "union_base".to_string(),
                        candidate.base_reg.clone(),
                    ));
                    e.extra.push((
                        "union_score".to_string(),
                        candidate.score.to_string(),
                    ));
                    e.extra.push(("union_type".to_string(), union_def.clone()));

                    // Also add individual member annotations
                    for (i, member) in members.iter().enumerate() {
                        e.extra.push((
                            format!("union_member_{}", i),
                            member.trim().to_string(),
                        ));
                    }

                    // Add score breakdown as a single annotation
                    let breakdown = candidate.reasons.join("; ");
                    e.extra
                        .push(("union_score_breakdown".to_string(), breakdown.clone()));

                    changed = true;
                }
            }
        }

        changed
    }
}

impl Pass for UnionFieldDetectionPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "UnionFieldDetection",
            description:
                "Detect memory locations used as different types (union fields) via ScoreUnionFields",
            phase: 5,
            requires: &["StructRecovery"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        // Step 1: Collect access records
        let records = Self::collect_access_records(&exprs.exprs);
        if records.len() < 2 {
            return PassResult::Unchanged;
        }

        // Step 2: Find union candidates
        let candidates = Self::find_union_candidates(&records, &exprs.exprs);
        if candidates.is_empty() {
            return PassResult::Unchanged;
        }

        // Step 3: Annotate union fields
        if Self::annotate_union_fields(&mut exprs.exprs, &candidates) {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pass::PassIlOperand;

    fn make_expr(op: &str, size: u8, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size,
            pc: 0x1000,
            operands,
            extra: vec![],
        }
    }

    fn make_expr_at(op: &str, size: u8, pc: u64, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size,
            pc,
            operands,
            extra: vec![],
        }
    }

    fn imm(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }

    fn reg(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }

    fn expr_box(op: &str, operands: Vec<PassIlOperand>) -> PassIlOperand {
        PassIlOperand::Expr(Box::new(make_expr(op, 8, operands)))
    }

    fn base_offset(base: &str, offset: i64) -> PassIlOperand {
        if offset == 0 {
            reg(base)
        } else if offset < 0 {
            expr_box("LLIL_Sub", vec![reg(base), imm(-offset)])
        } else {
            expr_box("LLIL_Add", vec![reg(base), imm(offset)])
        }
    }

    // ------------------------------------------------------------------
    // ScoreUnionFields unit tests
    // ------------------------------------------------------------------

    #[test]
    fn test_score_single_type_no_union() {
        let records = vec![AccessRecord {
            base_reg: "x0".into(),
            offset: 0,
            size: 4,
            expr_index: 0,
            pc: 0x1000,
            type_name: "uint32_t".into(),
            kind: "load".into(),
        }];
        let refs: Vec<&AccessRecord> = records.iter().collect();
        let field_names = BTreeMap::new();
        let (score, _) = score_union_fields("x0", 0, &refs, &field_names);
        assert_eq!(score, 0, "single access should score 0");
    }

    #[test]
    fn test_score_distinct_types_same_offset() {
        let records = vec![
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 4,
                expr_index: 0,
                pc: 0x1000,
                type_name: "uint32_t".into(),
                kind: "load".into(),
            },
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 8,
                expr_index: 1,
                pc: 0x1004,
                type_name: "uint64_t".into(),
                kind: "load".into(),
            },
        ];
        let refs: Vec<&AccessRecord> = records.iter().collect();
        let field_names = BTreeMap::new();
        let (score, reasons) = score_union_fields("x0", 0, &refs, &field_names);
        // +1 for 2 distinct types, +2 for overlapping (different sizes)
        assert!(score >= 3, "expected >=3, got {} reasons: {:?}", score, reasons);
    }

    #[test]
    fn test_score_with_field_names() {
        let records = vec![
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 4,
                expr_index: 0,
                pc: 0x1000,
                type_name: "uint32_t".into(),
                kind: "load".into(),
            },
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 4,
                expr_index: 1,
                pc: 0x1008,
                type_name: "int32_t".into(),
                kind: "store".into(),
            },
        ];
        let refs: Vec<&AccessRecord> = records.iter().collect();
        let mut field_names = BTreeMap::new();
        field_names.insert(0, "field_0".to_string());
        field_names.insert(1, "field_int".to_string());
        let (score, reasons) = score_union_fields("x0", 0, &refs, &field_names);
        // +1 distinct types (uint32_t vs int32_t), +3 different field names
        assert!(score >= 4, "expected >=4, got {} reasons: {:?}", score, reasons);
    }

    #[test]
    fn test_score_temporal_penalty() {
        let records = vec![
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 4,
                expr_index: 0,
                pc: 0x1000,
                type_name: "uint32_t".into(),
                kind: "load".into(),
            },
            AccessRecord {
                base_reg: "x0".into(),
                offset: 0,
                size: 8,
                expr_index: 1,
                pc: 0x20000, // far away PC
                type_name: "uint64_t".into(),
                kind: "load".into(),
            },
        ];
        let refs: Vec<&AccessRecord> = records.iter().collect();
        let field_names = BTreeMap::new();
        let (score, _) = score_union_fields("x0", 0, &refs, &field_names);
        // Should have -1 temporal penalty but still positive from type/size bonuses
        assert!(score >= 2, "expected >=2 after penalty, got {}", score);
    }

    // ------------------------------------------------------------------
    // Union field detection: overlapping int32/float32
    // ------------------------------------------------------------------

    #[test]
    fn test_union_int32_float32_same_offset() {
        // Load(x0 + 0) as uint32_t (4 bytes)
        // Load(x0 + 0) as float (4 bytes) — different semantic type
        // Same offset, same size, but we mark them as different types
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            {
                let mut e = make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]);
                e.extra
                    .push(("struct_field".to_string(), "as_int".to_string()));
                e.extra
                    .push(("struct_field_type".to_string(), "uint32_t".to_string()));
                e
            },
            {
                let mut e = make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]);
                e.extra
                    .push(("struct_field".to_string(), "as_float".to_string()));
                e.extra
                    .push(("struct_field_type".to_string(), "float".to_string()));
                e
            },
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        // Should detect union: same offset, different field names, same size
        assert!(result.is_changed(), "should detect union for int32/float32");

        // Both should have union annotations
        for e in &exprs.exprs {
            let has_union = e.extra.iter().any(|(k, _)| k == "union_type");
            assert!(has_union, "expected union_type annotation");
        }
    }

    // ------------------------------------------------------------------
    // Struct with union member detection
    // ------------------------------------------------------------------

    #[test]
    fn test_struct_with_union_member() {
        // A struct at x0:
        //   field_0 at offset 0: Load(x0+0) as uint32_t
        //   union member at offset 8: Load(x0+8) as uint32_t (field_a)
        //   union member at offset 8: Load(x0+8) as uint64_t (field_b)
        //   field_10 at offset 16: Load(x0+16) as uint32_t
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            {
                let mut e = make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]);
                e.extra
                    .push(("struct_field".to_string(), "flags".to_string()));
                e
            },
            {
                let mut e = make_expr("LLIL_Load", 4, vec![base_offset("x0", 8)]);
                e.extra
                    .push(("struct_field".to_string(), "data_u32".to_string()));
                e
            },
            {
                let mut e = make_expr("LLIL_Load", 8, vec![base_offset("x0", 8)]);
                e.extra
                    .push(("struct_field".to_string(), "data_u64".to_string()));
                e
            },
            {
                let mut e = make_expr("LLIL_Load", 4, vec![base_offset("x0", 16)]);
                e.extra
                    .push(("struct_field".to_string(), "next".to_string()));
                e
            },
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "should detect union at offset 8");

        // offset 8 accesses should have union annotations
        let union_exprs: Vec<_> = exprs
            .exprs
            .iter()
            .filter(|e| {
                e.extra.iter().any(|(k, _)| k == "union_type")
            })
            .collect();
        assert!(
            !union_exprs.is_empty(),
            "at least some expressions should have union annotations"
        );

        // The union definition should contain both data_u32 and data_u64
        let union_def = exprs
            .exprs
            .iter()
            .find_map(|e| {
                e.extra
                    .iter()
                    .find(|(k, _)| k == "union_type")
                    .map(|(_, v)| v.clone())
            })
            .unwrap();
        assert!(
            union_def.contains("data_u32") || union_def.contains("field_8"),
            "union def should reference field names: {}",
            union_def
        );
        assert!(
            union_def.contains("data_u64") || union_def.contains("field_8"),
            "union def should reference field names: {}",
            union_def
        );
    }

    // ------------------------------------------------------------------
    // Pointer/intptr union detection
    // ------------------------------------------------------------------

    #[test]
    fn test_union_ptr_intptr_same_offset() {
        // Load(x0 + 0) as 8 bytes (pointer)
        // Store(x0 + 0) as 8 bytes (uint64)
        // With different field names
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            {
                let mut e = make_expr("LLIL_Load", 8, vec![base_offset("x0", 0)]);
                e.extra
                    .push(("struct_field".to_string(), "ptr".to_string()));
                e.extra
                    .push(("struct_field_type".to_string(), "void*".to_string()));
                e
            },
            {
                let mut e = make_expr(
                    "LLIL_Store",
                    8,
                    vec![base_offset("x0", 0), imm(0xDEADBEEF)],
                );
                e.extra
                    .push(("struct_field".to_string(), "raw_val".to_string()));
                e.extra
                    .push(("struct_field_type".to_string(), "uint64_t".to_string()));
                e
            },
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(
            result.is_changed(),
            "should detect ptr/intptr union at same offset"
        );

        let union_def = exprs
            .exprs
            .iter()
            .find_map(|e| {
                e.extra
                    .iter()
                    .find(|(k, _)| k == "union_type")
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_default();
        // Should mention "union" type
        assert!(
            union_def.contains("typedef union"),
            "should emit typedef union: {}",
            union_def
        );
        assert!(
            union_def.contains("ptr") || union_def.contains("raw_val"),
            "union def should include field names: {}",
            union_def
        );
    }

    // ------------------------------------------------------------------
    // Negative tests
    // ------------------------------------------------------------------

    #[test]
    fn test_no_union_single_access() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]),
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed(), "single access should not trigger union");
    }

    #[test]
    fn test_no_union_different_offsets_same_type() {
        // Load(x0 + 0) as uint32_t
        // Load(x0 + 4) as uint32_t
        // Same type, different offset — this is a struct, not a union
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]),
            make_expr("LLIL_Load", 4, vec![base_offset("x0", 4)]),
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        // Normal struct fields at different offsets should NOT be a union
        assert!(
            !result.is_changed(),
            "different offsets with same type should not be union"
        );
    }

    #[test]
    fn test_no_union_different_bases() {
        // Load(x0 + 0) as uint32_t
        // Load(x1 + 0) as uint64_t
        // Different bases — not related
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Load", 4, vec![base_offset("x0", 0)]),
            make_expr("LLIL_Load", 8, vec![base_offset("x1", 0)]),
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed(), "different bases should not be union");
    }

    // ------------------------------------------------------------------
    // Edge case: overlapping sizes at same offset
    // ------------------------------------------------------------------

    #[test]
    fn test_union_overlapping_sizes() {
        // Load(x0 + 0) as uint8_t (1 byte)
        // Load(x0 + 0) as uint32_t (4 bytes) — overlapping
        // Load(x0 + 0) as uint64_t (8 bytes) — overlapping
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr_at("LLIL_Load", 1, 0x1000, vec![base_offset("x0", 0)]),
            make_expr_at("LLIL_Load", 4, 0x1004, vec![base_offset("x0", 0)]),
            make_expr_at("LLIL_Load", 8, 0x1008, vec![base_offset("x0", 0)]),
        ];

        let pass = UnionFieldDetectionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 5,
            verbose: false,
            trace_targets: None,
            mem_shadow: None,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "overlapping sizes should score as union");

        // Should have high score: +2 for overlapping + at least +2 for multiple types
        let max_score = exprs
            .exprs
            .iter()
            .filter_map(|e| {
                e.extra
                    .iter()
                    .find(|(k, _)| k == "union_score")
                    .and_then(|(_, v)| v.parse::<i32>().ok())
            })
            .max()
            .unwrap_or(0);
        assert!(
            max_score >= 2,
            "overlapping access score should be >=2, got {}",
            max_score
        );
    }

    // ------------------------------------------------------------------
    // PassInfo checks
    // ------------------------------------------------------------------

    #[test]
    fn test_pass_info() {
        let pass = UnionFieldDetectionPass;
        let info = pass.info();
        assert_eq!(info.name, "UnionFieldDetection");
        assert_eq!(info.phase, 5);
        assert!(info.requires.contains(&"StructRecovery"));
    }
}
