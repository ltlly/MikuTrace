// Auto-generated BN vs traceMiku comparison tests
// Generated: 2026-05-14T07:43:42.626495
use tracemiku_core::decompiler::il_pipeline::decompile_static;


#[test]
fn compare_test_add() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400740u64, 0xd10043ffu32),
        (0x0000000000400744u64, 0xb9000fe0u32),
        (0x0000000000400748u64, 0xb9000be1u32),
        (0x000000000040074cu64, 0xb9400fe1u32),
        (0x0000000000400750u64, 0xb9400be0u32),
        (0x0000000000400754u64, 0x0b000020u32),
        (0x0000000000400758u64, 0x910043ffu32),
        (0x000000000040075cu64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_add (Arithmetic) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_add");
}

#[test]
fn compare_test_mul() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400780u64, 0xd10043ffu32),
        (0x0000000000400784u64, 0xb9000fe0u32),
        (0x0000000000400788u64, 0xb9000be1u32),
        (0x000000000040078cu64, 0xb9400fe1u32),
        (0x0000000000400790u64, 0xb9400be0u32),
        (0x0000000000400794u64, 0x1b007c20u32),
        (0x0000000000400798u64, 0x910043ffu32),
        (0x000000000040079cu64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_mul (Arithmetic) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_mul");
}

#[test]
fn compare_test_if_else() {
    let insns: Vec<(u64, u32)> = vec![
        (0x000000000040093cu64, 0xd10043ffu32),
        (0x0000000000400940u64, 0xb9000fe0u32),
        (0x0000000000400944u64, 0xb9400fe0u32),
        (0x0000000000400948u64, 0x7100001fu32),
        (0x000000000040094cu64, 0x5400006du32),
        (0x0000000000400950u64, 0x52800020u32),
        (0x0000000000400954u64, 0x14000007u32),
        (0x0000000000400958u64, 0xb9400fe0u32),
        (0x000000000040095cu64, 0x7100001fu32),
        (0x0000000000400960u64, 0x5400006au32),
        (0x0000000000400964u64, 0x12800000u32),
        (0x0000000000400968u64, 0x14000002u32),
        (0x000000000040096cu64, 0x52800000u32),
        (0x0000000000400970u64, 0x910043ffu32),
        (0x0000000000400974u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_if_else (ControlFlow) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_if_else");
}

#[test]
fn compare_test_while_loop() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004009dcu64, 0xd10083ffu32),
        (0x00000000004009e0u64, 0xb9000fe0u32),
        (0x00000000004009e4u64, 0xb9001bffu32),
        (0x00000000004009e8u64, 0xb9001fffu32),
        (0x00000000004009ecu64, 0x14000008u32),
        (0x00000000004009f0u64, 0xb9401be1u32),
        (0x00000000004009f4u64, 0xb9401fe0u32),
        (0x00000000004009f8u64, 0x0b000020u32),
        (0x00000000004009fcu64, 0xb9001be0u32),
        (0x0000000000400a00u64, 0xb9401fe0u32),
        (0x0000000000400a04u64, 0x11000400u32),
        (0x0000000000400a08u64, 0xb9001fe0u32),
        (0x0000000000400a0cu64, 0xb9401fe1u32),
        (0x0000000000400a10u64, 0xb9400fe0u32),
        (0x0000000000400a14u64, 0x6b00003fu32),
        (0x0000000000400a18u64, 0x54fffecbu32),
        (0x0000000000400a1cu64, 0xb9401be0u32),
        (0x0000000000400a20u64, 0x910083ffu32),
        (0x0000000000400a24u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_while_loop (Loop) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_while_loop");
}

#[test]
fn compare_test_call_two_args() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400aa8u64, 0xa9bd7bfdu32),
        (0x0000000000400aacu64, 0x910003fdu32),
        (0x0000000000400ab0u64, 0xf9000bf3u32),
        (0x0000000000400ab4u64, 0xb9002fe0u32),
        (0x0000000000400ab8u64, 0xb9002be1u32),
        (0x0000000000400abcu64, 0xb9402be1u32),
        (0x0000000000400ac0u64, 0xb9402fe0u32),
        (0x0000000000400ac4u64, 0x97ffff1fu32),
        (0x0000000000400ac8u64, 0x2a0003f3u32),
        (0x0000000000400accu64, 0xb9402be1u32),
        (0x0000000000400ad0u64, 0xb9402fe0u32),
        (0x0000000000400ad4u64, 0x97ffff2bu32),
        (0x0000000000400ad8u64, 0x0b000260u32),
        (0x0000000000400adcu64, 0xf9400bf3u32),
        (0x0000000000400ae0u64, 0xa8c37bfdu32),
        (0x0000000000400ae4u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_call_two_args (FunctionCall) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_call_two_args");
}

#[test]
fn compare_test_struct_field_read() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400b88u64, 0xd10043ffu32),
        (0x0000000000400b8cu64, 0xf90007e0u32),
        (0x0000000000400b90u64, 0xf94007e0u32),
        (0x0000000000400b94u64, 0xb9400001u32),
        (0x0000000000400b98u64, 0xf94007e0u32),
        (0x0000000000400b9cu64, 0xb9400400u32),
        (0x0000000000400ba0u64, 0x0b000020u32),
        (0x0000000000400ba4u64, 0x910043ffu32),
        (0x0000000000400ba8u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_struct_field_read (Struct) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_struct_field_read");
}

#[test]
fn compare_test_ptr_arith() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400d5cu64, 0xd10043ffu32),
        (0x0000000000400d60u64, 0xf90007e0u32),
        (0x0000000000400d64u64, 0xb90007e1u32),
        (0x0000000000400d68u64, 0xb98007e0u32),
        (0x0000000000400d6cu64, 0xd37ef400u32),
        (0x0000000000400d70u64, 0xf94007e1u32),
        (0x0000000000400d74u64, 0x8b000020u32),
        (0x0000000000400d78u64, 0xb9400000u32),
        (0x0000000000400d7cu64, 0x910043ffu32),
        (0x0000000000400d80u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_ptr_arith (Pointer) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_ptr_arith");
}

#[test]
fn compare_test_switch() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400e1cu64, 0xd10043ffu32),
        (0x0000000000400e20u64, 0xb9000fe0u32),
        (0x0000000000400e24u64, 0xb9400fe0u32),
        (0x0000000000400e28u64, 0x7100081fu32),
        (0x0000000000400e2cu64, 0x540001e0u32),
        (0x0000000000400e30u64, 0xb9400fe0u32),
        (0x0000000000400e34u64, 0x7100081fu32),
        (0x0000000000400e38u64, 0x540001ccu32),
        (0x0000000000400e3cu64, 0xb9400fe0u32),
        (0x0000000000400e40u64, 0x7100001fu32),
        (0x0000000000400e44u64, 0x540000a0u32),
        (0x0000000000400e48u64, 0xb9400fe0u32),
        (0x0000000000400e4cu64, 0x7100041fu32),
        (0x0000000000400e50u64, 0x54000080u32),
        (0x0000000000400e54u64, 0x14000007u32),
        (0x0000000000400e58u64, 0x52800140u32),
        (0x0000000000400e5cu64, 0x14000006u32),
        (0x0000000000400e60u64, 0x52800280u32),
        (0x0000000000400e64u64, 0x14000004u32),
        (0x0000000000400e68u64, 0x528003c0u32),
        (0x0000000000400e6cu64, 0x14000002u32),
        (0x0000000000400e70u64, 0x52800000u32),
        (0x0000000000400e74u64, 0x910043ffu32),
        (0x0000000000400e78u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_switch (Switch) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_switch");
}

#[test]
fn compare_test_factorial() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400ddcu64, 0xa9be7bfdu32),
        (0x0000000000400de0u64, 0x910003fdu32),
        (0x0000000000400de4u64, 0xb9001fe0u32),
        (0x0000000000400de8u64, 0xb9401fe0u32),
        (0x0000000000400decu64, 0x7100041fu32),
        (0x0000000000400df0u64, 0x5400006cu32),
        (0x0000000000400df4u64, 0x52800020u32),
        (0x0000000000400df8u64, 0x14000007u32),
        (0x0000000000400dfcu64, 0xb9401fe0u32),
        (0x0000000000400e00u64, 0x51000400u32),
        (0x0000000000400e04u64, 0x97fffff6u32),
        (0x0000000000400e08u64, 0x2a0003e1u32),
        (0x0000000000400e0cu64, 0xb9401fe0u32),
        (0x0000000000400e10u64, 0x1b007c20u32),
        (0x0000000000400e14u64, 0xa8c27bfdu32),
        (0x0000000000400e18u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_factorial (Recursion) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_factorial");
}

#[test]
fn compare_test_csel() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400f3cu64, 0xd10043ffu32),
        (0x0000000000400f40u64, 0xb9000fe0u32),
        (0x0000000000400f44u64, 0xb9000be1u32),
        (0x0000000000400f48u64, 0xb90007e2u32),
        (0x0000000000400f4cu64, 0xb94007e0u32),
        (0x0000000000400f50u64, 0x7100001fu32),
        (0x0000000000400f54u64, 0x54000060u32),
        (0x0000000000400f58u64, 0xb9400fe0u32),
        (0x0000000000400f5cu64, 0x14000002u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_csel (Csel) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_csel");
}

#[test]
fn compare_test_stack_spill() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400bf8u64, 0xd10143ffu32),
        (0x0000000000400bfcu64, 0xb9001fe0u32),
        (0x0000000000400c00u64, 0xb9001be1u32),
        (0x0000000000400c04u64, 0xb90017e2u32),
        (0x0000000000400c08u64, 0xb90013e3u32),
        (0x0000000000400c0cu64, 0xb9000fe4u32),
        (0x0000000000400c10u64, 0xb9000be5u32),
        (0x0000000000400c14u64, 0xb90007e6u32),
        (0x0000000000400c18u64, 0xb90003e7u32),
        (0x0000000000400c1cu64, 0xb9401fe1u32),
        (0x0000000000400c20u64, 0xb9401be0u32),
        (0x0000000000400c24u64, 0x0b000020u32),
        (0x0000000000400c28u64, 0xb9002fe0u32),
        (0x0000000000400c2cu64, 0xb94017e1u32),
        (0x0000000000400c30u64, 0xb94013e0u32),
        (0x0000000000400c34u64, 0x0b000020u32),
        (0x0000000000400c38u64, 0xb90033e0u32),
        (0x0000000000400c3cu64, 0xb9400fe1u32),
        (0x0000000000400c40u64, 0xb9400be0u32),
        (0x0000000000400c44u64, 0x0b000020u32),
        (0x0000000000400c48u64, 0xb90037e0u32),
        (0x0000000000400c4cu64, 0xb94007e1u32),
        (0x0000000000400c50u64, 0xb94003e0u32),
        (0x0000000000400c54u64, 0x0b000020u32),
        (0x0000000000400c58u64, 0xb9003be0u32),
        (0x0000000000400c5cu64, 0xb94053e1u32),
        (0x0000000000400c60u64, 0xb9405be0u32),
        (0x0000000000400c64u64, 0x0b000020u32),
        (0x0000000000400c68u64, 0xb9003fe0u32),
        (0x0000000000400c6cu64, 0xb94063e1u32),
        (0x0000000000400c70u64, 0xb9406be0u32),
        (0x0000000000400c74u64, 0x0b000020u32),
        (0x0000000000400c78u64, 0xb90043e0u32),
        (0x0000000000400c7cu64, 0xb9402fe1u32),
        (0x0000000000400c80u64, 0xb94033e0u32),
        (0x0000000000400c84u64, 0x0b000020u32),
        (0x0000000000400c88u64, 0xb90047e0u32),
        (0x0000000000400c8cu64, 0xb94037e1u32),
        (0x0000000000400c90u64, 0xb9403be0u32),
        (0x0000000000400c94u64, 0x0b000020u32),
        (0x0000000000400c98u64, 0xb9004be0u32),
        (0x0000000000400c9cu64, 0xb9403fe1u32),
        (0x0000000000400ca0u64, 0xb94043e0u32),
        (0x0000000000400ca4u64, 0x0b000020u32),
        (0x0000000000400ca8u64, 0xb9004fe0u32),
        (0x0000000000400cacu64, 0xb9402fe1u32),
        (0x0000000000400cb0u64, 0xb94033e0u32),
        (0x0000000000400cb4u64, 0x0b000021u32),
        (0x0000000000400cb8u64, 0xb94037e0u32),
        (0x0000000000400cbcu64, 0x0b000021u32),
        (0x0000000000400cc0u64, 0xb9403be0u32),
        (0x0000000000400cc4u64, 0x0b000021u32),
        (0x0000000000400cc8u64, 0xb9403fe0u32),
        (0x0000000000400cccu64, 0x0b000021u32),
        (0x0000000000400cd0u64, 0xb94043e0u32),
        (0x0000000000400cd4u64, 0x0b000021u32),
        (0x0000000000400cd8u64, 0xb94047e0u32),
        (0x0000000000400cdcu64, 0x0b000021u32),
        (0x0000000000400ce0u64, 0xb9404be0u32),
        (0x0000000000400ce4u64, 0x0b000021u32),
        (0x0000000000400ce8u64, 0xb9404fe0u32),
        (0x0000000000400cecu64, 0x0b000020u32),
        (0x0000000000400cf0u64, 0x910143ffu32),
        (0x0000000000400cf4u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_stack_spill (StackSpill) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_stack_spill");
}

#[test]
fn compare_test_ldrsw() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400eacu64, 0xd10043ffu32),
        (0x0000000000400eb0u64, 0xf90007e0u32),
        (0x0000000000400eb4u64, 0xf94007e0u32),
        (0x0000000000400eb8u64, 0xb9400000u32),
        (0x0000000000400ebcu64, 0x910043ffu32),
        (0x0000000000400ec0u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_ldrsw (LoadStore) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_ldrsw");
}

#[test]
fn compare_test_bitfield_extract() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400cf8u64, 0xd10043ffu32),
        (0x0000000000400cfcu64, 0xb9000fe0u32),
        (0x0000000000400d00u64, 0xb9400fe0u32),
        (0x0000000000400d04u64, 0x53047c00u32),
        (0x0000000000400d08u64, 0x12001c00u32),
        (0x0000000000400d0cu64, 0x910043ffu32),
        (0x0000000000400d10u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_bitfield_extract (Bitfield) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_bitfield_extract");
}

#[test]
fn compare_test_for_loop() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400a28u64, 0xd10083ffu32),
        (0x0000000000400a2cu64, 0xb9000fe0u32),
        (0x0000000000400a30u64, 0xb9001bffu32),
        (0x0000000000400a34u64, 0xb9001fffu32),
        (0x0000000000400a38u64, 0x14000008u32),
        (0x0000000000400a3cu64, 0xb9401be1u32),
        (0x0000000000400a40u64, 0xb9401fe0u32),
        (0x0000000000400a44u64, 0x0b000020u32),
        (0x0000000000400a48u64, 0xb9001be0u32),
        (0x0000000000400a4cu64, 0xb9401fe0u32),
        (0x0000000000400a50u64, 0x11000400u32),
        (0x0000000000400a54u64, 0xb9001fe0u32),
        (0x0000000000400a58u64, 0xb9401fe1u32),
        (0x0000000000400a5cu64, 0xb9400fe0u32),
        (0x0000000000400a60u64, 0x6b00003fu32),
        (0x0000000000400a64u64, 0x54fffecbu32),
        (0x0000000000400a68u64, 0xb9401be0u32),
        (0x0000000000400a6cu64, 0x910083ffu32),
        (0x0000000000400a70u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_for_loop (Loop) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_for_loop");
}

#[test]
fn compare_test_do_while() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400a74u64, 0xd10083ffu32),
        (0x0000000000400a78u64, 0xb9000fe0u32),
        (0x0000000000400a7cu64, 0xb9001fffu32),
        (0x0000000000400a80u64, 0xb9401fe0u32),
        (0x0000000000400a84u64, 0x11000400u32),
        (0x0000000000400a88u64, 0xb9001fe0u32),
        (0x0000000000400a8cu64, 0xb9401fe1u32),
        (0x0000000000400a90u64, 0xb9400fe0u32),
        (0x0000000000400a94u64, 0x6b00003fu32),
        (0x0000000000400a98u64, 0x54ffff4bu32),
        (0x0000000000400a9cu64, 0xb9401fe0u32),
        (0x0000000000400aa0u64, 0x910083ffu32),
        (0x0000000000400aa4u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== test_do_while (Loop) ===");
    println!("insns: {}", output.insn_count);
    println!("coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL: {} exprs", output.llil_count);
    println!("MLIL: {} exprs", output.mlil_count);
    println!("HLIL: {} exprs", output.hlil_count);
    println!();
    println!("--- LLIL SSA ---");
    println!("{}", output.llil_ssa_text);
    println!("--- MLIL ---");
    println!("{}", output.mlil_text);
    println!("--- HLIL ---");
    println!("{}", output.hlil_text);
    
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
    assert!(output.llil_coverage >= 0.85, "low coverage for test_do_while");
}
