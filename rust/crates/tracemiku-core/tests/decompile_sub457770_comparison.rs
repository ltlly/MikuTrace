
// Auto-generated decompile test for sub_457770 comparison
use tracemiku_core::decompiler::il_pipeline::decompile_static;

#[test]
fn decompile_sub_457770_trace() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000006f7a908780u64, 0xa9074ff4u32),
        (0x0000006f7a908784u64, 0x529175a8u32),
        (0x0000006f7a908788u64, 0x5290a3ecu32),
        (0x0000006f7a90878cu64, 0x72ad1b68u32),
        (0x0000006f7a908790u64, 0xaa0003f3u32),
        (0x0000006f7a908794u64, 0x72aa3d6cu32),
        (0x0000006f7a908798u64, 0xd53bd054u32),
        (0x0000006f7a90879cu64, 0x9b287c48u32),
        (0x0000006f7a9087a0u64, 0x52801429u32),
        (0x0000006f7a9087a4u64, 0x52828f6fu32),
        (0x0000006f7a9087a8u64, 0x910083eau32),
        (0x0000006f7a9087acu64, 0xd37ffd0bu32),
        (0x0000006f7a9087b0u64, 0x936cfd08u32),
        (0x0000006f7a9087b4u64, 0x0b0b0100u32),
        (0x0000006f7a9087b8u64, 0x5284e208u32),
        (0x0000006f7a9087bcu64, 0x9b2c7c4bu32),
        (0x0000006f7a9087c0u64, 0xf940168cu32),
        (0x0000006f7a9087c4u64, 0x1b088808u32),
        (0x0000006f7a9087c8u64, 0x910073edu32),
        (0x0000006f7a9087ccu64, 0xd37ffd6eu32),
        (0x0000006f7a9087d0u64, 0x9365fd6bu32),
        (0x0000006f7a9087d4u64, 0x13003d08u32),
        (0x0000006f7a9087d8u64, 0x0b0e016bu32),
        (0x0000006f7a9087dcu64, 0x52800c8eu32),
        (0x0000006f7a9087e0u64, 0xf81f83acu32),
        (0x0000006f7a9087e4u64, 0x1b0f7d08u32),
        (0x0000006f7a9087e8u64, 0xb9001fe9u32),
        (0x0000006f7a9087ecu64, 0x1b0e8962u32),
        (0x0000006f7a9087f0u64, 0x1000002eu32),
        (0x0000006f7a9087f4u64, 0x98000184u32),
        (0x0000006f7a9087f8u64, 0xd2800f29u32),
        (0x0000006f7a9087fcu64, 0xca090084u32),
        (0x0000006f7a908800u64, 0xd1033c84u32),
        (0x0000006f7a908804u64, 0xd2800cb1u32),
        (0x0000006f7a908808u64, 0xca110084u32),
        (0x0000006f7a90880cu64, 0xb98001abu32),
        (0x0000006f7a908810u64, 0xcb0b0084u32),
        (0x0000006f7a908814u64, 0x8b0401ceu32),
        (0x0000006f7a908818u64, 0x52801a9bu32),
        (0x0000006f7a90881cu64, 0xb900015bu32),
        (0x0000006f7a908820u64, 0xd61f01c0u32),
        (0x0000006f7a908834u64, 0x13137d09u32),
        (0x0000006f7a908838u64, 0xf90023e3u32),
        (0x0000006f7a90883cu64, 0x0b487d21u32),
        (0x0000006f7a908840u64, 0x9100a3e4u32),
        (0x0000006f7a908844u64, 0x910093e5u32),
        (0x0000006f7a908848u64, 0x52800023u32),
        (0x0000006f7a90884cu64, 0x290483ffu32),
        (0x0000006f7a908850u64, 0xa9034fffu32),
        (0x0000006f7a908854u64, 0x29058be1u32),
        (0x0000006f7a908858u64, 0x97fff5e4u32),
        (0x0000006f7a90885cu64, 0xb94027e8u32),
        (0x0000006f7a908860u64, 0xf9000be0u32),
        (0x0000006f7a908864u64, 0xb9000fe8u32),
        (0x0000006f7a908868u64, 0xb50000e0u32),
        (0x0000006f7a908884u64, 0xf9400be0u32),
        (0x0000006f7a908888u64, 0xf9401688u32),
        (0x0000006f7a90888cu64, 0xf85f83a9u32),
        (0x0000006f7a908890u64, 0xeb09011fu32),
        (0x0000006f7a908894u64, 0x540000c1u32),
        (0x0000006f7a908898u64, 0xa9474ff4u32),
        (0x0000006f7a90889cu64, 0xa9457bfdu32),
        (0x0000006f7a9088a0u64, 0xf94033fbu32),
        (0x0000006f7a9088a4u64, 0x910203ffu32),
        (0x0000006f7a9088a8u64, 0xd65f03c0u32),
    ];
    let output = decompile_static(&insns);
    
    println!("=== LLIL SSA ===");
    println!("{}", output.llil_ssa_text);
    println!("=== MLIL ===");
    println!("{}", output.mlil_text);
    println!("=== HLIL (OUR DECOMPILER) ===");
    println!("{}", output.hlil_text);
    println!("=== STATS ===");
    println!("Coverage: {:.1}%", output.llil_coverage * 100.0);
    println!("LLIL exprs: {}", output.llil_count);
    println!("MLIL exprs: {}", output.mlil_count);
    println!("HLIL exprs: {}", output.hlil_count);
    
    // Basic assertions
    assert!(output.insn_count > 0);
    assert!(!output.hlil_text.is_empty());
}
