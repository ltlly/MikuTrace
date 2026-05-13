// Auto-generated ARM64 decompiler verification test
// Generated from decomp_test_suite ARM64 binary
use tracemiku_core::decompiler::il_pipeline::decompile_static;

#[test]
fn verify_test_add() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400740u64, 0xd10043ffu32),
        (0x0000000000400744u64, 0xb9000fe0u32),
        (0x0000000000400748u64, 0xb9000be1u32),
        (0x000000000040074cu64, 0xb9400fe1u32),
        (0x0000000000400750u64, 0xb9400be0u32),
        (0x0000000000400754u64, 0x0b000020u32),
        (0x0000000000400758u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_add");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_add");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_add", output.llil_coverage*100.0);
}

#[test]
fn verify_test_and() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400864u64, 0xd10043ffu32),
        (0x0000000000400868u64, 0xb9000fe0u32),
        (0x000000000040086cu64, 0xb9000be1u32),
        (0x0000000000400870u64, 0xb9400fe1u32),
        (0x0000000000400874u64, 0xb9400be0u32),
        (0x0000000000400878u64, 0x0a000020u32),
        (0x000000000040087cu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_and");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_and");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_and", output.llil_coverage*100.0);
}

#[test]
fn verify_test_asr() {
    let insns: Vec<(u64, u32)> = vec![
        (0x000000000040091cu64, 0xd10043ffu32),
        (0x0000000000400920u64, 0xb9000fe0u32),
        (0x0000000000400924u64, 0xb9000be1u32),
        (0x0000000000400928u64, 0xb9400be0u32),
        (0x000000000040092cu64, 0xb9400fe1u32),
        (0x0000000000400930u64, 0x1ac02820u32),
        (0x0000000000400934u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_asr");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_asr");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_asr", output.llil_coverage*100.0);
}

#[test]
fn verify_test_bit_test() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400d30u64, 0xd10043ffu32),
        (0x0000000000400d34u64, 0xb9000fe0u32),
        (0x0000000000400d38u64, 0xb9400fe0u32),
        (0x0000000000400d3cu64, 0x121d0000u32),
        (0x0000000000400d40u64, 0x7100001fu32),
        (0x0000000000400d44u64, 0x54000060u32),
        (0x0000000000400d48u64, 0x52800020u32),
        (0x0000000000400d4cu64, 0x14000002u32),
        (0x0000000000400d50u64, 0x52800000u32),
        (0x0000000000400d54u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_bit_test");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_bit_test");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_bit_test", output.llil_coverage*100.0);
}

#[test]
fn verify_test_bitfield_extract() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400cf8u64, 0xd10043ffu32),
        (0x0000000000400cfcu64, 0xb9000fe0u32),
        (0x0000000000400d00u64, 0xb9400fe0u32),
        (0x0000000000400d04u64, 0x53047c00u32),
        (0x0000000000400d08u64, 0x12001c00u32),
        (0x0000000000400d0cu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_bitfield_extract");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_bitfield_extract");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_bitfield_extract", output.llil_coverage*100.0);
}

#[test]
fn verify_test_bitfield_sign_extend() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400d14u64, 0xd10043ffu32),
        (0x0000000000400d18u64, 0xb9000fe0u32),
        (0x0000000000400d1cu64, 0xb9400fe0u32),
        (0x0000000000400d20u64, 0x530c2c00u32),
        (0x0000000000400d24u64, 0x13147c00u32),
        (0x0000000000400d28u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_bitfield_sign_extend");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_bitfield_sign_extend");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_bitfield_sign_extend", output.llil_coverage*100.0);
}

#[test]
fn verify_test_call_eight_args() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400b20u64, 0xd10103ffu32),
        (0x0000000000400b24u64, 0xf9001fe0u32),
        (0x0000000000400b28u64, 0xf9001be1u32),
        (0x0000000000400b2cu64, 0xf90017e2u32),
        (0x0000000000400b30u64, 0xf90013e3u32),
        (0x0000000000400b34u64, 0xf9000fe4u32),
        (0x0000000000400b38u64, 0xf9000be5u32),
        (0x0000000000400b3cu64, 0xf90007e6u32),
        (0x0000000000400b40u64, 0xf90003e7u32),
        (0x0000000000400b44u64, 0xf9401fe1u32),
        (0x0000000000400b48u64, 0xf9401be0u32),
        (0x0000000000400b4cu64, 0x8b000021u32),
        (0x0000000000400b50u64, 0xf94017e0u32),
        (0x0000000000400b54u64, 0x8b000021u32),
        (0x0000000000400b58u64, 0xf94013e0u32),
        (0x0000000000400b5cu64, 0x8b000021u32),
        (0x0000000000400b60u64, 0xf9400fe0u32),
        (0x0000000000400b64u64, 0x8b000021u32),
        (0x0000000000400b68u64, 0xf9400be0u32),
        (0x0000000000400b6cu64, 0x8b000021u32),
        (0x0000000000400b70u64, 0xf94007e0u32),
        (0x0000000000400b74u64, 0x8b000021u32),
        (0x0000000000400b78u64, 0xf94003e0u32),
        (0x0000000000400b7cu64, 0x8b000020u32),
        (0x0000000000400b80u64, 0x910103ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_call_eight_args");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_call_eight_args");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_call_eight_args", output.llil_coverage*100.0);
}

#[test]
fn verify_test_call_four_args() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400ae8u64, 0xd10043ffu32),
        (0x0000000000400aecu64, 0xb9000fe0u32),
        (0x0000000000400af0u64, 0xb9000be1u32),
        (0x0000000000400af4u64, 0xb90007e2u32),
        (0x0000000000400af8u64, 0xb90003e3u32),
        (0x0000000000400afcu64, 0xb9400fe1u32),
        (0x0000000000400b00u64, 0xb9400be0u32),
        (0x0000000000400b04u64, 0x0b000021u32),
        (0x0000000000400b08u64, 0xb94007e0u32),
        (0x0000000000400b0cu64, 0x0b000021u32),
        (0x0000000000400b10u64, 0xb94003e0u32),
        (0x0000000000400b14u64, 0x0b000020u32),
        (0x0000000000400b18u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_call_four_args");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_call_four_args");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_call_four_args", output.llil_coverage*100.0);
}

#[test]
fn verify_test_call_two_args() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_call_two_args");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_call_two_args");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_call_two_args", output.llil_coverage*100.0);
}

#[test]
fn verify_test_csel() {
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
        (0x0000000000400f60u64, 0xb9400be0u32),
        (0x0000000000400f64u64, 0x910043ffu32),
        (0x0000000000400f68u64, 0xd65f03c0u32),
        (0x0000000000400f6cu64, 0xd10203ffu32),
        (0x0000000000400f70u64, 0xa9077bfdu32),
        (0x0000000000400f74u64, 0x9101c3fdu32),
        (0x0000000000400f78u64, 0xf00004e0u32),
        (0x0000000000400f7cu64, 0xf9462000u32),
        (0x0000000000400f80u64, 0xf9400001u32),
        (0x0000000000400f84u64, 0xf90037e1u32),
        (0x0000000000400f88u64, 0xd2800001u32),
        (0x0000000000400f8cu64, 0x52800081u32),
        (0x0000000000400f90u64, 0x52800060u32),
        (0x0000000000400f94u64, 0x97fffdebu32),
        (0x0000000000400f98u64, 0x2a0003e1u32),
        (0x0000000000400f9cu64, 0xb0000500u32),
        (0x0000000000400fa0u64, 0x91242000u32),
        (0x0000000000400fa4u64, 0xb9000001u32),
        (0x0000000000400fa8u64, 0x52800061u32),
        (0x0000000000400facu64, 0x52800140u32),
        (0x0000000000400fb0u64, 0x97fffdecu32),
        (0x0000000000400fb4u64, 0x2a0003e1u32),
        (0x0000000000400fb8u64, 0xb0000500u32),
        (0x0000000000400fbcu64, 0x91242000u32),
        (0x0000000000400fc0u64, 0xb9000001u32),
        (0x0000000000400fc4u64, 0x528000e1u32),
        (0x0000000000400fc8u64, 0x528000c0u32),
        (0x0000000000400fccu64, 0x97fffdedu32),
        (0x0000000000400fd0u64, 0x2a0003e1u32),
        (0x0000000000400fd4u64, 0xb0000500u32),
        (0x0000000000400fd8u64, 0x91242000u32),
        (0x0000000000400fdcu64, 0xb9000001u32),
        (0x0000000000400fe0u64, 0x528000a1u32),
        (0x0000000000400fe4u64, 0x52800c80u32),
        (0x0000000000400fe8u64, 0x97fffdeeu32),
        (0x0000000000400fecu64, 0x2a0003e1u32),
        (0x0000000000400ff0u64, 0xb0000500u32),
        (0x0000000000400ff4u64, 0x91242000u32),
        (0x0000000000400ff8u64, 0xb9000001u32),
        (0x0000000000400ffcu64, 0x528000a1u32),
        (0x0000000000401000u64, 0x52800c80u32),
        (0x0000000000401004u64, 0x97fffdefu32),
        (0x0000000000401008u64, 0x2a0003e1u32),
        (0x000000000040100cu64, 0x90000500u32),
        (0x0000000000401010u64, 0x91242000u32),
        (0x0000000000401014u64, 0xb9000001u32),
        (0x0000000000401018u64, 0x528000a1u32),
        (0x000000000040101cu64, 0x52800220u32),
        (0x0000000000401020u64, 0x97fffdf0u32),
        (0x0000000000401024u64, 0x2a0003e1u32),
        (0x0000000000401028u64, 0x90000500u32),
        (0x000000000040102cu64, 0x91242000u32),
        (0x0000000000401030u64, 0xb9000001u32),
        (0x0000000000401034u64, 0x5290d401u32),
        (0x0000000000401038u64, 0x72a00021u32),
        (0x000000000040103cu64, 0x5290d400u32),
        (0x0000000000401040u64, 0x72a00020u32),
        (0x0000000000401044u64, 0x97fffdf2u32),
        (0x0000000000401048u64, 0x2a0003e1u32),
        (0x000000000040104cu64, 0x90000500u32),
        (0x0000000000401050u64, 0x91242000u32),
        (0x0000000000401054u64, 0xb9000001u32),
        (0x0000000000401058u64, 0x5290d401u32),
        (0x000000000040105cu64, 0x72a00021u32),
        (0x0000000000401060u64, 0x5290d400u32),
        (0x0000000000401064u64, 0x72a00020u32),
        (0x0000000000401068u64, 0x97fffdf1u32),
        (0x000000000040106cu64, 0x2a0003e1u32),
        (0x0000000000401070u64, 0x90000500u32),
        (0x0000000000401074u64, 0x91242000u32),
        (0x0000000000401078u64, 0xb9000001u32),
        (0x000000000040107cu64, 0x52800540u32),
        (0x0000000000401080u64, 0x97fffdf3u32),
        (0x0000000000401084u64, 0x2a0003e1u32),
        (0x0000000000401088u64, 0x90000500u32),
        (0x000000000040108cu64, 0x91242000u32),
        (0x0000000000401090u64, 0xb9000001u32),
        (0x0000000000401094u64, 0x528001e1u32),
        (0x0000000000401098u64, 0x52801fe0u32),
        (0x000000000040109cu64, 0x97fffdf2u32),
        (0x00000000004010a0u64, 0x2a0003e1u32),
        (0x00000000004010a4u64, 0x90000500u32),
        (0x00000000004010a8u64, 0x91242000u32),
        (0x00000000004010acu64, 0xb9000001u32),
        (0x00000000004010b0u64, 0x528001e1u32),
        (0x00000000004010b4u64, 0x52801e00u32),
        (0x00000000004010b8u64, 0x97fffdf3u32),
        (0x00000000004010bcu64, 0x2a0003e1u32),
        (0x00000000004010c0u64, 0x90000500u32),
        (0x00000000004010c4u64, 0x91242000u32),
        (0x00000000004010c8u64, 0xb9000001u32),
        (0x00000000004010ccu64, 0x528001e1u32),
        (0x00000000004010d0u64, 0x52801fe0u32),
        (0x00000000004010d4u64, 0x97fffdf4u32),
        (0x00000000004010d8u64, 0x2a0003e1u32),
        (0x00000000004010dcu64, 0x90000500u32),
        (0x00000000004010e0u64, 0x91242000u32),
        (0x00000000004010e4u64, 0xb9000001u32),
        (0x00000000004010e8u64, 0x52800000u32),
        (0x00000000004010ecu64, 0x97fffdf6u32),
        (0x00000000004010f0u64, 0x2a0003e1u32),
        (0x00000000004010f4u64, 0x90000500u32),
        (0x00000000004010f8u64, 0x91242000u32),
        (0x00000000004010fcu64, 0xb9000001u32),
        (0x0000000000401100u64, 0x528000a1u32),
        (0x0000000000401104u64, 0x52800020u32),
        (0x0000000000401108u64, 0x97fffdf5u32),
        (0x000000000040110cu64, 0x2a0003e1u32),
        (0x0000000000401110u64, 0x90000500u32),
        (0x0000000000401114u64, 0x91242000u32),
        (0x0000000000401118u64, 0xb9000001u32),
        (0x000000000040111cu64, 0x52800041u32),
        (0x0000000000401120u64, 0x52800400u32),
        (0x0000000000401124u64, 0x97fffdf6u32),
        (0x0000000000401128u64, 0x2a0003e1u32),
        (0x000000000040112cu64, 0x90000500u32),
        (0x0000000000401130u64, 0x91242000u32),
        (0x0000000000401134u64, 0xb9000001u32),
        (0x0000000000401138u64, 0x52800041u32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_csel");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_csel");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_csel", output.llil_coverage*100.0);
}

#[test]
fn verify_test_div_s() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004007a0u64, 0xd10043ffu32),
        (0x00000000004007a4u64, 0xb9000fe0u32),
        (0x00000000004007a8u64, 0xb9000be1u32),
        (0x00000000004007acu64, 0xb9400fe1u32),
        (0x00000000004007b0u64, 0xb9400be0u32),
        (0x00000000004007b4u64, 0x1ac00c20u32),
        (0x00000000004007b8u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_div_s");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_div_s");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_div_s", output.llil_coverage*100.0);
}

#[test]
fn verify_test_div_u() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004007c0u64, 0xd10043ffu32),
        (0x00000000004007c4u64, 0xb9000fe0u32),
        (0x00000000004007c8u64, 0xb9000be1u32),
        (0x00000000004007ccu64, 0xb9400fe1u32),
        (0x00000000004007d0u64, 0xb9400be0u32),
        (0x00000000004007d4u64, 0x1ac00820u32),
        (0x00000000004007d8u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_div_u");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_div_u");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_div_u", output.llil_coverage*100.0);
}

#[test]
fn verify_test_do_while() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_do_while");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_do_while");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_do_while", output.llil_coverage*100.0);
}

#[test]
fn verify_test_factorial() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_factorial");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_factorial");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_factorial", output.llil_coverage*100.0);
}

#[test]
fn verify_test_for_loop() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_for_loop");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_for_loop");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_for_loop", output.llil_coverage*100.0);
}

#[test]
fn verify_test_if_else() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_if_else");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_if_else");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_if_else", output.llil_coverage*100.0);
}

#[test]
fn verify_test_if_nested() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400978u64, 0xd10043ffu32),
        (0x000000000040097cu64, 0xb9000fe0u32),
        (0x0000000000400980u64, 0xb9000be1u32),
        (0x0000000000400984u64, 0xb90007e2u32),
        (0x0000000000400988u64, 0xb9400fe1u32),
        (0x000000000040098cu64, 0xb9400be0u32),
        (0x0000000000400990u64, 0x6b00003fu32),
        (0x0000000000400994u64, 0x5400012du32),
        (0x0000000000400998u64, 0xb9400fe1u32),
        (0x000000000040099cu64, 0xb94007e0u32),
        (0x00000000004009a0u64, 0x6b00003fu32),
        (0x00000000004009a4u64, 0x5400006du32),
        (0x00000000004009a8u64, 0xb9400fe0u32),
        (0x00000000004009acu64, 0x1400000au32),
        (0x00000000004009b0u64, 0xb94007e0u32),
        (0x00000000004009b4u64, 0x14000008u32),
        (0x00000000004009b8u64, 0xb9400be1u32),
        (0x00000000004009bcu64, 0xb94007e0u32),
        (0x00000000004009c0u64, 0x6b00003fu32),
        (0x00000000004009c4u64, 0x5400006du32),
        (0x00000000004009c8u64, 0xb9400be0u32),
        (0x00000000004009ccu64, 0x14000002u32),
        (0x00000000004009d0u64, 0xb94007e0u32),
        (0x00000000004009d4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_if_nested");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_if_nested");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_if_nested", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ldrb() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400ec4u64, 0xd10043ffu32),
        (0x0000000000400ec8u64, 0xf90007e0u32),
        (0x0000000000400eccu64, 0xf94007e0u32),
        (0x0000000000400ed0u64, 0x39400000u32),
        (0x0000000000400ed4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ldrb");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ldrb");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ldrb", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ldrh() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400edcu64, 0xd10043ffu32),
        (0x0000000000400ee0u64, 0xf90007e0u32),
        (0x0000000000400ee4u64, 0xf94007e0u32),
        (0x0000000000400ee8u64, 0x79400000u32),
        (0x0000000000400eecu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ldrh");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ldrh");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ldrh", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ldrsb() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400e7cu64, 0xd10043ffu32),
        (0x0000000000400e80u64, 0xf90007e0u32),
        (0x0000000000400e84u64, 0xf94007e0u32),
        (0x0000000000400e88u64, 0x39c00000u32),
        (0x0000000000400e8cu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ldrsb");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ldrsb");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ldrsb", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ldrsh() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400e94u64, 0xd10043ffu32),
        (0x0000000000400e98u64, 0xf90007e0u32),
        (0x0000000000400e9cu64, 0xf94007e0u32),
        (0x0000000000400ea0u64, 0x79c00000u32),
        (0x0000000000400ea4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ldrsh");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ldrsh");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ldrsh", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ldrsw() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400eacu64, 0xd10043ffu32),
        (0x0000000000400eb0u64, 0xf90007e0u32),
        (0x0000000000400eb4u64, 0xf94007e0u32),
        (0x0000000000400eb8u64, 0xb9400000u32),
        (0x0000000000400ebcu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ldrsw");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ldrsw");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ldrsw", output.llil_coverage*100.0);
}

#[test]
fn verify_test_lsl() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004008dcu64, 0xd10043ffu32),
        (0x00000000004008e0u64, 0xb9000fe0u32),
        (0x00000000004008e4u64, 0xb9000be1u32),
        (0x00000000004008e8u64, 0xb9400be0u32),
        (0x00000000004008ecu64, 0xb9400fe1u32),
        (0x00000000004008f0u64, 0x1ac02020u32),
        (0x00000000004008f4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_lsl");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_lsl");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_lsl", output.llil_coverage*100.0);
}

#[test]
fn verify_test_lsr() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004008fcu64, 0xd10043ffu32),
        (0x0000000000400900u64, 0xb9000fe0u32),
        (0x0000000000400904u64, 0xb9000be1u32),
        (0x0000000000400908u64, 0xb9400fe1u32),
        (0x000000000040090cu64, 0xb9400be0u32),
        (0x0000000000400910u64, 0x1ac02420u32),
        (0x0000000000400914u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_lsr");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_lsr");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_lsr", output.llil_coverage*100.0);
}

#[test]
fn verify_test_mod_s() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004007e0u64, 0xd10043ffu32),
        (0x00000000004007e4u64, 0xb9000fe0u32),
        (0x00000000004007e8u64, 0xb9000be1u32),
        (0x00000000004007ecu64, 0xb9400fe0u32),
        (0x00000000004007f0u64, 0xb9400be1u32),
        (0x00000000004007f4u64, 0x1ac10c02u32),
        (0x00000000004007f8u64, 0xb9400be1u32),
        (0x00000000004007fcu64, 0x1b017c41u32),
        (0x0000000000400800u64, 0x4b010000u32),
        (0x0000000000400804u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_mod_s");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_mod_s");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_mod_s", output.llil_coverage*100.0);
}

#[test]
fn verify_test_mul() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400780u64, 0xd10043ffu32),
        (0x0000000000400784u64, 0xb9000fe0u32),
        (0x0000000000400788u64, 0xb9000be1u32),
        (0x000000000040078cu64, 0xb9400fe1u32),
        (0x0000000000400790u64, 0xb9400be0u32),
        (0x0000000000400794u64, 0x1b007c20u32),
        (0x0000000000400798u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_mul");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_mul");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_mul", output.llil_coverage*100.0);
}

#[test]
fn verify_test_mull() {
    let insns: Vec<(u64, u32)> = vec![
        (0x000000000040080cu64, 0xd10043ffu32),
        (0x0000000000400810u64, 0xb9000fe0u32),
        (0x0000000000400814u64, 0xb9000be1u32),
        (0x0000000000400818u64, 0xb9800fe1u32),
        (0x000000000040081cu64, 0xb9800be0u32),
        (0x0000000000400820u64, 0x9b007c20u32),
        (0x0000000000400824u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_mull");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_mull");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_mull", output.llil_coverage*100.0);
}

#[test]
fn verify_test_neg() {
    let insns: Vec<(u64, u32)> = vec![
        (0x000000000040084cu64, 0xd10043ffu32),
        (0x0000000000400850u64, 0xb9000fe0u32),
        (0x0000000000400854u64, 0xb9400fe0u32),
        (0x0000000000400858u64, 0x4b0003e0u32),
        (0x000000000040085cu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_neg");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_neg");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_neg", output.llil_coverage*100.0);
}

#[test]
fn verify_test_not() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004008c4u64, 0xd10043ffu32),
        (0x00000000004008c8u64, 0xb9000fe0u32),
        (0x00000000004008ccu64, 0xb9400fe0u32),
        (0x00000000004008d0u64, 0x2a2003e0u32),
        (0x00000000004008d4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_not");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_not");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_not", output.llil_coverage*100.0);
}

#[test]
fn verify_test_or() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400884u64, 0xd10043ffu32),
        (0x0000000000400888u64, 0xb9000fe0u32),
        (0x000000000040088cu64, 0xb9000be1u32),
        (0x0000000000400890u64, 0xb9400fe1u32),
        (0x0000000000400894u64, 0xb9400be0u32),
        (0x0000000000400898u64, 0x2a000020u32),
        (0x000000000040089cu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_or");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_or");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_or", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ptr_arith() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ptr_arith");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ptr_arith");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ptr_arith", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ptr_diff() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400db8u64, 0xd10043ffu32),
        (0x0000000000400dbcu64, 0xf90007e0u32),
        (0x0000000000400dc0u64, 0xf90003e1u32),
        (0x0000000000400dc4u64, 0xf94007e1u32),
        (0x0000000000400dc8u64, 0xf94003e0u32),
        (0x0000000000400dccu64, 0xcb000020u32),
        (0x0000000000400dd0u64, 0x9342fc00u32),
        (0x0000000000400dd4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ptr_diff");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ptr_diff");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ptr_diff", output.llil_coverage*100.0);
}

#[test]
fn verify_test_ptr_write() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400d84u64, 0xd10043ffu32),
        (0x0000000000400d88u64, 0xf90007e0u32),
        (0x0000000000400d8cu64, 0xb90007e1u32),
        (0x0000000000400d90u64, 0xb90003e2u32),
        (0x0000000000400d94u64, 0xb98007e0u32),
        (0x0000000000400d98u64, 0xd37ef400u32),
        (0x0000000000400d9cu64, 0xf94007e1u32),
        (0x0000000000400da0u64, 0x8b000020u32),
        (0x0000000000400da4u64, 0xb94003e1u32),
        (0x0000000000400da8u64, 0xb9000001u32),
        (0x0000000000400dacu64, 0xd503201fu32),
        (0x0000000000400db0u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_ptr_write");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_ptr_write");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_ptr_write", output.llil_coverage*100.0);
}

#[test]
fn verify_test_stack_spill() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_stack_spill");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_stack_spill");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_stack_spill", output.llil_coverage*100.0);
}

#[test]
fn verify_test_strb() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400ef4u64, 0xd10043ffu32),
        (0x0000000000400ef8u64, 0xf90007e0u32),
        (0x0000000000400efcu64, 0x39001fe1u32),
        (0x0000000000400f00u64, 0xf94007e0u32),
        (0x0000000000400f04u64, 0x39401fe1u32),
        (0x0000000000400f08u64, 0x39000001u32),
        (0x0000000000400f0cu64, 0xd503201fu32),
        (0x0000000000400f10u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_strb");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_strb");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_strb", output.llil_coverage*100.0);
}

#[test]
fn verify_test_strh() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400f18u64, 0xd10043ffu32),
        (0x0000000000400f1cu64, 0xf90007e0u32),
        (0x0000000000400f20u64, 0x79000fe1u32),
        (0x0000000000400f24u64, 0xf94007e0u32),
        (0x0000000000400f28u64, 0x79400fe1u32),
        (0x0000000000400f2cu64, 0x79000001u32),
        (0x0000000000400f30u64, 0xd503201fu32),
        (0x0000000000400f34u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_strh");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_strh");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_strh", output.llil_coverage*100.0);
}

#[test]
fn verify_test_struct_field_read() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400b88u64, 0xd10043ffu32),
        (0x0000000000400b8cu64, 0xf90007e0u32),
        (0x0000000000400b90u64, 0xf94007e0u32),
        (0x0000000000400b94u64, 0xb9400001u32),
        (0x0000000000400b98u64, 0xf94007e0u32),
        (0x0000000000400b9cu64, 0xb9400400u32),
        (0x0000000000400ba0u64, 0x0b000020u32),
        (0x0000000000400ba4u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_struct_field_read");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_struct_field_read");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_struct_field_read", output.llil_coverage*100.0);
}

#[test]
fn verify_test_struct_field_write() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400bacu64, 0xd10043ffu32),
        (0x0000000000400bb0u64, 0xf90007e0u32),
        (0x0000000000400bb4u64, 0xb90007e1u32),
        (0x0000000000400bb8u64, 0xf94007e0u32),
        (0x0000000000400bbcu64, 0xb94007e1u32),
        (0x0000000000400bc0u64, 0xb9000001u32),
        (0x0000000000400bc4u64, 0xb94007e0u32),
        (0x0000000000400bc8u64, 0x531f7801u32),
        (0x0000000000400bccu64, 0xf94007e0u32),
        (0x0000000000400bd0u64, 0xb9000401u32),
        (0x0000000000400bd4u64, 0xd503201fu32),
        (0x0000000000400bd8u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_struct_field_write");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_struct_field_write");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_struct_field_write", output.llil_coverage*100.0);
}

#[test]
fn verify_test_struct_nested_read() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400be0u64, 0xd10043ffu32),
        (0x0000000000400be4u64, 0xf90007e0u32),
        (0x0000000000400be8u64, 0xf94007e0u32),
        (0x0000000000400becu64, 0xf9400400u32),
        (0x0000000000400bf0u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_struct_nested_read");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_struct_nested_read");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_struct_nested_read", output.llil_coverage*100.0);
}

#[test]
fn verify_test_sub() {
    let insns: Vec<(u64, u32)> = vec![
        (0x0000000000400760u64, 0xd10043ffu32),
        (0x0000000000400764u64, 0xb9000fe0u32),
        (0x0000000000400768u64, 0xb9000be1u32),
        (0x000000000040076cu64, 0xb9400fe1u32),
        (0x0000000000400770u64, 0xb9400be0u32),
        (0x0000000000400774u64, 0x4b000020u32),
        (0x0000000000400778u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_sub");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_sub");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_sub", output.llil_coverage*100.0);
}

#[test]
fn verify_test_switch() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_switch");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_switch");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_switch", output.llil_coverage*100.0);
}

#[test]
fn verify_test_umull() {
    let insns: Vec<(u64, u32)> = vec![
        (0x000000000040082cu64, 0xd10043ffu32),
        (0x0000000000400830u64, 0xb9000fe0u32),
        (0x0000000000400834u64, 0xb9000be1u32),
        (0x0000000000400838u64, 0xb9400fe1u32),
        (0x000000000040083cu64, 0xb9400be0u32),
        (0x0000000000400840u64, 0x9b007c20u32),
        (0x0000000000400844u64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_umull");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_umull");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_umull", output.llil_coverage*100.0);
}

#[test]
fn verify_test_while_loop() {
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
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_while_loop");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_while_loop");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_while_loop", output.llil_coverage*100.0);
}

#[test]
fn verify_test_xor() {
    let insns: Vec<(u64, u32)> = vec![
        (0x00000000004008a4u64, 0xd10043ffu32),
        (0x00000000004008a8u64, 0xb9000fe0u32),
        (0x00000000004008acu64, 0xb9000be1u32),
        (0x00000000004008b0u64, 0xb9400fe1u32),
        (0x00000000004008b4u64, 0xb9400be0u32),
        (0x00000000004008b8u64, 0x4a000020u32),
        (0x00000000004008bcu64, 0x910043ffu32),
    ];
    let output = decompile_static(&insns);
    assert!(output.insn_count > 0, "no insns for test_xor");
    assert!(!output.hlil_text.is_empty(), "empty HLIL for test_xor");
    assert!(output.llil_coverage >= 0.90, "low coverage {:.1}% for test_xor", output.llil_coverage*100.0);
}

