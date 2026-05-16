# Crypto Scan Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate cryptographic constant scanning (constscan) and ARM Crypto Extensions detection (cryptoinstr) into traceMiku CLI and WebUI, inspired by AlgoKiller.

**Architecture:** Core `crypto_scan.rs` gains full fingerprint coverage, NEON SIMD detection, cached Capstone, and a single-pass `scan_combined()`. A new server route `/api/crypto-analysis` returns MemShadow + instruction-level + hardware results in one response. CLI dispatches to this route. Frontend CryptoPanel renders three sub-tabs (Memory / Instructions / Hardware) with algorithmic verdict.

**Tech Stack:** Rust (axum, capstone, serde), SolidJS + TypeScript, Python argparse.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `rust/crates/tracemiku-core/src/crypto_scan.rs` | Modify | Fingerprint DB, NEON detection, Capstone cache, scan_combined |
| `rust/crates/tracemiku-core/src/lib.rs` | Modify | Already has `pub mod crypto_scan;` (added, uncommitted) |
| `rust/crates/tracemiku-server/src/routes/crypto_analysis.rs` | Create | Combined `/api/crypto-analysis` handler |
| `rust/crates/tracemiku-server/src/routes/crypto_scan.rs` | Keep | Existing `/api/crypto-scan` unchanged |
| `rust/crates/tracemiku-server/src/routes/mod.rs` | Modify | Register `crypto_analysis` module + route |
| `rust/crates/tracemiku-server/src/state.rs` | Modify | Change `crypto_scan` type to new combined response |
| `rust/crates/tracemiku-server/src/lib.rs` | Keep | Already `pub mod crypto_scan;`, no change needed |
| `rust/crates/tracemiku-server/tests/crypto_scan_tests.rs` | Modify | Add tests for new endpoint |
| `rust/crates/tracemiku-cli/src/main.rs` | Modify | Add `Cmd::Crypto` variant + match arm |
| `rust/crates/tracemiku-cli/Cargo.toml` | Modify | Remove standalone `[[bin]] crypto_scan` |
| `rust/crates/tracemiku-cli/src/bin/crypto_scan.rs` | Delete | Replaced by Cmd::Crypto in main binary |
| `tracemiku` (Python) | Modify | Add `crypto <call_dir>` subcommand |
| `frontend/src/api/types.ts` | Modify | Add `CryptoAnalysisResponse` types |
| `frontend/src/api/client.ts` | Modify | Add `fetchCryptoAnalysis()` |
| `frontend/src/panels/crypto/CryptoPanel.tsx` | Create | New panel component |
| `frontend/src/App.tsx` | Modify | Register panel in tabs |

---

### Task 1: Core — Complete fingerprints, NEON, cache, scan_combined

**Files:**
- Modify: `rust/crates/tracemiku-core/src/crypto_scan.rs`

- [ ] **Step 1: Add missing fingerprint entries to `build_fingerprints()`**

After the existing ECC section (before the closing `fps`), add:

```rust
    // === SHA-512 ===
    let sha512_iv: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    for (i, &v) in sha512_iv.iter().enumerate() {
        fps.push(exact(&format!("SHA512.IV{}", i), Category::Hash, "SHA-512", v as u32));
    }
    // SHA-512 K[0..79] — keep low 32 bits (most distinctive)
    let sha512_k: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    ];
    for (i, &k) in sha512_k.iter().enumerate() {
        fps.push(exact(&format!("SHA512.K[{}]", i), Category::Hash, "SHA-512", k as u32));
    }

    // === Blake2b ===
    let blake2b_iv: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    for (i, &v) in blake2b_iv.iter().enumerate() {
        fps.push(exact(&format!("Blake2b.IV{}", i), Category::Hash, "Blake2b", v as u32));
    }

    // === AES sbox — grouped by 4 bytes for efficient matching ===
    let aes_sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];
    for chunk in aes_sbox.chunks(4) {
        let idx = (chunk[0] as usize).div_ceil(4).saturating_sub(1);
        let val = u32::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0), chunk.get(3).copied().unwrap_or(0)]);
        fps.push(exact(&format!("AES.sbox[{}..{}]", idx*4, idx*4+3), Category::SymCipher, "AES", val));
    }

    // === SM4 sbox — grouped by 4 bytes ===
    let sm4_sbox: [u8; 256] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
        0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
        0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
        0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
        0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
        0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
        0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
        0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
        0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
        0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
        0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
        0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
        0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
        0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
        0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
        0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ];
    for chunk in sm4_sbox.chunks(4) {
        let idx = (chunk[0] as usize).div_ceil(4).saturating_sub(1);
        let val = u32::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0), chunk.get(3).copied().unwrap_or(0)]);
        fps.push(exact(&format!("SM4.sbox[{}..{}]", idx*4, idx*4+3), Category::SymCipher, "SM4", val));
    }

    // === SM4 CK full table (32 entries) ===
    let sm4_ck_full: [u32; 32] = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x6c777e85, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1,
        0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
        0x484f565d, 0x646b7279, 0x80878e95, 0x9ca3aab1,
        0xb8bfc6cd, 0xd4dbe2e9, 0xf0f7fe05, 0x0c131a21,
        0x282f363d, 0x444b5259, 0x60676e75, 0x7c838a91,
        0x989fa6ad, 0xb4bbc2c9, 0xd0d7dee5, 0xecf3fa01,
        0x080f161d, 0x242b3239, 0x40474e55, 0x5c636a71,
    ];
    for (i, &ck) in sm4_ck_full.iter().enumerate() {
        fps.push(exact(&format!("SM4.CK[{}]", i), Category::SymCipher, "SM4", ck));
    }

    // === XXH32 primes ===
    fps.push(exact("XXH32.PRIME1", Category::Hash, "XXH32", 0x9e3779b1));
    fps.push(exact("XXH32.PRIME2", Category::Hash, "XXH32", 0x85ebca77));
    fps.push(exact("XXH32.PRIME3", Category::Hash, "XXH32", 0xc2b2ae3d));
    fps.push(exact("XXH32.PRIME4", Category::Hash, "XXH32", 0x27d4eb2f));
    fps.push(exact("XXH32.PRIME5", Category::Hash, "XXH32", 0x165667b1));

    // === XXH64 primes ===
    fps.push(exact("XXH64.PRIME1_lo", Category::Hash, "XXH64", 0x9e3779b1));
    fps.push(exact("XXH64.PRIME2_lo", Category::Hash, "XXH64", 0x85ebca77));
    fps.push(exact("XXH64.PRIME3_lo", Category::Hash, "XXH64", 0xc2b2ae3d));
    fps.push(exact("XXH64.PRIME4_lo", Category::Hash, "XXH64", 0x27d4eb2f));
    fps.push(exact("XXH64.PRIME5_lo", Category::Hash, "XXH64", 0x165667b1));

    // === MurmurHash3 ===
    fps.push(exact("Murmur3.c1", Category::Hash, "Murmur3", 0xcc9e2d51));
    fps.push(exact("Murmur3.c2", Category::Hash, "Murmur3", 0x1b873593));

    // === FNV-1a ===
    fps.push(exact("FNV32.offset", Category::Hash, "FNV-1a", 0x811c9dc5));
    fps.push(exact("FNV32.prime", Category::Hash, "FNV-1a", 0x01000193));
    fps.push(exact("FNV64.offset_lo", Category::Hash, "FNV-1a", 0xcbf29ce4));
    fps.push(exact("FNV64.prime_lo", Category::Hash, "FNV-1a", 0x000001b3));
```

- [ ] **Step 2: Add `Verdict::RealSimd` variant and NEON `movi` detection**

Add `RealSimd` to the `Verdict` enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Real,
    RealSimd,
    AluOnly,
    Weak,
}
```

Add NEON movi detection in `scan_constants()`. After the existing register value check (before `fp_hits` and `hits` push code), add:

```rust
        // NEON movi SIMD broadcast detection (HMAC ipad/opad)
        if mnem == "movi" {
            // Look for patterns like "v0.16b, #0x36" or "v0.4s, #0x5c"
            let maybe_n = op_str.split(',').nth(1).map(|s| s.trim().to_string());
            if let Some(imm_str) = maybe_n {
                let cleaned = imm_str.trim_start_matches('#').trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(cleaned, 16) {
                    if v == 0x36 {
                        let hit = ConstHit {
                            fingerprint: "HMAC.ipad.simd_movi".to_string(),
                            category: Category::Mac,
                            alg: "HMAC".to_string(),
                            idx: i,
                            pc: rec.pc,
                            source: ConstHitSource::Imm,
                            verdict: Verdict::RealSimd,
                            sample_value: v as u32,
                        };
                        fp_hits.entry("HMAC.ipad.simd_movi".to_string()).or_default().push(i);
                        hits.push(hit);
                    } else if v == 0x5c {
                        let hit = ConstHit {
                            fingerprint: "HMAC.opad.simd_movi".to_string(),
                            category: Category::Mac,
                            alg: "HMAC".to_string(),
                            idx: i,
                            pc: rec.pc,
                            source: ConstHitSource::Imm,
                            verdict: Verdict::RealSimd,
                            sample_value: v as u32,
                        };
                        fp_hits.entry("HMAC.opad.simd_movi".to_string()).or_default().push(i);
                        hits.push(hit);
                    }
                }
            }
        }
```

- [ ] **Step 3: Add cached Capstone instance**

Replace the `decode_inst()` function and add a cached instance:

```rust
use std::sync::OnceLock;

static CS: OnceLock<capstone::Capstone> = OnceLock::new();

fn cs() -> &'static capstone::Capstone {
    CS.get_or_init(|| {
        capstone::Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .expect("Capstone arm64 build")
    })
}

fn decode_inst(inst: u32) -> Option<(String, String)> {
    let insns = cs().disasm_all(&inst.to_le_bytes(), 0).ok()?;
    insns.first().map(|i| {
        (i.mnemonic().unwrap_or("").to_string(), i.op_str().unwrap_or("").to_string())
    })
}
```

- [ ] **Step 4: Add `scan_combined()` single-pass function**

After the existing `scan_crypto_instrs()` function, add:

```rust
/// Single-pass combined scan: const scan + crypto instr scan.
pub fn scan_combined(trace: &Trace) -> (ConstScanResult, CryptoInstrResult) {
    let fingerprints = build_fingerprints();
    let mut const_hits: Vec<ConstHit> = Vec::new();
    let mut fp_hits: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut mnem_counts: BTreeMap<String, (usize, Option<usize>, Vec<usize>)> = BTreeMap::new();
    let alu_set: std::collections::HashSet<&str> = ALU_MNEMS.iter().copied().collect();
    let imm_load_set: std::collections::HashSet<&str> = IMM_LOAD_MNEMS.iter().copied().collect();
    let crypto_mnem_set: std::collections::HashSet<&str> = CRYPTO_INSTRS.iter().map(|&(m, _)| m).collect();

    for i in 0..trace.len() {
        let rec = trace.record(i);
        let inst = rec.inst;

        let (mnem, op_str) = match decode_inst(inst) {
            Some(d) => d,
            None => continue,
        };

        let is_alu = alu_set.contains(mnem.as_str());
        let is_imm_load = imm_load_set.iter().any(|&m| mnem.starts_with(m));

        // --- Crypto instruction detection ---
        if crypto_mnem_set.contains(mnem.as_str()) {
            let entry = mnem_counts.entry(mnem.clone()).or_insert((0, None, Vec::new()));
            entry.0 += 1;
            if entry.1.is_none() { entry.1 = Some(i); }
            if entry.2.len() < 10 { entry.2.push(i); }
        }

        // --- NEON movi detection ---
        if mnem == "movi" {
            let imm_str = op_str.split(',').nth(1).map(|s| s.trim());
            if let Some(s) = imm_str {
                let cleaned = s.trim_start_matches('#').trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(cleaned, 16) {
                    let (name, verdict_val) = if v == 0x36 {
                        ("HMAC.ipad.simd_movi", v as u32)
                    } else if v == 0x5c {
                        ("HMAC.opad.simd_movi", v as u32)
                    } else {
                        continue;
                    };
                    let hit = ConstHit {
                        fingerprint: name.to_string(),
                        category: Category::Mac,
                        alg: "HMAC".to_string(),
                        idx: i, pc: rec.pc,
                        source: ConstHitSource::Imm,
                        verdict: Verdict::RealSimd,
                        sample_value: verdict_val,
                    };
                    fp_hits.entry(name.to_string()).or_default().push(i);
                    const_hits.push(hit);
                    continue;
                }
            }
        }

        // --- Immediate operand const scan ---
        let imms = extract_imm32(&op_str);
        for &imm in &imms {
            if imm == 0 { continue; }
            for fp in &fingerprints {
                if (imm & fp.mask) == fp.value {
                    let verdict = if is_imm_load { Verdict::Real } else if is_alu { Verdict::AluOnly } else { Verdict::Real };
                    let hit = ConstHit {
                        fingerprint: fp.name.clone(),
                        category: fp.category, alg: fp.alg.clone(),
                        idx: i, pc: rec.pc, source: ConstHitSource::Imm,
                        verdict, sample_value: imm,
                    };
                    fp_hits.entry(fp.name.clone()).or_default().push(i);
                    const_hits.push(hit);
                }
            }
        }

        // --- Register value const scan ---
        if !is_alu {
            for reg_idx in 0..31 {
                let val = rec.regs[reg_idx] as u32;
                if val == 0 { continue; }
                for fp in &fingerprints {
                    if (val & fp.mask) == fp.value {
                        let hit = ConstHit {
                            fingerprint: fp.name.clone(),
                            category: fp.category, alg: fp.alg.clone(),
                            idx: i, pc: rec.pc, source: ConstHitSource::Reg,
                            verdict: Verdict::Real, sample_value: val,
                        };
                        fp_hits.entry(fp.name.clone()).or_default().push(i);
                        const_hits.push(hit);
                    }
                }
            }
        }
    }

    // Build const scan summaries
    let mut summaries: Vec<FingerprintSummary> = fingerprints.iter().map(|fp| {
        let idxs = fp_hits.get(&fp.name).cloned().unwrap_or_default();
        FingerprintSummary {
            name: fp.name.clone(), category: fp.category, alg: fp.alg.clone(),
            total_hits: idxs.len(), first_idx: idxs.first().copied(),
            sample_idxs: idxs.iter().take(10).copied().collect(),
            verdict: if idxs.is_empty() { Verdict::Weak } else { Verdict::Real },
        }
    }).collect();
    summaries.sort_by(|a, b| b.total_hits.cmp(&a.total_hits));

    let const_result = ConstScanResult {
        hits: const_hits,
        summaries,
        records_scanned: trace.len(),
    };

    // Build crypto instr result
    let instr_hits: Vec<CryptoInstrHit> = mnem_counts.into_iter().map(|(mnem, (count, first_idx, sample_idxs))| {
        let alg = CRYPTO_INSTRS.iter()
            .find(|&&(m, _)| m == mnem)
            .map(|&(_, a)| a.to_string())
            .unwrap_or_default();
        CryptoInstrHit { mnemonic: mnem, alg, count, first_idx, sample_idxs }
    }).collect();

    let instr_result = CryptoInstrResult {
        hits: instr_hits,
        records_scanned: trace.len(),
    };

    (const_result, instr_result)
}
```

- [ ] **Step 5: Update `scan_constants` to delegate to `scan_combined`**

```rust
pub fn scan_constants(trace: &Trace) -> ConstScanResult {
    scan_combined(trace).0
}

pub fn scan_crypto_instrs(trace: &Trace) -> CryptoInstrResult {
    scan_combined(trace).1
}
```

- [ ] **Step 6: Build check**

Run: `cargo check -p tracemiku-core`
Expected: Compiles without errors.

- [ ] **Step 7: Run existing tests**

Run: `cargo test -p tracemiku-core -- crypto_scan`
Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add rust/crates/tracemiku-core/src/crypto_scan.rs
git commit -m "feat: complete crypto fingerprints, NEON simd, Capstone cache, scan_combined

Adds SHA-512, Blake2b, AES sbox (256), SM4 sbox/CK, XXH32/64,
Murmur3, FNV constants. Adds NEON movi detection for HMAC SIMD
broadcast with Verdict::RealSimd. Caches Capstone instance.
Single-pass scan_combined() does const + instr in one traversal."
```

---

### Task 2: Server — New `/api/crypto-analysis` route + state update

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/crypto_analysis.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs:11,79`
- Modify: `rust/crates/tracemiku-server/src/state.rs:83`
- Modify: `rust/crates/tracemiku-server/tests/crypto_scan_tests.rs` (add new endpoint tests)

- [ ] **Step 1: Create `routes/crypto_analysis.rs`**

```rust
//! GET /api/crypto-analysis — combined crypto scan (mem + const + instr).
//!
//! Returns MemShadow byte-pattern matches, instruction-level cryptographic
//! constant hits (with verdict classification), and ARM Crypto Extensions
//! hardware instruction counts.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use tracemiku_core::crypto_scan::{
    ConstScanResult, CryptoInstrResult,
};
use crate::crypto_scan::{scan_crypto_memory, CryptoScanResponse};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAnalysisResponse {
    pub mem_scan: CryptoScanResponse,
    pub const_scan: ConstScanResult,
    pub crypto_instrs: CryptoInstrResult,
}

pub async fn crypto_analysis_handler(
    State(state): State<AppState>,
) -> Result<Json<CryptoAnalysisResponse>, StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || crypto_analysis(&inner))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn crypto_analysis(inner: &crate::state::AppStateInner) -> Result<CryptoAnalysisResponse, StatusCode> {
    let mem_scan = {
        let mem = inner.memshadow_ready_or_block_if_idle()
            .map_err(|status| {
                tracing::warn!(target: "tracemiku-server", "crypto-analysis: MemShadow {status}");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        if mem.bytes.is_empty() {
            CryptoScanResponse {
                status: "ready",
                scanned: 0,
                primitives: Vec::new(),
                any_hit: false,
            }
        } else {
            scan_crypto_memory(mem)
        }
    };

    let (const_scan, crypto_instrs) =
        tracemiku_core::crypto_scan::scan_combined(&inner.trace);

    Ok(CryptoAnalysisResponse {
        mem_scan,
        const_scan,
        crypto_instrs,
    })
}
```

- [ ] **Step 2: Register route in `routes/mod.rs`**

Add after `pub mod crypto_scan;`:
```rust
pub mod crypto_analysis;
```

Add after `.route("/api/crypto-scan", ...)`:
```rust
        .route(
            "/api/crypto-analysis",
            get(crypto_analysis::crypto_analysis_handler),
        )
```

- [ ] **Step 3: Update state type in `state.rs`**

Change line 83 from:
```rust
    pub(crate) crypto_scan: OnceLock<crate::crypto_scan::CryptoScanResponse>,
```
to:
```rust
    pub(crate) crypto_analysis: OnceLock<crate::routes::crypto_analysis::CryptoAnalysisResponse>,
```

In the `AppStateInner` constructor (around line 242), change:
```rust
            crypto_scan: OnceLock::new(),
```
to:
```rust
            crypto_analysis: OnceLock::new(),
```

- [ ] **Step 4: Build check**

Run: `cargo check -p tracemiku-server`
Expected: Compiles without errors.

- [ ] **Step 5: Add integration test**

In `rust/crates/tracemiku-server/tests/crypto_scan_tests.rs`, add:

```rust
#[tokio::test]
async fn crypto_analysis_returns_all_three_scan_types() {
    let (_tmp, cd) = synth_call_dir(0x67452301);
    let (status, v) = get(cd, "/api/crypto-analysis").await;
    assert_eq!(status, StatusCode::OK);
    // Check mem_scan present
    assert!(v["mem_scan"]["scanned"].as_u64().unwrap() > 0);
    assert!(v["mem_scan"]["primitives"].is_array());
    // Check const_scan present
    assert!(v["const_scan"]["records_scanned"].as_u64().unwrap() > 0);
    assert!(v["const_scan"]["hits"].is_array());
    assert!(v["const_scan"]["summaries"].is_array());
    // Check crypto_instrs present
    assert!(v["crypto_instrs"]["records_scanned"].as_u64().unwrap() > 0);
    assert!(v["crypto_instrs"]["hits"].is_array());
}
```

- [ ] **Step 6: Run all crypto tests**

Run: `cargo test -p tracemiku-server -- crypto`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-server/src/routes/crypto_analysis.rs rust/crates/tracemiku-server/src/routes/mod.rs rust/crates/tracemiku-server/src/state.rs rust/crates/tracemiku-server/tests/crypto_scan_tests.rs
git commit -m "feat: add /api/crypto-analysis combined endpoint (mem+const+instr)

New route returns MemShadow byte-pattern hits, instruction-level
crypto constant hits (with verdict), and ARM Crypto Extensions
hardware instruction counts in a single response."
```

---

### Task 3: CLI — Integrate into main.rs and ./tracemiku

**Files:**
- Modify: `rust/crates/tracemiku-cli/src/main.rs`
- Modify: `rust/crates/tracemiku-cli/Cargo.toml`
- Delete: `rust/crates/tracemiku-cli/src/bin/crypto_scan.rs`
- Modify: `tracemiku` (Python script)

- [ ] **Step 1: Delete standalone binary**

```bash
rm rust/crates/tracemiku-cli/src/bin/crypto_scan.rs
```

- [ ] **Step 2: Remove [[bin]] from Cargo.toml**

In `rust/crates/tracemiku-cli/Cargo.toml`, remove the `[[bin]]` section for `crypto_scan`.

- [ ] **Step 3: Add `Cmd::Crypto` variant to main.rs**

In the `Cmd` enum, add after the existing variants:

```rust
    /// Run combined crypto analysis (const scan + crypto instr detection).
    Crypto {
        /// Per-call trace directory.
        trace_dir: PathBuf,
    },
```

- [ ] **Step 4: Add match arm in `main()`**

In `async fn main()`, after another match arm, add:

```rust
        Some(Cmd::Crypto { trace_dir }) => {
            route_get_json(trace_dir, "/api/crypto-analysis".to_string()).await
        }
```

- [ ] **Step 5: Wire into Python `./tracemiku`**

Add a new `crypto` subcommand to the Python argparse. Near the other subparsers:

```python
    # crypto
    p_crypto = sub.add_parser("crypto", help="Combined crypto analysis: constant scan + ARM CE detection")
    p_crypto.add_argument("call_dir", help="Per-call trace directory")
```

And in the dispatch:

```python
    if args.cmd == "crypto":
        return _run_rust_cli(["crypto", args.call_dir])
```

- [ ] **Step 6: Build check**

Run: `cargo check -p tracemiku-cli`
Expected: Compiles without errors.

- [ ] **Step 7: Smoke test CLI**

Run: `cargo run -p tracemiku-cli -- crypto /path/to/a/call_dir` (use a real call dir if available)
Expected: JSON output with mem_scan, const_scan, crypto_instrs fields.

- [ ] **Step 8: Commit**

```bash
git add -u rust/crates/tracemiku-cli/ tracemiku
git commit -m "feat: integrate crypto scan into CLI (tracemiku crypto <dir>)"
```

---

### Task 4: Frontend — Types, Client, CryptoPanel, App registration

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`
- Create: `frontend/src/panels/crypto/CryptoPanel.tsx`
- Create: `frontend/src/panels/crypto/CryptoPanel.css`
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Add TypeScript types in `api/types.ts`**

Add at the end of the file:

```typescript
// ── /api/crypto-analysis ─────────────────────────────────────────────────

export interface CryptoMemHit {
  addr: string;
  first_idx: number | null;
}

export interface CryptoMemPrimitive {
  name: string;
  pattern: string;
  hit_count: number;
  hits: CryptoMemHit[];
}

export interface CryptoMemScan {
  status: string;
  scanned: number;
  primitives: CryptoMemPrimitive[];
  any_hit: boolean;
}

export type ConstHitSource = "imm" | "reg" | "mem_r";
export type ConstHitVerdict = "real" | "real_simd" | "alu_only" | "weak";
export type ConstCategory = "hash" | "sym_cipher" | "ecc" | "crc" | "mac";

export interface ConstHit {
  fingerprint: string;
  category: ConstCategory;
  alg: string;
  idx: number;
  pc: string;
  source: ConstHitSource;
  verdict: ConstHitVerdict;
  sample_value: number;
}

export interface FingerprintSummary {
  name: string;
  category: ConstCategory;
  alg: string;
  total_hits: number;
  first_idx: number | null;
  sample_idxs: number[];
  verdict: ConstHitVerdict;
}

export interface ConstScanResult {
  hits: ConstHit[];
  summaries: FingerprintSummary[];
  records_scanned: number;
}

export interface CryptoInstrHit {
  mnemonic: string;
  alg: string;
  count: number;
  first_idx: number | null;
  sample_idxs: number[];
}

export interface CryptoInstrResult {
  hits: CryptoInstrHit[];
  records_scanned: number;
}

export interface CryptoAnalysisResponse {
  mem_scan: CryptoMemScan;
  const_scan: ConstScanResult;
  crypto_instrs: CryptoInstrResult;
}
```

- [ ] **Step 2: Add client function in `api/client.ts`**

In imports, add `CryptoAnalysisResponse` from `"./types"`. At bottom of file:

```typescript
export async function fetchCryptoAnalysis(): Promise<CryptoAnalysisResponse> {
  const r = await fx("/api/crypto-analysis");
  if (!r.ok) throw new Error(`/api/crypto-analysis ${r.status}: ${await r.text()}`);
  return (await r.json()) as CryptoAnalysisResponse;
}
```

- [ ] **Step 3: Create `CryptoPanel.tsx`**

```typescript
//! CryptoPanel — combined crypto analysis display
//! Sub-tabs: Memory (MemShadow byte patterns), Instructions (trace const hits),
//! Hardware (ARM Crypto Extensions mnemonics)

import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { fetchCryptoAnalysis } from "~/api/client";
import type {
  CryptoAnalysisResponse,
  CryptoMemPrimitive,
  FingerprintSummary,
  CryptoInstrHit,
  ConstHitVerdict,
} from "~/api/types";
import "./CryptoPanel.css";

interface CryptoPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

type SubTab = "memory" | "instructions" | "hardware";

const CATEGORY_COLORS: Record<string, string> = {
  hash: "#4a9eff",
  sym_cipher: "#ff6b6b",
  ecc: "#ffd93d",
  crc: "#6bcb77",
  mac: "#c084fc",
};

const VERDICT_COLORS: Record<ConstHitVerdict, string> = {
  real: "#2ecc71",
  real_simd: "#3498db",
  alu_only: "#e74c3c",
  weak: "#f39c12",
};

const VERDICT_LABELS: Record<ConstHitVerdict, string> = {
  real: "Real",
  real_simd: "SIMD",
  alu_only: "ALU",
  weak: "Weak",
};

function verdictBadge(v: ConstHitVerdict) {
  return (
    <span
      class="verdict-badge"
      style={{ background: VERDICT_COLORS[v] }}
    >
      {VERDICT_LABELS[v]}
    </span>
  );
}

export default function CryptoPanel(props: CryptoPanelProps) {
  const [subTab, setSubTab] = createSignal<SubTab>("memory");
  const [showAluOnly, setShowAluOnly] = createSignal(false);

  const [resp] = createResource(
    () => props.active,
    async (active) => {
      if (!active) return undefined;
      return fetchCryptoAnalysis();
    },
  );

  // Summary verdict string
  const summaryVerdict = createMemo(() => {
    const r = resp();
    if (!r) return "";
    const constHits = r.const_scan.summaries.filter(
      (s) => s.verdict === "real" || s.verdict === "real_simd",
    ).length;
    const hwHits = r.crypto_instrs.hits.length;
    if (constHits === 0 && hwHits === 0) return "None detected";
    if (constHits > 0 && hwHits === 0) return "Software Crypto";
    if (constHits === 0 && hwHits > 0) return "Hardware Crypto (ARM CE)";
    return "Mixed (HW + SW)";
  });

  // Top-N detected algorithms
  const detectedAlgs = createMemo(() => {
    const r = resp();
    if (!r) return [];
    const algs: Record<string, number> = {};
    for (const s of r.const_scan.summaries) {
      if (s.total_hits > 0 && s.verdict !== "alu_only") {
        algs[s.alg] = (algs[s.alg] || 0) + s.total_hits;
      }
    }
    for (const h of r.crypto_instrs.hits) {
      algs[h.alg] = (algs[h.alg] || 0) + h.count;
    }
    return Object.entries(algs)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  });

  const filteredSummaries = createMemo(() => {
    const r = resp();
    if (!r) return [];
    return r.const_scan.summaries.filter(
      (s) => showAluOnly() || s.verdict !== "alu_only" || s.total_hits > 0,
    );
  });

  return (
    <section class="panel crypto-panel">
      {/* Summary bar */}
      <Show when={resp()}>
        <div class="crypto-summary">
          <span class="crypto-verdict">{summaryVerdict()}</span>
          <span class="crypto-algs">
            <For each={detectedAlgs()}>
              {([alg, count]) => (
                <span class="crypto-alg-tag" style={{ background: CATEGORY_COLORS[alg] || "#888" }}>
                  {alg}: {count}
                </span>
              )}
            </For>
          </span>
        </div>
      </Show>

      {/* Sub-tabs */}
      <div class="crypto-subtabs">
        <button
          classList={{ active: subTab() === "memory" }}
          onClick={() => setSubTab("memory")}
        >
          Memory
        </button>
        <button
          classList={{ active: subTab() === "instructions" }}
          onClick={() => setSubTab("instructions")}
        >
          Instructions
        </button>
        <button
          classList={{ active: subTab() === "hardware" }}
          onClick={() => setSubTab("hardware")}
        >
          Hardware
        </button>
      </div>

      {/* Loading / Error */}
      <Show when={resp.loading}>
        <p class="dim">loading crypto analysis...</p>
      </Show>
      <Show when={resp.error}>
        <p class="err">failed: {String(resp.error)}</p>
      </Show>

      <Show when={resp()}>
        {(r) => (
          <>
            {/* Memory sub-tab */}
            <Show when={subTab() === "memory"}>
              <div class="crypto-table-wrap">
                <table class="crypto-table">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Pattern</th>
                      <th>Algorithm</th>
                      <th>First Idx</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().mem_scan.primitives.filter((p) => p.hit_count > 0)}>
                      {(p: CryptoMemPrimitive) => (
                        <For each={p.hits}>
                          {(hit) => (
                            <tr
                              class="clickable"
                              onClick={() => hit.first_idx != null && props.onSelect(hit.first_idx)}
                            >
                              <td class="mono">{hit.addr}</td>
                              <td>{p.name}</td>
                              <td>
                                <span
                                  class="alg-dot"
                                  style={{ background: CATEGORY_COLORS[p.name] || "#888" }}
                                />
                                {inferAlg(p.name)}
                              </td>
                              <td class="mono">{hit.first_idx ?? "-"}</td>
                            </tr>
                          )}
                        </For>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>

            {/* Instructions sub-tab */}
            <Show when={subTab() === "instructions"}>
              <label class="crypto-toggle">
                <input
                  type="checkbox"
                  checked={showAluOnly()}
                  onChange={(e) => setShowAluOnly(e.currentTarget.checked)}
                />
                show ALU-only (high false-positive rate)
              </label>
              <div class="crypto-summary-list">
                <For each={filteredSummaries().filter((s) => s.total_hits > 0)}>
                  {(s: FingerprintSummary) => (
                    <div class="crypto-summary-row">
                      <span class="mono">{s.name}</span>
                      <span style={{ color: CATEGORY_COLORS[s.category] || "#888" }}>{s.alg}</span>
                      {verdictBadge(s.verdict)}
                      <span>{s.total_hits} hits</span>
                      <span class="dim">
                        first: {s.first_idx != null ? `#${s.first_idx}` : "-"}
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>

            {/* Hardware sub-tab */}
            <Show when={subTab() === "hardware"}>
              <div class="crypto-table-wrap">
                <table class="crypto-table">
                  <thead>
                    <tr>
                      <th>Mnemonic</th>
                      <th>Algorithm</th>
                      <th>Count</th>
                      <th>First Idx</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().crypto_instrs.hits}>
                      {(h: CryptoInstrHit) => (
                        <tr
                          class="clickable"
                          onClick={() => h.first_idx != null && props.onSelect(h.first_idx)}
                        >
                          <td class="mono">{h.mnemonic}</td>
                          <td>{h.alg}</td>
                          <td>{h.count}</td>
                          <td class="mono">{h.first_idx ?? "-"}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
              <Show when={r().crypto_instrs.hits.length === 0}>
                <p class="dim">No ARM Crypto Extensions instructions detected.</p>
              </Show>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}

function inferAlg(name: string): string {
  if (name.startsWith("SHA1_")) return "SHA-1";
  if (name.startsWith("SHA256_")) return "SHA-256";
  if (name.startsWith("SHA512_")) return "SHA-512";
  if (name.startsWith("MD5_")) return "MD5";
  if (name.startsWith("AES_")) return "AES";
  if (name.startsWith("SM3_") || name.startsWith("SM4_")) return name.split("_")[0];
  if (name.startsWith("CHACHA20_")) return "ChaCha20";
  if (name.startsWith("HMAC_")) return "HMAC";
  if (name.startsWith("CRC32")) return "CRC32";
  if (name.startsWith("XXH")) return name.split("_")[0];
  if (name.startsWith("Murmur3")) return "Murmur3";
  return "";
}
```

- [ ] **Step 4: Create `CryptoPanel.css`**

```css
.crypto-panel { display: flex; flex-direction: column; gap: 4px; overflow: hidden; }

.crypto-summary {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 8px; background: #1a1a2e; border-radius: 4px;
  flex-shrink: 0;
}
.crypto-verdict { font-weight: 600; font-size: 0.95em; }
.crypto-algs { display: flex; gap: 4px; flex-wrap: wrap; }
.crypto-alg-tag {
  padding: 1px 6px; border-radius: 3px;
  font-size: 0.78em; color: #fff;
}

.crypto-subtabs {
  display: flex; gap: 2px; flex-shrink: 0;
}
.crypto-subtabs button {
  padding: 3px 10px; border: none; background: #2a2a3e;
  color: #aaa; cursor: pointer; font-size: 0.82em;
  border-radius: 3px 3px 0 0;
}
.crypto-subtabs button.active { background: #3a3a5e; color: #fff; }

.crypto-table-wrap { overflow: auto; flex: 1; }
.crypto-table { width: 100%; border-collapse: collapse; font-size: 0.82em; }
.crypto-table th { text-align: left; padding: 4px 6px; border-bottom: 1px solid #333; color: #888; position: sticky; top: 0; background: #1e1e2e; }
.crypto-table td { padding: 3px 6px; border-bottom: 1px solid #222; }
.crypto-table tr.clickable { cursor: pointer; }
.crypto-table tr.clickable:hover { background: #2a2a4e; }

.verdict-badge {
  display: inline-block; padding: 0 6px; border-radius: 3px;
  font-size: 0.72em; font-weight: 600; color: #fff; text-transform: uppercase;
}

.crypto-summary-list { overflow: auto; flex: 1; display: flex; flex-direction: column; gap: 2px; }
.crypto-summary-row {
  display: flex; align-items: center; gap: 8px;
  padding: 2px 6px; border-radius: 3px; font-size: 0.82em;
}
.crypto-summary-row:hover { background: #2a2a4e; }
.crypto-summary-row .mono { min-width: 120px; }
.crypto-summary-row .dim { margin-left: auto; }

.crypto-toggle { font-size: 0.78em; color: #888; flex-shrink: 0; display: flex; align-items: center; gap: 4px; }
.crypto-toggle input { margin: 0; }

.alg-dot {
  display: inline-block; width: 6px; height: 6px; border-radius: 50%;
  margin-right: 4px; vertical-align: middle;
}
```

- [ ] **Step 5: Register in App.tsx**

Add import at top:
```typescript
import CryptoPanel from "./panels/crypto/CryptoPanel";
```

Add `"crypto"` to the `LeftTab` type union.

Add leftTitle mapping:
```typescript
    crypto: "Crypto",
```

Add vtab call after the settings tab:
```tsx
{vtab("crypto", "Crypto", "密码学常数扫描 + ARM CE 检测")}
```

Add help body:
```typescript
    if (leftTab() === "crypto") return "Crypto 面板整合了三层密码学检测：Memory（MemShadow 字节级常数匹配）、Instructions（trace 指令级立即数/寄存器常数命中，带 Real/ALU/Weak 判定）、Hardware（ARM Crypto Extensions 硬件指令统计）。Summary bar 给出综合判定（Software/Hardware/Mixed/None）。";
```

Add panel render in `left-panel-body` before the closing `</div>`:
```tsx
            <div class="lp-tab" classList={{ active: leftTab() === "crypto" }}>
              <CryptoPanel
                idx={selectedIdx()}
                onSelect={setSelectedIdx}
                active={leftTab() === "crypto"}
              />
            </div>
```

- [ ] **Step 6: Build frontend**

Run: `cd frontend && npm run build`
Expected: Builds without errors.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api/types.ts frontend/src/api/client.ts frontend/src/panels/crypto/ frontend/src/App.tsx
git commit -m "feat: add CryptoPanel with Memory/Instructions/Hardware sub-tabs

CryptoPanel integrates three crypto detection layers:
- Memory tab: MemShadow byte-level constant pattern matches
- Instructions tab: trace instruction-level const hits with verdict badges
- Hardware tab: ARM Crypto Extensions instruction counts
Summary bar provides automatic Software/Hardware/Mixed/None verdict."
```

---

### Task 5: End-to-end verification

- [ ] **Step 1: Run full test suite**

```bash
cd rust && cargo test -p tracemiku-core && cargo test -p tracemiku-server && cargo test -p tracemiku-cli && cd ../frontend && npm run build
```

Expected: All tests pass, frontend builds clean.

- [ ] **Step 2: Smoke test server**

Run: `cd rust && cargo run -p tracemiku-server -- <call_dir> --port 18901` (if available), then:
`curl -s http://127.0.0.1:18901/api/crypto-analysis | jq '.mem_scan.any_hit, .const_scan.records_scanned, .crypto_instrs.hits | length'`

Expected: Valid JSON response.

- [ ] **Step 3: Smoke test CLI**

Run: `cargo run -p tracemiku-cli -- crypto <call_dir> | head -20`
Expected: JSON with mem_scan, const_scan, crypto_instrs fields.

- [ ] **Step 4: Final commit (if any fixes)**

```bash
git status
# commit any remaining fixes
```
