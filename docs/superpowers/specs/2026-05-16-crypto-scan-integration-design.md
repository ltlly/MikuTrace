# Crypto Scan Integration Design

> Based on AlgoKiller `constscan` + `cryptoinstr`, integrated into traceMiku CLI + WebUI.

## Architecture

```
tracemiku-core::crypto_scan (complete fingerprints + capstone cache)
         │
    ┌────┴────┐
    │         │
tracemiku-cli   tracemiku-server
crypto <dir>    GET /api/crypto-analysis  (combined: mem + const + instr)
                GET /api/crypto-scan       (keep existing, backward compat)
                     │
              CryptoPanel.tsx  [Memory|Instructions|Hardware]
```

## 1. Core (`tracemiku-core::crypto_scan.rs`)

### 1.1 Missing fingerprints
- SHA-512 IV (8) + K table (80, low 32-bit)
- AES full sbox+inv_sbox (256+256, grouped by 4 bytes)
- SM4 full sbox (256) + CK (32)
- AES Te0-Te3 full tables (grouped)
- SHA-3 RC full 64-bit (24)
- Blake2b IV (8)
- XXH32/XXH64 primes, murmur3 constants

### 1.2 NEON SIMD detection
- New `Verdict::RealSimd` variant
- Match `movi v{}.{}s, #0x36` and `#0x5c` for HMAC ipad/opad SIMD broadcast

### 1.3 Capstone cache
- `OnceLock<Capstone>` cached instance, avoid per-instruction creation

### 1.4 `scan_combined()` 
- Single trace pass producing `ConstScanResult` + `CryptoInstrResult`

## 2. Server

### New route: `GET /api/crypto-analysis`
- Response: `{ mem_scan, const_scan, crypto_instrs }`
- `spawn_blocking` for trace scan; MemShadow may be async loading
- Cache result in `AppStateInner.crypto_scan` (type changed to new response)
- Keep existing `/api/crypto-scan` unchanged

### Type change
- `state.rs`: `crypto_scan: OnceLock<CryptoScanResponse>` → `OnceLock<CryptoAnalysisResponse>`

## 3. CLI

### Rust (`tracemiku-cli/src/main.rs`)
- Remove standalone `src/bin/crypto_scan.rs`
- Add `Cmd::Crypto` variant dispatching to `/api/crypto-analysis`

### Python (`./tracemiku`)
- Add `crypto <call_dir>` subcommand

## 4. Frontend (CryptoPanel)

### Location
- Left panel, new `"crypto"` tab in LeftTab type union

### Summary bar
- `const=0 + hw>0` → "Hardware Crypto (ARM CE)"
- `const>0 + hw=0` → "Software Crypto"
- `both>0` → "Mixed (HW + SW)"
- `both=0` → "None detected"

### Sub-tabs
1. **Memory** — Table: Address | Pattern Name | Algorithm | First Trace Idx. Color by algorithm family.
2. **Instructions** — Table: Idx | PC | Fingerprint | Verdict Badge | Sample Value. Hide `alu_only` by default (toggle). Green/Red/Yellow badges. Click row → jump trace cursor.
3. **Hardware** — Table: Mnemonic | Algorithm | Count | First Idx. Plus summary cards per algorithm family.

### Registration
- Import in App.tsx, extend LeftTab, add vtab call, add conditional panel render.
