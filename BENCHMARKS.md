# traceMiku 性能基准 (实测)

> 测试设备: Pixel 7 (Tensor G2) / Android 16 / arm64
> frida-server: stealth build (codeslab fallback + anti-detect 重命名), `/data/local/tmp/.miku-srv`
> 目标: com.taobao.taobao 10.60.10 (libsgmainso-6.8.260403.so)
> 函数: doCommandNative @ +0x57770 (`fnOffset`), cmd 70102

## 1. trace mode 对比 — 完整 cold-launch (`--cold-launch`, dropped=0 是硬要求)

| mode | 架构 | 实测 rate | 完整 6.8M records 时长 | dropped | 完整性 |
|---|---|---:|---:|---:|---|
| `js` (baseline) | JS putCallout, host send blob, IPC bound | 17K rec/s | 405s | 0 | ✓ |
| `cmodule-v3` (回归) | CModule callout, send blob via IPC | callout 7.9M/s 但 ring drop 91% | — | ~7M/s | **✗** |
| **`cmodule` (v5, 默认)** | **CModule + SPSC ring + 设备落盘 + gzip pull** | **1.56M rec/s** | **~7-9s** | **0** | **✓** |

v5 关键: cmodule on_insn 写 SPSC lock-free ring (17 MB, head/tail monotonic);
v8 setInterval 10ms flush → File.write 到 `/data/data/<pkg>/cache/.miku/trace_NNN.bin`;
trace 完成后 host `adb exec-out 'gzip -1 -c <path>' | gunzip` 流式 pull.
ring 满时 cmodule spin (≤200ms) 等 v8 推进, dropped=0 完整保证.

**总加速: cmodule v5 vs js baseline = 92x**, 完整性 100% 保留.

## 2. 完整 trace 实测 (TB cold-launch 14 calls, 同一 trace)

```bash
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 600 \
  --cold-launch --out traces/run
```

| call | records | dropped | 采集 ms | 采集 rate | gzip pull MB | pull s |
|---:|---:|---:|---:|---:|---:|---:|
| #1 | 6,425,711 | **0** | 4180 | 1.54 M/s | 1666.8 | 5.2 |
| #2 | 4,440,905 | **0** | 2938 | 1.51 M/s | 1152.0 | 3.6 |
| #3 | 4,529,082 | **0** | 2855 | 1.59 M/s | 1174.8 | 3.7 |
| #4 | 4,649,566 | **0** | 3016 | 1.54 M/s | 1206.1 | 3.7 |
| ... | ... | ... | ... | ... | ... | ... |
| #14 | 4,165,751 | **0** | 2679 | 1.55 M/s | 1080.0 | 3.6 |
| **total** | **67,294,254** | **0** | **43,038** | **1.56 M/s** | **16,375** | **50.6** |

**file_size = records × 272 字节精确匹配**, race-free.

gzip 压缩: 16 GB raw → 0.6 GB on-wire (~26x), USB 物理 21 MB/s × 15.4x = 323 MB/s effective.

## 3. cold-path vs fail-path 路径分歧

同一函数同一 cmd, 不同时机走完全不同代码:

| 时机 | records | 解释 |
|---|---:|---|
| `monkey` 直启 / cache 命中 | ~4,675 | 短 fail-path, 设错误码 `mov w8, #0x961` (=2401) 后 ret |
| 业务请求触发 / 冷启第一次 | ~6,800,000 | cold-path, 真做白盒 sign 计算 |

`--cold-launch` 自动: `force-stop` + `pm clear` + `monkey` + `uiautomator dump`
找 `text="同意"` + `input tap` + 等首页 → trace 此时多 calls, 单 call 上限可达 6.8M.

## 4. 离线分析吞吐 (2.06M / 562 MB legacy trace, 仍可用)

| 操作 | 耗时 |
|---|---:|
| `tracemiku info` (mmap + meta 解析) | < 50 ms |
| `tracemiku query records --range 0..1000` | ~200 ms (cold cache) |
| `tracemiku query func-summary` | ~13 s (全表扫 + symbols) |
| `tracemiku query forward-taint --from 0 --reg x0 --max 500` | ~3 s |
| `tracemiku web ...` SPA 启动 + 大 trace 滚动 | viewport-only, < 100 ms / scroll frame |

## 5. 复现 (默认 v5 cmodule)

```bash
# stealth frida-server 安装 (一次性)
./vendor/frida-patched/install-stealth.sh    # 推到 /data/local/tmp/.miku-srv, forward 6699

# 抓完整 trace (默认 --mode cmodule = v5 device-spool)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 600 \
  --cold-launch --remote 127.0.0.1:6699 --out traces/cold_full

# run 概要 + 每次 call 概要 (records 降序)
./tracemiku list traces/cold_full
./tracemiku info traces/cold_full

# 挑最长那次 (cold-path) 直接看
COLD=$(ls -d traces/cold_full/calls/call_* | sort -t_ -k4 -n -r | head -1)
./tracemiku info "$COLD"
./tracemiku web  "$COLD" --port 18900 --no-browser
```

`tracemiku web` now serves the Rust/Solid analysis v2 UI. Old Python FastAPI/TUI
paths are not part of the benchmark surface.

## 6. 已知反例 / 限制

- `--follow-workers` 在 TB 这类 346+ 线程的 app 上 OOM/闪退 — 默认关.
- stock frida-server 17 在 Pixel 7 + Android 16 + OLLVM 大库 trace ~4500 条后
  `Unable to allocate code slab` SIGTRAP, 整个 target 挂. 必须用 stealth build
  (内置 codeslab fallback patch).
- 默认 frida-server 的 `gum-js-loop` 线程名 + `re.frida.server` socket 路径会被
  anti-frida 静态扫到. stealth build 重命名为 `miku-js-loop` / `re.miku.server`,
  详见 `vendor/frida-patched/README.md`.
- TB 启动后立即 trace, 70102 走 housekeeping fail-path, ~4675 条 stalker 跟丢
  → 用 `--cold-launch` 让 trace 在隐私协议同意之后才开始, cold-path 才会被走到.
- 设备 cache dir 单 cold-path ~1.7 GB, 14 calls 16 GB. 默认每次 trace 完 host
  pull 后 `rm` device 文件, 不累积. 但跑前最好 `pm clear` 一次确保空间.
