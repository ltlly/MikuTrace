# traceMiku 性能基准 (实测)

> 测试设备: arm64 / Android 12 / Florida frida-server 17.9.1
> 目标: com.taobao.taobao (libsgmainso-6.8.260403.so)
> 函数: doCommandNative @ +0x57770 (`fnOffset`), cmd 70102

## 1. 完整 cold-path trace

```bash
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 120 \
  --mode js --cold-launch --out traces/run
```

| 实测 | 数字 |
|---|---|
| **records** | **2,066,291** |
| **bytes**   | **562 MB** |
| trace 持续 | ~50 s |
| 平均吞吐 | ~40 K rec/s (含 `send` blob 网络回程) |
| flush 模式 | size (16K rec / batch) + interval (200 ms) |

> 历史对比 trace `doCommand_70102_complete` 1.75M 条同样 cold-path, 数据一致.

## 2. cold-path vs fail-path 路径分歧

同一函数同一 cmd, 不同时机走完全不同代码:

| 时机 | records | 解释 |
|---|---|---|
| `monkey` 直启 / cache 命中 | **4,675** | 短 fail-path, 设错误码 `mov w8, #0x961` (=2401) 后 ret |
| 业务请求触发 / 冷启第一次 | **2,066,291** | cold-path, 真做白盒 sign 计算 |

fail-path 在最后 ~30 条 cleanup 时走出 SO 范围, 因为 `Stalker.exclude` 排除了
system 库, stalker 跟丢, onLeave 不触发 → 现象像"卡死". 但 99% 的执行流已抓到.

`--cold-launch` 自动: `force-stop` + `pm clear` + `monkey` + `uiautomator dump`
找 `text="同意"` + `input tap` + 等首页 → trace 此时第一次 70102 必走 cold-path.

## 3. trace mode 对比 (`--mode`)

| mode | 实现 | 实测 cold-path 上限 | 备注 |
|---|---|---|---|
| `js` | JS transform + JS callout (`iter.putCallout(jsFn)`) | **2,066,291 ✓** | 推荐 |
| `cmodule` | JS transform + CModule `on_insn` callout | 短 trace 与 js 一致 | 默认, 但 TB cold-path 与 js 一样在 fail-path cleanup 处跟丢 |

CModule callout 在简单进程上 ground-truth 测试 (`agent_cm_simple.js` runc/runjs
RPC) work 正常, JS 与 CModule 抓到同一计数. 真机 TB 跟丢现象与 mode 无关, 是
函数自己走出 SO 范围导致.

## 4. 离线分析吞吐 (2.06M / 562 MB trace)

| 操作 | 耗时 |
|---|---|
| `tracemiku info` (mmap + meta 解析) | < 50 ms |
| `tracemiku query records --range 0..1000` | ~200 ms (cold cache) |
| `tracemiku query func-summary` | ~13 s (全表扫 + symbols) |
| `tracemiku query forward-taint --from 0 --reg x0 --max 500` | ~3 s |
| `tracemiku view ...` Textual TUI 启动 + 滚动 | < 100 ms / 帧 (viewport-only) |

## 5. 复现

```bash
# 假设 TB apk 已装, frida-server 跑 6699 端口
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 120 \
  --mode js --cold-launch --out traces/cold_full

./tracemiku info traces/cold_full
./tracemiku view traces/cold_full
```

## 6. 已知反例 / 限制

- `--follow-workers` 在 TB 这类 346+ 线程的 app 上 OOM/闪退 — 默认关.
- 默认 frida-server 的 `/frida-{uuid}` socket 被 TB 反调秒杀 → 必须 Florida fork.
- TB 启动后立即 trace, 70102 走 housekeeping fail-path, 4675 条就跟丢 → 用 `--cold-launch`.
- Stalker JIT cache 不是问题 (16MB), 不要把"4675 条卡死"误读为 frida bug.
