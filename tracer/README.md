# traceMiku — Stage 1 (Tracer)

实时 ARM64 指令级 + 全寄存器快照 trace 工具，针对 Android 真机上的 native 库（特别是 OLLVM 混淆的 libsgmainso 之类）。基于 Frida 17 Stalker + Florida 反检测 server。

## 当前状态

✅ Stage 1 全部完成 —— **完整 JNI_OnLoad trace 跑通（67407 条指令 / 干净 ret 收尾）**
- libsgmainso JNI_OnLoad 真机首次完整执行：return=0x10004 (JNI_VERSION_1_4)，~4 秒
- 5756 个 unique libsgmainso PC，覆盖 JNI_OnLoad 实际走过的所有 basic block
- 关键修复：**`Stalker.exclude(libc/libart/...)`** 避开 ARM64 LL/SC 死锁（Stalker 在 LDXR/STXR 之间插桩会清除 exclusive monitor，atomic 永远 retry → 之前以为是反调试杀进程，实际是 Stalker 自身 bug）
- 可直接 attach 已运行进程或 spawn-gate 子进程
- per-instruction 全寄存器（X0-X30, FP, LR, SP, raw inst）
- 二进制 frame 流式回传，host 落盘 per-PID `trace_<pid>.bin`
- ~1M insn/s 吞吐（per-insn callout）

🔜 Stage 2: viewer (CLI/TUI 翻 trace、寄存器/内存视图、def-use)
🔜 Stage 3: trace-augmented decompiler (集成 IDA / Binary Ninja MCP)
🔜 后续：扩展 trace 长度（绕过 SO 内反调试、按 session 分文件）

## 设备前置

1. ARM64 Android，root（adb shell 直接是 root 即可）
2. **Florida** server (Ylarod/Florida) 或 **undetected-frida** (zer0def)：<https://github.com/Ylarod/Florida/releases> | <https://github.com/zer0def/undetected-frida/releases>
   - 都把 server-side abstract socket 改成 `frida-zymbiote-{uuid}`，足够让 TB 启动
   - 原版 frida-server 跑默认 27042 + `/frida-{uuid}` 会被 TB SecurityGuard 秒杀
3. host 端 frida 17.9.x（与 device 版本对得上）

部署示例（host）：
```bash
curl -L -o florida.gz https://github.com/Ylarod/Florida/releases/download/17.9.1/florida-server-17.9.1-android-arm64.gz
gunzip florida.gz && adb push florida /data/local/tmp/florida
adb shell 'chmod 755 /data/local/tmp/florida && nohup /data/local/tmp/florida -l 0.0.0.0:6699 >/data/local/tmp/florida.log 2>&1 &'
adb forward tcp:6699 tcp:6699
```

### 关键陷阱（踩坑总结）
1. **`init()` 不能在 spawn-gated 状态调 `enumerateModules()`**：进程被 SIGSTOP 时 /proc 读不出来，Frida JS 调用永久 block。解决：on_spawn 只 attach + load + resume，把 init 推到主线程。
2. **`device.resume()` 在 on_spawn 回调里只是入队**，立刻调 RPC 对方还在 SIGSTOP。解决：必须等 on_spawn 返回让 frida event loop 再跑一次才真正 resume。
3. **`Interceptor.attach(android_dlopen_ext)` 不会被 TB 检测** —— 之前以为它被 detect 是上面 init() 卡死的假象。
4. **🔴 ARM64 LL/SC + Stalker 死锁**：Frida Stalker 在 LDXR/STXR 之间插桩会清除 exclusive monitor，STXR 永远失败 → libc atomic 自旋无限循环。**任何 trace 进入 libc/libart 都会卡死**。表象：trace 在某固定条数（如 4976）"结束"，实际是线程死循环。解决：`Stalker.exclude({base, size})` 排除 libc / libart / linker / libnativehelper / libcrypto / libssl / libc++ / liblog / libutils / libbase / libcutils / libbinder / 等所有非目标库，让它们原生执行。

## 工具集

| 文件 | 用途 |
|---|---|
| **`agent_tracer_excl.js` + `host_channel.py`** | **生产级**：Stalker.exclude libc/libart/linker → spawn-gate `:channel` → dlopen hook → 完整 JNI_OnLoad trace（67K 条 / `ret` 收尾） |
| `agent_tracer_dlopen.js` | 不带 exclude，会因 LL/SC bug 在 ~4976 条卡死（保留作对比） |
| `agent_tracer_full.js` | 不过滤任何 PC + 200K cap，看跨模块完整 trace（含 libart/libc 噪声） |
| `agent_tracer_poll.js` | dlopen 不 hook，靠 polling 检测 SO 加载（一般会错过 JNI_OnLoad 首次） |
| `agent_tracer.js` + `host_tracer.py` | 通用 spawn 模式（友好目标） |
| `agent_taobao.js` + `host_taobao.py` | attach 已运行 TB + 手动 invoke（撞 SO 反重入 BRK ~37 条） |
| `agent_smoke.js` + `host_smoke.py`   | spawn-gating + dlopen 链路验证 |
| `agent_min.js` + `host_min.py`       | 最小 Stalker 验证（任意进程） |
| `agent_noop.js` + `test_spawn_noop.py` + `test_full_spawn.py` | 隔离测试 |
| `analyze_tail.py` | trace 末尾深度分析（找 syscall / outbound call / 反调试线索） |
| `dump_trace.py` | trace 反汇编打印（需 capstone） |

## 运行示例

### 友好目标 — system_server malloc（基线烟雾测试）
```bash
python3 host_tracer.py \
    --pkg system_server --so libc.so --export malloc \
    --mode attach --out /tmp/trace_malloc --duration 5
python3 dump_trace.py /tmp/trace_malloc 8
```
预期：每次 malloc 调用产生 ~180 条指令，反汇编正确（看到 ARM64 malloc 序言）。

### libsgmainso（Taobao 真机）—— 推荐生产路线
spawn-gate `:channel`，hook android_dlopen_ext，Stalker exclude libc/libart 避免 LL/SC 死锁，捕获完整 JNI_OnLoad：
```bash
TRACE_AGENT=agent_tracer_excl.js python3 host_channel.py /tmp/trace_tb 30 127.0.0.1:6699
python3 dump_trace.py /tmp/trace_tb 40    # 或针对特定 session: per-pid trace_<pid>.bin
```
预期：~67000 条 libsgmainso 指令 / 5700 unique PC，约 4 秒采集。trace 以 JNI_OnLoad 的 `ret` 收尾，`return=0x10004`。

### 备选：手动 invoke（TB 已运行）
trace 范围更小（SO 自身反重入 BRK），但快速验证 attach 路径用：
```bash
adb shell 'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'
sleep 3
python3 host_taobao.py --remote 127.0.0.1:6699 --pkg com.taobao.taobao \
    --so libsgmainso --out /tmp/trace_tb_invoke --wait-secs 10
```
预期：~37 条指令。看到 OLLVM CFF 的 `br x3` / `br x17`，然后 SO 反重入 BRK 终止。

## 二进制 trace 格式

每条记录 272 字节，little-endian：
```
0x000  u64  pc
0x008  u64  x[31]      (x0..x28, fp=x29, lr=x30)
0x100  u64  sp
0x108  u32  nzcv       (保留)
0x10c  u32  inst       (原始 4-byte 机器码)
```

`meta.json` 记录目标 SO 基址、JNI_OnLoad 地址、PID、时间戳等。

## 下一步路线

### Stage 1 增强项（可选）
- ✅ **session 分文件** —— host_channel.py 已支持 per-PID `trace_<pid>.bin` + `meta_<pid>.json`
- ✅ **过 LL/SC 死锁** —— `agent_tracer_excl.js` Stalker.exclude 全部 system 库
- **NEON/FP 寄存器**：当前只抓 GPR；OLLVM 用 NEON 算 jump table 的话需要扩展 record 格式
- **跨模块 trace（精简）**：在 exclude 模式下可选地记录 outbound call 的 args/ret，用于看 JNI 调用链而不引入 libart 噪声

### Stage 2: viewer
- 解析 trace.bin，TUI（textual）上刷 PC/regs/内存
- def-use 链、字符串引用搜索（krash 文章里那套"杀手级"功能）
- session 分隔显示（多个 :channel run 并排比对）

### Stage 3: trace-augmented decompile
- 调用本机已配置的 IDA / Binary Ninja MCP server 拉伪代码
- 把每行汇编上的具体寄存器/内存值 overlay 到伪代码旁
- 不重写反编译器，做"具体执行上下文 vs 静态伪代码"的对照

## 性能数据

| 场景 | 速度 |
|---|---|
| Stalker block-only callout | ~1 M block/s |
| Stalker per-insn callout（无快照） | ~1.3 M insn/s |
| per-insn + 33-寄存器写入 native batch | ~10–60 K insn/s（视目标），约 272 byte/record |

## 参考

- 看雪 ATTD 系列（FANGG3）：<https://bbs.kanxue.com/thread-281555-1.htm> / <https://bbs.kanxue.com/thread-285745.htm>
- krash 时间无关调试：<https://bbs.kanxue.com/thread-273055.htm>
- Tenet trace 格式：<https://github.com/gaasedelen/tenet>
- undetected-frida：<https://github.com/zer0def/undetected-frida>
