# cmd 70102 (doCommandNative) 流程分析

> 基于 trace `traces/doCommand_70102_complete/` (1.75M 条) + Binary Ninja headless HLIL.

## 1. 函数签名

Java: `Object doCommandNative(int cmdId, Object[] args)` (动态注册)

Native (libsgmainso `sub_457770` = doCommandNative):
```c
jobject doCommandNative(JNIEnv* env, jobject this, jint cmdId, jobjectArray args)
                       // x0,        x1,           x2,         x3
```

trace 第 0 条验证：`x2=0x111d6 = 70102` ✓

## 2. 入口的 3 级 dispatcher（关键发现）

BN HLIL 反编译入口前 30 条：
```c
sub_457770(env, this, cmdId, args):
    canary = TPIDR_EL0[0x28]                         // 栈保护
    
    // 三级解构：cmd 的语义结构
    major  = cmdId / 10000                            //  cmd 70102 → 7
    middle = (cmdId - major*10000) / 100              //  → 1
    last_2 = cmdId % 100                              //  → 2

    // 准备调度上下文
    var_64 = 0xa1; var_60 = 0xd4; var_5c = 0
    
    // 第一次调用: 解析 handler
    result, x3_1, x4_1 = sub_454fe8(major, middle, last_2, /*flag*/1,
                                      &handler_out, &aux_out)
    handler = handler_out
    
    if (result == 0 && handler != 0) {
        // 第二次调用: 执行 handler
        sub_547bc8(env, handler, &data_423f2c, x3_1, x4_1)
    }
    
    check_stack_canary(); return result
```

→ **70102 = (major=7, middle=1, last=2)**，handler 由 `sub_454fe8` 按这三个数查表得出。

## 3. 调用图（前 1000 条 trace 的执行链）

```
doCommandNative
├─ #50  bl sub_454fe8           ← 解析 handler
│  ├─ #83  bl sub_447b0          ← 表查找 (3 维)
│  ├─ #125 bl __stack_chk_fail-style?
│  └─ ...
│
├─ #383 bl sub_547bc8           ← 执行 handler
│  ├─ #427 bl sub_447b0
│  ├─ #475 bl ...               ← 多次 byte/string 操作
│  ├─ #601 bl sub_519b6b8        
│  ├─ #622 bl sub_1496b8        ← JNI 相关 (很多)
│  ├─ #655 bl sub_618304
│  ├─ #702 bl sub_519ba6c
│  ├─ #718 bl sub_149a6c        ← JNI 相关
│  └─ ...
│
└─ ... (循环 763K 次 sub_584a1c, 见 §4)
```

## 4. 异步执行 — 70102 不在调用线程算签名

`sub_584a1c` 被调用 **763,289 次** (热循环)。BN HLIL 显示：

```c
sub_584a1c(arg1 /* something */, arg2 /* req */, arg3 /* slot */, arg4 /* tag */):
    x8_1 = *(*arg1 + 0x138)                  // 取某个对象的成员
    if (*(x8_1 + 0x80) == 0) {
        *(x8_1 + 0x80) = data_6f7a70         // 标记 work item 准备好
        *(x8_1 + 0x7c) = 1
        pthread_cond_signal(x8_1 + 0x90)     // ★★★ 唤醒 worker 线程 ★★★
    }
    *(arg2 + 0x1b) = 1                        // request flag
    *(arg3 + 0xb8) = &data_6bd8d8             // slot tag
    if (queue_empty) {
        result = sub_56ae04(arg2, arg3, &data_6f7000, ...)
        if (result != 0) return result
    }
    __dmb()                                   // memory barrier
    sub_569938(arg1, arg3, arg2, arg4, arg3+0x40, data_6f7a70)
    return 0
```

→ **doCommandNative 70102 的真实工作不在调用线程，它把任务派到 worker 线程，被 763K 次的循环不停 enqueue 工作。** 调用线程跑了 1.75M 条之后还是没返回 — 它在等所有 worker 干完。

## 5. 为什么签名计算不在 trace 里

我们的 Stalker 只 follow 了调用线程。worker 线程被 `pthread_cond_signal` 唤醒，但我们没 follow。**真正的签名 (HMAC / SHA / RSA / 自研算法) 都跑在 worker 上，trace 里看不到。**

## 6. 下一步采集策略

要拿到完整签名逻辑，**两个角度**：

### A. trace worker 线程
改 agent 在 `pthread_cond_signal` 时记录目标 cond_var 地址，然后 hook `pthread_cond_wait` 在 wakeup 时 Stalker.follow 唤醒方。代码骨架：

```js
const sigFn = Module.findGlobalExportByName("pthread_cond_signal");
const waitFn = Module.findGlobalExportByName("pthread_cond_wait");
const wakeup_targets = new Set();   // cond_var addrs we care about
Interceptor.attach(sigFn, {
    onEnter(args) { wakeup_targets.add(args[0].toString()); }
});
Interceptor.attach(waitFn, {
    onLeave() {
        // 当前线程刚 wakeup; 如果它等的 cond 在我们集合里, 开始 follow
        const cv = this.condVar;
        if (wakeup_targets.has(cv.toString())) {
            const tid = Process.getCurrentThreadId();
            Stalker.follow(tid, /* same params */);
        }
    },
    onEnter(args) { this.condVar = args[0]; }
});
```

### B. 直接 trace handler 函数本身
从 trace 找 `sub_547bc8(env, handler, ...)` 这条调用的 x8_5 — 即 70102 真正的 handler 函数地址。然后单独 hook 这个函数 trace 之，避开 dispatcher 的 763K 噪音。

让我从 trace 里挖出 handler 地址：
```bash
./tracemiku query traces/doCommand_70102_complete records --range 380..400 --regs x0,x1,x2,x3,x8 --json
```
看 #383 处 sub_547bc8 调用前 x8 的值 — 那就是 handler。

## 7. 加速方案 (针对你的"trace 太慢"问题)

| 方案 | 速度提升 | 信息损失 |
|---|---|---|
| 当前 (per-insn 全寄存器) | 1× (~30K rec/s) | 无 |
| **fast-pc** (`tracer/agent_fast_pc.js`, Stalker exec event 全 native) | **30-100×** (~1M+ pc/s) | 只有 PC, 无寄存器 |
| 混合: PC + 每 N 条寄存器快照 | 5-20× | 中间寄存器需 viewer 推算 |
| 只 hook handler (避开 dispatcher 763K 噪音) | 1000× | 跳过派发逻辑 |

`tracer/agent_fast_pc.js` + `tracer/host_fast_pc.py` 已写好。等 cmd 70102 在 TB 上被触发时跑：
```bash
python3 tracer/host_fast_pc.py --out traces/fast_70102 --duration 120 --cmd 70102
# 在手机上操作触发 70102 (登录 / 网络请求)
```
