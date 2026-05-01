# CLI 工具 AI 逆向场景 gap 清单

> 实际逆向 TB libsgmainso x-sign 时发现的 CLI 工具不足。
> 2026-05-01.

## P0 阻塞性

### Gap-A: `taint-bwd` / `taint-fwd` 通过 sp/fp/lr 爆炸式扩展, 噪音 >> 信号

**症状**: backward-taint 一个 reg, 26 个 hits 里 20+ 是 stack frame 操作 (`sub sp`,
`ldp x29,x30`, `mov x29, sp` 等), 真数据 dependency 被淹没。

**根因**: 当前 `taint.py` 把所有 `regs_use` 都当数据 dependency 追, 不区分:
- 真数据 dep: `mov x0, x22` 里的 x22
- 寻址 dep: `ldr x0, [sp, #0x1f8]` 里的 sp (sp 是 base reg, 不是数据来源)
- frame 链: `add x29, sp, #0x90` 里 fp 链整个函数都在变

**实际 workaround**: 我自己写了 SDK chase, 跳过 `{sp, fp, lr}`, 当遇到 `ldr` 时
不去追 base reg 而是追 mem store 的 source reg。这才能从 final x0 一路追到
真正的数据来源 (1000 步深还能命中关键计算)。

**建议改动**:
- `taint-fwd` / `taint-bwd` 加 `--exclude-regs sp,fp,lr` (或默认就排除)
- 加 `--data-only` 标志: 遇到 ldr 时只追 mem store 的 src reg, 不追 base/idx
- 同时还支持显式 `--include-regs sp` 当用户真要看 stack 邻域时

### Gap-B: 没有 `last-write-of-addr` 子命令 (CLI mirror missing)

**症状**: 当我看到 `ldr x0, [sp, #8]` 想知道这地址上次被谁写时, 必须自己写 SDK
代码 (查 `index.mem_addr_to_writes` + bisect).

**Web API 已有类似的**: `/api/last-write-of-reg` 但没 `last-write-of-addr`.

**建议加**:
```
python -m viewer last-write-of-addr <trace> --addr 0x... --before-idx N
# → {"addr":"0x...", "writer_idx":..., "writer_pc":"0x...", "src_reg":"x8", "value":"0x..."}
```

## P1 体验性

### Gap-C: `stats` 在多 SO 设备上输出 60KB+, LLM 不友好

**症状**: TB 进程加载 250 个 module, `stats` 全列出来, JSON 63KB。

**建议**: 加 `--top-modules N` (默认 10) 只显示主 SO + 前 N 大模块,
完整列表用 `--all-modules`.

### Gap-D: 没有 `records <trace> --start N --count M` (查看连续 record 区间)

**症状**: 想看 #7624400-7624430 这 30 条 (找 ret 前 def x0 的位置), CLI 没有
直接命令。我用 SDK 写循环。

**Web API 已有**: `/api/records?start=N&count=M`. CLI 缺这个 mirror。

**建议加**:
```
python -m viewer records <trace> --start 7624400 --count 30 [--regs x0,x1]
```

### Gap-E: `fn-summary` callees 把 trace 边数当 callees 调用次数, 容易误读

**症状**: callees 里 `sub_135c1c` count=121, 但其实是 doCommandNative 内边过来
121 次, 不一定 sub_135c1c 被调 121 次 (可能从其他位置也被调)。

**建议**: 输出每个 callee 时同时列 `callee_total_executions` (该 callee 函数自己
所有 entry 累计被调次数)。

### Gap-F: 没有 chase / call-graph-from / data-flow-from 这种"跨函数追到数据来源"的命令

**症状**: 我手写的 SDK chase 实际是逆向最常用的"找 reg 数据真正来自哪", 跨多个
ldr/str/mov 跳转。这功能缺失意味着 LLM 用 CLI 没法做这个最常见操作。

**建议加** (基于 Gap-A 的 data-only 模式):
```
python -m viewer data-chase <trace> --start <idx> --reg <name> --max-steps 40 \
       [--skip-regs sp,fp,lr]  [--cross-fn]
# → list of (idx, pc, fn, asm, reg|mem-source) 一路到真数据源
```

## P2 增强

### Gap-G: `taint-fwd` / `taint-bwd` 不会自动跨"被调用函数"

**症状**: 我从 final x0 追到 `mov x22, x0` (#7622820), 这个 x0 是某个 bl 调用
的返回值, 但 taint 不会自动跳进 callee 内部追 callee 的 return chain。

**建议**: `--cross-fn-call` 标志, 让 taint 在遇到 `bl <fn>` 后自动追到 `fn` 的
ret 之前哪条指令 def 了 ret reg。

### Gap-H: 没有 `find-mem-pattern <trace> --bytes 'hex' --since N` 在 MemShadow 里 grep
**用例**: 找 trace 里某时刻内存里出现某 hex pattern (比如 SHA-256 IV `6a09e667`)
来定位 hash 算法。

### Gap-I: `mem-dump` 没有 `--reg <name>` 直接以 reg 当前值为地址

**当前**: `mem-dump <trace> --addr 0x...` 必须手算地址。

**建议**: `mem-dump <trace> --reg x0 --idx N --count 64` 自动取 idx 时 x0 当地址。


---

## 实战演练: 用 CLI 逆 TB doCommandNative(70102) 的 x-sign 生成

实际跑了一遍, 顺序如下:

1. `stats <trace>` → 知道 records=7.6M, module=libsgmainso, cmd=70102 (这步**前置阻塞**: 旧 trace 因 cmodule agent 写 inst=0 全 udf, 必须先修)
2. `fn-summary --fn doCommandNative` → 49 blocks, 968 executions, 列出 callees
3. `taint-fwd --start 0 --reg x2` → 看到 magic-multiply-divide cmd dispatch (smull/asr/msub 经典模式)
4. **手写 SDK chase** (Gap-A, F 阻塞): backward 追 final x0, 跳过 sp/fp 噪音, 跨函数过 mem store
5. 追到 `#7622819 blr x8` (JNI vtable[0xe0] = NewObject)
6. 至此 sign 的"包装"已知: doCommandNative 返回的是 JNI NewObject 创建的 jobject

**还需要的 CLI 能力**:

### Gap-J: trace 内 JNI 调用识别 / 标注

当前我得自己看 vtable offset 推断 JNI 函数 (0xe0/8 = idx 28 = NewObject)。

**建议**: 加 `python -m viewer jni-calls <trace> [--in-fn <name>]`, 自动识别
所有形如 `ldr x?, [x?, #0x..]; blr x?` 的 JNI vtable 调用, 输出:
```json
[{"idx": 7622819, "pc": "0x...", "jni_fn": "NewObject", "args": {"x1": "...", "x2": "..."}}, ...]
```
JNI vtable 的 layout 是 ABI 稳定的, 项目可以内置一份 offset → name 映射表。

### Gap-K: 看一个 jobject 的所有 SetField/SetArrayRegion 操作

x-sign 真正的字符串内容来自 JNI Set*Field 写到 NewObject 创建的对象上。
当前没法快速在 trace 里找"这个 jobject 上后续被设了什么"。

**建议**: `python -m viewer jobj-history <trace> --idx N` —
追踪 idx 处某 reg 持有的 jobject pointer, 找之后所有以它为 x1 的 JNI 调用
(SetByteArrayRegion / SetObjectField / NewStringUTF→SetField 等)。

### Gap-L: trace 里所有 NewStringUTF / GetStringUTFChars / 字符串相关 JNI

这是逆向 sign 时最常被问的 — sign 字符串什么时候被 build, 什么时候被 read?

**建议**: `python -m viewer jni-strings <trace>` — 列所有 JNI string 操作 +
对应的 char* 参数所指内容 (用 MemShadow 读)。

