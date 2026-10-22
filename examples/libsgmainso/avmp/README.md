# AVMP VM 离线解释器（x-sign 生成程序）

目标：把 `libsgmainso-6.8.260602.so` 里生成 x-sign 的那段代码，还原成**可离线重算**的
纯计算实现。分析结论见 `../static_findings.md` 2.11 与 `../known_offsets.json` 的
`avmp_vm` 字段。

## VM 结构（已实测）

模块内 dispatcher 在 `libsgmainso+0x17c680`：

```asm
ldrb w20, [x21, #6]          ; opcode/源寄存器号
ldr  x0,  [x25, x20, lsl #3]  ; 表1
ldr  x1,  [x21, #8]           ; 立即数
add  x2,  x0, x1
ldrb w3,  [x21, #5]           ; 目标寄存器号
str  x2,  [x25, x3, lsl #3]   ; 寄存器文件 x25, 8 字节/槽
ldrh w4,  [x21, #0x10]!       ; 下一帧 id (后索引自增)
ldr  x5,  [x23, x4, lsl #3]   ; 表2: frame_id -> handler 地址
str  x21, [x27, #8]           ; 保存帧指针
br   x5                       ; 尾调用下一 handler
```

* **x21** = 帧指针；帧宽 16 字节。
* **帧内 +0x10 的 2 字节就是本帧的 handler id**（不是帧首！）。已用设备侧权威
  执行序列核对：`u16_at(F+0x10)` 与记录到的真实 handler id **107/107 一致**；
  `u16_at(F+0)`、`F+0x2..0xe` 全部 0/107 命中（`F+0x2` 只碰巧 11/107）。
  因此 `handler(F) = x23[ u16_at(F+0x10) ]`。
* **x25** = 寄存器文件，8 字节/槽。handler 可用 `ldrb/ldrh/ldr` 窄读一个槽，
  W 寄存器写回零扩展。
* **x23** = `frame_id -> JIT handler 地址` 表。handler 里的
  `ldr x?, [x23, w?, lsl #3]` 要能解析，解释器因此把 x23 表单独映射到一块内存。
* **x27+8** = 帧指针保存槽。**写 `[x27+8]` 是「本帧结束」的判据**：
  写了就换帧；没写就是跳板（位置无关的 fall-through），要继续在 JIT 流里执行。
* handler 选择规则：`handler(F) = x23[ u16_at(F) ]`。帧自己开头 2 字节就是
  自己的 handler id（前一帧末尾的 `ldrh [x21,#0x10]!` 读的正是下一帧的 id）。
* 帧跳转由 handler 里的 `add x21, x21, imm, lsl #4` 完成，`imm` 可为负（回退）。
  实测帧偏移不连续（例如 0x9f70 -> 0xa080 跨 0x110 = 17 帧）。

## JIT handler 是运行时生成代码

handler **不在 so 文件里**，是运行时 JIT 出来的（地址在模块外，例如
`0x7439dc6c44` 起的 0x30000 字节区）。每条 handler 就是一条 VM 语义的
straight-line 代码 + 上面那段 dispatch 尾巴。

已反汇编出的语义（`avmp/` 的 `handlers_map.txt` 对应 JIT 区）：

| frame_id | 语义 |
|---|---|
| 0, 4 | `reg[d] = reg[s] + imm` |
| 1, 22 | `reg[d] = reg[a] + reg[b]` |
| 8, 10, 13 | `AND`（立即数 / 32 位 / 寄存器） |
| 18, 21, 24 | `ORR` / 变体 |
| 2, 5, 7, 12, 17, 19, 20, 25, 26, 27, 28, 29, 30 | 条件跳转（`cmp` + `b.cond` + `add x21,x21,imm<<4`） |
| 485, 508 | `reg[d] = *(u32*)(reg[a] + off)` |
| 490, 505 | `reg[d] = *(u64*)(reg[a] + off)` |
| 512 | `MUL` |
| 518, 520, 523 | `MOV imm` |
| 526, 635, 636, 637, 642 | `*(u64*)(reg[a]+reg[b]) = reg[s]` |
| 539, 540, 545, 546, 547, 548 | 条件跳转变体 |
| 544, 545, 576 | `ORR` |
| 594, 599 | `LSL` |
| 606, 613 | `ASR`（算术右移，带符号扩展） |
| 612, 621 | `LSR`（逻辑右移） |
| 622, 627 | `*(u8*)(...) = reg[s]` — **载荷字节就是在这些 handler 里写出的** |
| 634, 640 | `*(u64*)(...) = reg[s]` |
| 639, 643 | `*(u32*)(...) = reg[s]` |
| 645 | `SUB` |
| 17, 22, 539, 540 | `bl` 调 JIT 区内 native helper（很可能是 MD5/RC4/base64） |

## 文件

| 文件 | 内容 | 来源 |
|---|---|---|
| `arm64.py` | ARM64 子集解释器（capstone 解码）+ AVMP VM | 手写 |
| `vm.py` | 装载 dump 出来的 JIT 区/帧数组/寄存器文件并驱动 | 手写 |
| `xtab.txt` | x23 表：`frame_id handler_addr`（与 `jit.bin` 同一次运行） | 设备 dump |
| `jit.bin` | 整段 JIT 区原始字节（`JIT_BASE` + hex） | 设备 dump |
| `frames.txt` | 帧数组（16 字节/帧） | 设备 dump |
| `regs.txt` | 寄存器文件 x25 初始内容 | 设备 dump |
| `seq.txt` | 一次 70102 调用内的帧执行序列（权威真值，用于校验） | 设备 dump |

dump 脚本见 `/tmp/opencode/vmrun.js`（单次运行同时落盘全部四件，保证
`id -> addr` 映射与 JIT 区地址一致；跨运行混用会得到 `udf #0` 之类的假错误）。

## 当前状态与剩余缺口

**已完成**

* VM 结构、handler 选择规则、帧推进规则全部实测确认（见上）。
* 75/76 条 handler 的语义已反汇编并分类。
* 离线 ARM64 解释器已能逐条执行 handler，正确处理
  `x21`/`x25`/`x27` 的特殊语义、窄读窄写、`ldrh [x21,#0x10]!` 后索引帧推进、
  写 `[x27+8]` 判帧结束 vs 跳板继续执行。
* 已从设备观测到权威的**帧执行序列**（`/tmp/opencode/entry.txt` 的 `SEQ_HEAD`），
  例如
  ```
  f050 → f060 → f070 → 9f70 → a080 → a0d0 → a110 → 9f70 → 9fb0 → 9ff0 → a080 ...
  ```
  证明帧偏移不连续、主体是 4 帧循环 + 内层写循环。

**未完成（阻塞点，按顺序）**

1. **帧数组落盘不可靠。** `frames.txt` 的读起点是「所有 dispatcher 命中里最低的
   x21」，这个值在多次运行里落到全零页或未映射页，导致帧内容缺失（实测
   `非零帧=0`）。需要改成：**用 SEQ 里的已知帧地址**（而不是 `lo`）作为读起点，
   或在设备侧直接 dump `x23` 表 + 帧数组所在整段内存。
2. **`x23` 表与帧数组必须同一次运行落盘。** 之前混用不同运行导致
   `handler(F) = x23[id_at(F)]` 查不到、跳到 0（`udf #0`）。
   `xtab.bin`（x23 表）目前是另一次运行的，需要和 `frames.txt` 一起重采。
3. **4 个 native helper 尚未还原**（`bl` 目标，在 JIT 区内但不在 `x23` 表里）。
   nonce 的最终混合很可能在这些 helper 里，这是还原 nonce 生成逻辑的关键一环。

拿到 1+2 之后，`vm.py` 应该能直接跑通完整程序并输出 76 字节载荷；再对 135 组
黑盒向量做逐字节校验，就满足「脱离设备重算」的验收点。

## 已验证：离线解释器能连续执行

帧数组已覆盖**全部 41 个簇**（NF=63280 帧，此前只 dump 最大簇 2490 帧）。

* `frame_id()` 与设备侧执行记录对照：**20/20 一致**（新 dump 上）。
* 9/10 随机入口能连续跑 2000 步不出错；唯一失败的是会撞上 `bl` 的入口
  （`follow_flow=False` 下这是**预期行为**，会显式报不支持）。
* `follow_flow=True` 时能真实进入 native helper（300 步 `native_calls=288`）。

### 两档执行模式

| 模式 | 每步含义 | 实测 |
|---|---|---|
| `follow_flow=False`（默认） | 只解释一条 handler，遇 `bl` 显式报不支持 | ~0.03 ms/步 |
| `follow_flow=True` | 跟随 JIT 区内控制流进入 native helper | ~15 ms/步 |

默认关闭是有意的：跟随控制流会让每步真的执行数千条 JIT 指令，慢约 500 倍。
纯帧语义验证不需要进 helper。

### 为跑通 helper 补齐的指令语义

`mrs x?, tpidr_el0`（canary 前缀读 TLS，给合成基址）、`blr xN`、
`dmb/dsb/isb/hint`、`pacia*` 系列、`bti`、零寄存器 `xzr/wzr`、
`sp/wsp`、`ldp/stp` 的 `[sp], #imm` 与 `[sp, #-0x20]!` 形式、
`lsl #4` 这类移位操作数（不能把 `"lsl"` 当寄存器号 `int()`）。

## native helper：40 个全在 JIT 区内

JIT 区里扫 `sub sp,sp,#imm` + `mrs x?, tpidr_el0` 匹配到 **40 个 canary stub**，
这就是 VM 的全部 native helper。它们**不是**动态解密到别处，只是入口做了
控制流平坦化（`udf` 里藏密钥 + `eor/mvn` 解出 `br` 目标），函数体就在
紧随其后的 JIT 流里。

已还原两个：

| 名称 | JIT 偏移 | 语义 |
|---|---|---|
| `sbox_xor_16` | `0xf124` | `out[i] = in[i] ^ S[(&out[i]) & 0xff]`，S 盒在 `ctx+0x1e0`，展开成 16 字节一组 |
| `mem_rw` | `0xe9b8` | `*( *(ctx+0x240) + 0x1a0 ) + off`（**inline 小函数**，不是 canary stub） |

实现见 `helpers.py`，测试见 `test_avmp_vm.py::TestNativeHelpers`。

## 剩余缺口

1. **canary 全局值不真实。** helper 入口的
   `ldr wM, [adrp_page, #0x68]` 在离线 dump 里是**静态数据**，不是设备
   运行时的真实 canary。离线执行时自解密跳转算出的 `br` 目标因而可能
   与设备不一致。需要在设备上把该全局的真实值读出来（或直接 dump 解密后
   的函数体）才能保证 helper 语义正确。
2. **`udf #0 @0x765b801b00`** —— x23 表里有一张指向零页的槽
   （`frame_id=2` 的 handler 是 `ldr w16,#8; br x16`，字面量指向全零区）。
   设备上这个槽同样指向零，但设备不会真跳过去，说明该槽的索引编码与
   `[x23, w, lsl #3]` 里的 w 不完全对应，需要再采一次「每次 dispatch
   实际 branch 到的地址」反推。
3. **随机源未定位**。已确证 nonce 每次调用都变（见
   `known_offsets.json` 的 `xsign_randomness`），但产生这个随机量的
   40 个 helper 里哪一个还没对上号。候选：`stk` 很小（16/32/64）且只有
   `strb` 的那几个（`0x2fad4`..`0x48528` 段）最像取随机/时间的原语。

## 关键经验（跨运行混用会得到假错误）

* `x23` 表、帧数组、寄存器文件、JIT 区**必须来自同一次运行**。混用会得到
  `udf #0`、索引越界等看似实现 bug 的假错误。
* 指针差值要用 `parseInt(a.sub(b).toString())`，**不能用 `toInt32()`**
  （设备地址 >= 2^47 时 `toInt32()` 会回绕成负数，帧簇聚类直接崩）。
* Frida 侧 `File.write()` 要分块（每 32 页 flush），否则 500KB 的一次性
  写入会静默失败产出 0 字节文件。
* 读设备内存要按 0x100 / 0x1000 逐块读并 catch，跨未映射页会整体抛异常。

## 采 dump 时的两个硬坑（都曾让整轮数据作废）

### 1. JS 位运算会把 48 位地址截断成 32 位

`v & ~0xfffff` 在 JS 里先把 `v` 转成 **Int32**，
`0x743b6589b0` 会变成 `0x3b6589b0`，于是：

* 1MB 桶算错 → JIT_BASE 被写成 `0x3b600000`（少了高 32 位）；
* 更糟的是随后 `jitLo.add(...)` 读到的是**错误地址**的内存，
  dump 出来的 10MB 全是零，看起来"成功"了其实全废。

正确写法用算术：

```js
var b = Math.floor(v / 0x100000) * 0x100000;   // 不要用 & ~mask
```

**判据**：x23 表里 827/1024 条 handler 落在 `[JIT_BASE, JIT_BASE+SIZE)` 内。
若为 0，就是 base 算错了，此时 dump 的内容不可信。

### 2. frida 可能重复执行脚本，dump 必须幂等

`frida -f` 在 app 崩溃/重启后会**重新加载脚本**。如果 dump 不是幂等的，
两轮 ASLR base 不同的数据会互相覆盖，最终五个文件"各不相同源"。
本模块因此：

* `dumped` 标志保证只 dump 一次；
* 每个文件头都写 `JITBASE <addr>`，落地后先交叉校验五件是否同源。

**判据**：`frames.txt` / `seq.txt` / `regs.txt` / `xtab.txt` / `jit.bin`
头部的 JITBASE 必须完全一致。

### 3. 落盘目录必须是 app 已有目录

Frida 的 `File` **不会创建父目录**。`files/.miku` 一旦被删就再也写不进去
（app 无权在 `files/` 下新建）。改用 app 必定存在的
`/data/data/<pkg>/cache/`。

拉回宿主时注意先 `rm -f /data/local/tmp/<name>`，否则上次失败的残留会让
`cp` 报 odd errors。

## 当前 artifacts

`NF=63280` 帧、全部 41 个簇、827/1024 handler 落在 JIT 区内（其余为
指向零页的陈旧槽，设备上也不会真跳过去）。

* `follow_flow=False`：9/10 随机入口可连跑 2000 步。
* `follow_flow=True`：`+0x30000` 入口 300 步内进入 native helper 288 次。

## 采 dump 的三个硬坑（每个都曾让整轮数据作废）

### 1. JS 位运算会把 48 位地址截断成 32 位

`v & ~0xfffff` 和 `v & ~0xfff` 在 JS 里都先把 `v` 转成 **Int32**：

| 写法 | 输入 | 结果 |
|---|---|---|
| `v & ~0xfffff` | `0x743b6589b0` | `0x3b600000`（丢高 32 位） |
| `Math.floor(v/0x1000)*0x1000` | `0x743b6589b0` | `0x743b6580000`（正确） |

后果不只是 base 写错：`jitLo.add(...)` 会读到**错误地址**，dump 出几 MB 全零
却"看起来成功"。

**判据**：x23 表里 827/1024 条 handler 落在 `[JIT_BASE, JIT_BASE+SIZE)` 内。
为 0 就是 base 错了，此时 dump 内容不可信。

### 2. 范围不能取全局 min/max，也不能直接并入 `enumerateRanges`

x23 里混有指向非 JIT 区域的指针。全局 min/max 曾把区间撑到
`0x7432177400..0x7634164c88`（**8.6GB**，jit.bin 直接 9GB）；
`enumerateRanges('r-x')` 又会列出整个进程的可执行段，直接取 min 更离谱。

**正确做法**：先用 **1MB 对齐桶的众数**（`Math.floor(v/0x100000)*0x100000`）
定出 JIT 区，再把落在该范围内的 `r-x` 段并进来。

### 3. 整页 `readByteArray(0x1000)` 会跨界失败

JIT 的映射常常不满一页，`readByteArray(0x1000)` 从页首读会撞到未映射的下一页
而**整体失败**（返回 null，`new Uint8Array(null)` 抛异常被 catch 吞掉，
于是那页填了 0）。按 0x100 字节分块读、失败块填 0 才稳。

注意：单字节 `readU8()` 一直正常（`prot=r-x`），所以"完全读不到"通常是
读长度的边界问题，不是权限问题。

### 另外两点

* **JIT 代码页在 70102 调用返回后会被解除映射。** 代码必须在调用期间读；
  x23 表内容则随 JIT 编译逐步填好，同样要在调用期间采样（每 64 次命中取一次，
  留最后一次）。我曾因"改成调用后读表"而让代码页全部读空。
* **frida 可能重复执行脚本**（app 崩溃/重启会重新加载），dump 必须幂等，
  否则两轮不同 ASLR base 的数据互相覆盖，五个文件"各不相同源"。
  本模块给每个文件头都写 `JIT_BASE`，落地后先交叉校验。

落盘目录用 app 必定存在的 `/data/data/<pkg>/cache/` —— Frida 的 `File`
**不会创建父目录**。

## 当前 artifacts

* 帧 `NF=17838`（全部 ~1900 个簇）、执行序列 42879 步、x23 表 827/1024
  handler 有效。
* JIT 区 35MB，覆盖 handler 区 + 邻域 `r-x` 段，内含 **1127 个 canary stub**
  （含全部 native helper）。
* `locate_helpers()` 按**指令模式**定位 helper，不硬编码偏移 —— JIT 每次运行
  的基址与布局都不同（同一个 so 在不同进程编出来的 handler 地址完全不一样）。
* `follow_flow=False`：候选入口里 6/10 能跑满 2000 步；撞到 `bl` 的入口
  显式报不支持（预期行为）。
* `follow_flow=True`：多个入口 300 步内进入 native helper ~290 次。

## canary 全局页：必须按需单独 dump

helper 入口的形态固定：

```asm
sub  sp, sp, #N
mrs  xT, tpidr_el0
adrp xP, #PAGE
ldr  wG, [xP, #0x68]      ; ← canary 全局值
mov  wK, #IMM
add  wK, wK, wG            ; 栈上值 = IMM + 全局 canary
adr  xA, #SELF
ldrsw xB, #UDFF            ; udf 里藏的密钥
ldrsw xC, [栈]             ; 栈上值
eor/sub xB, xB, xC
add  xA, xA, xB
br   xA                    ; ← 真实函数体
```

所以「真实函数体在哪」完全由 canary 全局值决定。**缺了它，br 会算到
`udf` 指令上**（表现为 `NotImplementedError: insn udf #0`），而不是报
"地址非法"——很容易误判成 dump 缺页。

这些 canary 页散落在 JIT 区**之外**的其他映射段（实测偏离 1.6GB），
无法靠扩大 dump 范围覆盖，只能在设备侧按需逐页读取 → `canary_pages.txt`
（实测 27 页，1097 个 stub 里 91 个用到 adrp）。

装上之后：`follow_flow=True` 下 6 个入口 500 步全跑通，其中 4 个进入
native helper 约 490 次。

## 随机源已定位

全程序最热的 helper（一次调用 118~398 次）：

```
JIT+0x2ed08:  mov x0, x26
              mov x1, x27
              ldr x2, [x21, #8]      ; 偏移
              bl  <mem_rw>
              ldrb w16, [x21, #7]
              str x0, [x25, x16, lsl #3]   ; 存回 VM 寄存器

JIT+0x2b368:  ldr x8, [x1, #0x240]        ; mem_rw
              ldr x8, [x8, #0x1a0]
              add x0, x8, x2
              ret
```

即：每次取一个值都来自 **VM 状态缓冲 `*(ctx+0x240) + 0x1a0` + 偏移**。
这块区域每次 70102 调用被重写，读出的值逐次不同 —— 这就是 nonce 逐次
变化的来源。

**下一步**：逆出「谁写 `*(ctx+0x240)+0x1a0` 这块状态、写的值从哪来」。

## 解释器的观测钩子（定位数据流用）

`AvmpVm` 上有三个观测点，都是为回答「这个值从哪来 / 谁写的」准备的：

| 钩子 | 签名 | 覆盖范围 |
|---|---|---|
| `vm.on_call(pc, target, cpu)` | 每次 `bl`/`blr` 目标 | **包括内联小函数**（`mem_rw` 不走 dispatch，只能挂这里） |
| `vm.on_store(pc, addr, size, val)` | 解释器层写 | 普通访存 |
| `mem.on_write(addr, size, val)` | 内存层写 | **全部**写入路径（普通访存 / `x25` 寄存器文件 / `x21` 帧 / `x27` 帧指针） |
| `vm.last_cpu` | 当前 `Cpu` | 任意时刻读 `x0..x30` |

装载镜像（JIT 区 / canary 页 / 帧数组）期间用 `mem.quiet()` 抑制
`on_write`，否则会被几十万次装载写淹没。

用 `on_call` 统计一次 70102 的执行：

```python
v = x.new_vm(); v.follow_flow = True; v.frame = 0x100
v.on_call = lambda pc, t, c: calls[t] += 1
v.run(max_steps=400)
# 298 次 bl，全部指向 mem_rw(0x7438793368)；
# dispatch 层只看得到 3 个地址，因为内联小函数不经过 dispatch
```

## 已修：寄存器形式 `mov` 被当成立即数

```asm
mov x1, x27        ; 汇编为 ORR x1, xzr, x27 —— 寄存器间移动
```

原先 `_exec` 的 `mov` 分支只认 `#imm`，遇到寄存器形式一律 `imm=0`，
于是 `mov x1, x27` 把 x1 **置 0**。

危害特别隐蔽：它不抛任何异常。表现是 helper 取 `ctx` 时恒为 0，
随机缓冲地址算成 `0x1600000001ba`，看起来像"数据没 dump"，
实际上是解释器算错了。

回归测试用 JIT 里**真实存在**的 `mov xD, xS` 走一遍 `exec_one` 断言复制生效，
并单独锁定 `mem_rw` 调用点前那条 `mov .., x27`。

## 仍需的 dump：真实入口帧 + x21/x23/x27 初值

修完 `mov` 后 `ctx` 读出来是正确的 `0x400000000`（我建模的 SAVE_AREA），
但 `*(ctx+0x240) == 0` —— SAVE_AREA 是我合成的 0x200 字节栈，里面没有
设备运行时真实的 VM 上下文结构。

同时从 `0x100` 入口执行会**原地打转**（帧立即数恒为 `0x16000000001a`，
明显不是合法偏移），说明 `0x100` 不是本次调用的真实入口。

所以离线 VM 目前能跑通「单条 handler + helper 调用」，但要跑出**完整程序**
还差两项设备侧数据：

1. 本次 70102 调用的**真实入口帧**（dispatcher 首次命中时的 x21，以及它之前的
   VM 上下文指针）；
2. 那一刻的 **x21 / x23 / x27 寄存器初值**（x27 指向的 VM 上下文结构本体）。

这两项加上后，mem_rw 的 `*(ctx+0x240) + 0x1a0` 就能算出真实随机缓冲地址，
再顺写入者追下去即是 nonce 的来源。

## vminit：真实入口帧 + 寄存器初值（已导出，尚未接上）

`avmp/vminit.txt` / `vmframes2.txt` / `vmregs3.txt` 是一次设备运行里同源导出的：

```
ENTRY {"x21":"0x7433fb1930","x23":"0x754b08b400",
       "x25":"0x75394d62a0","x27":"0x75394d6260"}
X27_CTX  0x75394d6260   4096 字节的 VM 上下文本体
CTX240   0x754b127000   *(ctx+0x240)
CTX240_DATA               再往下一层
BUF_DATA 0x7433f95ffc    随机缓冲候选
vmframes2.txt            从入口起 24576 帧（10839 非零）
vmregs3.txt              x25 寄存器文件 512 槽（23 非零）
```

### 为什么还没接上

`XsignVm(use_vminit=True)` 可以装载它们，**并且确实让帧推进起来了**
（入口 `frame=0x0 -> 0x10`），但随后在 `id=367` 那个比较分支上**原地打转**：

```asm
+0x00 ldrb  w3, [x21, #3]      ; 寄存器号
+0x04 ldr   x2, [x25, x3, lsl #3]
+0x08 ldrsw x5, [x21, #8]       ; 立即数 = 0xff
+0x0c cmp   w2, w5
+0x10 b.hs  <跳走>
+0x14 ldrsw x8, [x21, #0xc]     ; 分支偏移
+0x18 add   x21, x21, x8, lsl #4
```

该帧 `[0xc:0x10] == 0`，所以 `add x21, x21, 0` —— 帧指针不动。
也就是说**静态 dump 的帧数组里，分支偏移字段是 0**；这些字段是 handler
在运行时根据寄存器值算出来写回的，静态快照拿不到。

而且 `frame[0x10]` 那 2 字节是 **handler id=367**，`ldrh [x21,#0x10]!`
读的正是它——即「下一帧 id」与「本帧 id」在同一位置，这一点与我先前
`handler(F) = x23[u16_at(F+0x10)]` 的结论一致。

**结论**：帧数组必须带**执行时的写入**，纯静态 dump 不够。可行的下一招是
在设备侧 hook `str x21, [...]` 之外的所有 `str [x21, ...]`（即帧字段回写），
把每个 16 字节帧的真实内容按执行序列落盘。

### 已确认的 VM 上下文层次

```
ctx      = x27            = 0x75394d6260
*(ctx+0x240)               = 0x754b127000
*(*(ctx+0x240)+0x1a0)      = 0x7433f95ffc   <- 落在 JIT/帧区附近
```

## 帧数组必须取「晚期」快照（重要）

帧数组就是 VM **自解密解码出来的程序体**：handler 运行时把解码结果写回帧里。
所以：

| dump 时机 | 非零帧占比 | 分支偏移 `frame[0xc]` |
|---|---|---|
| dispatcher 第 8 次命中（早） | 44% | 基本全 0 |
| dispatcher 第 3000 次命中（晚） | **76%** | 6890 帧非零（含 `-1` 回退、`8/10/16/1028` 前进） |

早期快照跑离线 VM 会在 `id=367` 那个比较分支上原地打转：

```asm
ldrsw x8, [x21, #0xc]     ; 分支偏移，早期快照里 = 0
add   x21, x21, x8, lsl #4 ; +0，帧指针不动
```

**所以 `vminit.js` 记录入口地址用第 8 次命中，但帧数组/寄存器在第 3000 次
命中才落盘。**

## 同源必须一次跑齐（并且要自检）

`jit.bin` / `vmxtab.txt` / `vmframes2.txt` / `vminit.txt` **必须来自同一次运行**。
跨运行混用的症状很隐蔽：帧内容看起来正常（有 76% 非零），但**所有
handler id 都查不到**——因为 `x23` 表指向的是另一次运行的 JIT 区。

`XsignVm.new_vm()` 现在会做同源自检并在非同源时**直接报错**：

```
x23 表与 JIT 区非同源: 0/0 条 handler 落在 [0x7438500000,0x743a800000) 内。
需要同一次运行同时导出 jit.bin 与 vmxtab.txt。
```

之前这个错误是静默的，表现为"帧 id 全部查不到"，很容易误判成帧内容有问题
而去查分支偏移——绕了好几轮。

## 条件跳转：两个真 bug

```asm
cmp   x15, x8
b.eq  #0x743bc66170        ; capstone 的 #imm 已是绝对地址
```

1. **目标算错**：`b.cond` 的 `#imm` 是 capstone 给的绝对地址，原实现又加了一次
   `ins.address` → 跳到野地址。
2. **不跟随跳转**：dispatch 的控制转移只认 `br/b/bl`，漏了 `b.cond/cbz/cbnz/
   tbz/tbnz`，于是条件跳转后仍继续执行下一条 —— 表现为**循环出口判定失效**，
   每个循环都多走错一步、帧推进到某个点就卡住。

修完后离线 VM 的帧推进从「停在 0xa0」变成正常穿出循环（0x0→0x10→…→0xa0→0xc0）。

回归测试 `TestControlFlow` 三项：目标绝对地址正确、���成立时顺序执行、
`cmp` 设的 NZCV 能被随后的 `b.cond` 读到。

## 当前同源 artifacts

`vmonce.js` 一次运行导出六件，全部带 `X23`/`JITLO` 头可交叉校验：

| 文件 | 内容 |
|---|---|
| `jit.bin` | 34MB JIT 区 |
| `vmxtab.txt` | x23 表，827/1024 handler 有效 |
| `vmframes2.txt` | 帧数组（晚期快照），24576 帧 |
| `vminit.txt` | 入口帧 + x21/x23/x25/x27 + x27 上下文 + ctx240 + 随机缓冲 |
| `vmregs3.txt` | x25 寄存器文件 |
| `canary_pages.txt` | canary 全局页 65 页（44 非空） |

`XsignVm.new_vm()` 会做同源自检，非同源直接报错而不是静默用错表。
`seq.txt` 目前仍属另一次采集，相关用例会**显式 skip** 而不是假装通过。

## 已还原的 VM handler 语义（离线实测）

| frame_id | 语义 |
|---|---|
| 0 / 545 / 547 | `reg[d] = reg[a] \| reg[b]`（OR） |
| 547 | `reg[d] = reg[a] & (reg[a] \| reg[b])` |
| 545 | `reg[d] = reg[a] + imm` |
| 672 / 658 | 比较 + 条件跳转（循环出口/继续） |
| 16 | 跳板（写 `[x27+8]` 后 `br`） |
| 494 / 505 / 606 / 638 | 各类运算 |

## canary 链是 fall-through，不是间接跳转

实测确认（这次 canary 页与 JIT 区同源）：

```asm
sub  sp, sp, #0x180
mrs  x22, tpidr_el0
adrp x9, #0x74394f7000
mov  w10, #0xab              ; 局部 canary
ldr  w19, [x9, #0x68]        ; 全局 canary (adrp 页)
add  w8, w8, w19
adr  x5, #<adr 目标>
ldrsw x6, #<udf 里的密钥>    ; 读到的常量 0xc8
ldrsw x14, [栈上的 w8]        ; = 0xab + 全局 canary
eor  x6, x6, x14
add  x5, x5, x6              ; x5 = adr 目标 + (0xc8 ^ 栈值)
br   x5
```

算出来的 `x5` 落在 **`udf` 指令之后的那一条**，也就是函数体本身 ——
它是「跳过 udf 密钥继续执行」的 fall-through 跳板，**不是**指向别处的间接跳转。
所以缺 canary 页时 `br` 会落到 `udf` 上，报
`NotImplementedError: insn udf #0`，而不是"地址非法"。

## 帧数组基准必须是入口 x21

`dumpTail` 一度用 `onLeave` 时的 x21 作基准，而那时 x21 已跑到别处
（实测偏了 0x4EE0），导致整张帧表错位、所有 id/偏移取错位置，
表现为"推进最好的入口一个都没有"。改用**入口 x21** 后正常。

## 一个重要观察：VM 通过 JNI 回调宿主

解出的真实函数体（canary stub `0x…28bc` 的 br 目标）开头是：

```asm
stur x8, [x29, #-0x20]
blr  x9                       ; 调 JNI 方法
stur x0, [x29, #-0x88]
cbz  x0, ...
ldrb w8, [x8, #0x1b]         ; 读结果对象 +0x1b 字段
strb w8, [x9, #0x1b]
```

这是**JNI 反射调用**：VM 通过 JNI 拿到宿主对象并读它的字段。调用时
`x1=0x7422455e60`（稳定的 VM 上下文指针）、`x0=x2=0`。

**这很可能就是 nonce 随机值的来源方向**：nonce 不是 VM 内部算出来的，
而是 VM 回调宿主、从宿主对象字段里取的。离线复现必须把这个 JNI 回调
替换成等价实现——这正是「脱离设备重算」的最后一块拼图。

## VM 的原语派发表（canary 页 +0x70）

VM 侧解析出 canary 后，用**同一张 canary 页**派发内部原语：

```asm
adrp x21, #<canary 页>
add  x21, x21, #0x70
ldr  x9, [x21, w9, sxtw #3]     ; w9 = 原语索引
...
blr  x9
```

`canary_page + 0x70` 起的 8 项实测全部指向 JIT 区内的 VM 原语（不是宿主地址）：

| idx | 地址 | 开头 |
|---|---|---|
| 0 | `0x…ad878` | `ldr w8,[x0]; cmp w8,#4` |
| 1 | `0x…b3c00` | `mov w8,w1; mov w19,w0` |
| 2 | `0x…bf234` | 保存 x22/x21/x20/x19 |
| 3 | `0x…ac3d4` | `cmp w0,#4; b.hi` |
| 4 | `0x…ac408` | `cmp w0,#4; b.hi` |
| 5 | `0x…b2648` | 大栈帧 0xf0 |
| 6 | `0x…ad8cc` | `ldr w8,[x0]; cmp w8,#4` |
| 7 | `0x…ad7b0` | `ldr w8,[x0]; orr w8,w8,#2` |

`cmp #4` 那几个是按**参数个数/类型**分派的通用原语（像是一个小解释器）。

## 当前卡点（已定位到具体一步）

离线执行到帧 `0x10` 的循环时，`blr` 的目标是
`0xffffffffffffff5c` —— 符号扩展的负偏移，说明**派发索引 `w9` 越界**
（表只有 8 项）。也就是说执行路径在该处已经跑偏，回路是
「索引越界 → 跳到野地址 → 回到同一帧」。

根因是帧数组里该 handler 的**分支偏移/派发索引字段仍是快照值**，
而不是执行时的真值 —— 帧数组是 VM 逐块自解码的程序体，静态快照拿不全。

**下一步**：在设备侧 hook `str x21, [...]`（帧字段回写）与这张派发表的
写点，按执行序列落盘每条指令**执行前**的完整帧内容与 `w9`，用真实执行轨迹
驱动离线重放。
