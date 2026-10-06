# 静态分析发现（libsgmainso-6.8.260602.so，设备断开期间完成）

分析工具：ghidra-cli（Ghidra 12.1.4），项目 `sg68`，导入后自动分析出 **1819 个函数**。
注意：so 的 section header 被剥（地址全为 -1），Ghidra 只在低地址区（0x1xxxx–0x25xxx）
识别出函数；0x4e000–0x1b2000 区间**未被识别为函数**，需手工反汇编。

## 1. 找到完整的 RC4 实现（KSA + PRGA + drop-N）

`FUN_00254ee4`（模块偏移 `0x254ee4`），反编译结果：

```c
void FUN_00254ee4(byte *out, int len, byte *key, long keylen, uint drop)
{
    byte S[256];              // 由 0x25000 常量页初始化
    byte i = 0, j = 0;
    // KSA
    do {
        uint q = drop ? (uint)i / drop : 0;
        c = S[i];
        j = c + j + key[(uint)i - q * drop];      // j = j + S[i] + key[i % keylen]
        S[i] = S[j];
        i++;
        S[j] = c;
    } while (i != 0x100);
    // PRGA
    if (len) {
        do {
            i++;
            len--;
            c = S[i];
            j2 += c;
            S[i] = S[j2];
            S[j2] = c;
            *out = S[(uint8)(c + S[i])] ^ *key;   // 密钥流再与 key 异或
            out++; key++;
        } while (len);
    }
}
```

- `param_5` 是 **drop-N**：`i - (i/drop)*drop == i % drop`，即 RC4-drop-N。
- 输出 = RC4 密钥流 ⊕ key。
- 共有 **14 个调用者**（`ghidra-cli find calls FUN_00254ee4`）：
  `0x254cec 0x2651c4 0x263418 0x2635e8 0x2636d0 0x2a0108 0x2a0270 0x2a04c8
   0x2a0630 0x2a5e2c 0x2a58c8 0x2a59ac 0x2a5f8c 0x2a5528`

**在现有 4 份 trace 的执行窗口内，RC4 及其 14 个调用者均未被执行**（见 §4）。

## 1.5 关键判断：70102 很可能跑在 AVMP 式 VM 解释器里

`0x25000` 是一个 **4KB 页**（0x25000–0x25fff）。逐条统计 588 处 `adrp` 引用的**具体偏移**后发现：

- 0x25000–0x25300：规整的查表/哈希 padding（见 §2）
- **0x25400–0x25f00：大块随机字节**（例：`0x25618` = `472985891b803f127131148045d49f61`），
  引用次数最高的前 24 个偏移**几乎全落在这个区间**（0x25772/0x2577c/0x257d2/0x257e3… 反复引用）

即：最热的代码簇（0x05da80..0x05e79c，99 处引用）读的是**加密数据块**，不是常量表。
结合设备侧发现（`app_SGLib/.utask_64/<id>/52@24` 约 200KB 的 VM 任务块），
最合理的解释是：**70102 的载荷生产逻辑被 AVMP 风格的字节码保护**，由解释器逐条 dispatch。

这同时解释了三个此前 puzzled 的现象：
1. 为什么 24000 条指令的 trace 窗口连 RC4 都没碰到——VM dispatch 的
   「每条基础块上千条指令」开销极大；
2. 为什么静态反汇编在该区域无法形成函数（字节码被当数据/混淆）；
3. 为什么载荷结构高度模板化（41 字节常量区）而变化部分只有 10 字节——
   模板是数据，变化部分是 VM 里的计算结果。

**逆向路线因此调整为**：不要试图静态还原 VM 解释器，而是
(a) 找到 VM 的入口（`avg_getSecurityFactors` 字符串的解出者 `sub_54b70` 附近）与
(b) 在设备上对 VM dispatch 循环做 trace，`coverage` 拿到 VM 解释器的执行块集合，
(c) 对解释器做 taint，从「请求缓冲」追到「输出缓冲」——**解释器是通用的，
数据流依然成立**，只是多了一层调度。

## 2. 常量页 0x25000 前段（被 588 处 `adrp` 引用）

| 地址 | 内容 | 推测 |
|---|---|---|
| `0x25000` | `01 00 00 00 05 00 00 00 0b 00 00 00 10 00 00 00` | 4 字节索引/长度表 |
| `0x25010` | `8a79b675 847eb553 8a428d71 8e768ae5` | 哈希类轮常数 |
| `0x25020` | `dd26c926 121de413 dad0061d e414d681` | 位掩码表 |
| `0x25030` | `05e636d8 17cc2ab0 1bac29b4 1bd73526` | 哈希类轮常数 |
| `0x25040` | `90 91 … 9f` | 高位字节表 |
| `0x25050` | `b0 b1 … bf` | 高位字节表 |
| `0x25060` | `f0e649ca fb48f8ed 4a85e615 ea953d09` | 密钥调度类常数 |
| `0x25070` | `a88030f3 4ece5b0c 0ac170fe 7b93a729` | 密钥调度类常数 |
| `0x25080` | `01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10` | **MD5/SHA padding 常量** |
| `0x25090` | `d59439d3 cc39ea94 0e3923f7 c4e33909` | 密钥调度类常数 |
| `0x250a0` | `80 81 … 8f` | 高位字节表 |
| `0x250b0` | `0c 10 10 10 0d 10 10 10 0e 10 10 10 0f 10 10 10` | 4 组 4 字节查表 |
| `0x250c0` | `03 0b 13 1b ff ff …` | 查表 |
| `0x250d0` | `02 00 … 01 00 …` | 查表 |
| `0x250e0` | `01 09 11 19 ff ff …` | 查表 |
| `0x250f0` | `06 0e 16 1e ff ff …` | 查表 |

`0x250b0`–`0x250f0` 呈「4 字节一组 + 0xff 填充」形态，符合 **base64 解码/字符分类查表**的特征，
与已知的 5 个参数都用 base64 类编码吻合。

**引用该页最多的代码簇**：

| 区间 | adrp 处数 |
|---|---|
| `0x05da80..0x05e79c` | 99 |
| `0x05eb20..0x05efa0` | 37 |
| `0x071034..0x071494` | 30 |
| `0x05cacc..0x05d06c` | 24 |
| `0x06a494..0x06a704` | 19 |
| `0x068ff4..0x06925c` | 18 |
| `0x058490..0x058658` | 17 |

`0x05da80` 距离 `doCommandNative`（`0x57b60`）仅约 24 KB，属同一子系统。

## 2.5 用 capstone 手工反混淆出 JNI 分发链（关键）

`capstone` + 手工计算解出了 `doCommandNative` 的完整控制流。**多处「ldrsw 字面量 +
sub/eor/mvn + add → br xN」的常量跳转专门用于破坏静态反汇编**，已逐个解出：
`0x57be4→0x57c24`、`0x5542c→0x55460`、`0x54c64→0x54c98`。

调用链（cmd=70102）：

```c
// doCommandNative @ 0x57b60   (x0=JNIEnv, w2=cmd)
x8  = (s64)cmd * 0x68db8bad;   w0 = x8 / 10000;      w8 = cmd % 10000;      // = 102
x11 = (s64)cmd * 0x51eb851f;   w11 = x11 / 100;       w2 = cmd % 100;        // = 2
w8  = (int16)w8 * 0x147b;     w1 = w8 >> 19;                            // = 1
bl 0x553d8(x0=sp+0x28, x1=w1, x2=w2, x3=1, x4=sp+0x28, x5=sp+0x24)

// 0x553d8
bl 0x54b70(自身, 4)                       // 字符串常量解码器, 做一次性初始化
x25 = [0x2c73b0]; bl 0x1b18d0
bl 0x54c10(x0=x25, w1=1, w2=2, w3=?, w4=0, x5=sp+0x40)

// sub_54c10 @ 0x54c10  —— 核心
idx = (w23*10000 + w21*100 + w20) * 10000
// 以 w23 (=w1 = 1) 为 id 在**运行时命令表** x26 中线性查找:
for (i = 0; ; i++) { p = base[i]; if (*(int*)p == w23) { found = p; break; } }
```

**决定性结论**：70102 的实际处理函数是**运行时注册表里的函数指针**，
`sub_54c10` 只负责查表 + 调度。这解释了：

- 为什么 Ghidra 在 0x4e000–0x1b2000 区域**无法形成函数**（控制流被常量跳转打散）；
- 为什么静态反汇编毫无进展——目标根本不在静态可达路径上；
- 唯一可行的定位手段是 trace：**观测 `sub_54c10` 里那个 `blr` 的实际目标地址**。

## 2.6 完整定位链（trace + capstone 交叉确认，设备断开期间完成）

自建离线 trace 解码器（已用工具输出逐条校验：idx 0/1 的反汇编与 `./tracemiku records` 完全一致；
`pc` 在记录偏移 0，`inst` 在偏移 268，`regs[i]=x_i` 在偏移 `8+8i`；注意 `blr` 的寄存器在
bits[9:5] 而非 bits[4:0]）扫描出全部 `blr`，与 `./tracemiku resolve` 交叉验证：

```
doCommandNative  0x57b60
  └─ [常量跳转混淆] → 0x57c24
     bl 0x553d8   (x0=sp+0x28, x1=1, x2=cmd%100, x3=1, x4=sp+0x28, x5=sp+0x24)
        ├─ bl 0x54b70(自身, 4)          字符串常量解码器, 一次性初始化
        ├─ 取全局 [0x2c73b0]; bl 0x1b18d0
        └─ bl 0x54c10(表项, w1=1, w2=2, w3, 0, sp+0x40)      exec_count=11
              └─ 以 w1(=1) 为 id 在**运行时命令表**线性查找
                 blr x8 @ 0x555cc        exec_count=10   ← 分发点
                    ├─→ 0xcc4f4    (字符串解码器, 1 次)
                    ├─→ 0x4e5f0    ★ 4 次 = 4 次 70102 调用
                    ├─→ 0x97010 / 0x62968 / 0x72cc4 / 0x965c0 / 0x60340  (各 1 次, 其它子命令)
                    └─→ 0x1abd00   (1 次)
```

**`libsgmainso+0x4e5f0` 就是 70102 的 handler**（`resolve` 确认 exec_count=4，
first_idx=2630 / last_idx=5581，与 4 次调用一一对应；它同时是整个 trace 的最小执行偏移）。

而 0x4e5f0 本身只是一个 **lazy-init stub**：

```asm
0x4e5f0  sub sp,sp,#0x50 ... ldrb w9,[0x2c72e0] ; tbnz -> 已初始化则直接跳 0x4e660
0x4e618  x10 = 0x1b6248 ; str wzr,[sp,#0xc] ; strb 1,[0x2c72e0]      ; 置初始化标记
0x4e62c  ldr q0,[x10] ; ldr x10,[x10,#0x10] ; str q0,[sp,#0x10] ; str x10,[sp,#0x20]
0x4e63c  bl  0x13688c                      ; ★ 一次性初始化(AVMP 装载)
0x4e640  ldr x8,[x0,#0x10]                 ; ★ 从返回结构取**运行时函数指针**
0x4e64c  w0=1, w1=0x1e(30), w2=1, w3=0, x4=sp+0x10, x5=sp+0xc
0x4e65c  blr x8                             ; ★ 真正的 handler
```

**结论：真正的载荷生产函数地址是运行时决定的（`[x0+0x10]`），静态不可达。**
这与 §1.5 的 AVMP 假设完全一致，并给出了确凿证据链。

设备恢复后要做的事因此非常明确：trace 必须 `--max-records 60000` 以上
（ring 上限 65536），让 70102 的真实 handler 落在窗口内；然后
`resolve` 出 `[x0+0x10]` 的目标、`coverage` 拿其块集合、对它做 `taint-bwd`。

## 2.7 五个输出参数的生成器地址（逐一对应）

从单次 70102 调用的 trace 里读出 `blr x8 @ 0x555cc` 的**全部 10 次分发**及其寄存器：

| idx | w1 | w2 | w3 | 目标（模块偏移） | 判读 |
|---|---|---|---|---|---|
| 393 | 0x7C9BE4 | 1 | 2 | `+0xcc4f4` | 字符串常量解码器（一次性） |
| 2629/3497/4709/5580 | 0x7C96C4 | 1 | 13 | `+0x4e5f0` | 共享 lazy-init stub，**参数完全相同、幂等**，4 次 |
| 6611 | 0x7C9B60 | 32 | 12 | `+0x97010` | 生成器 A |
| 8412 | 0 | 31 | 3 | `+0x62968` | 生成器 B |
| 9212 | 0 | 8 | 2 | `+0x72cc4` | 生成器 C |
| 10421 | 0 | 32 | 9 | `+0x965c0` | 生成器 D |
| 11680 | 0 | 31 | 15 | `+0x60340` | 生成器 E |

`blr x8` 之后是 `str x0,[sp,#0x10]` → 直接 epilogue `ret`，即**尾调用，返回值即 70102 的返回值**。

**5 个各调用一次的生成器与 5 个输出参数一一对应**：

```
0x97010  (w2=32, w3=12)
0x62968  (w2=31, w3=3)
0x72cc4  (w2=8,  w3=2)
0x965c0  (w2=32, w3=9)
0x60340  (w2=31, w3=15)
```

全部是**模块内普通函数**（标准 prologue，非运行时指针），因此**静态可分析**——
这修正了上一节「静态不可达」的结论：不可达的只有共享 loader `0x4e5f0`
（它取 `[x0+0x10]` 的运行时指针），而 5 个真正的生成器是固定地址。

初步特征（反汇编前若干条 + adrp 页引用统计）：

| 地址 | 规模 | 引用的页 | 备注 |
|---|---|---|---|
| `0x97010` | 短 | — | 简单 wrapper |
| `0x62968` | 短 | — | 首条 `mov w8,#0x53`(83) |
| `0x72cc4` | 长 | `0xe4000` `0x33a000` | 读 `x0` 描述符 4 字段 + 全局 `[0x2c84b8]` |
| `0x965c0` | 长 | `0x360000` `0x25f000` `0xbe000` `0x24d000` `0xba000` | **引用 `0x25f000`，即前述加密数据块区 → 最可能是走 VM 的那个** |
| `0x60340` | 短 | — | `mov w9,#0x48`(72) |

`w2` 只取 {8, 31, 32} 三种取值，疑似输出类别/长度类别；`w3` 取 {2,3,9,12,15}，
每个生成器一个稳定值，可作为离线对齐的指纹。

**下一步（设备）**：对 5 个生成器分别 `coverage` + `mem-dump`，把输出缓冲与
`x-sign`/`wua` 等键名对应起来（生成器返回的 HashMap 条目），再对命中者做 `taint-bwd`。

## 2.8 窗口边界与「结果组装」的位置（离线分析的终点）

时间线（单次 70102 调用，trace idx）：

```
   137..12553   sub_54c10 主循环
   477..1189    键名解码（sub_54b70 尾调用 9 次）→ 写入 0x2cba64..0x2cba9b
                x-mini-wua 0x2cba64 / x-umt 0x2cba6f / x-sgext 0x2cba75 / x-sign 0x2cba7d
                x-pipu1 0x2cba84 / x-us 0x2cba8c / wua 0x2cba93 / x-gst 0x2cba97
                avg_getSecurityFactors 0x2cba9b
   6611..23999  5 个生成器依次执行（见 §2.7）
   >24000       结果 HashMap 的组装（超窗口）
```

**离线能做的已经做完**，原因有三条硬证据：

1. 5 个生成器在窗口内**都没有持有任何键名地址**（逐寄存器扫过 31 个 GPR × 各生成器区间，
   0 命中）——说明「键 → 值」的装配发生在窗口之后。
2. 生成器 E（`0x60340`）拿到 12320 条记录仍未返回，热点是 `0x17c680` 处
   **16 条指令的循环、执行 71 次**，且循环体内是 `br x5` 尾调用（状态机式逐字节处理，
   不是普通 base64 编码器）。
3. 输出缓冲在堆上，trace 的 memshadow 不覆盖 → 离线无法 `mem-dump` 载荷。

## 2.9 设备恢复后的精确执行清单

```bash
# 1) 一次 trace 覆盖整次调用（ring 上限 65536）
./tracemiku trace --pkg <pkg> --spawn --so libsgmainso   --method doCommandNative --cmd 70102 --cmd-arg 2 --remote 127.0.0.1:27099   --transport frida --out traces/full --duration 60 --max-records 65000

# 2) 确认窗口覆盖到结果组装：sub_54c10 的 blr 次数应 >= 10 且生成器区间延伸到 trace 末尾
# 3) 对 5 个生成器分别取覆盖与块集合
for g in 0x97010 0x62968 0x72cc4 0x965c0 0x60340; do
  ./tracemiku resolve traces/full/calls/<call> --addr $((BASE+g))   # 拿绝对地址
  ./tracemiku coverage traces/full/calls/<call> --addr <abs>
done

# 4) 用 watch --kind mem-touch 在每个生成器的输出缓冲上设观察点，
#    再 taint-bwd 回溯到请求缓冲，判定 nonce 是否 = Enc(key, H(INPUT))
# 5) 用 mem-dump 读出 x-sign 的 76 字节缓冲，验证与 test_vectors.json 的黑盒结论一致
```

已就绪的离线资产（无需重新摸索）：
- 5 个生成器地址 + `(w2,w3)` 指纹（`known_offsets.json` 的 `five_generators`）
- JNI 分发链与常量跳转解法（`static_findings.md` §2.6）
- 键名运行时地址表（§2.8）
- 自建 trace 解码器（校验过的字段布局，`inst@268`、`blr` 寄存器在 bits[9:5]）

## 3. 字符串混淆形态

- 字符串多以**编码字节**存放（如 `0x12309b` 处是 `f0 22 85 2f 91 69 0d`），由运行时解码器还原。
- 已定位的解码器 `sub_54b70`（`0x54b70`）：`dst[i] = src2[i] ^ (src1[i] - key)`，key=0x81，
  src 全部落在 `.rodata`；由 `sub_cc4f4` 尾调用。
- trace 中确认它解出的是输出键名（`x-sign` / `x-mini-wua` / …）与内部名
  `avg_getSecurityFactors`，**不是载荷生产者**。

## 4. trace 执行窗口的量化结论

对 `traces/real2/calls/*`（4 份，各 24000 条）逐记录取 `pc`（记录偏移 0）并减去模块基址
`0x74c0b13000`：

- 唯一执行偏移：**5160–5166 个**
- 偏移范围：`0x4e5f0 .. 0x1b206c`
- 命中：`doCommandNative` 入口 51 处、`sub_54b70` 252 处、`sub_cc4f4` 268 处
- **未命中**：`FUN_00254ee4`(RC4) 0 处、其 14 个调用者全部 0 处

即：**这 4 份 trace 只覆盖了 70102 调用的开头一小段**（24000/65536 条，
Stalker 上限 65536），载荷生产逻辑在窗口之外。`--max-records` 需要提到 60000 以上
才可能覆盖整次调用。

执行偏移集合已存为 `/tmp/opencode/offs_call_*.txt`，供设备恢复后直接比对。

## 5. 设备恢复后的确定步骤

1. 重新 trace，`--max-records 65536`（ring 上限），`--duration` 放宽，确保单次 70102 完整覆盖。
2. 用执行偏移集合与 `find calls FUN_00254ee4` 的 14 个调用者取交集 → 定位 RC4 使用点。
3. 对命中的调用者做 `coverage` + `call-tree`，找写 76 字节缓冲的循环（`w1=0x4c`）。
4. `taint-bwd` 从该循环回溯，判断 nonce 是否 = `RC4(key, H(请求))` 之类。

## 6. 本阶段对目标的净进展

- 五个参数的**传输编码层**：已全部破解并可无损剥离/重建（`xparams_codec.py --selftest` 全绿）。
- `x-sign` 的载荷结构：已确定（41 字节模板 + 计数器 + 10 字节请求绑定 nonce）。
- `x-umt`：设备级恒定，可直接复用。
- **新增**：在二进制中定位到 RC4（含 drop-N）实现、MD5/SHA padding 常量页、
  base64 查表，以及 588 处常量页引用点与 14 个 RC4 调用者清单。
- 未变：明文生产逻辑仍需设备。


## 2.10 完整 trace（设备恢复后重采，815 万条，`is_complete=True`）

按「不设捕获上限」的要求重采：

```bash
./tracemiku trace --pkg <pkg> --spawn --so libsgmainso \
  --method doCommandNative --cmd 70102 --cmd-arg 2 --remote 127.0.0.1:27099 \
  --transport frida --out traces/FULL --duration 120 \
  --max-calls 1 --max-records 0 --ring-recs 4194304
```

结果：

```
records = 8,154,376     bytes = 2,217,990,272     ms = 5,949
rec_per_sec = 1,370,714     dropped = 0
last_asm = ret     last_insn_is_ret = true     is_complete = true     truncated = false
```

**ring 是循环复用的暂存缓冲**（消费端每 10ms 落盘），因此记录数（8.15M）可以远超 ring 容量（4.19M）。
要拿到完整调用，正确的组合是 `--max-records 0`（不设上限）+ 足够大的 `--ring-recs` 吸收 IO 抖动，
而不是调小 `--max-records`（那会主动截断调用）。

### 完整 trace 带来的新结论

对 8,154,376 条全量扫描寄存器（31 GPR）后：

| 区域 | 现象 |
|---|---|
| idx 602..1590 | 键名解码阶段（`avg_getSecurityFactors` 262 次；`x-pipu1`/`x-us`/`wua`/`x-gst` 只在此出现） |
| idx > 7,140,000（尾部 8.15M） | **结果装配区**：`x-mini-wua`/`x-umt`/`x-sgext`/`x-sign` 各出现 **240 次**，且**共用同一段代码 0x1b1870–0x1b193c** |

- 装配区对 4 个键走同一条路径 → 是同一个「键 + 值」写入循环。
- `x-sign` 键地址被作为参数传入 `0x1453cc` 的函数：
  ```asm
  0x1453cc  stp x29,x30,[sp,#-0x30]!
  0x1453dc  mov  x20, x0        ; x0 = 目标结构
  0x1453e8  mov  x19, x1        ; x1 = "x-sign" 键地址
  0x1453f0  ldr  w21,[x20,#8]    ; 读一个 32 位字段
  0x1453f8  ldr  w8, [x20,#0xc]
  0x1453fc  cmp  w21, w8
  ```
- 之前「窗口内 0 命中键名」的结论**只对 24000 条的小窗口成立**；完整 trace 下键名在尾部
  大量出现，说明装配确实在调用末尾——现在有完整数据可继续回溯。

剩余工作（用这份完整 trace 即可完成，不再需要重新采集）：
1. 用 `coverage` / `call-tree` 覆盖 0x1b1870–0x1b193c 的装配循环；
2. 找出「值」侧：x-sign 对应的 base64 字符串缓冲地址（`--snapshot-mem` 或在装配点对寄存器
   指向的堆区做 `mem-dump`）；
3. 沿 `x-sign` 的值反向 `taint-bwd` 回溯到请求缓冲，判定 10 字节 nonce 是
   `Enc(key, H(INPUT))` 还是含随机掩模。


## 2.11 关键更正：0x17c680 是 AVMP VM 分发器，不是 base64 编码器

先前据 `ubfx #0x1a/#0x14/#0xe/#0x8` + `and #0x3f` + `strb` 判它是 base64 编码器，**该判断不成立**。
完整看 0x17c680 起的一整块：

```asm
0x17c680  ldrb  w20, [x21, #6]         ; opcode = ctx[6]
0x17c684  ldr   x0,  [x25, x20, lsl #3] ; handler 表: x25 + opcode*8
0x17c688  ldr   x1,  [x21, #8]          ; 下一条字节码地址
0x17c68c  add   x2,  x0, x1
0x17c690  ldrb  w3,  [x21, #5]          ; 寄存器号
0x17c694  str   x2,  [x25, x3, lsl #3]  ; 回写 VM 寄存器
0x17c698  ldrh  w4,  [x21, #0x10]!      ; 下一个字节码偏移(后索引自增)
0x17c69c  ldr   x5,  [x23, x4, lsl #3]  ; 第二张表 base=x23
0x17c6a0  str   x21, [x27, #8]           ; 保存 VM 上下文
0x17c6a4  br    x5                      ; 尾调用下一个 handler
```

这是标准的 **threaded-code VM**：opcode 索引 handler 表，算出下一 handler 后 `br` 过去。
`0x17c6a8` 起那一大片 `ubfx / and / strb` 是**各个 opcode 的 handler 体**，与 base64 无关。

- VM 上下文 = `x21`；`ctx[5]`=寄存器号、`ctx[6]`=opcode、`ctx[8]`=下一条地址、
  `ctx[0x10]`=字节码偏移（**后索引**，用完自增）。
- 两张表：`x25`（handler 表）、`x23`（续表）。`x27[8]` 保存上下文。
- 完整 trace 里 `0x17c680` 被执行 125 次，`x21` 每次都不同 → 一个上下文跑一条 VM 程序。

**影响**：76 字节载荷的生成逻辑整体运行在这个 VM 里。因此
1. 在 5 个生成器（0x97010/0x62968/0x72cc4/0x965c0/0x60340）里找 `strb` 循环是找不到的；
2. 载荷缓冲（`x19=0x70d4fe20a0`、编码器输入 `x21=0x71abdc4670`）在 trace 内**没有任何写指令**，
   因为写入方也在 VM 内部（VM 解释器的 `strb` 走的是 VM 寄存器间接寻址，
   不落在「模块内 store 目标 = 堆地址」这个过滤条件上）。

**因此纯算法还原的下一步明确**：在设备上 hook `0x17c680`，读出 VM 上下文的字节码基址，
把**解密后的 VM 字节码**落盘（对应 so 里 0x25400–0x25f00 那片加密数据），
然后离线解释这个 VM，直接还原 5 个参数的算法。

## 2.12 AVMP VM：x-sign 生成程序的实际形态

x-sign 的 76 字节载荷不是由普通 ARM64 代码拼出来的，而是由一个
**threaded-code VM**（AVMP）生成。模块内 dispatcher 在 `libsgmainso+0x17c680`：

```asm
ldrb w20, [x21, #6]          ; 源寄存器号
ldr  x0,  [x25, x20, lsl #3]  ; 表1
ldr  x1,  [x21, #8]           ; 立即数
add  x2,  x0, x1
ldrb w3,  [x21, #5]           ; 目标寄存器号
str  x2,  [x25, x3, lsl #3]   ; 寄存器文件 x25
ldrh w4,  [x21, #0x10]!       ; 下一帧 id（后索引）
ldr  x5,  [x23, w4, lsl #3]   ; frame_id -> handler
str  x21, [x27, #8]           ; 保存帧指针
br   x5
```

要点：

- **x21** 帧指针，16 字节/帧；**x25** 寄存器文件（8 字节/槽）；
  **x23** `frame_id -> handler` 表；**x27+8** 帧指针保存槽。
- handler 是**运行时 JIT 出来的代码，不在 so 文件里**（实测在模块外
  `0x7439dc6c44` 起的 0x30000 字节区），每条 handler 就是一条 VM 语义。
- `handler(F) = x23[ u16_at(F) ]`：帧开头 2 字节就是自己的 handler id。
- 帧推进由 `add x21, x21, imm, lsl #4` 完成，`imm` 可为负；**帧偏移不连续**
  （实测 0x9f70 -> 0xa080 跨 0x110 = 17 帧）。
- 写 `[x27+8]` 是「本帧结束」的判据；不写就是跳板（位置无关 fall-through），
  要继续在 JIT 流里执行。
- **载荷字节由 handler 622/627/634/639/643 写出**（`strb`/`str`/`str w`）。
- 另有 4 个 handler（17/22/539/540）`bl` 调 JIT 区内 native helper，
  疑似 MD5/RC4/base64，**nonce 的最终混合大概率在这里**。

已把整套 JIT 区、帧数组、寄存器文件落盘，并写了可执行的 ARM64 子集解释器：
`examples/libsgmainso/avmp/`（含 `README.md` 记录结构、语义表与剩余缺口）。

这也解释了为什么在 5 个生成器（0x97010/0x62968/0x72cc4/0x965c0/0x60340）里
找不到写载荷的 `strb` 循环：那些函数只是调用 VM，逻辑在 JIT 出来的 handler 里。
