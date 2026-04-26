# 从0开发你自己的Trace后端分析工具 系列文章整理

> 作者：FANGG3  来源：看雪安全社区

---

## 第一篇：（1）概述

**原文链接：** https://bbs.kanxue.com/thread-281555-1.htm
**发布时间：** 2024-4-28

### 一、概述

在Native层进行逆向分析，有两种途径：**静态分析**和**动态分析**。静态分析使用反编译工具对ELF文件进行反汇编，提取符号，还可以还原出伪代码（但有准确性问题，如IDA的JUMPOUT、函数范围判断错误等）。动态分析通过程序断点、插桩等形式窥探程序运行时的状态，但无法对整个程序进行全面分析。

逆向分析往往是动静结合的：静态分析拿到线索之后，动态分析验证思路。

**Trace** 是记录整个程序的运行过程，包括指令、寄存器以及内存，记录粒度可以是函数或线程。Trace 是程序某次运行过程中的唯一路径——伪代码可能会骗人，静态反编译可能会骗人(Self InlineHook)，但 Trace 不会骗你。

### 二、采集Trace

在Android平台上，采集Trace的工具有很多：
- Frida Stalker
- QDBI
- Unidbg Trace
- IDA Trace

只要保证 Trace 格式一致，能被后端工具正常解析即可。tenet 作为一个IDA插件，也仅要求了这一点。

### 三、难点

#### 1. Trace效率

IDA Trace 较 Frida Stalker 会慢一个数量级左右（插桩实现方式不同）。OLLVM控制流混淆、指令膨胀时大量控制流代码会大幅增加采集时间，甚至导致程序崩溃。

三个解决方案：
1. 不需要的So，不Trace
2. 插入优化，判断循环、重复的数据，仅采集程序变化的部分
3. 换台更好的手机（钞能力）

#### 2. 分析效率

后端分析面对上亿条级别的Trace记录，可能导致内存不足、分析缓慢。需要解决的建模问题包括：
- 函数符号建模
- 寄存器状态建模
- 内存状态建模
- 控制流图建模

### 四、展望功能

- 控制流优化
- 函数调用交叉索引（anti blr）
- 内存字符串
- Python插件及脚本系统（联动IDA、Binary Ninja）

### 参考（第一篇）

- [使用时间无关调试技术(Timeless Debugging)高效分析混淆代码](https://bbs.kanxue.com/thread-273055.htm) —— @krash
- [tenet trace format](https://github.com/gaasedelen/tenet) —— IDA插件tenet的Trace格式说明
- [TTD调试与ttd-bindings逆向工程实践](https://bbs.kanxue.com/thread-278069.htm)

---

## 第二篇：（2）Trace前端的构建

**原文链接：** https://bbs.kanxue.com/thread-285745.htm
**发布时间：** 2025-2-25

相关链接：
- 概述: https://bbs.kanxue.com/thread-281555-1.htm
- 前端构建: https://bbs.kanxue.com/thread-285745.htm

基本概念定义：
- **Record**：Trace记录，包含分析所需要的运行时信息
- **Tracer**：前端采集器，注入至目标进程并记录Record
- **Backend**：后端分析器

### 一、Tracer的基本功能

常规需求：
- 汇编指令
- 寄存器信息
- 内存读写信息
- 符号信息

ATTD 中的 Record 格式示例（使用指令执行后作为记录点）：

```
X8=0xa7baccc8585dee7d,PC=0x759d98cc9c,mr=768aea3048:12086197710850223741:8,inst=759d98cc98:081540f9:Java_com_f_testcase_testCase_stringFromJNI+16
```

同时可将 maps 信息保存，将当前指令地址与 So 对应起来。

### 二、Tracer的原理

主要有两大类：**指令模拟器（Simulator）** 和 **动态插桩（Binary Dynamic Instrument）**。

#### 1. 指令模拟器

将目标平台机器码抽象成平台无关中间语言IR，再通过虚拟机（VM）模拟执行IR，实现跨平台运行。相关开源项目：unicorn(qemu)、dynamic、vixl。

实现Trace时，循环读取PC地址对应机器码，翻译成IR，编写handler函数处理IR执行，直到函数返回。

存在的问题：
- **原子指令模拟**（cas, ldxr...）：VM难以保证时序性和一致性
- **浮点寄存器模拟**：在目标平台运行VM时效率太慢
- **特权指令模拟**：与内核模式相关，实际几乎遇不到

#### 2. 动态插桩

代表：Frida、DobbyHook。劫持目标函数控制流，跳到自己编写的逻辑中执行，即 inlinehook。

实现Trace的流程：
1. 初始化：替换目标地址指令，跳转至自己的逻辑中
2. 备份原指令
3. 内联汇编获取寄存器（func_getRegs）
4. 重定位 func_getRegs + 原指令，处理地址相关指令
5. 内联汇编获取寄存器，获取原指令执行结果
6. 根据执行结果，计算下一条指令的地址
7. 循环执行，直到函数结束

需要自己计算内存读写信息，并将实际执行权交由CPU处理。

### 三、简单实现Trace前端的思路

选取**动态插桩**结合**IR**的形式实现Tracer：对于可以使用IR解释的指令，使用VM执行；其他指令使用插桩形式执行。将指令提升为IR后可得到内存读写信息。

#### 1. 寄存器信息
通过 inlinehook 获取函数进入时的寄存器信息（或使用ptrace）。注意防止重入，进入自己的逻辑时应第一时间 unhook。

#### 2. 汇编指令和符号信息
通过 PC 寄存器获取当前指令地址（ARM64取4字节），通过 `dladdr` 获取符号信息。

#### 3. 内存读写信息
使用已有库（vixl、RzIL 或 Dynamic）将机器码解析为IR，使用实际寄存器值计算内存地址及读写值。

使用 RzIL 计算内存读写信息的核心流程：

```c
void liftToIR(ut64 pc){
    RzILVM *vm = rz_il_vm_new(pc, 64, false);
    init_vm_regs(vm); // 同步VM寄存器和实际寄存器
    // 初始化 RzAnalysis 和 plugin ...
    RzAnalysisOp op = { 0 };
    int ret = toOp(&op, pc, *(ut64 *)pc);
    rz_il_vm_step(vm, op.il_op, pc + op.size);
    print_vm_event(vm); // 打印 MEM_READ / MEM_WRITE 等事件
}
```

作者使用 Dobby 结合 QBDI 实现了简单 Demo（非生产用）：
[FANGG3/DobbyWithQBDI](https://github.com/FANGG3/DobbyWithQBDI)

### 拓展：Unidbg

使用 Unidbg 输出 ATTD 的 Record 格式，作为 Unidbg 的简单插件（速度较慢，但可用）。

核心实现（Java，`AttdTracer` 类）：
- `CodeHook`：记录每条指令执行前后的寄存器状态及指令信息
- `ReadHook`：记录内存读（格式：`mr=地址:值:大小`）
- `WriteHook`：记录内存写（格式：`mw=地址:值:大小`）
- 支持符号信息输出

---

## 参考文章一：使用时间无关调试技术(Timeless Debugging)高效分析混淆代码

**原文链接：** https://bbs.kanxue.com/thread-273055.htm
**作者：** krash
**发布时间：** 2022-5-29

### 文章概述

本文介绍了作者自研的时间无关调试器，用于高效分析混淆代码。时间无关调试核心思想：记录程序执行过程中的寄存器和内存变化，使用记录的 trace 离线调试分析。

最初的 qira（https://github.com/geohot/qira）、微软的TTD、Mozilla的record-replay debugging（https://github.com/rr-debugger/rr）本质都是一样的。

### 工具主要功能

**指令流视图**：可来回浏览任意历史时间点的指令状态。

**寄存器视图**：与实时调试器类似，可查看任意历史时间点的寄存器状态。

**内存视图**：可像实时调试器一样浏览任意程序点、任意地址的内存内容。只在内存被使用（读写）时才记录内容，未被访问的内存显示为"??"。

**交叉引用视图**：
- `<-` 使用定义链：某条指令定义的值被当前指令使用
- `->` 定义使用链：当前指令定义的值的使用者
- 内存交叉引用：显示当前指令读写的内存地址及定义/使用指令编号

**字符串参考（杀手级功能）**：分析trace时内存出现过的所有字符串，直接秒杀所有字符串加密防护。

**污点追踪**：
- 正向污点追踪（Forward Taint Analysis）：标记受输入影响的相关指令
- 逆向污点追踪（Backward Taint Analysis）：自动回溯变量来源和相关计算过程

**调用栈**：快速跳转到上层调用者，考察调用参数。

**控制流图（CFG）**：
- 从trace中重建CFG，天然对抗间接跳转混淆
- 支持代码动态修改和映射（加壳、动态mmap代码）
- 使用自研结构化算法布局CFG（参考Ghidra Decompiler Layout）
- 强连通分量绘制在一起，函数返回块固定于最底层
- 配套块导航图：可视化调试进度、识别循环头、评估函数规模

### 实战演示

样本：看雪论坛2021年11月3w班题目（libnative-lib.so）
- KanxueSign 函数 trace 约42万条指令
- 记录文件大小 6.42MB
- Pixel 3 上 trace 耗时小于500毫秒

分析流程：
1. 以输出字符串切入，搜索首字节在内存中的位置
2. 逆向污点追踪，回溯计算过程
3. 发现标准 sha256 算法（通过与标准实现对比ctx确认）
4. 分析出5次 sha256 transform 的调用关系及输入
5. 还原完整算法

最终还原的算法（Python实现）：

```python
# part 1: HMAC-SHA256 变体
s0 = '{:08x}{:08x}'.format(start_time, first_install_time)
s0 = (s0 + (64 - len(s0)) * chr(0)).encode()
sha_a = hashlib.sha256()
s1 = bytes([c ^ 0x5c for c in s0])
sha_a.update(s1)
sha_b = hashlib.sha256()
s2 = bytes([c ^ 0x6a for c in s1])
sha_b.update(s2)
sha_b.update(package_code_path.encode())
sha_a.update(sha_b.digest())
part1 = sha_a.hexdigest()

# part 2: 查表编码
part2 = ''
for c in package_code_path:
    part2 += '{:04x}'.format(dword_5C008[random_long % 5 + ord(c)])

# part 3: 自定义Base64
s0 = '{:08x}{:08x}'.format(start_time, first_install_time)
part3 = base64.b64encode(s0.encode())
std_b64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom_b64 = b'0123456789_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
part3 = part3.translate(bytes.maketrans(std_b64, custom_b64))
```

### 参考（krash文章）
- [对ollvm的算法进行逆向分析和还原](https://bbs.kanxue.com/thread-270220.htm)

---

## 参考文章二：TTD调试与ttd-bindings逆向工程实践

**原文链接：** https://bbs.kanxue.com/thread-278069.htm
**作者：** 0x指纹
**发布时间：** 2023-7-18

### 文章概述

由沈沉舟前辈发布的 scz's puzzles（Win10 UWP Calculator问题）展开，记录了 TTD 调试与 ttd-bindings 的逆向工程实践，以及 TTD 互联网考古的发现。

### 什么是TTD

TTD（Time Travel Debugging）是微软推出的用户级进程 trace 录制工具，可在调试器中向前向后重放，无需重新运行程序即可让调试器状态回退。

主要特点：
- 需要 WinDbg 版本 1.0.13.0 或更新，录制需管理员权限
- 生成 .run 后缀的 trace 文件，自动生成 .idx 优化索引（通常为trace文件两倍大小）
- 支持几百 GB 大小的 trace 文件重放
- 侵入式技术，可能与反病毒软件等有冲突
- 时间点位置表示为 `Major:Minor`（十六进制）格式

### TTD数据模型与LINQ查询

TTD 将 trace 过程中各种属性和事件生成对应数据模型对象，可使用 LINQ 查询。

示例——查询特定地址的内存读写：
```
dx -g @$cursession.TTD.Memory(0x149808ac440, 0x149808ac444, "rw")
         .Where(m=>m.Value==0x9420fef2)
```

### ttd-bindings

ttd-bindings 是对 TTDReplay.dll 逆向工程后得出的编程API，用于脚本化操作 .run 文件。

- C++ bindings 功能较多
- Python bindings 功能弱（无法设置 CallRetCallback、MemCallback）
- 项目地址：https://github.com/commial/ttd-bindings

### TTD互联网考古

- 反向调试（Reverse Debugging）是更通用的说法，Time Travel Debugging 是较新的叫法
- 反向调试分为两类：Trace-based（基于录制trace） 和 Full-system-simulation-based（如Simics）
- TTD 采用 "re-execution + trace-based" 混合方案，只记录无法通过运行代码重构出来的内存值
- Keyframes/Checkpoints：保存所有线程完整状态，便于跳转到特定时间点
- 历史上的反向调试器：Borland Turbo Debugger（1992）、gdb 7.0、Mozilla rr、Simics等

### 问题解答

**问题一**（用TTD定位Win10 UWP Calculator乘法汇编）：
```
CalcViewModel+0x12cb06:
00007ff9`5eeccb06  4c0fafc5  imul r8,rbp
```

**问题二**（用ttd-bindings在一分钟内定位四则运算汇编）：

实现思路：
1. 获取 CalcViewModel.dll 模块起始地址和大小
2. 设置 call/ret 回调，找到第一次进入 CalcViewModel 模块的时间点
3. 从该时间点单步 ReplayForward，判断通用寄存器是否包含运算输入值
4. 符合条件则打印时间点，在 WinDbg 里验证过滤

踩坑记录：
- ReplayBackward 极其慢，ReplayForward 很快
- `GetContextx86_64()` 执行后必须 `free(ctxt)`，否则内存耗尽
- `ReplayForward` 第三个形参为 `-1` 时无法触发 call/ret 回调
- 多线程调用 ttd-bindings 函数会导致程序直接停止
- callret 回调函数中的操作和时间点顺序有关时，需要先生成 idx 文件

### 引用的主要文章

1. [对一个apk协议的继续分析—libsgmain反混淆与逆向](https://bbs.kanxue.com/thread-277665.htm)
2. [使用时间无关调试技术(Timeless Debugging)高效分析混淆代码](https://bbs.kanxue.com/thread-273055.htm) —— krash
3. [commial/ttd-bindings（GitHub）](https://github.com/commial/ttd-bindings)
4. [rr - Mozilla Reverse Debugger](https://github.com/rr-debugger/rr)
5. Jakob博客系列：Reverse History（https://jakob.engbloms.se/archives/category/revexec）

---

## 所有相关链接汇总

| 文章/资源 | 链接 | 作者 | 时间 |
|---|---|---|---|
| 第(1)篇：从0开发Trace后端分析工具-概述 | https://bbs.kanxue.com/thread-281555-1.htm | FANGG3 | 2024-4-28 |
| 第(2)篇：从0开发Trace后端分析工具-Trace前端的构建 | https://bbs.kanxue.com/thread-285745.htm | FANGG3 | 2025-2-25 |
| 使用时间无关调试技术(Timeless Debugging)高效分析混淆代码 | https://bbs.kanxue.com/thread-273055.htm | krash | 2022-5-29 |
| TTD调试与ttd-bindings逆向工程实践 | https://bbs.kanxue.com/thread-278069.htm | 0x指纹 | 2023-7-18 |
| tenet（IDA插件，Trace格式参考） | https://github.com/gaasedelen/tenet | gaasedelen | - |
| DobbyWithQBDI（FANGG3的简单Demo） | https://github.com/FANGG3/DobbyWithQBDI | FANGG3 | - |
| ttd-bindings（TTD编程接口） | https://github.com/commial/ttd-bindings | commial | - |
| rr（Mozilla反向调试器） | https://github.com/rr-debugger/rr | Mozilla | - |
| qira（geohot的时间无关调试器） | https://github.com/geohot/qira | geohot | - |