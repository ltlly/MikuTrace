# traceMiku — 安卓真机 ARM64 指令级 trace 全栈工具

> **目标**：抓任意 app 任意 SO 任意函数的真机 ARM64 指令级 trace，pwndbg 风格离线分析，AI 可调用。

## 一行安装

```bash
# 假设已有 root 安卓 + Florida frida-server 跑在 6699 端口
cd /home/ltlly/Code/traceMiku
python3 -m pip install --user textual capstone frida
chmod +x tracemiku tracemiku-view
```

## 快速上手

```bash
# 列出已有 trace
./tracemiku list

# 一行抓 TB cold-path: 清数据 → 启动 → 自动点"同意" → trace 第一次 cmd 70102
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 120 \
  --mode js --cold-launch --out traces/run1

# 任意 app 任意 SO 任意函数 (动态注册的方法)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --method doCommandNative --cmd 70102 \
  --duration 90 --out traces/run2

# SO 内固定偏移
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --duration 60 --out traces/run3

# SO 导出函数 (如 JNI_OnLoad)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --export JNI_OnLoad --duration 30 --out traces/run4

# 启动可视化 TUI
./tracemiku view traces/run1

# 元信息
./tracemiku info traces/run1 --json
```

### `--cold-launch` (TB 类首启隐私协议自动化)
内置流程: `am force-stop` → `pm clear` → `monkey` 拉起 → `uiautomator dump`
找 `text="同意"` 按钮 → `input tap` → 轮询直到首页 (推荐/淘宝直播/百亿补贴 等
标志出现) 才返回. 实测 0s 找按钮, 6s 进首页. 独立脚本: `tracer/tb_launcher.sh <pkg>`.

### `--mode {js,cmodule}`
- `js` (推荐用于真机大 trace): JS callout, 已实测稳定抓 200 万+ 条
- `cmodule` (默认, 实验性): CModule + native callout, 短 trace 与 js 相当, **TB 类目标
  在 fail-path cleanup 出 SO 范围时 stalker 跟丢, 后续 onLeave 不触发** —
  这是函数走法导致 (~99% 已抓), 不是 frida bug, 但抓 cold-path 大计算建议先用 `--mode js`.

## TUI 操作（中文）

| 键 | 动作 |
|---|---|
| ↑↓/k/j | 单步 |
| PgUp/PgDn | 翻 20 条 |
| Home/End | 头/尾 |
| 鼠标点击指令行 | 跳转 |
| 鼠标点击 Tab | 切换面板 |
| `g` | 跳转（`#1234`=按编号 / `0xabcd`=按PC / `@0xabcd`=列出此 PC 所有 trace）|
| `/` | 正则搜索反汇编 |
| `d` / `u` | 跳到第一个定义/使用 |
| `f` / `b` | 正向/反向污点（输入寄存器名）|
| `m` | 查看内存（输 0x... 或 `sp`/`x0` 等寄存器名）|
| `s` | 提取字符串 |
| `C` | 构建 CFG 文本视图 |
| `B` | 构建块导航像素图 |
| `Ctrl-S` | 导出 CFG dot/SVG |
| `Ctrl-O` | 浏览器打开 SVG |
| `q` | 退出（二次确认）|

**寄存器面板**：变化的寄存器红色高亮（pwndbg 风格），智能解引用：
- 代码指针 → `[func+offset]`
- 栈指针 → `[SP+0x...]`
- 字符串指针 → `→ "..."`
- 多级指针 → 递归解引用 `→ 0x... → "..."`
- 已知 region (libart/libc/JavaHeap) → 标注

**命令栏**：g/m/f/b/搜索时弹出在底部，**完全可见**输入内容，中文提示。

## AI 友好的 query 接口（供 Claude Code 等调用）

每个查询子命令都有 `--json` 输出，可直接被 AI 解析：

```bash
# 取指定范围的指令记录（带寄存器）
./tracemiku query traces/run1 records --range 0..50 --regs x0,x1,x2 --json

# 正向污点：从 #0 跟踪 x2 的传播
./tracemiku query traces/run1 forward-taint --from 0 --reg x2 --max 200 --json

# 反向污点：回溯 #100 处 x0 的来源
./tracemiku query traces/run1 backward-taint --from 100 --reg x0 --json

# 字符串提取
./tracemiku query traces/run1 strings --min-len 4 --json

# CFG 数据（block + edge 列表）
./tracemiku query traces/run1 cfg --json

# 反汇编正则搜索
./tracemiku query traces/run1 search --pattern "smull|umull" --json

# 函数命中频次
./tracemiku query traces/run1 func-summary --json
```

返回都是干净 JSON，键名稳定，便于自动化分析。

## 性能

### 离线分析 (viewer/query)
| 操作 | 4500 条 | 67000 条 | 2.06M 条 (实测) |
|---|---|---|---|
| mmap 加载 | <1ms | <1ms | <1ms |
| 完整 def/use 索引 | 20ms | 300ms | ~5s |
| CFG 重建 | 20ms | 250ms | ~4s |
| 正向污点 (cap=500) | 5ms | 50ms | ~50ms |
| 视图渲染（每帧）| <10ms | <10ms | <10ms (只渲染可见页)|

百万行 OK：viewport-only 渲染 + mmap + capstone 反汇编缓存。

### 在线 trace 采集 (`--mode`)
| mode | 实现 | 实测最大单次 trace | 适用 |
|---|---|---|---|
| `js` | JS transform + JS callout | **2,066,291 条 / 562 MB** ✓ TB cold-path | 大 trace 首选 |
| `cmodule` (默认) | JS transform + CModule on_insn | ≈短 trace 可用; TB 长 fail-path 在 cleanup 出 SO 范围时跟丢 | 短 trace / 实验 |

**实测细节**: `libsgmainso!doCommandNative` cmd=70102 cold-path (真做白盒 sign 计算) JS mode
稳定抓到 200 万+ 条, 100K rec/s 流式 flush. 短 fail-path 调用 (~4675 条) 因为 cleanup 走出
SO 范围 + Stalker.exclude 排除了 system 库, stalker 跟丢导致 onLeave 不触发 (与
mode 无关, 是函数走法导致, 99% 已抓). cmodule mode 在 TB 上同样现象.

## 架构

```
traceMiku/
├── tracemiku           # 统一 CLI 入口（trace/view/query/list/info）
├── tracemiku-view      # 兼容旧入口
├── tracer/             # Stage-1 采集端
│   ├── agent_generic.js   # 通用 JS callout agent (主推, 实测稳跑 200 万+ 条)
│   ├── agent_cmodule_v3.js # CModule on_insn (实验性, 短 trace OK)
│   ├── agent_fast_pc.js   # PC-only 流 (Stalker exec events, viewer 暂不支持)
│   ├── tb_launcher.sh     # TB 冷启动 + 自动同意脚本 (供 --cold-launch)
│   └── ...
├── viewer/             # Stage-2 离线 TUI
│   ├── trace.py        # mmap binary trace 解析
│   ├── disasm.py       # capstone 包装 + def/use 提取
│   ├── index.py        # reg_defs/reg_uses 索引
│   ├── symbols.py      # 函数符号推断
│   ├── memshadow.py    # 稀疏内存 shadow + 字符串提取
│   ├── cfg.py          # 从 trace 重建 BB-CFG，graphviz 输出
│   ├── taint.py        # 正向/反向污点
│   ├── display.py      # pwndbg 风格智能解引用
│   ├── app.py          # textual TUI 主程序
│   └── README.md
└── traces/             # 采集到的 trace 文件
```

## 关键技术点

### Trace 采集（避坑）
1. **Stalker.exclude libc/libart**：ARM64 LDXR/STXR 之间插桩会清除 exclusive monitor，atomic 死锁。必须排除全部 system 库。
2. **on_spawn 回调里别调 init**：spawn-gated 进程被 SIGSTOP，`enumerateModules` 永久 block。init 必须推到主线程异步跑。
3. **Florida frida-server**（zer0def/undetected-frida 同样可）：默认 frida-server 的 `/frida-{uuid}` socket 被 TB 类反调试秒杀。
4. **冷启 vs warm**：TB 类 sgmain 类 SO 的同一 cmd 在不同时机走不同路径 — `monkey` 直启后第一次 70102 走 fail-path (~4675 条), 真业务请求触发的 70102 走 cold-path 真算 sign (~200 万条). 用 `--cold-launch` 自动 force-stop+pm clear+点同意, 抓真业务请求的 cold-path.
5. **CModule import 语义**：`extern T name;` (无 `*`) → name 的 STORAGE 在 JS 传入指针; `extern T *name;` 错 (name 是变量, 默认 0 = NULL deref). 详见 `feedback_frida_cmodule_import_semantics.md`.

### 反调试 / 多线程异步
- 统一 agent 自动 hook `pthread_create` 跟所有新线程
- 通过 JNIEnv vtable[215] 拿到 `RegisterNatives`（libart 不导出）
- 已经运行过 RegisterNatives 的进程：用 `--fn-offset` 直接 hook 偏移

### 性能
- 二进制固定格式 272 字节/记录（PC + 31×GPR + SP + raw inst）
- mmap + 按需 record() 读取
- viewport-only TUI 渲染（百万行也只渲染可见 30 行）
- capstone 反汇编 lru_cache(200000)
- 索引懒构建

## 已知限制

- NEON/FP 寄存器没记（OLLVM 用 SIMD 算 jump table 时需扩展 record 格式）
- Stage-3 反编译辅助（叠加 trace 到 IDA/binja MCP）暂未做
- CFG 布局用 graphviz `dot`，不是 krash 自研的 Decompiler Layout（可改用 ghidra 的算法重写）
- 字符串只能从内存 shadow 抠（trace 没读过的字节不在）

## 文档

- [`viewer/README.md`](viewer/README.md) — TUI 详细说明
- [`tracer/README.md`](tracer/README.md) — 采集器内部细节

## 来源 / 感谢

- 看雪 [krash 时间无关调试](https://bbs.kanxue.com/thread-273055.htm) — UI 设计参考
- 看雪 [FANGG3 ATTD 系列](https://bbs.kanxue.com/thread-281555-1.htm) — trace 格式
- [Ylarod/Florida](https://github.com/Ylarod/Florida) — frida-server 反检测 fork
- [zer0def/undetected-frida](https://github.com/zer0def/undetected-frida) — 同上
- IDA tenet 插件 trace 格式
