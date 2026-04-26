# traceMiku — Stage 2 Viewer (PDF-parity)

按看雪 krash 时间无关调试 PDF 的功能完整复刻。

## 视图（与 PDF 1:1 对应）

| krash 视图 | traceMiku 实现 |
|---|---|
| 指令流视图 | ✅ 函数前置、当前 PC 高亮、分支着色、固定高度（不抖动）、鼠标点击跳转 |
| 寄存器视图 | ✅ 全 33 寄存器 + pwndbg 智能解引用 + **变化的红色 ★ 标记 + 数值红色加粗** |
| 内存视图 | ✅ hex+ascii，未访问字节显示 `??`（红色暗色） |
| 交叉引用 | ✅ ← def-chain / → use-chain / mem ops，跳转链 d/u |
| 字符串参考 | ✅ 从内存 shadow 自动提取 ASCII 串 |
| 污点追踪 | ✅ 正向/反向，结果内联显示，自动跳到首条 |
| CFG | ✅ **TUI 内交互式**：热点块列表 + 当前块完整反汇编 + 出/入边可跳转（不再开外部 SVG）|
| 块导航图 | ✅ 像素网格按热度着色 |
| 调用栈 | 🔜 |

### CFG 交互（v5）
按 `C` 在 CFG tab 内：
- 热点块按执行次数排序
- 当前块完整反汇编展示
- ↑↓ 切换块；Enter 跳到主 trace 第一次执行；← 跳到上游块；→ 跳到首个出边块
- 鼠标点击块条目也可选

不再依赖 graphviz 外部窗口。仍需 SVG 的话 `Ctrl-S` 导出 `Ctrl-O` 浏览器打开。

## 快捷键

| 键 | 动作 |
|---|---|
| ↑ / ↓ / k / j | 单步 |
| PgUp / PgDn | 翻页 |
| Home / End | 头/尾 |
| `g` | Goto: 输入 `#1234` 或 `0xabcd` |
| `/` | Search: 输入 regex 在反汇编里跳找 |
| `d` / `u` | 跳到第一个 def-chain / use-chain |
| `m` | 设置内存视图地址（hex 或寄存器名 `sp`/`x0`...）|
| `f` / `b` | 正向/反向污点追踪（输入寄存器名）|
| `s` | 提取 strings 到 Strings tab |
| `C` | 构建 CFG 文本视图 |
| `B` | 构建块导航图（像素网格）|
| `c` | 导出 CFG 到 `/tmp/cfg_*.dot` 并自动 `dot -Tsvg` |
| `o` | 浏览器打开 SVG |
| `q` | 退出 |
| `Esc` | 关命令栏 |

## 用法

```bash
# 从项目根目录
cd /home/ltlly/Code/traceMiku
python3 -m viewer traces/doCommand_70102

# 或独立启动器
./tracemiku-view traces/doCommand_70102

# 看任意 trace.bin
python3 -m viewer traces/doCommand_70102/trace_26215.bin
```

## 内存视图说明

trace 只记录寄存器，不直接采集内存。我们通过 trace 重建一个**稀疏内存 shadow**：
- 对于 `str x0, [x1, #0x10]`：从源寄存器 x0 取值，地址 = x1+0x10
- 对于 `ldr x8, [x9]`：从下一条记录的 x8（执行后值）反推加载值
- 任意 (addr, time) 查询：返回 ≤time 的最近一次读/写
- 从未被 trace 读写的字节显示为 **??**（与 krash PDF 同款行为）

按 `m` 输入十六进制地址或寄存器名（如 `sp`, `x0`）跳转。

## 字符串提取

按 `s` 触发：扫描内存 shadow，把所有 ≥4 字节的连续可打印 ASCII 范围识别为字符串。在 doCommand_70102 trace 上能挖出 34 个字符串（其中包含 SDK 自带常量、文件路径、Java 类名等）。

## 污点追踪示例

进 trace 任意条指令（比如 doCommandNative 入口 #0），按 `f` → 输 `x2` → 看到 cmd id (70102) 怎么被处理：
```
正向 taint of x2 from #0:
  #7  smull x8, w2, w8       ; regs:x2
  #11 lsr   x11, x8, #0x3f   ; regs:x8
  #12 asr   x8, x8, #0x2c    ; regs:x8
  ...                          ← 揭示 cmd dispatch 用 magic-multiply 实现 mod
```

## 块导航图（krash 杀手级）

按 `B` → BlockMap tab：所有 BB 一格一个像素，颜色编码执行次数：
- ░ 灰 — 未执行
- · 白 — 1×
- ▒ 黄 — ≤5×
- ▓ 亮黄 — ≤20×
- █ 红 — ≤100×
- ▓▓ 亮红粗体 — >100× (热循环)
- [Y] 黄色高亮 — 当前 cursor 所在块

可视化整个 trace 的覆盖率和热点。

## 目前限制

1. **trace 只到 ~4500 条就停**：`doCommandNative(70102)` 是异步——同步部分约 4500 条指令完成后线程就 block 在 libart/libc（被 Stalker.exclude），看起来"trace 没完"实际是函数已把控制权让给 binder/IPC。要看更多需要追踪 worker 线程或包含部分 libart trace。
2. **NEON / FP 寄存器没抓**：当前 record 格式只有 GPR。OLLVM 用 NEON 的话需扩展 record 格式。
3. **字符串只能从内存 shadow 抠**：trace 没读到的字节没法识别字符串；如需更多字符串，用 trace 时让设备多走几次代码路径。

## 文件

```
viewer/
  trace.py        # mmap binary trace 解析、meta 加载
  disasm.py       # capstone 反汇编 + def/use/mem 提取（缓存）
  index.py        # reg_defs / reg_uses 索引、def-use 链
  symbols.py      # 函数符号推断（trace bl-target + 已知导出表）
  memshadow.py    # 稀疏内存 shadow + ?? 占位 + 字符串提取
  cfg.py          # 从 trace 重建 BB-CFG，输出 graphviz dot
  taint.py        # 正向 / 反向污点
  app.py          # textual TUI 主程序
  __main__.py
  README.md
```
