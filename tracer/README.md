# 设备端采集器

`tracer/` 负责 Android 真机 ARM64 指令采集、调用边界、sidecar 和可选反检测插件。

## 入口

| 文件 | 用途 |
|---|---|
| `_agent.js` | 唯一 agent（默认入口），由 TypeScript 编译的模块化实现 |
| `src/` | 源码：CModule、ring、hook、sidecar 和插件 |

```bash
cd tracer
npm install
npm run typecheck
npm run build
```

`_agent.js` 是生成物，不提交 Git。修改采集逻辑必须改 `src/`。

## 数据通路

```text
Stalker/CModule -> SPSC ring -> 设备文件 -> host 拉取 -> Rust mmap
```

热路径只采集固定 272 字节寄存器记录。大对象、字符串、初始内存和外部写进入有上限的
sidecar，不能阻塞或无限增长。trace 达到限制时必须正常收尾并标记 `truncated`。

## 模块

- `src/core/`：状态、ring、Stalker、CModule 和通用工具。
- `src/hooks/`：调用边界、fork、pthread 和 JNI vtable。
- `src/sidecar/`：语义事件、SIMD、内存快照。
- `src/anti_detect/`：默认关闭的通用插件。

反检测目标细节应放到 `tools/hooks/*.json`。禁止在 agent 中写死包名、SO 版本和偏移。

## 修改后的最低验证

```bash
npm --prefix tracer run typecheck
npm --prefix tracer run build
make test-device
```

格式或 sidecar 变化还需验证 host 拉取、`meta.json`、Rust core、server 和显示。真机不可用
时不能宣称链路已完整验证。
