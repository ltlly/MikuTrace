# 设备端采集器

入口为 `src/agent.ts`，构建产物 `_agent.js` 不提交 Git。仓库根目录执行 `make agent`；
依赖安装后用 `npm --prefix tracer run typecheck` 检查类型。

```text
Stalker/CModule → SPSC ring → 设备 spool → host 回传 → core mmap
```

| 目录 | 职责 |
|---|---|
| `src/core/` | 状态、ring、Stalker、CModule |
| `src/hooks/` | 调用边界、fork、pthread、JNI、边界差分 |
| `src/sidecar/` | 语义事件、SIMD、初始内存快照 |
| `src/anti_detect/` | 可选反检测插件 |
| `src/target_plugins.ts` | 用户 agent 插件生命周期 |

记录与 sidecar 格式见 [数据契约](../docs/PER_CALL_TRACE_DESIGN.md)，profile 与插件接口见
[功能目录](../docs/FEATURES.md#目标配置与插件)，改动验证见 [AGENTS.md](../AGENTS.md#验证)。
