# 设备采集与反检测边界

反检测能力只用于保证合法研究场景下的采集稳定性。目标专用补丁必须通过 JSON spec 或
独立案例提供，不能写死在通用采集路径。

## 当前层次

| 检测面 | 当前措施 | 剩余边界 |
|---|---|---|
| `TracerPid`、ptrace | root 与 patched server | 内核级策略依设备而异 |
| `/proc/self/maps`、RWX | `hide_rwx_maps` 插件 | 直接 syscall、自带 parser |
| 自杀信号 | `block_self_kill` 与 spec 驱动 patch | 内联 SVC 需要目标 spec |
| Frida 名称、端口、路径 | patched server、非默认端口、应用缓存目录 | 新指纹需重新审计 |
| 线程名、符号 | patched runtime 覆盖部分特征 | 完整消除会提高维护成本 |
| `libart` 完整性 | 尽量不修改系统库代码 | 深度 trace 仍可能触发检测 |
| fork/ptrace 守护 | 无通用用户态解法 | 需要内核/eBPF 方案 |
| 时间检测 | 降低热路径开销 | 指令级 Stalker 无法完全隐身 |

## 插件原则

当前插件接口位于 `tracer/src/anti_detect/`：

- 默认关闭，用户显式启用。
- 安装失败应记录诊断并按策略降级，不能静默改变目标行为。
- hook、缓存和事件队列必须有上限。
- 通用插件不能出现包名、SO 版本或固定偏移。
- 固定偏移必须进入 `tools/hooks/*.json`，并校验模块名、大小或哈希，避免误 patch。

## 运行流程

```bash
./tracemiku doctor --pkg <package>
./tracemiku trace --pkg <package> --so <module> --method <export> \
  --hide-rwx-maps --block-self-kill \
  --patch-suicide --suicide-patch-spec tools/hooks/<spec>.json \
  --out traces/run1
```

参数语义与默认值以 `./tracemiku trace --help` 为准。先在低风险目标验证 attach、
心跳和短 trace，再增加深度与范围。设备改动必须执行 `make test-device`，并检查
trace 是否截断、是否丢记录、目标返回值是否改变。

## 故障分类

- attach 前死亡：server、端口、spawn 时序或 ptrace 检测。
- attach 后、Stalker 前死亡：agent 映射、线程名、符号或 maps 检测。
- Stalker 后死亡：RWX、时间、代码缓存或 inline syscall 检测。
- 采集成功但结果异常：补丁改变语义、记录截断或 sidecar 不完整。

诊断脚本不应永久堆在 `tools/`。确认根因后，应将通用能力纳入插件和测试，将目标细节
转成 spec；一次性脚本由 Git 历史保存。
