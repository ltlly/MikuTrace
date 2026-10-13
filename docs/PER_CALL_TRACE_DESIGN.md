# Trace 数据格式

```text
<run>/meta.json
<run>/calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/
  trace.bin
  meta.json
  external_writes.bin    # 可选
  memory_snapshot.bin    # 可选
```

分析命令通常接收单次调用目录。采集中使用 `_pending_call_*`；回传失败保留 pending
和设备 spool，恢复后由 `finalize` 回填元数据并重命名。旧平铺格式仅用于读取兼容。

## trace.bin

小端、每条 272 字节，与 core `Record` 对应；寄存器均为指令执行前状态。

| 字段 | 类型 |
|---|---|
| `pc` | `u64` |
| `regs[31]` | `x0..x28, fp, lr`，各 `u64` |
| `sp` | `u64` |
| `nzcv` | `u32` |
| `inst` | `u32` |

无保留字段，不内嵌 SIMD/FP 或内存字节。记录数须与文件长度一致。

## 元数据与 sidecar

调用级 `meta.json` 保存记录数、线程、目标、模块映射、寄存器顺序、截断/丢弃信息及
sidecar 描述。地址用 `0x` 字符串，计数与长度用整数。旧字段缺失或 `null` 不能视为
已验证完整；格式变更须版本化并测试迁移。

`external_writes.bin` 每条为 `idx:u64 + addr:u64 + byte:u8`，小端 17 字节。
初始快照布局及来源归因见 [内存契约](memory-completeness-design.md)。
采集 sidecar 与可重建的分析缓存不同；后者必须校验输入长度和内容指纹。

## 完整调用采集契约

默认以目标函数一次调用自然返回为结束条件。没有条数、等待时长或文件总量截断；
批缓冲、分块大小和控制面响应预算只约束资源，不改变调用边界。

- 采集前以目标 UID 完成创建、写入、fsync、回读、删除探测，再由 host 使用 ADB/root
  回读同一个 `session.json`，核对 session、PID 和实际路径。自定义路径探测失败即停止。
- 主 trace 和 SIMD 使用 CModule 固定批缓冲，生产线程满批同步写盘，不依赖 JS 消费者。
  短写续写、EINTR 重试；其他 I/O 错误阻塞并重试，host 进度报告 errno。磁盘恢复后
  从未写完的位置继续；不覆盖、不跳过记录，也不自动换目录。
- JNI、语义、fork、worker、外部写事件按批持久化；模块映射和调用元数据保存在设备。
  Frida 消息仅用于观察进度。采集器在启用入口前 eternalize，host 断线不会卸载它。
- 调用返回后 unfollow，排空主 trace/worker/SIMD 和事件，fsync，再原子发布 call
  manifest。session 仅在所有请求的调用已封口后进入 `SEALED`。显式停止只取消后续
  调用，不能截断正在执行的调用。
- host 只压缩 `SEALED` session，按 65536 条主 trace 的字节大小分块，gzip -1 后通过
  ADB 回传；其他记录格式向下按各自记录长度对齐。每块有原始/压缩长度和 SHA-256，
  host 凭据另存序号、字节偏移和记录区间。
  解压流式拼装，完整文件 SHA-256 一致后原子提交。最终仍是 272 字节/条的 `trace.bin`。
- 本地 `.transfer/` 保留已校验块及凭据；恢复复用有效块，只传缺失或损坏块。
  部分 `.part` 不算完成。`recovery.json` 保存实际设备路径，恢复不依赖目标存活、
  Frida 连通或重新执行函数。设备原件一直保留，校验成功另写 verified ACK。

本地调用元数据包含 `transfer_state`、`required_artifacts`、`artifact_checksums`。
`finalize/info` 只在全部必需文件已提交且长度匹配时接受完成状态；`info` 不扫描整份
trace 重算摘要，重新完整校验使用恢复流程。旧 trace 缺少这些字段仍按原契约读取。
`trace/recover` 每次调用的 `is_complete` 由 core `info` 返回；回传完成但采集有缺口
时顶层状态为 `incomplete`，退出 2，不能以 `VERIFIED` 冒充完整采集。

## 范围与失败事实

“不丢记录”指已插桩范围内的生产/落盘/回传不主动丢弃。范围由模块、线程、边界和
sidecar 配置决定；ART/linker 排除和未跟踪线程不在记录承诺内。显式 SIMD
采样步长大于 1 表示用户选择采样。

入口用对齐的单条 ARM64 `B` 接入附近的桥，在桥上执行 Interceptor 回调后才执行
搬移的原始首指令。桥保存并恢复 `x16/x17`，原始寄存器上下文进入 native writer；
首指令记录使用原 PC/opcode，后续指令直接回到原函数。只改写 4 字节，支持短函数。
无法安全准备入口、附近分配失败、敏感 LR/独占访问 prologue 或入口被其他 hook
改写且被检查发现时明确失败。恢复时也检查 opcode，发现第三方修改则拒绝覆盖。

`capture_scope` 保存 `primary_tid`、`include_ranges`、`entry_boundary`、`exit_boundary`、
`expected_entry_pc`、`first_pc`、`entry_complete`、`return_observed`、`simd_sample_stride`
和 `coverage_gaps`；`info.metadata.capture_scope` 以同一类型输出，缺失证据保持 `null`。
有 scope 的 trace 只有首条真实 PC、声明首 PC 和目标入口一致、观察到返回且无缺口
才可报告完整。末条 `ret` 不能代替这些证据；尾调用正常返回也不要求范围内末条是 `ret`。
早期 scope 缺少入口/返回验证字段时判为不完整；没有 scope 的旧 trace 保留旧读取判定。

Stalker 将含 exclusive-monitor 指令的整个翻译块标为不可插入内存 callout，相关
翻译缺口和插桩异常保存到 `coverage_gaps.jsonl`，快照不可读区域
保存到 `snapshot_errors.jsonl`，这些缺口使 `truncated=true`，不能冒充完整覆盖。
磁盘一直不可写会使目标持续等待；SIGKILL、目标崩溃、强制重启或掉电可能丢失未同步
的内存尾批。未封口 session 保持 `pending`，文件存在或末尾是 ret 均不能替代封口证据。
关闭文件或排空 sidecar 失败时 session 进入 `FAILED`，不会发布成功的调用封口。

封口后恢复原入口、卸载 hook、回收 Stalker/CModule 及大缓冲。小型入口桥保留到进程
退出，避免其他线程仍在桥上执行时被释放。Frida eternalize 的最小 JS 运行时
保留到目标退出；重复采集建议使用新的目标进程。worker 跟踪仍为可选的启发式能力，
不能把它当作所有线程的完整覆盖。
