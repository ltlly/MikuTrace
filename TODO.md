# 未完成工作

## CLI 契约与资源

- [ ] 统一 host、Rust 执行错误和旧查询 `status=error` 的退出语义；细分组合报告的 `command_failed`。
- [ ] 补齐目录枚举、组合报告、全量索引的分析预算与截断信息；采集完整性不得依赖这些查询预算。

## 采集可靠性

- [ ] 继续覆盖[完整采集契约](docs/PER_CALL_TRACE_DESIGN.md#完整调用采集契约)的物理 USB 拔插、目标崩溃、真实慢盘/空间耗尽、跨文件系统和超大文件；测量吞吐和资源占用。
- [ ] 在 Android 真机验证入口桥的并发调用、JNI、PAC/BTI 和特殊 prologue；当前离线 ARM64 覆盖不能代替这些场景。
- [ ] 精确归因并验证可选 worker 线程；消除 exclusive-monitor 翻译块的插桩缺口，不能把已有范围外的执行当作已采集。
- [ ] 核实初始快照中内核映射与并发变化区域的可读取性；保留无法取得的地址与原因，不能用填零冒充快照。

## 分析证据

- [ ] 将 `byte-lineage` 已具备的结构化 provenance、`unlogged_write_gap` 与 VM 寄存器槽折叠扩展到试验性 `experimental vm-*` token 分析。
- [ ] 用代表性大 trace 和固定 AI 查询任务评估按需加载、重复查询成本、输出预算及命令冗余，建立可复现基线。
