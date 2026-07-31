# traceMiku 路线图

本文件只记录尚未完成且已确认属于产品方向的工作。完成历史由 Git 保存，不在此堆积。

## P1：运行时真相

- [ ] 内存完整性 Phase 2：设备端捕获 `read`、`recv`、`stat`、`getrandom` 等外部写，
  复用现有 `external_writes.bin` 与 MemShadow `x` 层；必须有单次和总量上限。
- [ ] Trace 锚定重放 A1：以真实寄存器为 oracle，报告整数执行、SIMD、syscall 和未知
  内存导致的首个发散点。
- [ ] 为 IL token 增加结构化 provenance，标明寄存器、内存、外部写、常量和未知来源。
- [ ] 将 coverage 和间接跳转命中数叠加到 Web CFG；其他运行时查询保持 CLI 优先。

## P2：分析质量

- [ ] 完成 Varnode -> HighVariable -> VariableGroup 合并，并贯通 MLIL/HLIL。

## P2：工程治理

- [ ] 拆分 host 侧 `tracemiku`（2159 行，超 1500 红线）：`_is_ret_inst` 位掩码解码与
  `_read_trace_tail` 按 272 字节偏移读 trace 属重写 core 语义，改为调用 CLI 解析；
  `tools/vm_replay_plan_eval.py` 的表达式求值器、`scripts/build_smoke_trace.py` 的
  272 字节布局同样应收敛到单一实现源。已确认设备驱动与 cmd_trace 深交织
  （单函数跨 500 行），需真机全链路验证后分步执行。
- [ ] tracer legacy 维护：`agent_cmodule_v5.js` 保留（`--mode legacy` 主动选项 +
  README 文档化边界）；已知缺陷待修——legacy 模式静默忽略 `--max-records` 上限
  （违反设备端采集边界），需补参数校验或移除 legacy 模式（需真机验证后决策）。
- [ ] 后续新增输出时保持「core 只出结构化数据，格式化进 CLI/展示层」原则（当前
  经审计无跨层格式化错位：`render_calls_*` 仅 core 测试消费、`hex_dump` 属反编译
  排除范围、watchpoints status 由 server 构造）。

## 验收原则

- 分析功能按 core -> CLI -> server -> frontend 顺序实现。
- 每项必须有资源上限、失败语义、结构化输出和测试。
- 设备改动必须通过 agent -> host -> meta -> core -> server/display 全链路验证。
- 不增加与本文件并行的路线图或阶段计划。
