# traceMiku 路线图

本文件只记录尚未完成且已确认属于产品方向的工作。完成历史由 Git 保存，不在此堆积。

## P1：运行时真相

- [ ] Trace 锚定重放 A1：以真实寄存器为 oracle，报告整数执行、SIMD、syscall 和未知
  内存导致的首个发散点。
- [ ] 为 IL token 增加结构化 provenance，标明寄存器、内存、外部写、常量和未知来源。
- [ ] 将 coverage 和间接跳转命中数叠加到 Web CFG；其他运行时查询保持 CLI 优先。

## P2：分析质量

- [ ] 完成 Varnode -> HighVariable -> VariableGroup 合并，并贯通 MLIL/HLIL。

## P2：工程治理

- [ ] `tracemiku` 的 `_read_trace_tail`/`_decode_last_inst`/`_is_ret_inst` 收敛为「保留
   + 契约锁定」：调用点均在 meta.json 未就绪的 trace-begin/finalize 阶段（CLI info
   无法服务），已加注释说明与单测锁定（tests/host_trace_helpers_test.py，2000 编码
   与 core 掩码零冲突）。`tools/vm_replay_plan_eval.py` 是消费 `vm-ops --replay-plan`
   输出的独立评估器（非重复实现，自带 --verify-emitted-python 交叉验证）；
   `scripts/build_smoke_trace.py` 是测试 fixture 独立构造器，其 272 布局已通过 core
   实际读取验证（普通 9 记录 + extended 12 记录均正确解析）。
## 架构原则（已审计确认）

- 后续新增输出时保持「core 只出结构化数据，格式化进 CLI/展示层」原则。当前经审计
  无跨层格式化错位：`render_calls_*` 仅 core 测试消费（公共 API，契约锁定）、
  `hex_dump` 属反编译器排除范围、watchpoints status 由 server 构造。

## 验收原则

- 分析功能按 core -> CLI -> server -> frontend 顺序实现。
- 每项必须有资源上限、失败语义、结构化输出和测试。
- 设备改动必须通过 agent -> host -> meta -> core -> server/display 全链路验证。
- 不增加与本文件并行的路线图或阶段计划。
