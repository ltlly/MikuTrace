# traceMiku 路线图

本文件只记录尚未完成且已确认属于产品方向的工作。完成历史由 Git 保存，不在此堆积。

## P0：架构治理

- [ ] 审计 server route 是否存在文本后处理、哨兵值、扁平响应修补或重复分析逻辑；
  将语义下沉到 core，并为响应增加类型化错误。
- [ ] 将 Clippy 的未使用导入、重复属性和结构警告降到可持续基线，并在 CI 阻止新增。

## P1：运行时真相

- [ ] 内存完整性 Phase 2：设备端捕获 `read`、`recv`、`stat`、`getrandom` 等外部写，
  复用现有 `external_writes.bin` 与 MemShadow `x` 层；必须有单次和总量上限。
- [ ] Trace 锚定重放 A1：以真实寄存器为 oracle，报告整数执行、SIMD、syscall 和未知
  内存导致的首个发散点。
- [ ] 为 IL token 增加结构化 provenance，标明寄存器、内存、外部写、常量和未知来源。
- [ ] 将 coverage 和间接跳转命中数叠加到 Web CFG；其他运行时查询保持 CLI 优先。

## P2：分析质量

- [ ] 为 CLI 输出自动生成并交付 JSON Schema（`output_types*.rs` 已带 schemars
  派生，但 schema 导出与 `docs/schema/` 交付物未落地）。
- [ ] 完成 Varnode -> HighVariable -> VariableGroup 合并，并贯通 MLIL/HLIL。
- [ ] 增加 Tenet 导出，保留每字节来源与未知状态，不伪造缺失内存。
- [ ] 为 CLI 生成 shell completion。

## 验收原则

- 分析功能按 core -> CLI -> server -> frontend 顺序实现。
- 每项必须有资源上限、失败语义、结构化输出和测试。
- 设备改动必须通过 agent -> host -> meta -> core -> server/display 全链路验证。
- 不增加与本文件并行的路线图或阶段计划。
