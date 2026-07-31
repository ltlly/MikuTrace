# traceMiku 路线图

本文件只记录尚未完成且已确认属于产品方向的工作。完成历史由 Git 保存，不在此堆积。

## P0：架构治理

- [ ] 审计 server route 是否存在文本后处理、哨兵值、扁平响应修补或重复分析逻辑；
  将语义下沉到 core，并为响应增加类型化错误。
- [ ] 将 Clippy 的未使用导入、重复属性和结构警告降到可持续基线，并在 CI 阻止新增。
- [ ] 修复已确认的确定性分析错误（每条均需失败断言测试）：
  - `crypto_scan.rs` XXH64/FNV64 指纹常量抄错高 32 位（PRIME/offset 值），constscan 误判算法；
  - `record.rs` `reg()` 与 `reg_by_name()` 双 API 语义分歧（别名接受与否），统一为单一语义；
  - `taint.rs` `mem_writers_overlapping` 双语义（非 through_mem 只回最新 writer），溯源链断裂；
  - `field_at` route 永远返回 `hit: false` 哨兵，未实现却已挂路由；
  - `call_analysis.rs` 整模块 `#![allow(dead_code, unused_variables)]`，含死代码 `is_blr`、恒 `size: 8`、魔法窗口 `idx+200`。

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

## P2：工程治理

- [ ] 拆分 host 侧 `tracemiku`（2159 行，超 1500 红线）：`_is_ret_inst` 位掩码解码与
  `_read_trace_tail` 按 272 字节偏移读 trace 属重写 core 语义，改为调用 CLI 解析；
  `tools/vm_replay_plan_eval.py` 的表达式求值器、`scripts/build_smoke_trace.py` 的
  272 字节布局同样应收敛到单一实现源。
- [ ] 决策 tracer legacy 双实现去留：`agent_cmodule_v5.js`（1695 行）已漂移——
  `--method` 不支持、静默忽略 `--max-records` 上限；确认无真机依赖后删除或补测试。
- [ ] core 内格式化错位下沉：`render_calls_*`、`hex_dump`、`format_asm`、ollvmdet
  中文提示、watchpoints `status:"ready"` 等出串逻辑移至 CLI 层，core 只出结构化数据。
- [ ] 消除重复实现：sidecar 二进制 IO 三份拷贝（index/memshadow/analysis_index）、
  `trace_fingerprint` 两份、hex 解析器至少三套 + server 41 处 `from_str_radix`（收敛为
  单一 `parse_addr`）、`mnemonic.split('.')` 四处、CLI `compact_*` 序列化辅助 32 处。
- [ ] 前端纯逻辑去重：clamp ×4、PC 提取 ×3、LLIL tokenizer ×2、寄存器别名 ×2；
  消费服务端 `asm-tokens`/类型字段，停止用正则重实现指令分类。
- [ ] 测试体系：`contract_audit.py` 硬编码 100+ 命令/61 route 映射改为从
  `args.rs`/router 生成；`algo_tests.rs`（9244 行）、`cli_smoke.rs`（1347 行）
  按模块拆分；`index.rs` 生产零调用的 `last_def_before`/`next_use_after` 或被
  taint 采用、或删除，避免两套二分漂移。
- [ ] 清理过期文档：`taint.rs` 引用的未落地 Task 编号、`symbols.rs` 声称二分实为
  线性 find、`agent.ts` 指向已删除文件的注释。

## 验收原则

- 分析功能按 core -> CLI -> server -> frontend 顺序实现。
- 每项必须有资源上限、失败语义、结构化输出和测试。
- 设备改动必须通过 agent -> host -> meta -> core -> server/display 全链路验证。
- 不增加与本文件并行的路线图或阶段计划。
