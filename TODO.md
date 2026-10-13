# traceMiku 路线图

本文件只记录尚未完成且已确认属于产品方向的工作。维护范围为 trace 采集与离线分析
CLI；需求、当前依赖及裁剪验收见 [采集与 CLI 设计](docs/CLI_FIRST_DESIGN.md)。
完成历史由 Git 保存，不在此堆积。

## P0 分析 CLI 独立运行

- [ ] 将保留查询所需的 trace、索引、符号与按需缓存从 server AppState 解耦；
  CLI 直接调用 core，依赖树不再包含 server、Axum 或 Tower。
- [ ] 将保留的 route 分析语义以及 CLI 中 VM/lineage 的计算语义迁入 core；保留
  对应边界测试，迁移期间锁定现有 JSON 字段与含义。超长源文件先按职责拆分。
- [ ] 在保留能力通过离线验收后裁剪 frontend、HTTP/OpenAPI、Web 状态与 SVG 设施；
  移除内部 BN 桥接，同步收敛 Makefile、CI、依赖、文档和契约覆盖声明。
- [ ] 统一保留分析命令的错误/退出语义，补齐可增长输出的截断与继续查询信息；
  按真实查询任务继续评估语义重叠，命令变更只在 FEATURES 汇总维护。

## P1 采集可靠性

- [ ] 补齐跨 agent、host、meta 与 core 的离线故障用例，覆盖 ring 满载、丢记录、
  回传超时/断线、sidecar 不完整与 pending 恢复；保持已有数据格式。
- [ ] 真机可用后验证 attach/spawn、记录/调用上限、Frida/adb 回传、进程异常终止及
  可选线程与 sidecar 路径，记录真实采集吞吐和资源预算；离线通过不替代真机验收。

## P2 分析证据与资源预算

- [ ] 为 VM 分析 token 增加结构化 provenance，标明寄存器、内存、外部写、常量和
  未知来源；保留输出级回溯和 trace replay 对证据缺口的表达。
- [ ] 用代表性大 trace 和固定 AI 查询任务验证裁剪后的按需加载、重复查询成本、
  输出预算与命令发现效果；为仍需优化的路径建立可复现基线。
