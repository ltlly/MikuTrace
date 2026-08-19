# 工程参考资料

本文件只保留仍会影响当前实现的算法来源。具体实现和路线图分别以代码与 `TODO.md`
为准。

## 动态追踪与污点

- Newsome 与 Song：动态污点传播的经典模型。
- Schwartz、Avgerinos、Brumley：动态污点与符号执行综述。
- Triton、angr、libdft64：指令语义、def-use 和污点测试参考。
- Mozilla rr、Microsoft TTD、Tenet：record-and-replay、时间旅行和 trace 交互参考。

traceMiku 采用真实设备采集、主机离线分析，不追踪隐式流。内存采用 byte overlap 和
MemShadow，并显式区分已观测与未知字节。

## SSA、类型与结构化

- Cytron 等：SSA 与 Phi 放置。
- Cooper-Harvey-Kennedy：支配树计算。
- retypd、TIE：二进制类型恢复。
- Phoenix、DREAM、SAILR：控制流结构化与减少 goto。
- Cifuentes：跳转表与高级控制流恢复。

## 去混淆

- Binary Ninja HLIL/IL：sidecar 集成与 IL 表达能力的参考。
- Syntia、Xyntia、QSynth：基于 I/O 的表达式综合。
- Yadegari 等：trace + taint 去混淆。
- LLM4Decompile、SLaDe、DIRTY、ReSym：模型辅助反编译、改名和类型恢复；只能作为可选
  增强，不能成为本地分析依赖。

## 同类 trace 工具

GumTrace、trace-ui、Tenet、Frinet 和 Hooah-Trace 的有效经验已归纳为当前实现原则：

- 大 trace 使用 mmap、并行分块和持久化索引。
- 数据流查询必须有扫描上限、停止原因和截断元数据。
- trace 只能证明执行过的路径，不能把未执行路径判定为不存在。
- 未观测内存必须显示为未知，不能以零填充后冒充真值。
