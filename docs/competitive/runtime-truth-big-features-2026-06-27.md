# 开发设计：运行时真相的两个大件 — provenance 反编译 & trace-anchored 重放

> 2026-06-27。本文把两个"想做大"的方向认真调研并落到可执行设计，**先写清楚
> 再动手**，避免半成品堆积。配套已完成的 P0/P1 运行时真相 CLI
> (`docs/competitive/ai-cli-strategy-2026-06-27.md`)。三件都属"工具中立、只认
> `(SO,偏移)`/PC"的同一条战略。

## 已确认的 ground truth（决定可行性的事实）

每条 272 字节 trace 记录 (`trace/record.rs`) 携带：
- `pc`、`x0..x28`、`fp`、`lr`、`sp`、`nzcv`、`inst`（**每条指令的完整 GPR 状态**）。
- **缺**：SIMD/FP 寄存器 `q0..q31`、`v*`；完整 PSTATE（只有 nzcv）。

`MemShadow.byte_at(addr,t) -> (value, kind, src)`，kind ∈ {w=store, r=load,
x=external/syscall, i=initial-snapshot, ??=未观测}。内存是**部分**的，空洞用
`??` 显式标注（见 `memory-completeness-design.md`）。

**关键推论**：因为每条指令处都有寄存器真值，重放**不需要完美模拟器** —— trace
本身就是 oracle，可在每一步交叉校验，并在模拟器会发散的地方（syscall、`??`
前沿、SIMD）直接注入真值。这把"盲目模拟"变成"trace 锚定重放"，鲁棒得多。

---

## 大件 A：trace-anchored 重放生成器（`replay-export`）

### 目标
给定 `(SO,偏移)` 或 idx 范围，导出一个**自包含、可确定性重放**的工件：用真实
初始内存 + 初始寄存器播种，按记录的指令流逐步执行；模拟器与 trace 真值不符处
以 trace 为准。用途：(1) 离线在 IDA/BN/Ghidra 之外重现一段执行；(2) 喂给
emulator/符号执行做 what-if；(3) 验证我们对一段代码的理解。

### 不是什么
不是"完美 CPU 模拟器"。SIMD/FP 不在 trace 里，纯模拟必发散。本设计**故意**用
trace 当 oracle，因此它是"重放 + 校验 + 填洞"，不是从零模拟。

### 工件内容（`(SO,偏移,范围)` 键化）
- `seed`: 起点 idx 的全 GPR + sp + nzcv + pc。
- `mem`: 该范围触及地址的初始字节（MemShadow `i`/最早 `w` 层）+ provenance。
- `insts`: 指令流（pc, inst bytes）。
- `oracle`: 每步（或每 N 步）的 GPR 快照，供校验/填洞；`??` 前沿与 SIMD 写处
  标"需注入"。
- `syscall_effects`: 区间内 `x` 层内存写（内核/JNI 注入），见大件 C。

### 两种消费形态
1. **校验式重放**（先做）：内置一个最小 ARM64 步进器（复用 LLIL 求值或
   Unicorn 可选后端），每步执行后与 oracle 比对，发散即报告"第一处发散 +
   原因（SIMD/syscall/`??`）"。这本身就是**对我们 IL/lifter 正确性的回归测试**。
2. **可移植种子**（后做）：导出 Unicorn-ready 的内存映射 + 寄存器 + hook 点
   列表，让外部工具加载。纯数据，不绑定任何模拟器。

### 难度/分期
- A1 校验式重放（内置步进器 + oracle 比对 + 首处发散报告）：**中**。数据全有。
- A2 Unicorn 种子导出：**中**。主要是格式 + 映射对齐。
- A3 注入式续跑（在发散点注入真值继续）：**中高**。

### 测试
真机 trace 上：对一段纯整数运算块，校验式重放应**零发散**走到底；对含
`ldr` 命中 `??` 前沿的块，应在该处精确报告"需注入"且 idx/addr 正确；对含
SIMD 的块，应报告 SIMD 发散点。全部对拍记录的 GPR 真值。

---

## 大件 B：provenance 注解的 AI 友好反编译

### 目标
反编译/IL 渲染里**每个值都带来源标注**：`mem@0xADDR(kind=w,idx=N)` /
`reg x0(idx=N)` / `syscall read#3` / `import strlen` / `??frontier`。让 AI/人
一眼看出"这个值是真观测到的(w/x/i) 还是静态推断/未知(??)"。

### 为什么是运行时真相轴
静态反编译给类型与结构，但给不了"这个字节此刻真值 + 它从哪来"。我们已有
MemShadow provenance、reg 真值、taint lineage——B 是把这些**编织进 IL token 流**，
不是再造反编译器（自研 IL 仍只作内部引擎，见战略"明确不做"）。

### 设计
- 复用 `hlil/render_tokens` 的 CToken 流，给每个 `Var`/`Deref`/`Const` token 附
  `provenance` 字段（来源 kind + idx + 可选 `(SO,偏移)`）。
- 值来源解析复用 `reg-at`/`mem-export`/`byte-lineage` 的现成逻辑。
- 输出两形态：人看（行内灰字注解）、AI 看（每 token 带结构化 provenance 的 JSON）。

### 难度/分期
- B1 token 级 provenance 标注（reg/mem/const）：**中**，复用现成 provenance。
- B2 跨调用 lineage 链接进 token（"此值来自 sub_X 的返回"）：**中高**，接 taint。

### 测试
对已知块：常量 token 标 `const`，`ldr` 出来的 token 标 `mem@addr(kind)`，
未观测处标 `??`；与 `mem-dump`/`reg-at` 的 provenance 对拍一致。

---

## 大件 C：内存完整性 Phase 2 —— syscall/JNI 回读（device-agent）

> **重要发现 (2026-06-27)**：host 侧已**完整且经测试**。`external_writes.bin`
> (17 字节/记录: `idx:u64, addr:u64, byte:u8`) 已被 `memshadow.rs::
> merge_external_writes` 读入为 `x` 层，单测 `memshadow_loads_external_writes_as_x_events`
> 已验证。**所以 Phase 2 唯一剩下的是 device 侧捕获** —— agent 在 syscall 返回边界
> 把内核写入的 buffer 字节按这个**已有格式**追加进 `external_writes.bin` 即可，
> host/core/mem-export/reg-at 全部自动受益，无需改动。这把 C 从"全栈新功能"
> 缩成"纯 agent 捕获"，但仍触设备、风险最高，**最后做**。

### 目标
补齐"内核写进用户 buffer 但指令流看不到"的字节（`read`/`recvfrom`/`stat`/
`gettimeofday`/`clock_gettime`/`__system_property_get`/`getrandom` 等），作为
MemShadow `x` 层喂给大件 A/B 与 `mem-export`/`reg-at`。

### 设计（已在 memory-completeness-design.md 起草，这里定形）
- **device 侧**：在 `svc` 返回边界，按 per-syscall ABI 表读出 buffer 指针+长度
  （来自入参寄存器快照），snapshot 写入的字节，emit 到 sidecar 流。
- **host 侧**：合并进 MemShadow 作为 `x` 层（已有 external_writes.bin 通路）。
- **难点**：ABI 表（每 syscall 哪个寄存器是 out-buffer/长度）；长度上界（cap，
  防爆内存，参照 trace-all 的 50M guard）；JNI 走 vtable hook 而非 svc。

### 难度/风险
**中**，但**触及 device agent**——必须遵守内存上界 + 默认 cap + 全链路验证
(agent→host→meta→core→display)，且真机别搞崩（见项目记忆）。比 A/B 风险高，
**最后做**，先在易目标上验证 ABI 表正确性。

### 实现路径（2026-06-27 勘察，turnkey）
agent **两半都已存在**，只差接线：
1. `tracer/src/sidecar/semantic.ts` 已 hook libc `syscall` wrapper 的 `onEnter`，
   且已收集 `outStringPtrs`。加一个 `onLeave`：按 per-syscall ABI 表
   (read=buf@x1/len=ret, recvfrom=buf@x1/len=ret, stat=statbuf@x1/固定长 等)
   读出内核写入的字节。
2. 复用 `agent_cmodule_v5.js` 已有的 **`external_writes.bin` 17 字节格式**
   (`idx:u64, addr:u64, byte:u8`) 追加这些字节 —— host/core 零改动自动吃进 `x` 层
   (已测 `memshadow_loads_external_writes_as_x_events`)。
3. ABI 表放 JSON spec (`tools/hooks/syscall_abi.json`)，不硬编码 (项目规则)。
4. cap：单 syscall buffer 上限 (如 64KiB) + 总量 guard (参照 trace-all 50M)。
   opt-in、默认 off (参照 anti-detect 默认关 + 不搞崩设备)。
5. 全链路验证：易目标 (douyin) 上 `read`/`getrandom` → 确认 `mem-export`/`reg-at`
   对应地址 completeness 从 `??` 变 `x`，字节与设备真值对拍。

**为何本轮未实现**：纯 device-agent 改动 (cross-compile→push→trace→verify 多步)，
设备崩溃风险最高，且需 ABI 表逐 syscall 校验；按项目"先易目标验证、别搞崩设备、
重测试不堆量"的纪律，作为下一个专注 session 谨慎做，而非在本轮一并赶出。

---

## 推进顺序（建议）
1. **A1 校验式重放** —— 纯 host、数据全有、顺带成为 lifter 回归测试，价值/风险比最高。
2. **B1 token provenance** —— 纯 host，复用现成 provenance。
3. **C syscall Phase 2** —— 触设备，最后做，先验 ABI 表。
4. A2/A3、B2 视需要。

每件都：core → CLI(JSON) → server route → (可选)前端；每件都带真机 trace 上的
对抗性测试，**修对了再 commit**。
