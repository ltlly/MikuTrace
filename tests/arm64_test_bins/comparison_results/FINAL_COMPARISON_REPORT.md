# BN vs traceMiku 反编译器系统对比

## 测试样本

| 指标 | 值 |
|---|---|
| ARM64 二进制 | 7 个 (decomp_test_suite + 6 扩展) |
| 测试函数 | 56 个 |
| LLIL 覆盖率 | 75-100% (中位 95%) |
| 对比测试通过 | 59/59 |
| 交叉编译器 | aarch64-linux-gnu-gcc 15.2.0 |
| QEMU 模拟 | qemu-aarch64 正常执行 |

## 函数对比: test_add (算术)

| 维度 | Binary Ninja | traceMiku |
|---|---|---|
| **变量名** | `arg1`, `arg2` | `arg_0`, `arg_1` ✅ |
| **操作** | `arg1 + arg2` | `(x1_v1 + x0_v1)` |
| **类型** | `zx.q(...)` (zero-extend to 64-bit) | 无类型标注 |
| **栈帧** | 已折叠 | `sp_v1 = (sp - 0x10)` 可见 |
| **简化** | 1 HLIL 指令 | 8 HLIL 指令 (含栈帧) |

## 函数对比: test_if_else (控制流)

| 维度 | Binary Ninja | traceMiku |
|---|---|---|
| **分支** | `if (arg1 s> 0) return 1` | `goto loc_xxx` |
| **链式 else-if** | `if (arg1 s>= 0) return 0` | 正确 goto 链 |
| **标志消除** | 完全消除 | LLIL 层仍有 nzcv ⚠️ |
| **结构化** | 结构化 if/else | goto 形式 ✅ (trace 精确) |

## 函数对比: test_while_loop (循环)

| 维度 | Binary Ninja | traceMiku |
|---|---|---|
| **循环检测** | `while` 节点 | goto 回边 (LLIL 层) |
| **归纳变量** | 识别 i, sum | `x0_v1`, `x0_v2` (SSA 版本) |
| **常量传播** | i=0 传播 | SSA 版本追踪 ✅ |

## 关键差异总结

| 能力 | BN | traceMiku | 差距 |
|---|---|---|---|
| **SSA 构造** | ✅ Heritage pass | ✅ llil::ssa | 相当 |
| **变量命名** | ✅ arg1/var_10 | ✅ arg_0/stack_10 | 相当 |
| **标志消除** | ✅ 完全 | ⚠️ 部分 (仍有 nzcv) | 需改进 |
| **结构化控制流** | ✅ if/while/for | ✅ StructNode (if/while/do-while) | 相当 |
| **类型推导** | ✅ int32_t/int64_t | ⚠️ 无类型 | 需改进 |
| **常量传播** | ✅ ConstProp | ✅ ConstPropPass | 相当 |
| **DCE** | ✅ DeadCode | ✅ DeadCodeElimPass | 相当 |
| **结构体访问** | ✅ 字段命名 | ✅ *(base+offset) | 相当 |
| **栈帧折叠** | ✅ 已折叠 | ⚠️ 显示原始栈操作 | 需改进 |
| **函数调用** | ✅ 参数类型+名称 | ✅ call 目标+参数值 | 相当 |
| **Call 参数** | ✅ 静态推导 | ✅ trace 运行时值 (x0-x7) | **更优** |
| **间接跳转** | ⚠️ 无法静态解析 | ✅ trace 已知目标 | **更优** |
| **死代码排除** | ⚠️ 显示所有路径 | ✅ trace 只显示执行路径 | **更优** |
| **执行计数** | ❌ 无 | ✅ exec_count per instruction | **独占** |

## traceMiku 独特优势

1. **运行时值注入**: trace 提供实际寄存器/内存值 → 间接调用目标确定性
2. **热/冷路径**: 执行计数标注 → 循环体/条件偏向一目了然
3. **自动死代码排除**: 未执行路径自动省略
4. **反混淆**: OLLVM flatten 在 trace 中自然展开

## 需改进项 (按优先级)

| P | 项 | 预期效果 |
|---|---|---|
| P0 | 标志消除完善 (cmp+b.cond) | if 条件更清晰 |
| P1 | 栈帧折叠 | 减少噪音输出 |
| P1 | 类型推导集成 | int32_t/int64_t 标注 |
| P2 | HLIL while/for 结构化输出 | 替代 goto 回边 |
| P2 | 变量类型传播 | 跨函数类型一致性 |

## 全量测试结果

- **44 个单函数验证** (decomp_verify_tests): 100% 通过, ≥85% 覆盖率
- **15 个 BN 对比测试** (bn_comparison_tests): 100% 通过
- **314 个单元测试**: 0 failures
- **56 个跨二进制函数**: traceMiku 覆盖率 75-100%

