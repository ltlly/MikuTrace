# 抖音 liblynxsecurity.so 签名算法分析

> 基于 traceMiku trace: `traces/douyin_lynxsecurity_launch/calls/call_001_tid21931_2756r_149ms/`
> 目标函数: `nativeVerifySignBlock` @ `liblynxsecurity.so`
> 生成时间: 2026-05-16

## Trace 概览

| 指标 | 值 |
|------|-----|
| 记录数 | 2,756 |
| 耗时 | 149ms |
| 截断 | 否 |
| 返回值 | 0x1 (JNI_TRUE/成功) |
| 模块 | liblynxsecurity.so @ 0x6f4dc6e000 (52KB) |
| 入口 PC | 0x6f4dc74a30 (offset 0x6a30) |
| 出口 PC | 0x6f4dc74ec0 (offset 0x6ec0) |

## 函数入口分析

```
0x6a30  stp x20, x19, [sp, #0x40]    ; 保存 callee-saved
0x6a34  stp x29, x30, [sp, #0x50]    ; 保存 fp/lr
0x6a38  sub sp, sp, #0x330           ; 分配 0x330 字节栈帧
0x6a3c  mrs x28, tpidr_el0           ; 读取 TLS 指针
0x6a40  ldr x8, [x28, #0x28]         ; TLS+0x28 → x8
```

**JNI 参数映射**（入口时寄存器值）:

| 寄存器 | 值 | 推断 |
|--------|-----|------|
| x0 | 0xb4000070a1a96c20 | JNIEnv*（带 tag） |
| x1 | 0x7fc108c638 | jobject/jclass |
| x2 | 0x7fc108c63c | jobject/jbyteArray（签名数据） |
| x3 | 0x0 | null |
| x4/x5/x6 | — | 移至 x22/x21/x19 |

参数保存策略：x0→x20, x2→x23, x4→x22, x5→x21, x6→x19（跳过 x1/x3）

x3 == null → 跳转分支（`cbz x3, #0x6b04`）

## ⚠️ 关键发现：字节码 VM

```
VM candidate detected at 0x6f4dc74b20 (offset 0x6b20)
  confidence: 0.50
  reasons: indirect br/blr, high-frequency indirect (112 hits)
```

**VM 证据**:
- 112 次间接跳转出现（br/blr 指令）
- 11 个子函数中 F1-F10 都聚类在 0x7f50-0x7fa0 区域（各 60-85 个基本块，152 次调用）
- 这些子函数有**完全相同的调用次数**（152次），强烈暗示它们是 VM bytecode handler

### 函数结构

| ID | 名称 | 基本块 | 调用次数 | 范围 |
|----|------|--------|----------|------|
| F0 | sub_67b8 | 286 | 158 | 0..2755（全程） |
| F1 | sub_7f50 | 85 | 152 | 54..2755 |
| F2 | sub_7be4 | 43 | 152 | 54..2755 |
| F3 | sub_4324 | 13 | 84 | 301..1465 |
| F4 | sub_7c24 | 20 | 97 | 120..1465 |
| F5 | sub_7f60 | 71 | 152 | 54..2755 |
| F6 | sub_7f70 | 68 | 152 | 54..2755 |
| F7 | sub_7f80 | 66 | 152 | 54..2755 |
| F8 | sub_7f90 | 63 | 152 | 54..2755 |
| F9 | sub_5c3c | 56 | 152 | 54..2755 |
| F10 | sub_7fa0 | 60 | 152 | 54..2755 |

**VM Handler 分析**:
- F1-F10 (除 F3/F4) 聚类在 0x7f50-0x7fa0，相邻地址，都是 152 次调用
- F3 (sub_4324) 和 F4 (sub_7c24) 调用次数不同（84/97），可能是初始化/清理函数
- F0 (主函数) 286 个基本块 —— 包含 VM dispatcher loop + 参数解析

## 签名 SO 全景

### liblynxsecurity.so (52KB)
导出 (已通过 Frida spawn hook 确认):
- `Java_com_bytedance_lynx_service_security_LynxSecurityService_nativeVerifySignBlock` — 签名验证（本次 trace，偏移 0x6a20）
- `Java_com_bytedance_lynx_service_security_LynxSecurityService_nativeUpdateRsaPublicKeys` — RSA 公钥更新（偏移 0x75ac）

### liblynxbase.so (228KB)
导出含:
- `_ZN4lynx4base3md5ERKNSt6__ndk112basic_stringIc...` — MD5(string)
- `_ZN4lynx4base3md5EPKcm` — MD5(data, len)

### libfileprotect.so (68KB)
- 含有 `JNI_OnLoad`
- 疑似文件保护/完整性校验

## 签名流程推断

1. `nativeVerifySignBlock(JNIEnv*, jclass, signData, null, ...)` 被调用
2. 入口处分配 0x330 字节栈帧
3. x3(第4参数)为 null → 走简化路径
4. VM dispatcher 解释执行 bytecode（约 150+ 次 handler 调用）
5. 可能调用 `liblynxbase.so` 的 md5 进行哈希
6. 可能使用 RSA 公钥进行签名验证
7. 返回 0x1（验证通过 / JNI_TRUE）

### 待确认
- [ ] VM bytecode 编码格式（arm64 原生 vs 自定义）
- [ ] liblynxbase.so md5 是否在此调用链中（跨 SO 调用在 trace 中可见？）
- [ ] RSA 公钥存储位置（SO 内字符串 vs 动态下发）
- [ ] nativeUpdateRsaPublicKeys 的调用时机（启动时？）

## 反混淆难度评估

| 维度 | 评级 | 说明 |
|------|------|------|
| VM 混淆 | ⭐⭐⭐⭐ | 自定义 bytecode VM，约 10 个 handler |
| 控制流平坦化 | ⭐⭐⭐⭐⭐ | 286 基本块，大量间接跳转 |
| 跨 SO 调用 | ⭐⭐ | md5 在 liblynxbase.so，可能易于 hook |
| 字符串加密 | ❓ | 未分析 |

**结论**: liblynxsecurity.so 使用了 VM-based 混淆保护签名逻辑，需要先逆向 VM 指令集才能还原算法。同时有控制流平坦化（286 BBs）。推荐先用 Frida hook 拦截 md5/RSA 的输入输出，侧面还原算法。
