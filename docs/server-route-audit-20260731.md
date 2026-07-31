# traceMiku Server 路由审计报告

**日期**: 2026-07-31  
**范围**: `rust/crates/tracemiku-server/src/routes/` 全部 63 个路由  
**目标**: 识别文本后处理、哨兵值、扁平响应修补、重复分析逻辑

---

## 执行摘要

审计发现 5 类主要问题，影响 40+ 个路由文件。核心问题是：**地址解析、错误处理和状态响应逻辑分散在路由层，缺乏类型化错误，大量使用 `.unwrap_or(0)` 等哨兵值掩盖解析失败**。

### 优先级分类

- **P0 (正确性风险)**: 地址解析静默失败 (3 处)
- **P1 (架构违规)**: 重复地址解析逻辑 (8+ 路由)
- **P2 (可维护性)**: 扁平 JSON 响应拼接 (15+ 路由)
- **P3 (清理)**: 未使用导入、冗余克隆 (已知 clippy 警告)

---

## 问题 1: 地址解析静默失败 (P0)

### 受影响路由
- `idxs_for_pc.rs:54`
- `idxs_for_block.rs:63`
- `so_stats.rs:71`

### 问题描述
```rust
let target = u64::from_str_radix(q.pc.trim_start_matches("0x"), 16).unwrap_or(0);
```

**风险**: 无效地址 (如 `"invalid"`) 静默转换为 `0`，用户得到错误但看似成功的响应。

### 根因
路由层自行处理地址解析，失败时返回哨兵值 `0`。`resolve.rs` 已有正确实现 (`parse_u64`) 返回 `Option<u64>`，但未被复用。

### 修复方案
1. 将 `resolve::parse_u64` 移至 `tracemiku-core` 作为 `parse_address` 公共 API
2. 返回 `Result<u64, ParseAddressError>` 类型化错误
3. 所有路由使用统一解析器，失败时返回 `400 Bad Request` + 结构化错误

### 影响范围
- **直接**: `idxs_for_pc`, `idxs_for_block`, `so_stats`
- **间接**: 所有手动 `from_str_radix` 的路由 (8+ 处)

---

## 问题 2: 重复地址解析逻辑 (P1)

### 受影响路由
至少 8 个路由各自实现了地址/偏移解析：
- `resolve.rs` - `parse_u64` (最完整，支持 hex/decimal/`d` 前缀)
- `field_at.rs` - `parse_int` (支持 `i64`)
- `coverage.rs` - 内联 `parse_u64` 调用
- `mem_export.rs` - 复用 `resolve::parse_u64`
- `idxs_for_pc.rs`, `idxs_for_block.rs` - 仅 hex + `.unwrap_or(0)`
- `bn_hlil.rs` - `parse_u64` (未充分错误处理)

### 问题描述
每个路由对十六进制/十进制、`0x` 前缀、`d` 前缀的处理规则不一致。

### 根因
缺乏统一的 core 层地址解析 API。`resolve.rs` 的实现最健壮但位于 server 层。

### 修复方案
1. 在 `tracemiku-core` 新增 `pub fn parse_address(s: &str) -> Result<u64, ParseAddressError>`
2. 支持 `0x` hex、bare hex (按 disassembler 惯例)、`d` 前缀 decimal
3. 所有路由迁移至统一 API
4. 添加 core 单元测试覆盖所有格式

---

## 问题 3: `memshadow_ready_or_block_if_idle` 状态字符串 (P1)

### 受影响路由
- `strings.rs`
- `mem_export.rs`
- `backward_taint.rs` (通过 `memshadow_ready_or_block_if_idle`)
- 其他使用 MemShadow 的路由

### 问题描述
```rust
match inner.memshadow_ready_or_block_if_idle() {
    Ok(mem) => mem,
    Err(status) => {
        return StringsResponse {
            status,  // &'static str: "building", "error", etc.
            ...
        };
    }
}
```

**问题**: 返回字符串 `status` 而非类型化错误。前端需字符串匹配判断错误类型。

### 根因
`memshadow_ready_or_block_if_idle` 返回 `Result<&MemShadow, &'static str>`。

### 修复方案
1. 在 `tracemiku-core` 定义 `pub enum MemShadowError` 使用 `thiserror`
2. 变体: `Building`, `Failed(String)`, `NotInitialized`
3. 更新 `memshadow_ready_or_block_if_idle` 返回 `Result<&MemShadow, MemShadowError>`
4. 路由层将错误映射为 HTTP 状态码 + JSON

---

## 问题 4: BN sidecar 错误处理扁平化 (P1)

### 受影响路由
- `bn_hlil.rs` (多个 handler)
- `dec_fn.rs` (依赖 BN sidecar)
- `functions.rs`

### 问题描述
```rust
let cfg = request_sidecar(...).await?;
let ok = cfg.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
let ready = cfg.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
let error = cfg.get("error").cloned().unwrap_or(Value::Null);
```

**问题**: 路由层通过 JSON 字段提取、布尔判断、字符串拼接来构造响应，而非结构化类型。

### 根因
BN sidecar 返回松散 `serde_json::Value`，路由层做后处理。

### 修复方案
1. 在 server 定义 `struct BnSidecarResponse` / `enum BnSidecarError`
2. `request_sidecar` 返回 `Result<BnSidecarResponse, BnSidecarError>`
3. 路由层只做编排和序列化，不提取字段重组 JSON

**注**: 这是 server 内部重构，不涉及 core，优先级相对较低。

---

## 问题 5: `field_at.rs` 的占位符实现 (P2)

### 问题描述
```rust
pub async fn field_at_handler(Query(q): Query<FieldAtQuery>) -> Json<FieldAtResponse> {
    Json(FieldAtResponse {
        pc: q.pc,
        reg: q.reg,
        offset: parse_int(&q.offset).unwrap_or(0),  // 哨兵值
        hit: false,  // 永远返回 miss
        r#struct: None,
        field: None,
        type_name: None,
    })
}
```

**问题**: 路由存在但未实现，永远返回 `hit: false`。用户无法区分"功能未实现"还是"真的没找到字段"。

### 修复方案
1. 返回 `501 Not Implemented` 或在响应中增加 `"status": "not_implemented"`
2. 或彻底移除路由，在 OpenAPI 文档标记已废弃

---

## 问题 6: 默认值 `-1` 作为哨兵 (P2)

### 受影响路由
- `strings.rs:30` - `default_cursor() -> i64 { -1 }`
- `idxs_for_block.rs:29` - `default_near() -> isize { -1 }`
- `bn_hlil.rs:348` - `best.map(...).unwrap_or(-1)` 表示"未找到"

### 问题描述
使用 `-1` 表示"无游标"或"未找到"，而非 `Option<usize>`。前端需特殊处理负数。

### 根因
兼容 Python 旧 API 的有符号整数 + `-1` 哨兵惯例。

### 修复方案
**不建议立即修改** (会破坏 API 兼容性)。文档化 `-1` 语义，或在 v2 API 迁移到 `Option<usize>`。

---

## 问题 7: 缺少类型化错误传播 (P1)

### 全局观察
大部分路由的错误处理模式：
```rust
.unwrap_or_else(|err| {
    tracing::warn!("route worker failed: {err}");
    SomeResponse {
        status: "error",
        ...默认值...
    }
})
```

**问题**: 
1. 错误只记录在日志，HTTP 响应只有 `"status": "error"` 字段
2. 前端无法区分错误类型 (解析失败 vs 内部错误 vs 资源不足)
3. 没有 HTTP 状态码语义 (全是 200 OK)

### 修复方案
1. 为常见错误增加 `thiserror` 枚举:
   - `ParseAddressError` - 地址解析
   - `MemShadowError` - 内存影子
   - `IndexError` - 索引越界
2. 路由层映射错误到 HTTP 状态码:
   - 解析错误 → 400 Bad Request
   - 资源未就绪 → 503 Service Unavailable
   - 内部错误 → 500 Internal Server Error
3. 响应包含 `error` 对象: `{ "type": "parse_address", "message": "...", "input": "..." }`

---

## 实施计划

### 阶段 1: 高置信度修复 (本次实施)

**任务 1.1**: 统一地址解析 (P0/P1)
- [ ] 在 `tracemiku-core` 新增 `parse_address` 函数 + `ParseAddressError`
- [ ] 迁移 `idxs_for_pc`, `idxs_for_block`, `so_stats` 使用新 API
- [ ] 添加 core 测试 + server 集成测试
- [ ] **风险**: 低。纯新增 API，现有路由可选迁移

**任务 1.2**: MemShadow 类型化错误 (P1)
- [ ] 定义 `tracemiku_core::memshadow::MemShadowError`
- [ ] 更新 `memshadow_ready_or_block_if_idle` 签名
- [ ] 更新 `strings.rs`, `mem_export.rs`, `backward_taint.rs` 错误处理
- [ ] 添加错误序列化测试
- [ ] **风险**: 中。涉及 core API 变更，需同步更新所有调用方

**任务 1.3**: 修复 `field_at` 占位符 (P2)
- [ ] 返回 `501 Not Implemented` 或标记 `status: "not_implemented"`
- [ ] 更新 OpenAPI 文档
- [ ] **风险**: 极低

**任务 1.4**: Clippy 警告清理 (P3)
- [ ] 修复已知的 `unused_imports`, `noop_method_call`, `unused_assignments`
- [ ] 仅针对本次修改的文件
- [ ] **风险**: 极低

### 阶段 2: 架构改进 (推荐后续)

**任务 2.1**: BN sidecar 类型化 (P1)
- 定义 `BnSidecarResponse`, `BnSidecarError` 结构
- 重构 `request_sidecar` 返回类型
- 影响: `bn_hlil.rs`, `dec_fn.rs`, `functions.rs`

**任务 2.2**: 全面类型化错误 (P1)
- 为所有路由定义错误枚举
- 实现 `IntoResponse` trait 映射到 HTTP 状态码
- 移除 `status: "error"` 字符串模式

**任务 2.3**: API 版本化迁移 (P2)
- 将 `-1` 哨兵迁移到 `Option<usize>`
- 在 `/api/v2/*` 路径提供新 API

---

## 不推荐修复的项

1. **问题 6 的 `-1` 哨兵**: 需 API 版本升级，破坏性变更
2. **所有 format! 字符串拼接**: 大部分是合理的序列化逻辑，非后处理
3. **前端行为调整**: 如响应字段顺序、格式化样式等，不属于 server bug

---

## 测试覆盖

每个修复必须包含：
1. **单元测试**: core 层新增的解析器、错误类型
2. **集成测试**: server 路由返回正确 HTTP 状态码和错误结构
3. **回归测试**: 现有测试套件全部通过

---

## 附录: 扫描统计

- 总路由文件: 63
- 总代码行数: ~14,110
- 使用 `.unwrap_or(...)` 的位置: 100+
- 使用 `format!` 的位置: 461
- 已有测试文件: 43
- 定义类型化错误的 core 模块: 3 (`function_index`, `type_database`, `meta`)

---

**审计完成时间**: 2026-07-31  
**审计人员**: AI Worker (yunwu/claude-fable-5)
