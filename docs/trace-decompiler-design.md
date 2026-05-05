# Trace Decompiler Design

> 配套研究：[`docs/trace-decompiler-research.md`](trace-decompiler-research.md)。
> 本文档描述当前 Rust/Solid analysis v2 状态。旧 Python `viewer/decompiler/` 设计已归档。

## Position

traceMiku 的 decompiler 有三条边界清晰的路线：

| Route | Purpose | Current Surface |
|---|---|---|
| TraceIR route | 把真实 trace 折叠成函数、块、loop、call、data anchors，供人或 LLM 阅读 | Rust core decompiler + `/api/dec/*` + Decompile panel |
| In-house LLIL route | 不依赖 LLM 的 C-like pseudocode，适合 trace-only 快速解释 | Rust decompiler / frontend Pseudo C |
| Binary Ninja route | 静态 HLIL/Pseudo C/CFG 参考，补 trace 未覆盖或静态结构 | `TRACEMIKU_BN_SO` sidecar + HLIL panel |

LLM 调用能力可以保留在 CLI/API，但 UI 默认只开放可控延迟的 Decompile、Pseudo C 和
HLIL。LLM 面板需要等性能和错误面稳定后再显示。

## Data Flow

```text
trace.bin + meta.json
  └─ tracemiku-core Trace / Index / CFG / MemShadow / Taint / CallTree
       ├─ TraceIR builder
       │    └─ /api/dec/summary, /api/dec/fn/{id}
       ├─ in-house LLIL renderer
       │    └─ Pseudo C tab
       └─ BN sidecar, optional
            └─ /api/hlil-for-pc, /api/bn-cfg-svg-for-pc
```

所有重 CPU 路由必须移出 async runtime，并有响应上限或截断字段。前端需要把
`truncated`、`hidden_edges`、`stopped_at_max` 等状态显示给用户，不能把部分结果伪装成
完整分析。

## TraceIR Contract

摘要层默认小而稳定：

```yaml
trace:
  records: 2066291
  truncated: false
fns:
  - { id: F0, name: sub_547b0, blocks: 12, entry_idx: 84, exit_idx: 510 }
loops:
  - { id: L0, fn: F0, header_block: B4, iters: 256 }
hot_path:
  - F0
anchors:
  - { kind: string, idx: 421, addr: 0x740fd72f80, len: 113 }
```

函数层按需展开：

```yaml
fn:
  id: F0
  name: sub_547b0
  trace: { entry_idx: 84, exit_idx: 510, exec_count: 1 }
  blocks:
    - id: B0
      pc: 0x75f63067b0
      exec_count: 1
      exits:
        - { dst: B1, kind: cond, taken: 1, not_taken: 0 }
      asm:
        - { idx: 84, asm: "sub sp, sp, #0x30" }
  calls:
    - { idx: 120, name: sub_54fe8, ret_idx: 180 }
```

稳定 ID 比展示顺序更重要。前端和外部脚本应使用 `idx`、`pc`、`fn id` 做定位，不解析 UI
文本。

## BN Sidecar Behavior

BN sidecar 是可选静态后端：

```bash
TRACEMIKU_BN_SO=/path/to/libtarget.so ./tracemiku web <call_dir> --port 18900
```

当当前 trace PC 没有 BN 函数覆盖时，sidecar 可以创建 user function 并立即重试 HLIL /
Pseudo C / CFG 请求。前端要显示 created/timeout/error 状态，避免用户误以为 trace 里没有
函数。

## Frontend Interaction Contracts

- `g` 跳转支持 `#240` / `240` 到 trace index，`0x1234` 到该 PC 第一次出现的位置。
- Functions tab 单击选择函数并切 CFG 到手动模式；双击跳到该函数入口第一次执行。
- CFG sync 开启时跟随当前 trace 函数；手动选函数会暂停 sync。
- CFG Ctrl+滚轮以鼠标指针位置为锚点缩放。
- 大函数 CFG 可以显示 overview，并明确展示已绘制/隐藏 edge 数。
- HLIL 与 Pseudo C 都需要缩进和统一代码字体。

## Test Gates

```bash
cd rust
cargo test --workspace
npm --prefix frontend run build
uv run python scripts/frontend_event_smoke.py http://127.0.0.1:18900
```

涉及 BN 的改动还要用 `TRACEMIKU_BN_SO` 跑一遍 HLIL/Pseudo C/CFG 请求。涉及 LLM 的改动
不能影响默认 UI 启动和非 LLM decompiler 路径。
