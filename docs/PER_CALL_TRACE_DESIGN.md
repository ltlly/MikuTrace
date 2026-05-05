# Per-Call Trace Layout

traceMiku 现在以 per-call 目录作为分析单元。每次目标函数进入后独立保存一个
`trace.bin` 和 `meta.json`，用户后续从 run 目录中选择要看的那一次调用。

## Layout

```text
traces/<run_name>/
├── meta.json
├── log.txt
└── calls/
    ├── call_001_tid12345_4675r_98ms/
    │   ├── trace.bin
    │   └── meta.json
    └── call_002_tid12345_2066291r_50342ms/
        ├── trace.bin
        └── meta.json
```

目录名包含 call index、tid、record 数和耗时，方便直接按最长 call 找 cold path。
run 级 `meta.json` 保存 calls 概要；call 级 `meta.json` 保存完整性字段。

## Call Metadata

```json
{
  "callIdx": 2,
  "tid": 12345,
  "ts_in": 1714153200.123,
  "ts_out": 1714153250.465,
  "ms": 50342,
  "retval": "0x0",
  "records": 2066291,
  "dropped": 0,
  "truncated": false,
  "stalker_followed": true,
  "first_pc": "0x75f6306000",
  "last_pc": "0x75f6306800",
  "last_insn_is_ret": true
}
```

完整性判断优先看：

1. `truncated == false`
2. `dropped == 0`
3. 最后一条指令是 `ret` 或 `br lr`
4. records 与 `ms` 的比例没有明显异常

## Trace Record Contract

`trace.bin` 是稳定格式，每条记录 272 字节，little-endian：

```text
0x000  u64  pc
0x008  u64  x[0..28]
0x0F0  u64  fp   (= x29)
0x0F8  u64  lr   (= x30)
0x100  u64  sp
0x108  u32  nzcv
0x10C  u32  inst
```

格式变化需要 meta version bump 和迁移逻辑。`js`、`cmodule-v3`、`cmodule` v5 都必须
写出相同物理 record。

## Current Commands

```bash
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 600 \
  --cold-launch --remote 127.0.0.1:6699 --out traces/run1

./tracemiku list traces/run1
./tracemiku info traces/run1

COLD=$(ls -d traces/run1/calls/call_* | sort -t_ -k4 -n -r | head -1)
./tracemiku info "$COLD"
./tracemiku web "$COLD" --port 18900 --no-browser
```

`tracemiku web` 会启动 Rust server 并加载 Solid frontend。旧 Python viewer/TUI 不再是
维护目标。

## Constraints

- 同一 tid 不并发 follow 两次；agent 用 followed set 或单缓冲锁保证边界。
- MemShadow、taint、CFG 和 BN sidecar 都以单 call trace 为默认分析范围。
- 目标相关配置放在 `tools/hooks/` 或 `examples/<so>/known_offsets.json`，不要硬编码到
  core。
- 大 trace 需要有响应上限、后台 worker 和 UI 截断提示，避免一次请求阻塞交互。
