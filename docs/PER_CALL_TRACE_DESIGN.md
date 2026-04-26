# 设计: 每次目标函数调用独立保存为一个 trace

## 背景

当前 `./tracemiku trace` 把一次 run 的所有 frames 按 `(pid, tid)` 写到同一个 `trace_<pid>_<tid>.bin`. 同一线程多次进入目标函数会拼到同一文件, **fail-path 短调用 (~4675 条) 和 cold-path 长调用 (~2M 条) 混在一起或互相覆盖**, 还得赌哪次先到才能抓到 cold path.

## 目标

每次 onEnter 都开一个新的 trace 子目录, 与该次调用 1:1 绑定. 用户事后挑想分析的那次 (按 records 排序). 自然解决 fail-path / cold-path 混淆.

## 目录结构

```
traces/<run_name>/
├── meta.json                       # 顶层: pkg/so/method/cmd + calls[] 概要
├── log.txt
└── calls/
    ├── call_001_tid12345_4675r_98ms/      # idx_tid_records_durationMs
    │   ├── trace.bin                       # 该次调用的指令流
    │   └── meta.json                       # tid, ts_in, ts_out, retval, ms, records, dropped
    ├── call_002_tid12345_2066291r_50342ms/
    │   ├── trace.bin
    │   └── meta.json
    └── ...
```

**目录命名要点**:
- `call_<3 位 idx>_tid<tid>_<records>r_<ms>ms` — 一眼看出哪个是 cold-path
- 失败的调用 (cmdValue 不匹配/skip) 不建目录
- 异常截断的调用 (teardown 强制结束/stalker 跟丢): records 是已抓数, ms 字段标 `?` 或 elapsed-since-enter, meta.json 加 `truncated: true`

## Agent 改动

### `tracer/agent_generic.js`
1. `STATE.callIdx` 已存在, 每次 onEnter 自增. 改 `send` 时所有 `frames` 消息带 `callIdx`.
2. `trace-begin` 带 `callIdx, tid, ts`.
3. `trace-end` 带 `callIdx, tid, ms, retval, total, dropped, truncated`.
4. **关键**: `STATE.batches` 当前是 `Map<tid, batch>` — 改成 `Map<callIdx, batch>`. 不同 tid 不同 callIdx 不冲突.
5. `followThread` 当前用 `STATE.followed: Set<tid>` 防重复. 保留, 同 tid 上 stalker 已经 follow 就不重复 (但 callIdx 仍递增).

### `tracer/agent_cmodule_v3.js`
1. 同上加 `callIdx`.
2. `STATE.fnEntered` 单 trace 锁可以保留 (因为 cmodule v3 ring 是单缓冲), 或者改成 per-call ring (每次 onEnter Memory.alloc 新 ring) — 推荐保留单缓冲 + 单并发, 简单.
3. flush 消息带 `callIdx`.

## CLI 改动 (`tracemiku`)

### `cmd_trace`
- `sess_files` 从 `Map<(pid,tid), {fp,meta}>` 改成 `Map<callIdx, {fp,meta}>`.
- `open_sess(callIdx, tid, pid)` 创建 `traces/<run>/calls/_pending_call_<idx>/trace.bin` (临时名).
- 收到 `frames` 按 callIdx 写.
- 收到 `trace-end` 给目录改名为 `call_<idx>_tid<tid>_<records>r_<ms>ms` (用 records/ms 填实际值).
- teardown 时未结束的 call 强制 close, meta 标 `truncated: true`, 目录用 `_truncated_call_<idx>_<records>r` 命名.
- `top_meta["calls"] = [{idx, tid, records, ms, retval, truncated, dir}]`.

### `cmd_list`
- `tracemiku list` 列 run 概要 (calls 总数, 总 records, 最长一次).
- `tracemiku list <run>` 列该 run 下所有 calls, records 降序, 高亮最长那个.

### `cmd_view` / `cmd_info`
- 支持 `traces/<run>` (列 calls 让用户挑) 和 `traces/<run>/calls/<call_xxx>` (直接 view).
- 单 call 路径行为完全等同当前: `viewer/trace.py` load 一个 .bin 即可.

### `cmd_query`
- 同上, 支持 run 路径 (跨 calls 聚合) 或 call 路径 (单 call).
- 第一版只支持 call 路径即可.

## viewer/trace.py 改动

最小改动: 已经接受目录 (找到 .bin 文件加载). 单 call 目录直接 work, 不用改.

如果支持 run 级 viewer (跨 call 切换), 改 viewer/app.py 加一个"choose call" 入口. 第一版可跳过.

## 完整性核实 (用户最在意的点)

每个 call 的 `meta.json` 必须能回答 "这次调用真完整吗":

```json
{
  "callIdx": 2,
  "tid": 12345,
  "ts_in":  1714153200.123,
  "ts_out": 1714153250.465,
  "ms": 50342,
  "retval": "0x0",
  "records": 2066291,
  "dropped": 0,
  "truncated": false,           // ← onLeave 触发了 = false; 强制 teardown / 跟丢 = true
  "stalker_followed": true,
  "first_pc": "0x...",
  "last_pc": "0x...",
  "last_insn_is_ret": true      // ← capstone-decode 最后一条, true = 真完整
}
```

**判定真完整的条件**:
1. `truncated == false` (onLeave 触发)
2. 最后一条指令是 ret 或 br lr (函数真返回)
3. records 与 ts_out - ts_in 比例合理 (cold path ~40K rec/s)

`tracemiku info <call_dir>` 输出这些字段, 一眼看出.

## 空间预估

- fail-path: ~1.3 MB / call
- cold-path: ~560 MB / call
- 一次 90s run 最多 1-2 个 cold-path + 多个 fail-path → 单 run < 1 GB

加 `--max-records-per-call 5000000` 防失控.

## 验证方法

1. 改完跑: `./tracemiku trace --pkg com.taobao.taobao --so libsgmainso --fn-offset 0x57770 --cmd 70102 --duration 90 --mode js --cold-launch --out traces/percall_test`
2. `./tracemiku list traces/percall_test` 应看到多个 call, 至少一个 ≥1M records
3. `./tracemiku view traces/percall_test/calls/<最长那个>` 能开 viewer

## 已知约束 / 不做的事

- **不做并发 trace 同 tid**: stalker 不能同 tid follow 两次, agent_generic 已用 `STATE.followed` 去重.
- **不做 cross-call 寄存器关联**: 每个 call 是独立 trace, MemShadow / 污点不跨 call.
- **不做 retry-until-cold**: 已经 per-call 了, 用户挑就行, 不需要 retry.
- **CModule 路径**: ring 是单缓冲, 当一个 call 还在 follow 时, 下一个 onEnter 直接 skip (保留 fnEntered). JS 路径多 call 并发 OK.

## 改动清单 (按工作量从小到大)

1. **agent_generic.js** — 加 callIdx 字段到所有 send (~30 行)
2. **agent_cmodule_v3.js** — 同上 (~10 行)
3. **tracemiku cmd_trace** — sess_files 按 callIdx, 目录命名/重命名, truncated 标记 (~80 行)
4. **tracemiku cmd_list** — 支持 run 路径列 calls (~30 行)
5. **tracemiku cmd_info** — 支持 call 路径输出 last_insn_is_ret 等 (~30 行)
6. **README.md / BENCHMARKS.md** — 更新示例命令 + 目录结构说明 (~20 行)
7. **tests/** — 加 percall trace fixture + load 测试 (~50 行)

## 当前状态 (开新会话需知)

- 工作目录: `/home/ltlly/Code/traceMiku`
- frida-server: Florida fork, `127.0.0.1:6699` (`adb forward` 已固定)
- TB pkg: `com.taobao.taobao`, fnOffset 0x57770, cmd=70102 (sgmain doCommandNative)
- 已有完整 cold-path trace: `traces/doCommand_70102_coldpath/` (2,066,291 条 / 562 MB) — 别删
- `--cold-launch` 已实现 (`tracemiku:25-58`), `tracer/tb_launcher.sh` 也可独立用
- 测试: `python3 -m pytest tests/ -q` 当前 25 passed (9 skipped 是删旧 trace 后失效的 fixture)
- 关键 memory: `feedback_frida_cmodule_import_semantics.md` (CModule extern 语义)
