# traceMiku 性能与质量基线

本文件保存需要长期比较的基线，不记录一次性测试报告。数字来自 2026-05 的已知工作集；
环境或实现变化后应通过下列命令重新生成，禁止手工宣称提升。

## 已知基线

| 指标 | 基线 |
|---|---:|
| 真实 trace LLIL 覆盖率 | 主要函数 91.8% 至 100% |
| LLIL -> MLIL -> HLIL 平均耗时 | 约 8.28 微秒/指令 |
| 500 条记录反编译 | 统计少于 1 秒，含文本少于 5 秒 |
| 5000 条记录反编译 | 少于 30 秒 |
| 9.2 万条记录解析 | 约 2.35 秒 |

这些数字不是 CI 硬阈值，因为真实 trace、CPU 和 Binary Ninja 环境不同。任何性能改动
至少应报告同机修改前后结果、输入记录数、是否命中 sidecar 缓存和输出是否截断。

## 验证命令

```bash
make test-fast
make test-v2
make smoke-web RUN=<call_dir> SMOKE_ARGS='--all-surfaces --timeout 300'
uv run python scripts/web_api_perf_probe.py http://127.0.0.1:18900 --visible-ui-only
cd rust && cargo test --workspace -- --list
```

ARM64 回归夹具位于 `tests/arm64_test_bins/`。二进制是测试输入，不是发布产物；更新 C
源后必须同步重建并验证语义测试。
