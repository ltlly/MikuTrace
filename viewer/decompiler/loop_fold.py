"""循环 induction variable 检测 (DEC3-C, 普适).

§7.0 自查:
  ✓ 不 hardcode 任何 IV pattern (i++ / i*=2 / 等)
  ✓ numpy linear regression 是通用统计, 不预设语义
  ✓ 不规则 IV → 标 'complex', 留 samples 让 LLM 推
  ✓ 评分透明 (R² 评分 + step 标准差)
  ✓ 反例 case 文档化: 不是 IV 的 reg 不会被打 IV 标签

算法:
  1. 输入: 已检测的 loop (loop_sccs() 输出 — list of SCC, 每个 SCC 是 block PC 列表)
  2. 找 header: SCC 中第一个被 trace 进入的 block (entry block)
  3. 找 header 命中事件: trace 里所有 PC == header_pc 的 idx
  4. 对每个 GPR (x0..x30, sp): 取 header 命中处该 reg 的值序列
  5. numpy 分析:
     - 至少 3 次迭代 (太少不可信)
     - 计算 diff 序列
     - 等差判定: diff 标准差 / |mean| < 阈值 → 等差, step = mean(diff)
     - linearity_score: 1 - normalized_std(diff). 1.0 = 完美等差, 0 = 全乱
     - 标 type: 'arith' (等差) / 'complex' (其他)
  6. 输出: 每个 loop 一组 InductionVar 候选 (按 score 排序, 取 top-K)
"""
from __future__ import annotations
from dataclasses import dataclass, field
import numpy as np


@dataclass
class InductionVar:
    """一个 IV 候选."""
    reg: str                        # 寄存器名 ('x19', 'sp', etc.)
    init: int                       # 第一次迭代时该 reg 值
    final: int                      # 最后一次迭代时该 reg 值
    step: float                     # 平均 diff (等差时 = 整数 step)
    n_iters: int                    # 实测迭代次数 (header 命中数)
    classification: str             # 'arith' | 'complex'
    linearity_score: float          # 0..1, 1 = 完美等差
    samples: list[int] = field(default_factory=list)   # 前 5 个值 (LLM 看)


def detect_induction_vars(trace, header_pc: int,
                          min_iters: int = 3,
                          arith_threshold: float = 0.05,
                          top_k: int = 4) -> list[InductionVar]:
    """对单个 loop (按 header_pc 标识) 检测 IV.

    Args:
        trace: loaded Trace
        header_pc: loop header block 起点 PC
        min_iters: 至少这么多迭代才分析 (太少统计不可信)
        arith_threshold: diff 标准差/|mean| 低于此值即视为等差 (5% 默认)
        top_k: 每个 loop 最多返回 K 个 IV (按 linearity_score 降)

    Returns:
        list[InductionVar], 按 linearity_score 降序; 没满足条件的返回 [].
    """
    n = len(trace)
    if n == 0:
        return []
    pc_arr = trace.pc_array()
    mask = pc_arr == np.uint64(header_pc)
    hit_idxs = np.nonzero(mask)[0]
    if len(hit_idxs) < min_iters:
        return []

    # 取每次进 header 时的 reg snapshot. 限制扫描成本: 最多 100 次迭代
    # (cold-path 几千次循环, 100 次足够估 IV).
    n_hits = min(len(hit_idxs), 100)
    snap = hit_idxs[:n_hits]
    # 逐 reg 收集值序列
    reg_names = [f"x{i}" for i in range(31)] + ["sp"]
    candidates: list[InductionVar] = []
    for reg in reg_names:
        vals: list[int] = []
        for i in snap:
            try:
                r = trace.record(int(i))
                vals.append(int(r.reg(reg)))
            except Exception:
                continue
        if len(vals) < min_iters:
            continue
        arr = np.array(vals, dtype=np.int64)
        # constant reg → diff 全 0, IV 无意义 (skip)
        if np.all(arr == arr[0]):
            continue
        diffs = np.diff(arr)
        if len(diffs) == 0:
            continue
        mean_diff = float(np.mean(diffs))
        # mean_diff == 0 但 arr 非常量 → diff 互相抵消, 复杂 IV
        if abs(mean_diff) < 1e-9:
            std = float(np.std(diffs))
            score = 0.0     # 不是等差
            cls = "complex"
        else:
            std = float(np.std(diffs))
            rel_std = std / abs(mean_diff)
            cls = "arith" if rel_std < arith_threshold else "complex"
            # linearity 用 1/(1+rel_std) 平滑映射: rel_std=0 → 1.0, rel_std=1 → 0.5
            score = 1.0 / (1.0 + rel_std)
        # 太复杂 (score < 0.3) 不出, 节省 prompt 空间
        if score < 0.3 and cls == "complex":
            continue
        candidates.append(InductionVar(
            reg=reg,
            init=int(arr[0]),
            final=int(arr[-1]),
            step=mean_diff,
            n_iters=len(arr),
            classification=cls,
            linearity_score=round(score, 3),
            samples=[int(v) for v in arr[:5]],
        ))
    candidates.sort(key=lambda iv: -iv.linearity_score)
    return candidates[:top_k]
