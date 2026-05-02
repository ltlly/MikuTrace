"""类型锚点 (type anchor) — 从 trace 的 bl 调用注入 reg → type 关联.

设计文档: docs/trace-decompiler-design.md §7.2 + §7.0 (普适性原则).

核心思想:
  - 类型知识全从外部 JSON spec 读, **代码零硬编码** (无 hardcoded JNI/libc 表)
  - 我们做: 扫 trace 找匹配 callee_pc 的 bl, 标记 (idx, reg, type)
  - 不做: 假设特定 SDK; 决定语义; 把 spec 写进代码

Spec 来源 (优先级降序, 接口可扩展):
  1. 用户 explicit JSON (推荐): callee_pc 绝对 PC + reg → type 映射
  2. trace.jni_events (运行时抓的, 自动从 vtable_offset 推 callee_pc) — stretch
  3. BN/Ghidra prior (静态分析的函数签名) — DEC3-* 后续

普适性自查 (§7.0 checklist):
  ✓ 没写死 SO 名 / 函数名 / 偏移 / 寄存器名 (全 spec-driven)
  ✓ 没"只支持 X" 的限定; 输出 confidence + spec 来源 (provenance)
  ✓ 用户可加任意 spec 文件 (libssl / libc / 自定义 SDK)
  ✓ 检测和决定分开 (我们标 anchor, LLM 决定怎么用)
  ✓ 反例 case 文档化: 没 spec 就没 anchor, 加 JSON 即生效
"""
from __future__ import annotations
import json, pathlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TypeSpec:
    """One callee → type 映射. 用户 JSON 一个条目.

    `callee_pc` 是绝对运行时 PC (int). `params` 是 list of (reg, type_name).
    `ret` 是返回值规格 (默认 x0).
    `provenance` 标 spec 来源, 给 LLM 看是哪个 hook 文件给的.
    """
    callee_pc: int
    name: str = ""               # 友好名 'FindClass' (不强制, 用于显示)
    params: list[tuple[str, str]] = field(default_factory=list)
    ret_reg: str = "x0"
    ret_type: str = ""
    provenance: str = ""         # 'tools/hooks/libart_jni.json#FindClass' 这种


@dataclass
class TypeAnchor:
    """一次 trace bl 命中. 由 trace 真实执行时机决定."""
    idx: int                     # trace record idx (bl 指令所在)
    callee_pc: int               # 跟 spec.callee_pc 一致
    spec: TypeSpec               # 命中的 spec (含参数/返回类型表)


def load_type_specs(paths: list[str | pathlib.Path]) -> list[TypeSpec]:
    """加载 multiple type spec JSON. 每个文件:
        { "version": 1,
          "specs": [
            {"callee_pc": "0x75f88dd5dc",
             "name": "FindClass",
             "params": [["x0", "JNIEnv*"], ["x1", "const char*"]],
             "ret":   ["x0", "jclass"]
            },
            ...
          ] }
    callee_pc: 16/10 进制字符串或 int 都接受.
    """
    out: list[TypeSpec] = []
    for p in paths:
        path = pathlib.Path(p)
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for entry in data.get("specs", []):
            pc = entry.get("callee_pc")
            if pc is None:
                continue
            if isinstance(pc, str):
                pc = int(pc, 0)
            params = []
            for ent in entry.get("params", []):
                if isinstance(ent, (list, tuple)) and len(ent) >= 2:
                    params.append((str(ent[0]), str(ent[1])))
                elif isinstance(ent, dict):
                    params.append((str(ent.get("reg", "")), str(ent.get("type", ""))))
            ret = entry.get("ret") or [entry.get("ret_reg", "x0"),
                                       entry.get("ret_type", "")]
            if isinstance(ret, (list, tuple)) and len(ret) >= 2:
                ret_reg, ret_type = str(ret[0]), str(ret[1])
            elif isinstance(ret, dict):
                ret_reg, ret_type = str(ret.get("reg", "x0")), str(ret.get("type", ""))
            else:
                ret_reg, ret_type = "x0", ""
            out.append(TypeSpec(
                callee_pc=int(pc),
                name=str(entry.get("name", "")),
                params=params,
                ret_reg=ret_reg,
                ret_type=ret_type,
                provenance=f"{path.name}#{entry.get('name', f'{pc:#x}')}",
            ))
    return out


def find_anchors(trace, specs: list[TypeSpec]) -> list[TypeAnchor]:
    """扫 trace 找所有 bl/blr 命中 spec.callee_pc 的 idx.

    实现: 对每条 record 解 mnemonic, 若 bl/blr, 看 trace.pc(i+1) 是否在 spec
    callee_pc 集合里. 命中即记 anchor.
    O(n × |specs|) 用 set 退化成 O(n).
    """
    if not specs:
        return []
    from .builder import decode  # 复用 viewer.disasm
    pc_to_spec: dict[int, TypeSpec] = {s.callee_pc: s for s in specs}
    out: list[TypeAnchor] = []
    n = len(trace)
    if n == 0:
        return out
    pc_arr = trace.pc_array()
    for i in range(n - 1):
        # 只在 bl/blr 上看 (其他指令不重要)
        d = decode(int(pc_arr[i]), trace.inst(i))
        if d.mnemonic not in ("bl", "blr"):
            continue
        target = int(pc_arr[i + 1])
        spec = pc_to_spec.get(target)
        if spec is not None:
            out.append(TypeAnchor(idx=i, callee_pc=target, spec=spec))
    return out
