"""Decompiler bridge — pluggable backend over BN/Ghidra/IDA/r2.

Usage:
    from viewer.decompiler import make_backend, DecompCache

    bk = make_backend()                        # auto-select
    bk.open("/path/to/lib.so", base=0x6d52e7a000)
    fn = bk.function_at(0x6d52e7a780)
    for line in bk.hlil_for(fn):
        print(line.text)
"""
from .backend import DecompilerBackend, Function, HlilLine, FieldHint, VarType
from .cache import DecompCache
from .factory import make_backend, list_backends

# Trace decompiler (路线 B — LLM-friendly skeleton IR).
# 设计: docs/trace-decompiler-design.md
from .ir import (
    TopIR, FuncIR, BlockIR, LoopIR, CallIR, EdgeIR,
    TypeAnchorIR, VmCandidateIR, InductionVarIR,
)
from .builder import build_trace_ir, attach_type_anchors
from .render import render_summary_md, render_func_md, write_decompile_dir
from .type_anchor import TypeSpec, TypeAnchor, load_type_specs, find_anchors
from .vm_candidate import VmCandidate, detect_vm_candidates
from .loop_fold import InductionVar, detect_induction_vars
from .benchmark import (
    BenchResult, run_bench, run_bench_one, render_compare_md,
)
from .llm_bundle import (
    Bundle, build_fn_decompile_prompt, build_summary_prompt,
    SYSTEM_PROMPT_DECOMPILE, SYSTEM_PROMPT_DECOMPILE_ZH, SYSTEM_PROMPT_SUMMARY,
)
from .llm_client import (
    LlmModel, LlmResult,
    ClaudeModel, DeepSeekModel, QwenModel, MimoModel, OpenCodeModel,
    make_llm_model, list_llm_models,
)

__all__ = [
    # static decompiler bridge (existing)
    "DecompilerBackend", "Function", "HlilLine", "FieldHint", "VarType",
    "DecompCache", "make_backend", "list_backends",
    # trace decompiler IR (P2-DEC1 + DEC3-B + DEC3-D)
    "TopIR", "FuncIR", "BlockIR", "LoopIR", "CallIR", "EdgeIR",
    "TypeAnchorIR", "VmCandidateIR", "InductionVarIR",
    "build_trace_ir", "attach_type_anchors",
    "TypeSpec", "TypeAnchor", "load_type_specs", "find_anchors",
    "VmCandidate", "detect_vm_candidates",
    "InductionVar", "detect_induction_vars",
    "BenchResult", "run_bench", "run_bench_one", "render_compare_md",
    "render_summary_md", "render_func_md", "write_decompile_dir",
    # LLM (P2-DEC2)
    "Bundle", "build_fn_decompile_prompt", "build_summary_prompt",
    "SYSTEM_PROMPT_DECOMPILE", "SYSTEM_PROMPT_DECOMPILE_ZH", "SYSTEM_PROMPT_SUMMARY",
    "LlmModel", "LlmResult",
    "ClaudeModel", "DeepSeekModel", "QwenModel", "MimoModel", "OpenCodeModel",
    "make_llm_model", "list_llm_models",
]
