"""TraceIR 渲染器 — markdown / yaml / toon / tenet 多种格式.

MVP (P2-DEC1): 只 markdown.
"""
from .markdown import render_summary_md, render_func_md, write_decompile_dir

__all__ = ["render_summary_md", "render_func_md", "write_decompile_dir"]
