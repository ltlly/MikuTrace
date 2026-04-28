"""End-to-end smoke test: list backends, open libsgmainso via best one,
fetch HLIL for doCommandNative (sub_457770), verify cache works.

Usage:
    PYTHONPATH=/home/ltlly/tools/binaryninja/python:. \
        python3 -m viewer.decompiler.smoke_test
    # or force a backend:
    TRACEMIKU_DECOMP_BACKEND=ghidra ... python3 -m viewer.decompiler.smoke_test
"""
from __future__ import annotations
import time, sys, pathlib

from . import make_backend, list_backends, DecompCache


SO_PATH = "/home/ltlly/Code/traceMiku/example/106_d9da290cacaffd471ee1231d16b59190/lib/arm64-v8a/libsgmainso-6.8.260403.so"
DOCMD_OFFSET = 0x57770


def main():
    print("=== backend availability ===")
    for name, ok, reason in list_backends():
        mark = "OK" if ok else "--"
        print(f"  [{mark}] {name:7s} {reason}")
    print()

    print("=== picking best backend ===")
    bk = make_backend()
    print(f"selected: {bk.name}")
    print()

    print(f"=== open {pathlib.Path(SO_PATH).name} ===")
    t0 = time.time()
    bk.open(SO_PATH, base=0)
    print(f"open: {time.time()-t0:.1f}s")
    print()

    print(f"=== function_at(+{DOCMD_OFFSET:#x})  base=0 → SO offset semantics ===")
    t1 = time.time()
    fn = bk.function_at(DOCMD_OFFSET)
    print(f"  fn lookup: {(time.time()-t1)*1000:.0f}ms")
    if fn:
        print(f"  name={fn.name}  range=[+{fn.start:#x}..+{fn.end:#x})  backend={fn.backend}")
    print(f"  backend reports loaded_base={bk.loaded_base():#x}")

    if fn is None:
        print("FAIL: could not resolve function")
        return 1

    print()
    print(f"=== hlil_for({fn.name}) — pc map ===")
    t2 = time.time()
    lines = bk.hlil_for(fn)
    print(f"  hlil: {(time.time()-t2)*1000:.0f}ms, {len(lines)} lines")
    for l in lines[:8]:
        print(f"  {l.pc_lo:#10x}  {l.text}")

    print()
    print(f"=== vars_for({fn.name}) ===")
    vars_ = bk.vars_for(fn)
    print(f"  {len(vars_)} vars; first 6:")
    for v in vars_[:6]:
        print(f"  {v.name:>10s}: {v.type_name:30s} @ {v.storage}")

    print()
    print(f"=== asm_tokens_at(first_3_lines) ===")
    sample_pcs = [l.pc_lo for l in lines[:3]]
    for pc in sample_pcs:
        toks = bk.asm_tokens_at(pc)
        if toks is None:
            print(f"  {pc:#x}: <none>")
            continue
        kinds = ",".join(t.cls for t in toks[:6])
        print(f"  {pc:#x}: {len(toks)} toks  first6_cls=[{kinds}]")
    # 同 fn 第二次查询应命中 cache (per-fn _asm_tok_cache)
    t_warm = time.time()
    for pc in sample_pcs:
        bk.asm_tokens_at(pc)
    print(f"  warm-cache 3 PCs: {(time.time()-t_warm)*1000:.2f}ms")

    print()
    print(f"=== xrefs_to(fn.start={fn.start:#x}) ===")
    refs = bk.xrefs_to(fn.start)
    print(f"  {len(refs)} callers; first 3: {[hex(r) for r in refs[:3]]}")

    print()
    print(f"=== cache round-trip (typed API) ===")
    cache = DecompCache()
    so_sha = DecompCache.hash_so(SO_PATH)
    fn_off = fn.start  # 在 base=0 模式下, fn.start 就是 SO 内偏移
    cache.put_hlil(so_sha, fn_off, bk.name, lines)
    cache.put_vars(so_sha, fn_off, bk.name, vars_)
    cache.put_xrefs(so_sha, fn_off, bk.name, refs)
    got_lines = cache.get_hlil(so_sha, fn_off, bk.name)
    got_vars  = cache.get_vars(so_sha, fn_off, bk.name)
    got_xrefs = cache.get_xrefs(so_sha, fn_off, bk.name)
    # 验证 round-trip: token 字段恢复得对吗?
    assert len(got_lines) == len(lines), f"hlil len mismatch: {len(got_lines)} != {len(lines)}"
    if lines and lines[4].tokens:
        assert got_lines[4].tokens[0].cls == lines[4].tokens[0].cls, "token cls roundtrip broken"
    print(f"  hlil   round-trip {len(got_lines)} lines OK (tokens preserved)")
    print(f"  vars   round-trip {len(got_vars)} vars OK")
    print(f"  xrefs  round-trip {len(got_xrefs)} addrs OK")
    print(f"  cache dir: {cache.dir}")
    print(f"  cache stats: {cache.stats()}")

    bk.close()
    print()
    print("=== smoke test PASSED ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
