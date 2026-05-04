#!/usr/bin/env python3
"""Regenerate tools/jni_offsets.json from a JNI header via Binary Ninja.

Source of truth: vendor/jni/jni_bn.h (curated for BN parsing).
Output: tools/jni_offsets.json — { "0x20": "GetVersion", ... } (hex-string
keys for stable JSON serialization).

Run when jni_bn.h changes, or to validate the layout against an Android NDK
jni.h. Rust v2 falls back to parsing vendor/jni/jni_bn.h when this JSON is
absent, so the generated file is an optional checked asset.

Usage:
    python tools/regen_jni_offsets.py
    python tools/regen_jni_offsets.py --header /path/to/jni.h --struct JNINativeInterface_
"""
from __future__ import annotations
import sys, json, argparse, pathlib

PROJ = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_HEADER = PROJ / "vendor" / "jni" / "jni_bn.h"
DEFAULT_OUTPUT = PROJ / "tools" / "jni_offsets.json"


def extract_struct_offsets(header_path: pathlib.Path, struct_name: str) -> dict[int, str]:
    """Use BN to parse the C header, walk the named struct's members,
    return {byte_offset: member_name}. Filters `reservedN` placeholders."""
    try:
        import binaryninja
    except ImportError:
        print("error: binaryninja module not on sys.path", file=sys.stderr)
        print("  hint: PYTHONPATH=/path/to/binaryninja/python python tools/regen_jni_offsets.py",
              file=sys.stderr)
        sys.exit(1)
    src = header_path.read_text()
    # BN's clang can't find system stddef.h on this host. We don't actually
    # need <stdio.h> or <stdarg.h> for struct layout — just stub their types.
    src = src.replace("#include <stdio.h>",
                       "typedef void *__FILE_ptr; typedef int FILE;")
    src = src.replace("#include <stdarg.h>", "typedef void *va_list;")
    plat = binaryninja.Platform["linux-aarch64"]
    parsed = plat.parse_types_from_source(src)
    if not parsed.types:
        raise RuntimeError(f"BN parsed no types from {header_path}")
    # Look up struct by name (BN uses QualifiedName)
    target_type = None
    for qname, tobj in parsed.types.items():
        nm = str(qname)
        if nm == struct_name or nm.endswith(f"::{struct_name}"):
            target_type = tobj
            break
    if target_type is None:
        names = sorted(str(q) for q in parsed.types)
        raise RuntimeError(f"struct {struct_name!r} not found. Got: {names[:20]}")
    # target_type is a StructureType — .members is a list of StructureMember
    members = list(target_type.members)
    if not members:
        raise RuntimeError(f"{struct_name} has no members (BN.Type={type(target_type).__name__})")
    out: dict[int, str] = {}
    for m in members:
        nm = m.name
        if nm.startswith("reserved"): continue
        out[int(m.offset)] = nm
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--header", type=pathlib.Path, default=DEFAULT_HEADER)
    p.add_argument("--struct", default="JNINativeInterface_")
    p.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    args = p.parse_args()
    print(f"parsing {args.header} for struct {args.struct}...", file=sys.stderr)
    offsets = extract_struct_offsets(args.header, args.struct)
    print(f"  → {len(offsets)} fields extracted", file=sys.stderr)
    # Save as hex-keyed JSON for stable diffs
    out_data = {
        "_source": str(args.header.relative_to(PROJ) if args.header.is_absolute() else args.header),
        "_struct": args.struct,
        "_count": len(offsets),
        "offsets": {hex(off): name for off, name in sorted(offsets.items())},
    }
    args.output.write_text(json.dumps(out_data, indent=2, ensure_ascii=False) + "\n")
    print(f"  → wrote {args.output} ({args.output.stat().st_size} bytes)", file=sys.stderr)
    # Quick sanity: NewObject must be at 0xe0
    sample_check = {0x20: "GetVersion", 0xe0: "NewObject", 0x538: "NewStringUTF"}
    for off, expected in sample_check.items():
        actual = offsets.get(off)
        if actual != expected:
            print(f"  WARN: offset {hex(off)} expected={expected!r} got={actual!r}",
                  file=sys.stderr)
        else:
            print(f"  ✓ {hex(off)} = {actual}", file=sys.stderr)


if __name__ == "__main__":
    main()
