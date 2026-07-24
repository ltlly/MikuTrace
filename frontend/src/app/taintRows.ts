import type { RecordRow, TaintRow } from "../api/types";

export function recordRowFromTaintRow(row: TaintRow): RecordRow {
  const mnemonic = row.asm.trim().split(/\s+/, 1)[0]?.toLowerCase() ?? "";
  return {
    idx: row.idx,
    pc: row.pc,
    rel: row.rel,
    module: null,
    func: row.func,
    off: null,
    asm: row.asm,
    annotation: row.why ?? row.via ?? null,
    exec_count: null,
    is_branch: mnemonic.startsWith("b") || mnemonic === "cbz" || mnemonic === "cbnz" || mnemonic === "tbz" || mnemonic === "tbnz",
    is_call: mnemonic === "bl" || mnemonic === "blr",
    is_ret: mnemonic === "ret",
  };
}
