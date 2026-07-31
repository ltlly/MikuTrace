import type { RecordRow, TaintRow } from "../api/types";

export function recordRowFromTaintRow(row: TaintRow): RecordRow {
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
    // Classification comes from the server decode; fall back to a minimal
    // mnemonic check only for older responses without the fields.
    is_branch: row.is_branch ?? mnemonicStartsWithB(row.asm),
    is_call: row.is_call ?? (row.asm.trim().startsWith("bl") || row.asm.trim().startsWith("blr")),
    is_ret: row.is_ret ?? row.asm.trim().startsWith("ret"),
  };
}

function mnemonicStartsWithB(asm: string): boolean {
  const m = asm.trim().split(/\s+/, 1)[0]?.toLowerCase() ?? "";
  return m.startsWith("b") || m === "cbz" || m === "cbnz" || m === "tbz" || m === "tbnz";
}
