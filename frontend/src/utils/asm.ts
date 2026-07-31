// Assembly-text helpers shared across panels.
//
// extractPc was copy-pasted in DecompilerPanel and PseudoCPanel; this is the
// single implementation. HlilPanel's parsePc is deliberately different
// (decimal fallback for HLIL line headers) and stays local.

/** Extract the first 0x-prefixed address from a decompiler output line. */
export function extractPc(line: string): number | null {
  const m = line.match(/0x([0-9a-f]{8,})/i);
  if (m) return parseInt(m[1], 16);
  return null;
}
