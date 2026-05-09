import type { AsmToken } from "~/api/types";

const REG_RE_FULL = /^(?:x(?:[0-9]|1[0-9]|2[0-9]|3[01])|w(?:[0-9]|1[0-9]|2[0-9]|3[01])|sp|fp|lr|pc|xzr|wzr)$/i;

export function normalizeReg(reg: string): string {
  const r = reg.toLowerCase();
  if (r === "fp" || r === "x29" || r === "w29") return "fp";
  if (r === "lr" || r === "x30" || r === "w30") return "lr";
  if (r === "wzr") return "xzr";
  if (r.startsWith("w") && /^w(?:[0-9]|1[0-9]|2[0-9]|3[01])$/.test(r)) return `x${r.slice(1)}`;
  return r;
}

export function tokenText(token: AsmToken): string {
  return token.t ?? "";
}

export function tokenAddr(token: AsmToken): string | null {
  return token.a ? String(token.a) : null;
}

export function tokenReg(token: AsmToken): string | null {
  if ((token.c ?? "").toLowerCase() !== "reg") return null;
  const text = tokenText(token);
  return REG_RE_FULL.test(text) ? normalizeReg(text) : null;
}

export function tokenClass(token: AsmToken): string {
  const cls = (token.c || "other").replace(/[^a-z0-9_-]/gi, "").toLowerCase() || "other";
  return `tok-${cls}`;
}
