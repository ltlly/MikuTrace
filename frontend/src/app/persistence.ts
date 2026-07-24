import type { LayoutState } from "./types";

const HIDDEN_SOS_KEY = "tracemiku-hidden-sos";
const FUNCTION_RENAMES_PREFIX = "tracemiku-function-renames:";
const LEGACY_LAYOUT_KEY = "tracemiku-layout-v2";
export const LAYOUT_KEY = "tracemiku-layout-v4";

const DEFAULT_LAYOUT: LayoutState = {
  leftW: 340,
  rightW: 520,
  bottomH: 240,
  colDot: 18,
  colIdx: 60,
  colPc: 112,
  colFunc: 96,
  colAsm: 200,
  syncCfg: true,
};

export function clampNumber(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

export function initialLayout(): LayoutState {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    const isCurrentLayout = raw !== null;
    const legacyRaw = raw ?? localStorage.getItem(LEGACY_LAYOUT_KEY);
    const parsed = legacyRaw ? JSON.parse(legacyRaw) : {};
    return {
      leftW: clampNumber(Number(parsed.leftW) || DEFAULT_LAYOUT.leftW, 180, 680),
      rightW: clampNumber(Number(parsed.rightW) || DEFAULT_LAYOUT.rightW, 320, 960),
      bottomH: clampNumber(Number(parsed.bottomH) || DEFAULT_LAYOUT.bottomH, 120, 560),
      colDot: clampNumber(Number(parsed.colDot) || DEFAULT_LAYOUT.colDot, 12, 48),
      colIdx: clampNumber(Number(parsed.colIdx) || DEFAULT_LAYOUT.colIdx, 44, 140),
      colPc: clampNumber(Number(parsed.colPc) || DEFAULT_LAYOUT.colPc, 80, 260),
      colFunc: clampNumber(Number(parsed.colFunc) || DEFAULT_LAYOUT.colFunc, 80, 420),
      colAsm: clampNumber(Number(parsed.colAsm) || DEFAULT_LAYOUT.colAsm, 180, 900),
      syncCfg: isCurrentLayout && typeof parsed.syncCfg === "boolean" ? parsed.syncCfg : DEFAULT_LAYOUT.syncCfg,
    };
  } catch {
    return { ...DEFAULT_LAYOUT };
  }
}

export function initialHiddenSos(): Set<string> {
  try {
    const raw = localStorage.getItem(HIDDEN_SOS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? new Set(parsed.filter((x): x is string => typeof x === "string")) : new Set();
  } catch {
    return new Set();
  }
}

export function persistHiddenSos(hiddenSos: Set<string>): void {
  localStorage.setItem(HIDDEN_SOS_KEY, JSON.stringify([...hiddenSos]));
}

export function functionRenameStorageKey(path: string): string {
  return `${FUNCTION_RENAMES_PREFIX}${path}`;
}

export function loadFunctionRenames(key: string): Map<string, string> {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return new Map();
    return new Map(
      Object.entries(parsed).filter(
        (entry): entry is [string, string] =>
          typeof entry[0] === "string" && typeof entry[1] === "string" && entry[1].trim().length > 0,
      ),
    );
  } catch {
    return new Map();
  }
}

export function saveFunctionRenames(key: string, renames: Map<string, string>): void {
  const serialized: Record<string, string> = {};
  for (const [id, name] of renames) {
    const trimmed = name.trim();
    if (trimmed) serialized[id] = trimmed;
  }
  try {
    if (Object.keys(serialized).length) localStorage.setItem(key, JSON.stringify(serialized));
    else localStorage.removeItem(key);
  } catch {
    /* ignore */
  }
}

export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}
