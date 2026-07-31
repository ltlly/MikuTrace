// Shared numeric helpers used across panels.
//
// clamps were copy-pasted in recordsModel / RegistersPanel / persistence;
// this is the single implementation.

export function clamp(value: number, lower: number, upper: number): number {
  return Math.min(upper, Math.max(lower, value));
}
