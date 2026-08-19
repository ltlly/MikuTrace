import type { LeftTab, RightTab } from "./types";

const LEFT_TITLES: Record<LeftTab, string> = {
  funcs: "Functions",
  back: "Backtrace",
  calltree: "Call Tree",
  forks: "Forks",
  strings: "Strings",
  taint: "Taint",
  slice: "Slice",
  xref: "Refs",
  sofilter: "SO Filter",
  settings: "Settings",
  crypto: "Crypto",
};

const RIGHT_TITLES: Record<RightTab, string> = {
  cfg: "Graph",
  regs: "Registers",
  hlil: "BN HLIL",
};

export function leftTabTitle(tab: LeftTab): string {
  return LEFT_TITLES[tab];
}

export function rightTabTitle(tab: RightTab): string {
  return RIGHT_TITLES[tab];
}
