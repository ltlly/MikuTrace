export type LeftTab =
  | "funcs"
  | "back"
  | "calltree"
  | "forks"
  | "strings"
  | "taint"
  | "slice"
  | "xref"
  | "sofilter"
  | "settings"
  | "crypto";

export type RightTab = "cfg" | "regs" | "hlil";
export type BottomTab = "memory" | "navigation" | "trace-for-pc" | "string-provenance" | "query";
export type HelpTopic = "overview" | "left" | "disasm" | "right" | "bottom";
export type HelpState = { topic: HelpTopic; x: number; y: number };
export type CmdMode = "" | "/" | ":";
export type TaintRunDirection = "forward" | "backward";
export type MemoryRequest = { token: number; addr: string; count?: number };
export type TaintRunRequest = { token: number; idx: number; reg: string; direction: TaintRunDirection };

export interface LayoutState {
  leftW: number;
  rightW: number;
  bottomH: number;
  colDot: number;
  colIdx: number;
  colPc: number;
  colFunc: number;
  colAsm: number;
  syncCfg: boolean;
}
