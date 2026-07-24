import type { CfgDebugState, CursorRecordHint } from "../panels/cfg/CfgPanel";

interface DebugOverlayProps {
  selectedIdx: number;
  cursorHint?: CursorRecordHint;
  selectedFn: string;
  selectedReg: string;
  tabs: string;
  syncCfg: boolean;
  cfgDebugState: CfgDebugState | null;
  cfgDisplayFn: string;
  rowHintCacheSize: number;
  apiDebug: boolean;
  onApiDebugChange: (next: boolean) => void;
  onClose: () => void;
}

export default function DebugOverlay(props: DebugOverlayProps) {
  return (
    <div class="debug-overlay">
      <div class="debug-row"><span>selectedIdx</span><code>{props.selectedIdx}</code></div>
      <div class="debug-row"><span>cursorHint.idx</span><code>{props.cursorHint?.idx ?? "—"}</code></div>
      <div class="debug-row"><span>cursorHint.pc</span><code>{props.cursorHint?.pc ?? "—"}</code></div>
      <div class="debug-row"><span>cursorHint.func</span><code>{props.cursorHint?.func ?? "—"}</code></div>
      <div class="debug-row"><span>selectedFn</span><code>{props.selectedFn || "—"}</code></div>
      <div class="debug-row"><span>selectedReg</span><code>{props.selectedReg}</code></div>
      <div class="debug-row"><span>tabs</span><code>{props.tabs}</code></div>
      <div class="debug-row"><span>syncCfg</span><code>{props.syncCfg ? "on" : "off"}</code></div>
      <div class="debug-row"><span>cfg.fnName</span><code>{props.cfgDebugState?.fnName || props.cfgDisplayFn || "—"}</code></div>
      <div class="debug-row"><span>cfg.lastGraphFn</span><code>{props.cfgDebugState?.lastGraphFn || "—"}</code></div>
      <div class="debug-row"><span>cfg.loading</span><code>{props.cfgDebugState?.loading ? "yes" : "no"}</code></div>
      <div class="debug-row"><span>cfg.graphSeq</span><code>{props.cfgDebugState?.graphSeq ?? 0}</code></div>
      <div class="debug-row"><span>rowHintCache</span><code>{props.rowHintCacheSize} entries</code></div>
      <label class="debug-row debug-toggle">
        <input
          type="checkbox"
          checked={props.apiDebug}
          onChange={(event) => props.onApiDebugChange(event.currentTarget.checked)}
        />
        <span>log API calls (console)</span>
      </label>
      <button
        type="button"
        class="debug-close"
        onClick={props.onClose}
        title="hide overlay (state persists; toggle with topbar dbg button)"
      >
        close
      </button>
    </div>
  );
}
