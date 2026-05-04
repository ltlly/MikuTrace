import { createSignal, createResource, For, Show } from "solid-js";

import { fetchLastWriteOfReg, fetchRecord } from "~/api/client";

interface RegistersPanelProps {
  idx: number;
  selectedReg: string;
  onSelectReg: (reg: string) => void;
  onSelect: (idx: number) => void;
  active: boolean;
}

const REG_ORDER = [
  "x0",
  "x1",
  "x2",
  "x3",
  "x4",
  "x5",
  "x6",
  "x7",
  "x8",
  "x9",
  "x10",
  "x11",
  "x12",
  "x13",
  "x14",
  "x15",
  "x16",
  "x17",
  "x18",
  "x19",
  "x20",
  "x21",
  "x22",
  "x23",
  "x24",
  "x25",
  "x26",
  "x27",
  "x28",
  "fp",
  "lr",
  "sp",
  "pc",
  "nzcv",
];

const REG_COLS_KEY = "tracemiku-reg-cols-v1";

interface RegCols {
  name: number;
  value: number;
  delta: number;
  note: number;
}

const DEFAULT_REG_COLS: RegCols = {
  name: 52,
  value: 150,
  delta: 76,
  note: 220,
};

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function initialRegCols(): RegCols {
  try {
    const raw = localStorage.getItem(REG_COLS_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return {
      name: clamp(Number(parsed.name) || DEFAULT_REG_COLS.name, 36, 120),
      value: clamp(Number(parsed.value) || DEFAULT_REG_COLS.value, 90, 320),
      delta: clamp(Number(parsed.delta) || DEFAULT_REG_COLS.delta, 48, 180),
      note: clamp(Number(parsed.note) || DEFAULT_REG_COLS.note, 100, 520),
    };
  } catch {
    return { ...DEFAULT_REG_COLS };
  }
}

function sortedRegs(regs: Record<string, string>): [string, string][] {
  const rank = new Map(REG_ORDER.map((reg, i) => [reg, i]));
  return Object.entries(regs).sort(([a], [b]) => {
    const ar = rank.get(a) ?? Number.MAX_SAFE_INTEGER;
    const br = rank.get(b) ?? Number.MAX_SAFE_INTEGER;
    if (ar !== br) return ar - br;
    return a.localeCompare(b);
  });
}

function prevValue(reg: string, prevRegs: Record<string, string> | undefined): string | undefined {
  if (!prevRegs) return undefined;
  return prevRegs[reg] ?? prevRegs[aliasReg(reg)];
}

function aliasReg(reg: string): string {
  if (reg === "fp") return "x29";
  if (reg === "lr") return "x30";
  if (reg === "x29") return "fp";
  if (reg === "x30") return "lr";
  return reg;
}

function regListHas(regs: string[] | undefined, reg: string): boolean {
  if (!regs) return false;
  const alias = aliasReg(reg);
  return regs.includes(reg) || regs.includes(alias);
}

function sameSelected(a: string, b: string): boolean {
  return a === b || aliasReg(a) === b || aliasReg(b) === a;
}

function parseHex(value: string | undefined): bigint | null {
  if (!value) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function regNote(reg: string, value: string, regs: Record<string, string>, changed: boolean): string {
  const n = parseHex(value);
  if (n === null) return changed ? "changed" : "";
  if (n === 0n) return "zero";
  if (reg === "pc") return "pc";
  if (reg === "sp") return changed ? "stack changed" : "stack";
  const sp = parseHex(regs.sp);
  if (sp !== null) {
    const diff = n > sp ? n - sp : sp - n;
    if (diff < 0x100000n) return changed ? "stack ptr changed" : "stack ptr";
  }
  if (n > 0x100000000n) return changed ? "ptr changed" : "ptr?";
  return changed ? "changed" : "";
}

function deltaNote(value: string, before: string | undefined): string {
  const now = parseHex(value);
  const prev = parseHex(before);
  if (now === null || prev === null || now === prev) return "";
  const diff = now > prev ? now - prev : prev - now;
  const sign = now > prev ? "+" : "-";
  return `${sign}${diff === 0n ? "0" : `0x${diff.toString(16)}`}`;
}

export default function RegistersPanel(props: RegistersPanelProps) {
  const initialCols = initialRegCols();
  const [nameW, setNameW] = createSignal(initialCols.name);
  const [valueW, setValueW] = createSignal(initialCols.value);
  const [deltaW, setDeltaW] = createSignal(initialCols.delta);
  const [noteW, setNoteW] = createSignal(initialCols.note);
  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );

  function saveCols() {
    localStorage.setItem(
      REG_COLS_KEY,
      JSON.stringify({ name: nameW(), value: valueW(), delta: deltaW(), note: noteW() }),
    );
  }

  function startResize(kind: keyof RegCols, e: PointerEvent) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const starts = {
      name: nameW(),
      value: valueW(),
      delta: deltaW(),
      note: noteW(),
    };
    document.body.classList.add("is-resizing");
    document.body.style.cursor = "col-resize";
    const onMove = (ev: PointerEvent) => {
      const w = starts[kind] + ev.clientX - startX;
      if (kind === "name") setNameW(clamp(w, 36, 120));
      else if (kind === "value") setValueW(clamp(w, 90, 320));
      else if (kind === "delta") setDeltaW(clamp(w, 48, 180));
      else setNoteW(clamp(w, 100, 520));
    };
    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.classList.remove("is-resizing");
      document.body.style.cursor = "";
      saveCols();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  async function jumpLastWrite(reg: string) {
    const r = await fetchLastWriteOfReg(props.idx, reg);
    if (r.idx !== null && r.idx !== undefined) props.onSelect(r.idx);
  }

  return (
    <section class="panel">
      <h2>Registers</h2>
      <Show when={record.error}>
        <p class="err">load failed: {String(record.error)}</p>
      </Show>
      <Show when={record.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={record()}>
        {(r) => (
          <>
            <dl class="kv selected-record">
              <dt>idx</dt>
              <dd>{r().idx}</dd>
              <dt>pc</dt>
              <dd>
                <code>{r().pc}</code>
              </dd>
              <dt>asm</dt>
              <dd>
                <code>{r().asm}</code>
              </dd>
            </dl>
            <table
              class="reg-table reg-diff-table"
              style={{
                "--reg-col-name": `${nameW()}px`,
                "--reg-col-value": `${valueW()}px`,
                "--reg-col-delta": `${deltaW()}px`,
                "--reg-col-note": `${noteW()}px`,
              }}
            >
              <thead>
                <tr>
                  <th>
                    reg
                    <span class="col-resize" onPointerDown={(e) => startResize("name", e)} />
                  </th>
                  <th>
                    value
                    <span class="col-resize" onPointerDown={(e) => startResize("value", e)} />
                  </th>
                  <th>
                    delta
                    <span class="col-resize" onPointerDown={(e) => startResize("delta", e)} />
                  </th>
                  <th>
                    note
                    <span class="col-resize" onPointerDown={(e) => startResize("note", e)} />
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={sortedRegs(r().regs)}>
                  {([reg, value]) => {
                    const before = () => prevValue(reg, r().prev_regs ?? undefined);
                    const changed = () => before() !== undefined && before() !== value;
                    const note = () => r().regs_annotated?.[reg] || regNote(reg, value, r().regs, changed());
                    return (
                      <tr
                        classList={{
                          changed: changed(),
                          selected: sameSelected(reg, props.selectedReg),
                          def: regListHas(r().regs_def, reg),
                          use: regListHas(r().regs_use, reg),
                        }}
                        onClick={() => props.onSelectReg(reg)}
                        onDblClick={() => void jumpLastWrite(reg)}
                        title="double-click to jump to last write"
                      >
                        <th>{reg}</th>
                        <td>
                          <code>{value}</code>
                        </td>
                        <td class="reg-delta">{deltaNote(value, before())}</td>
                        <td class="reg-note">{note()}</td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
    </section>
  );
}
