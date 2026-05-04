import { createMemo, createResource, For, Show } from "solid-js";

import { fetchLastWriteOfReg, fetchRecord } from "~/api/client";

interface RegistersPanelProps {
  idx: number;
  selectedReg: string;
  onSelectReg: (reg: string) => void;
  onSelect: (idx: number) => void;
  active: boolean;
}

const REG_ORDER = [
  "pc",
  "sp",
  "lr",
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
  "x29",
  "x30",
];

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
  return prevRegs[reg];
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

export default function RegistersPanel(props: RegistersPanelProps) {
  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );
  const prevIdx = createMemo(() => (props.active ? (props.idx > 0 ? props.idx - 1 : 0) : undefined));
  const [prevRecord] = createResource(prevIdx, (idx) => fetchRecord(idx));

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
            <table class="reg-table reg-diff-table">
              <thead>
                <tr>
                  <th>reg</th>
                  <th>value</th>
                  <th>note</th>
                </tr>
              </thead>
              <tbody>
                <For each={sortedRegs(r().regs)}>
                  {([reg, value]) => {
                    const before = () => prevValue(reg, prevRecord()?.regs);
                    const changed = () => before() !== undefined && before() !== value;
                    return (
                      <tr
                        classList={{
                          changed: changed(),
                          selected: reg === props.selectedReg,
                        }}
                        onClick={() => props.onSelectReg(reg)}
                        onDblClick={() => void jumpLastWrite(reg)}
                        title="double-click to jump to last write"
                      >
                        <th>{reg}</th>
                        <td>
                          <code>{value}</code>
                        </td>
                        <td class="reg-note">{regNote(reg, value, r().regs, changed())}</td>
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
