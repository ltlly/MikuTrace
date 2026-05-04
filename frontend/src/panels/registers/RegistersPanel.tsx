import { createMemo, createResource, For, Show } from "solid-js";

import { fetchRecord } from "~/api/client";

interface RegistersPanelProps {
  idx: number;
  selectedReg: string;
  onSelectReg: (reg: string) => void;
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

export default function RegistersPanel(props: RegistersPanelProps) {
  const [record] = createResource(() => props.idx, fetchRecord);
  const prevIdx = createMemo(() => (props.idx > 0 ? props.idx - 1 : 0));
  const [prevRecord] = createResource(prevIdx, fetchRecord);

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
                  <th>prev</th>
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
                      >
                        <th>{reg}</th>
                        <td>
                          <code>{value}</code>
                        </td>
                        <td>
                          <Show when={changed()} fallback={<span class="dim">same</span>}>
                            <code>{before()}</code>
                          </Show>
                        </td>
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
