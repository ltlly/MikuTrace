import { createResource, For, Show } from "solid-js";

import { fetchRecord } from "~/api/client";

interface RegistersPanelProps {
  idx: number;
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

export default function RegistersPanel(props: RegistersPanelProps) {
  const [record] = createResource(() => props.idx, fetchRecord);

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
              <dd><code>{r().pc}</code></dd>
              <dt>asm</dt>
              <dd><code>{r().asm}</code></dd>
            </dl>
            <table class="reg-table">
              <tbody>
                <For each={sortedRegs(r().regs)}>
                  {([reg, value]) => (
                    <tr>
                      <th>{reg}</th>
                      <td><code>{value}</code></td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
    </section>
  );
}
