//! CryptoPanel — combined crypto analysis display
//! Sub-tabs: Memory (MemShadow byte patterns), Instructions (trace const hits),
//! Hardware (ARM Crypto Extensions mnemonics)

import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { fetchCryptoAnalysis } from "~/api/client";
import type {
  CryptoMemPrimitive,
  FingerprintSummary,
  CryptoInstrHit,
  ConstHitVerdict,
} from "~/api/types";
import "./CryptoPanel.css";

interface CryptoPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

type SubTab = "memory" | "instructions" | "hardware";

const CATEGORY_COLORS: Record<string, string> = {
  hash: "#4a9eff",
  sym_cipher: "#ff6b6b",
  ecc: "#ffd93d",
  crc: "#6bcb77",
  mac: "#c084fc",
};

const VERDICT_COLORS: Record<ConstHitVerdict, string> = {
  real: "#2ecc71",
  real_simd: "#3498db",
  alu_only: "#e74c3c",
  weak: "#f39c12",
};

const VERDICT_LABELS: Record<ConstHitVerdict, string> = {
  real: "Real",
  real_simd: "SIMD",
  alu_only: "ALU",
  weak: "Weak",
};

function VerdictBadge(props: { v: ConstHitVerdict }) {
  return (
    <span
      class="verdict-badge"
      style={{ background: VERDICT_COLORS[props.v] }}
    >
      {VERDICT_LABELS[props.v]}
    </span>
  );
}

function inferAlg(name: string): string {
  if (name.startsWith("SHA1_")) return "SHA-1";
  if (name.startsWith("SHA256_")) return "SHA-256";
  if (name.startsWith("SHA512_")) return "SHA-512";
  if (name.startsWith("MD5_")) return "MD5";
  if (name.startsWith("AES_")) return "AES";
  if (name.startsWith("SM3_") || name.startsWith("SM4_")) return name.split("_")[0];
  if (name.startsWith("CHACHA20_")) return "ChaCha20";
  if (name.startsWith("HMAC_")) return "HMAC";
  if (name.startsWith("CRC32")) return "CRC32";
  if (name.startsWith("XXH")) return name.split("_")[0];
  if (name.startsWith("Murmur3")) return "Murmur3";
  return "";
}

export default function CryptoPanel(props: CryptoPanelProps) {
  const [subTab, setSubTab] = createSignal<SubTab>("memory");
  const [showAluOnly, setShowAluOnly] = createSignal(false);

  const [resp] = createResource(
    () => props.active,
    async (active) => {
      if (!active) return undefined;
      return fetchCryptoAnalysis();
    },
  );

  const summaryVerdict = createMemo(() => {
    const r = resp();
    if (!r) return "";
    const constHits = r.const_scan.summaries.filter(
      (s) => s.verdict === "real" || s.verdict === "real_simd",
    ).length;
    const hwHits = r.crypto_instrs.hits.length;
    if (constHits === 0 && hwHits === 0) return "None detected";
    if (constHits > 0 && hwHits === 0) return "Software Crypto";
    if (constHits === 0 && hwHits > 0) return "Hardware Crypto (ARM CE)";
    return "Mixed (HW + SW)";
  });

  const detectedAlgs = createMemo(() => {
    const r = resp();
    if (!r) return [];
    const algs: Record<string, number> = {};
    for (const s of r.const_scan.summaries) {
      if (s.total_hits > 0 && s.verdict !== "alu_only") {
        algs[s.alg] = (algs[s.alg] || 0) + s.total_hits;
      }
    }
    for (const h of r.crypto_instrs.hits) {
      algs[h.alg] = (algs[h.alg] || 0) + h.count;
    }
    return Object.entries(algs)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  });

  const filteredSummaries = createMemo(() => {
    const r = resp();
    if (!r) return [];
    return r.const_scan.summaries.filter(
      (s) => showAluOnly() || s.verdict !== "alu_only" || s.total_hits > 0,
    );
  });

  return (
    <section class="panel crypto-panel">
      <Show when={resp()}>
        <div class="crypto-summary">
          <span class="crypto-verdict">{summaryVerdict()}</span>
          <span class="crypto-algs">
            <For each={detectedAlgs()}>
              {([alg, count]) => (
                <span class="crypto-alg-tag" style={{ background: CATEGORY_COLORS[alg.toLowerCase()] || "#888" }}>
                  {alg}: {count}
                </span>
              )}
            </For>
          </span>
        </div>
      </Show>

      <div class="crypto-subtabs">
        <button classList={{ active: subTab() === "memory" }} onClick={() => setSubTab("memory")}>
          Memory
        </button>
        <button classList={{ active: subTab() === "instructions" }} onClick={() => setSubTab("instructions")}>
          Instructions
        </button>
        <button classList={{ active: subTab() === "hardware" }} onClick={() => setSubTab("hardware")}>
          Hardware
        </button>
      </div>

      <Show when={resp.loading}>
        <p class="dim">loading crypto analysis...</p>
      </Show>
      <Show when={resp.error}>
        <p class="err">failed: {String(resp.error)}</p>
      </Show>

      <Show when={resp()}>
        {(r) => (
          <>
            {/* Memory sub-tab */}
            <Show when={subTab() === "memory"}>
              <div class="crypto-table-wrap">
                <table class="crypto-table">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Pattern</th>
                      <th>Algorithm</th>
                      <th>First Idx</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().mem_scan.primitives.filter((p) => p.hit_count > 0)}>
                      {(p: CryptoMemPrimitive) => (
                        <For each={p.hits}>
                          {(hit) => (
                            <tr
                              class="clickable"
                              onClick={() => hit.first_idx != null && props.onSelect(hit.first_idx)}
                            >
                              <td class="mono">{hit.addr}</td>
                              <td>{p.name}</td>
                              <td>
                                <span
                                  class="alg-dot"
                                  style={{ background: "#888" }}
                                />
                                {inferAlg(p.name)}
                              </td>
                              <td class="mono">{hit.first_idx ?? "-"}</td>
                            </tr>
                          )}
                        </For>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>

            {/* Instructions sub-tab */}
            <Show when={subTab() === "instructions"}>
              <label class="crypto-toggle">
                <input
                  type="checkbox"
                  checked={showAluOnly()}
                  onChange={(e) => setShowAluOnly(e.currentTarget.checked)}
                />
                show ALU-only (high false-positive rate)
              </label>
              <div class="crypto-summary-list">
                <For each={filteredSummaries().filter((s) => s.total_hits > 0)}>
                  {(s: FingerprintSummary) => (
                    <div class="crypto-summary-row">
                      <span class="mono">{s.name}</span>
                      <span style={{ color: CATEGORY_COLORS[s.category] || "#888" }}>{s.alg}</span>
                      <VerdictBadge v={s.verdict} />
                      <span>{s.total_hits} hits</span>
                      <span class="dim">
                        first: {s.first_idx != null ? `#${s.first_idx}` : "-"}
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>

            {/* Hardware sub-tab */}
            <Show when={subTab() === "hardware"}>
              <div class="crypto-table-wrap">
                <table class="crypto-table">
                  <thead>
                    <tr>
                      <th>Mnemonic</th>
                      <th>Algorithm</th>
                      <th>Count</th>
                      <th>First Idx</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().crypto_instrs.hits}>
                      {(h: CryptoInstrHit) => (
                        <tr
                          class="clickable"
                          onClick={() => h.first_idx != null && props.onSelect(h.first_idx)}
                        >
                          <td class="mono">{h.mnemonic}</td>
                          <td>{h.alg}</td>
                          <td>{h.count}</td>
                          <td class="mono">{h.first_idx ?? "-"}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
              <Show when={r().crypto_instrs.hits.length === 0}>
                <p class="dim">No ARM Crypto Extensions instructions detected.</p>
              </Show>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
