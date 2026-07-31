/**
 * Contract test: legacy agent must honor `maxRecords`.
 *
 * The host CLI always passes `maxRecords` in AGENT_OPTS. The modular agent
 * reads it (ring cap + watchdog finalize); the legacy single-file agent
 * silently ignored it, which violates the device-side capture boundary
 * (AGENTS.md: 设备端采集必须有明确记录上限). This test pins that the
 * legacy `init` parses and applies `opts.maxRecords`.
 *
 * Run: node tests/legacy_max_records_contract_test.ts
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const legacy = readFileSync(join(here, "../agent_cmodule_v5.js"), "utf8");

let failures = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}`);
  }
}

// 1) init() must read opts.maxRecords (host always sends it).
// Slice the init function via brace matching (rpc.exports precedes init in
// the file, so a plain indexOf split is wrong).
const initStart = legacy.indexOf("init(opts)");
let depth = 0;
let initEnd = legacy.indexOf("{", initStart);
while (initEnd < legacy.length) {
  if (legacy[initEnd] === "{") depth += 1;
  else if (legacy[initEnd] === "}") {
    depth -= 1;
    if (depth === 0) break;
  }
  initEnd += 1;
}
const initBody = legacy.slice(initStart, initEnd + 1);
check(
  "init reads opts.maxRecords",
  /opts\.maxRecords/.test(initBody),
);

// 2) The read value must flow into STATE (so the ring/watchdog can cap).
check(
  "maxRecords stored in STATE",
  /STATE\.maxRecords\s*=/.test(initBody) || /maxRecords\s*=\s*opts\.maxRecords/.test(initBody),
);

// 3) There must be a cap check that finalizes when maxRecords is reached
//    (not just stored — the capture boundary must actually stop).
check(
  "maxRecords cap enforced at runtime",
  /maxRecords\s*>\s*0\s*&&.*maxRecords/.test(legacy) || />=.*maxRecords/.test(legacy),
);

if (failures > 0) {
  console.error(`\n${failures} FAILED — legacy agent ignores maxRecords`);
  process.exit(1);
}
console.log("\nall legacy maxRecords contract holds");
