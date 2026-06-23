// ============================================================================
// test/run-tests.mjs
// ----------------------------------------------------------------------------
// netcore TEST SUITE  (what `npm test` runs)
//
// WHY: A single entry point that exercises the Engine end-to-end with Node's
// built-in assert — no test framework, so the open repo stays dependency-free
// and the proofs are self-evident. Covers: the CIDR tool's behavior, the
// registry's declarative load + omnibox routing, the D-49 manifest gate
// (accepting good manifests and REJECTING bad ones), the BYOAI separation,
// and the migration safety. Exits non-zero on any failure so CI can block merge.
// ============================================================================

import assert from "node:assert/strict";

import { validateManifest, createRegistry, createByoaiAdapter, runMigrations } from "../src/index.mjs";
import * as cidrTool from "../src/tools/cidr/index.mjs";
import {
  CIDR_GOLDEN_VECTORS,
  CIDR_REJECT_VECTORS,
  GOLDEN_VECTOR_SET_ID,
} from "../src/tools/cidr/index.mjs";

let passed = 0;
let failed = 0;
const lines = [];
async function check(label, fn) {
  try {
    await fn();
    lines.push(`  PASS ${label}`);
    passed++;
  } catch (e) {
    lines.push(`  FAIL ${label}\n       -> ${e.message.split("\n").join("\n       ")}`);
    failed++;
  }
}

console.log("\n=== @ronutz/netcore — TEST SUITE ===\n");

// --- CIDR tool correctness ---
await check("cidr: all golden vectors match", () => {
  for (const v of CIDR_GOLDEN_VECTORS) {
    assert.deepEqual(cidrTool.run(v.input), v.expect, `vector "${v.name}"`);
  }
});
await check("cidr: malformed input is rejected (fails loud)", () => {
  for (const bad of CIDR_REJECT_VECTORS) {
    assert.throws(() => cidrTool.run(bad), `should reject "${bad}"`);
  }
});

// --- Registry: declarative load + data-driven omnibox routing ---
await check("registry: tool registers and routes pasted input via inputDetectors", () => {
  const reg = createRegistry({ goldenVectorSets: new Set([GOLDEN_VECTOR_SET_ID]) });
  reg.register(cidrTool);
  const routed = reg.route("192.168.1.0/24");
  assert.ok(routed, "omnibox must route a pasted CIDR");
  assert.equal(routed.slug, "cidr");
});

// --- D-49 manifest gate: accepts good, REJECTS bad ---
await check("manifest: the CIDR manifest is valid", () => {
  const { ok, errors } = validateManifest(cidrTool.manifest, {
    goldenVectorSets: new Set([GOLDEN_VECTOR_SET_ID]),
  });
  assert.ok(ok, `manifest should be valid: ${errors.join("; ")}`);
});
await check("manifest: rejects a tool missing executionClass", () => {
  const bad = { ...cidrTool.manifest, executionClass: [] };
  assert.equal(validateManifest(bad).ok, false);
});
await check("manifest: rejects a networkEgress tool with no SSRF posture", () => {
  const bad = { ...cidrTool.manifest, toolSlug: "x", executionClass: ["networkEgress"], dangerousInputHandling: [] };
  const { ok, errors } = validateManifest(bad, { goldenVectorSets: new Set([GOLDEN_VECTOR_SET_ID]) });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => e.includes("ssrf")));
});
await check("manifest: rejects a sensitiveArtifact tool that is not fragment-or-stricter", () => {
  const bad = { ...cidrTool.manifest, toolSlug: "x", executionClass: ["sensitiveArtifact"], shareSafetyDefault: "safe" };
  const { ok, errors } = validateManifest(bad, { goldenVectorSets: new Set([GOLDEN_VECTOR_SET_ID]) });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => e.includes("'fragment' or stricter")));
});
await check("manifest: rejects raw HTML in metadata", () => {
  const bad = { ...cidrTool.manifest, toolSlug: "x", sources: [{ id: "s", label: "<script>x</script>", type: "rfc", access_date: "2026-06-23" }] };
  assert.equal(validateManifest(bad).ok, false);
});
await check("manifest: rejects non-https source URLs", () => {
  const bad = { ...cidrTool.manifest, toolSlug: "x", sources: [{ id: "s", type: "rfc", url: "http://insecure.example", access_date: "2026-06-23" }] };
  const { ok } = validateManifest(bad, { goldenVectorSets: new Set([GOLDEN_VECTOR_SET_ID]) });
  assert.equal(ok, false);
});

// --- BYOAI: assist is never authoritative ---
await check("byoai: assist does not alter the deterministic result", async () => {
  const deterministic = cidrTool.run("192.168.1.0/24");
  const adapter = createByoaiAdapter({ transport: async () => "advisory note" });
  const out = await adapter.assist({ deterministicResult: deterministic, prompt: "x", providerConn: {} });
  assert.deepEqual(out.deterministic, deterministic);
  assert.equal(out.assistIsAuthoritative, false);
});

// --- Migrations: safe + immutable ---
await check("migrations: no-op runs clean and does not mutate input", () => {
  const original = { data: "keep" };
  const { state, error } = runMigrations(original, 1);
  assert.equal(error, null);
  assert.equal(original._schemaVersion, undefined, "input must not be mutated");
  assert.equal(state._schemaVersion, 1);
});

console.log(lines.join("\n"));
console.log(`\n=== ${passed} passed, ${failed} failed ===\n`);
process.exit(failed === 0 ? 0 : 1);
