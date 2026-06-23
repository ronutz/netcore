// ============================================================================
// tools/ci/golden-vectors.mjs
// ----------------------------------------------------------------------------
// GOLDEN-VECTOR GATE  (D-1 / D-49 / Protocol v2.0 §10.13.2)
//
// WHY: "It runs" is not "it is correct." No tool ships unless its golden-vector
// set (RFC/IANA/IEEE-derived) EXISTS and PASSES. This runs each tool's positive
// vectors (output must match exactly) and reject vectors (malformed input MUST
// throw — a security tool fails loud, never silently coerces). CI runs this on
// every push; a red result blocks merge. Exits non-zero on any miss.
// ============================================================================

import assert from "node:assert/strict";
// Relative imports: in this standalone repo the code IS the repo (no package alias).
import * as cidrTool from "../../src/tools/cidr/index.mjs";
import { CIDR_GOLDEN_VECTORS, CIDR_REJECT_VECTORS } from "../../src/tools/cidr/index.mjs";

// Each suite under test: { slug, run, golden, reject }.
const SUITES = [
  {
    slug: "cidr",
    run: cidrTool.run,
    golden: CIDR_GOLDEN_VECTORS,
    reject: CIDR_REJECT_VECTORS,
  },
];

let failures = 0;
console.log("\n=== GOLDEN-VECTOR GATE ===\n");
for (const s of SUITES) {
  let ok = 0;
  // Positive vectors must match the expected result exactly.
  for (const v of s.golden) {
    try {
      assert.deepEqual(s.run(v.input), v.expect);
      ok++;
    } catch (e) {
      failures++;
      console.log(`  FAIL ${s.slug} "${v.name}": ${e.message.split("\n")[0]}`);
    }
  }
  // Reject vectors must throw.
  for (const bad of s.reject) {
    try {
      s.run(bad);
      failures++;
      console.log(`  FAIL ${s.slug} reject "${bad}": expected a throw, got a result`);
    } catch {
      ok++;
    }
  }
  console.log(`  OK   ${s.slug}: ${ok}/${s.golden.length + s.reject.length} vectors pass`);
}
console.log(`\n=== GOLDEN VECTORS: ${failures === 0 ? "ALL PASS" : failures + " FAILED"} ===\n`);
process.exit(failures === 0 ? 0 : 1);
