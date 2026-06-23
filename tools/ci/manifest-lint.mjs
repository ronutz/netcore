// ============================================================================
// tools/ci/manifest-lint.mjs
// ----------------------------------------------------------------------------
// D-49 MANIFEST LINT  (the CI gate for the tool-registry, C-82…C-87)
//
// WHY: Every netcore tool module carries one declarative D-49 manifest. This
// gate loads every tool and asserts its manifest passes validateManifest():
//   - capabilityBadge + executionClass required
//   - networkEgress ⇒ must declare the SSRF posture
//   - sensitiveArtifact ⇒ shareSafetyDefault fragment-or-stricter
//   - inputDetectors examples must match their own patterns
//   - goldenVectors must resolve to an existing set
//   - NO unsafe URLs / NO raw HTML in metadata
// CI runs this on every push; a malformed manifest blocks merge. Exits non-zero
// on any failure.
// ============================================================================

import { validateManifest } from "../../src/manifest/schema.mjs";
import * as cidrTool from "../../src/tools/cidr/index.mjs";
import { GOLDEN_VECTOR_SET_ID } from "../../src/tools/cidr/index.mjs";

// Known golden-vector sets in this repo. As tools are added, register their set
// ids here (or, later, discover them by scanning src/tools/*/golden-vectors.mjs).
const KNOWN_VECTOR_SETS = new Set([GOLDEN_VECTOR_SET_ID]);

// Every tool module that ships in this repo.
const TOOL_MODULES = [cidrTool];

let failures = 0;
console.log("\n=== D-49 MANIFEST LINT ===\n");
for (const mod of TOOL_MODULES) {
  const { ok, errors } = validateManifest(mod.manifest, { goldenVectorSets: KNOWN_VECTOR_SETS });
  if (ok) {
    console.log(`  OK   ${mod.manifest.toolSlug}: manifest valid`);
  } else {
    failures++;
    console.log(`  FAIL ${mod.manifest.toolSlug}: ${errors.length} error(s)`);
    errors.forEach((e) => console.log(`         - ${e}`));
  }
}
console.log(`\n=== MANIFEST LINT: ${TOOL_MODULES.length - failures}/${TOOL_MODULES.length} valid ===\n`);
process.exit(failures === 0 ? 0 : 1);
