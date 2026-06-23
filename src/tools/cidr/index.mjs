// ============================================================================
// netcore/src/tools/cidr/index.mjs
// ----------------------------------------------------------------------------
// THE SELF-DESCRIBING CIDR MODULE  (C-03 registry unit + D-49 manifest)
//
// WHY: A netcore tool is not just its compute function — it is a {manifest,
// run, vectors} triple that the registry loads DECLARATIVELY (C-03/C-21).
// The manifest below is a real, schema-valid D-49 manifest: the validator in
// ../../manifest/schema.mjs accepts it, and the omnibox would route a pasted
// "192.168.1.0/24" to this tool purely from its inputDetectors[].
// ============================================================================

import { computeCidr } from "./compute.mjs";
import { GOLDEN_VECTOR_SET_ID, CIDR_GOLDEN_VECTORS, CIDR_REJECT_VECTORS } from "./golden-vectors.mjs";

// Re-export the vector-set metadata by name so consumers importing this module
// at the package boundary (@ronutz/netcore/tools/cidr) can read them directly.
// WHY: the hosted endpoint and CI need the set id to wire goldenVectorSets.
export { GOLDEN_VECTOR_SET_ID, CIDR_GOLDEN_VECTORS, CIDR_REJECT_VECTORS } from "./golden-vectors.mjs";

// The D-49 declarative manifest for this tool. Every field here is checked by
// validateManifest(); this is the worked example the C-82…C-87 seams generalize.
export const manifest = Object.freeze({
  // -- Identity & routing --
  toolFamily: "Addressing & L2", // §8.A
  toolSlug: "cidr",
  canonicalAliases: ["subnet", "ip-cidr"], // 301'd to canonical (D-27 alias layer)
  inputDetectors: [
    {
      // This regex is what makes omnibox routing data-driven: paste a CIDR and
      // it is auto-detected. The example MUST match the pattern (CI asserts it).
      kind: "regex",
      pattern: "^\\d{1,3}(\\.\\d{1,3}){3}\\/\\d{1,2}$",
      priority: 10,
      example: "192.168.1.0/24",
    },
  ],

  // -- Capability & execution --
  capabilityBadge: "browser", // 🟢 runs client-side
  executionClass: ["localOnly"], // pure arithmetic, never leaves the device
  apiCapabilityClass: "local-equivalent",

  // -- Correctness & security --
  goldenVectors: GOLDEN_VECTOR_SET_ID, // resolves to an existing set (CI-checked)
  dangerousInputHandling: ["redos-guard"], // bounded regex; no catastrophic backtracking
  shareSafetyDefault: "safe", // CIDR input is not sensitive → clean SEO-visible path

  // -- Teaching & provenance --
  learnLinks: ["learn/subnetting-basics"], // D-27.j Tools↔Learn
  sources: [
    {
      id: "rfc4632",
      label: "RFC 4632 — CIDR",
      type: "rfc",
      url: "https://www.rfc-editor.org/rfc/rfc4632",
      access_date: "2026-06-23",
      scope: "address aggregation + prefix arithmetic",
      status: "active",
    },
    {
      id: "rfc3021",
      label: "RFC 3021 — /31 on point-to-point links",
      type: "rfc",
      url: "https://www.rfc-editor.org/rfc/rfc3021",
      access_date: "2026-06-23",
      scope: "/31 host accounting",
      status: "active",
    },
  ],
  credits: [
    { handle: "ronutz", display_name: "Rodolfo Nützmann", role: "implementation", public: true },
  ],
  license: { code: "Apache-2.0", content: "CC-BY-4.0" },
});

/**
 * run — the registry-facing entry point. The registry calls this; it does not
 * reach into compute.mjs directly. Same function in-browser and hosted (Seam 1).
 * @param {string} input a CIDR string
 * @returns {object} the deterministic result
 */
export function run(input) {
  return computeCidr(input);
}

// Re-export vectors so the golden-vector CI runner can find them via the module.
export const goldenVectors = CIDR_GOLDEN_VECTORS;
export const rejectVectors = CIDR_REJECT_VECTORS;
