// ============================================================================
// netcore/src/registry.mjs
// ----------------------------------------------------------------------------
// THE TOOL REGISTRY  (C-03 / C-21 — Seam 3)
//
// WHY: Tools are modules registered into a registry, so "tool #30 costs almost
// nothing" and the Store becomes possible later. The registry is also the
// enforcement point for the D-49 manifest contract: a module CANNOT register
// unless its manifest passes validateManifest(). This is what makes the
// manifest schema machine-checkable at the seam, not just on paper.
//
// The registry is brand-blind (C-60): it knows tool slugs and detectors, never
// branding, domain, or locale.
// ============================================================================

import { validateManifest } from "./manifest/schema.mjs";

/**
 * createRegistry — a small, explicit registry. No global singletons (testable).
 * @param {object} [opts] { goldenVectorSets: Set<string> } known vector sets,
 *        passed through to manifest validation so the goldenVectors linkage is checked.
 * @returns {object} registry API
 */
export function createRegistry(opts = {}) {
  const tools = new Map(); // toolSlug -> module
  const knownVectorSets = opts.goldenVectorSets ?? new Set();

  return {
    /**
     * register — add a tool module after validating its manifest.
     * @param {object} mod a module exporting { manifest, run }
     * @throws {Error} if the manifest is invalid (fails the D-49 gate)
     */
    register(mod) {
      if (!mod?.manifest || typeof mod.run !== "function") {
        throw new Error("module must export { manifest, run }");
      }
      const { ok, errors } = validateManifest(mod.manifest, { goldenVectorSets: knownVectorSets });
      if (!ok) {
        // Registration is the gate: a malformed manifest never enters the system.
        throw new Error(`manifest rejected for "${mod.manifest.toolSlug}":\n  - ${errors.join("\n  - ")}`);
      }
      tools.set(mod.manifest.toolSlug, mod);
      return mod.manifest.toolSlug;
    },

    /**
     * route — the omnibox core. Given raw pasted input, find the tool whose
     * inputDetectors match, highest priority first. DATA-DRIVEN: the registry
     * has no hardcoded knowledge of CIDR/IP/etc — it reads detectors.
     * @param {string} input pasted text
     * @returns {{slug:string, mod:object}|null}
     */
    route(input) {
      const candidates = [];
      for (const mod of tools.values()) {
        for (const d of mod.manifest.inputDetectors) {
          if (d.kind === "regex") {
            let re;
            try { re = new RegExp(d.pattern); } catch { continue; }
            if (re.test(String(input).trim())) {
              candidates.push({ slug: mod.manifest.toolSlug, mod, priority: d.priority ?? 0 });
            }
          }
          // format/heuristic detectors would dispatch to named handlers here.
        }
      }
      if (candidates.length === 0) return null;
      candidates.sort((a, b) => b.priority - a.priority);
      return { slug: candidates[0].slug, mod: candidates[0].mod };
    },

    /** get — fetch a registered tool by slug. */
    get(slug) {
      return tools.get(slug) ?? null;
    },

    /** list — all registered manifests (for catalogue/SEO/contributor views). */
    list() {
      return [...tools.values()].map((m) => m.manifest);
    },
  };
}
