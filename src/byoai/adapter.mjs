// ============================================================================
// netcore/src/byoai/adapter.mjs
// ----------------------------------------------------------------------------
// BYOAI — BRING YOUR OWN AI  (C-53 — Seam 5)
//
// WHY this shape matters (a 2026 principle, "a principle, not a feature"):
//   - The AI-assist layer is a PROVIDER-AGNOSTIC adapter, never wired to one vendor.
//   - The user's key is stored LOCALLY and the request goes client→provider DIRECT:
//     the provider never sees ARSENAL; ARSENAL never sees the key or the data.
//   - Critically for the seam: the assist call is ADVISORY. It must VISIBLY NOT
//     write the deterministic result panel. The deterministic answer (e.g. the
//     CIDR computation) is the source of truth; AI may annotate, never overwrite.
//
// In this rehearsal we don't call a real provider; we model the adapter's
// CONTRACT and prove the separation holds: deterministic result is computed by
// netcore, the assist is a separate, clearly-labelled, non-authoritative field.
// ============================================================================

/**
 * createByoaiAdapter — builds an adapter around a user-supplied transport.
 *
 * @param {object} cfg
 *   @param {function} cfg.transport  async ({endpoint, apiKey, body}) => text
 *          The caller supplies HOW the request reaches the provider (fetch in
 *          the browser, direct). netcore never embeds a provider URL or key.
 *   @param {string}   cfg.providerLabel  e.g. "openai" | "anthropic" | "ollama"
 * @returns {object} adapter
 */
export function createByoaiAdapter(cfg) {
  if (typeof cfg?.transport !== "function") {
    throw new Error("BYOAI requires a caller-supplied transport (client→provider direct)");
  }
  // The key is held by the CALLER's transport closure, not by netcore. We never
  // store, log, or forward it. This local variable exists only to assert that
  // netcore itself holds nothing sensitive.
  const providerLabel = cfg.providerLabel ?? "unknown";

  return {
    providerLabel,

    /**
     * assist — request an OPTIONAL natural-language annotation for a result.
     *
     * The returned object separates `deterministic` (passed straight through,
     * untouched) from `assist` (advisory text). The caller renders them in
     * different panels; the deterministic panel is never sourced from `assist`.
     *
     * @param {object} args
     *   @param {object} args.deterministicResult  the netcore result (authoritative)
     *   @param {string} args.prompt               what to ask about it
     *   @param {object} args.providerConn         { endpoint, apiKey } held by caller
     * @returns {Promise<{deterministic:object, assist:string, assistIsAuthoritative:boolean}>}
     */
    async assist({ deterministicResult, prompt, providerConn }) {
      // Defensive copy so the adapter physically cannot mutate the authoritative
      // result even by accident — the separation is structural, not just polite.
      const deterministic = structuredClone(deterministicResult);

      let assist = "";
      try {
        assist = await cfg.transport({
          endpoint: providerConn?.endpoint,
          apiKey: providerConn?.apiKey, // flows caller→provider; netcore never inspects it
          body: { prompt, context: deterministic },
        });
      } catch (e) {
        // If assist fails, the deterministic answer is UNAFFECTED — that is the
        // whole point: AI-compatible, not AI-dependent.
        assist = `「assist unavailable: ${e.message}」`;
      }

      return {
        deterministic, // byte-identical to input result
        assist, // advisory only
        assistIsAuthoritative: false, // ALWAYS false — the seam invariant
      };
    },
  };
}
