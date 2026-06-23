// ============================================================================
// netcore/src/migrations.mjs
// ----------------------------------------------------------------------------
// SCHEMA VERSIONING + MIGRATIONS  (C-16 — Seam 7)
//
// WHY: Every persisted schema is versioned with a migration path. Without this,
// later changes corrupt or lose user data. The seam only needs to prove a
// no-op migration runs CLEAN and that the framework has no data-corruption path
// (it advances a version pointer; it never destructively rewrites on failure).
//
// Design: migrations are an ORDERED, append-only list. Each has a `from`→`to`
// version and a pure `up(state)` returning NEW state (never mutates input).
// ============================================================================

/**
 * The migration ledger. Append-only. For the rehearsal we ship a single no-op
 * (v0 → v1) that returns the state unchanged except for the version stamp.
 */
export const MIGRATIONS = Object.freeze([
  {
    from: 0,
    to: 1,
    name: "init-noop",
    /**
     * up — the no-op migration. Returns a NEW object (immutability) and never
     * throws on well-formed state, so there is no partial-write corruption path.
     * @param {object} state prior persisted state
     * @returns {object} migrated state
     */
    up(state) {
      return { ...state, _schemaVersion: 1 };
    },
  },
]);

/**
 * runMigrations — advance state from its current version to the target.
 *
 * Last-known-good discipline: if any step throws, we STOP and return the last
 * successfully-migrated state plus the error — we never leave state half-written.
 *
 * @param {object} state initial state (may carry `_schemaVersion`, default 0)
 * @param {number} [target] target version (default: latest)
 * @returns {{state:object, appliedTo:number, error:(string|null)}}
 */
export function runMigrations(state = {}, target = undefined) {
  const latest = MIGRATIONS.reduce((m, x) => Math.max(m, x.to), 0);
  const goal = target ?? latest;
  let current = { ...state };
  let version = current._schemaVersion ?? 0;

  for (const m of MIGRATIONS) {
    if (m.from === version && m.to <= goal) {
      try {
        const next = m.up(current);
        current = next;
        version = m.to;
      } catch (e) {
        // Last-known-good: return the state as it stood BEFORE the failed step.
        return { state, appliedTo: version, error: `migration ${m.name} failed: ${e.message}` };
      }
    }
  }
  return { state: current, appliedTo: version, error: null };
}
