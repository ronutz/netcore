// ============================================================================
// netcore/src/index.mjs
// ----------------------------------------------------------------------------
// THE ENGINE PUBLIC SURFACE  (@ronutz/netcore)
//
// WHY: One import surface for the brand-blind Engine. Services (GUI/CLI/host)
// consume ONLY what is exported here — they never reach into internal paths.
// This is the C-04 API boundary expressed at the module level and the C-60
// Engine/Services contract: everything here is brand-blind.
// ============================================================================

export { validateManifest, _security } from "./manifest/schema.mjs";
export { createRegistry } from "./registry.mjs";
export { createByoaiAdapter } from "./byoai/adapter.mjs";
export { runMigrations, MIGRATIONS } from "./migrations.mjs";

// The reference tool module, re-exported so Services/registry can load it.
export * as cidrTool from "./tools/cidr/index.mjs";
