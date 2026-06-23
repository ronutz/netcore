// ============================================================================
// netcore/src/manifest/schema.mjs
// ----------------------------------------------------------------------------
// THE D-49 TOOL-MODULE MANIFEST CONTRACT  (Arch Spec §9.1, v1.6)
//
// WHY THIS FILE IS LOAD-BEARING:
//   Every `netcore` tool module carries ONE declarative, brand-blind manifest.
//   That manifest is the single source for (a) OMNIBOX input routing,
//   (b) the egress/privacy classifier, (c) the golden-vector correctness bind,
//   and (d) the share-safety permalink posture. The Build Conformance Gate
//   (Protocol v2.0 §10.13) is machine-checkable ONLY because this schema is.
//
//   This validator is what Seam 3 (manifest/registry) and the C-82…C-87
//   tool-registry seams assert in CI. It encodes the literal §9.1 CI rules:
//     - every tool declares capabilityBadge AND executionClass
//     - every networkEgress tool declares dangerousInputHandling incl. SSRF posture
//     - every sensitiveArtifact tool declares shareSafetyDefault: fragment or stricter
//     - every inputDetectors[] entry compiles and carries >=1 passing example
//     - goldenVectors resolves to an existing vector set
//     - NO unsafe URLs / NO raw HTML in any metadata (RB-01/RB-05)
// ============================================================================

// --- Controlled vocabularies (verbatim from Arch Spec §9.1) -----------------

// D8 capability badge: where the tool actually runs.
export const CAPABILITY_BADGES = Object.freeze(["browser", "cloud", "desktop"]);

// The canonical egress/privacy classifier. A tool may carry one or more.
//   localOnly         — pure client-side, never leaves the device
//   networkEgress     — touches the network (DNS/WHOIS/ping/SMTP/HTTP/live-TLS…)
//   sensitiveArtifact — ingests artifacts that commonly carry secrets/PII
export const EXECUTION_CLASSES = Object.freeze([
  "localOnly",
  "networkEgress",
  "sensitiveArtifact",
]);

// The metering classes — referenced here so the manifest is the single source.
export const API_CAPABILITY_CLASSES = Object.freeze([
  "local-equivalent",
  "hosted-compute",
  "network-egress",
  "premium",
  "partner",
]);

// Default result-permalink posture (privacy-aware permalink policy).
//   safe             — clean, SEO-visible path
//   fragment         — sensitive input → URL fragment, never transmitted
//   noindex-with-data— result-with-data URLs noindex + a second opt-in
export const SHARE_SAFETY = Object.freeze(["safe", "fragment", "noindex-with-data"]);

// Hardening postures for hostile input (maps to RB-01/02/05).
export const DANGEROUS_INPUT_POSTURES = Object.freeze([
  "parse-in-worker-no-dom",
  "ssrf-denylist-resolved-ip",
  "secret-redaction",
  "redos-guard",
]);

// Allowed source-metadata types (provenance subset, §9.1).
export const SOURCE_TYPES = Object.freeze([
  "standard", "rfc", "iana", "ieee", "w3c", "nist", "owasp", "mitre",
  "vendor-doc", "academic", "internal-test-vector",
]);

// inputDetectors[] matcher kinds.
export const DETECTOR_KINDS = Object.freeze(["regex", "format", "heuristic"]);

// "fragment or stricter" — anything at least as private as a URL fragment.
// safe is LESS strict (data can sit in an indexable path), so it is excluded.
const SHARE_SAFETY_FRAGMENT_OR_STRICTER = Object.freeze(["fragment", "noindex-with-data"]);

// --- Security primitives: no unsafe URLs, no raw HTML (RB-01 / RB-05) -------

// Only https:// links are permitted in any manifest metadata. Anything else
// (http, javascript:, data:, mailto-with-payload, protocol-relative //) is rejected.
function isSafeHttpsUrl(value) {
  if (typeof value !== "string") return false;
  let u;
  try {
    u = new URL(value);
  } catch {
    return false; // not a parseable absolute URL → reject (no protocol-relative)
  }
  return u.protocol === "https:";
}

// Raw-HTML smell test. Manifest metadata is rendered ESCAPED as text only;
// the presence of angle-bracket tags or an on*= handler is a hard reject so
// nothing can smuggle markup into the SourceList / chips.
const RAW_HTML_RE = /<[a-z!\/][\s\S]*?>|on\w+\s*=/i;
function containsRawHtml(value) {
  return typeof value === "string" && RAW_HTML_RE.test(value);
}

// Walk every string in the manifest and collect raw-HTML violations.
function collectRawHtmlViolations(node, path, out) {
  if (typeof node === "string") {
    if (containsRawHtml(node)) out.push(`${path}: contains raw HTML / event handler ("${node.slice(0, 40)}")`);
  } else if (Array.isArray(node)) {
    node.forEach((v, i) => collectRawHtmlViolations(v, `${path}[${i}]`, out));
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) collectRawHtmlViolations(v, `${path}.${k}`, out);
  }
}

/**
 * validateManifest — the machine-checkable D-49 gate.
 *
 * @param {object} m        a tool-module manifest
 * @param {object} [ctx]    optional context: { goldenVectorSets: Set<string> }
 *                          so "goldenVectors resolves to an existing set" is checkable.
 * @returns {{ok: boolean, errors: string[]}}
 *
 * Pure and side-effect-free: returns a verdict, never throws on bad data.
 */
export function validateManifest(m, ctx = {}) {
  const errors = [];
  const knownVectorSets = ctx.goldenVectorSets ?? new Set();

  if (!m || typeof m !== "object") {
    return { ok: false, errors: ["manifest is not an object"] };
  }

  // -- Identity & routing ----------------------------------------------------
  if (!m.toolSlug || typeof m.toolSlug !== "string") {
    errors.push("toolSlug: required, single canonical flat slug (D-27)");
  } else if (!/^[a-z0-9][a-z0-9-]*$/.test(m.toolSlug)) {
    errors.push(`toolSlug "${m.toolSlug}": must be a flat lowercase slug (D-27)`);
  }
  if (!m.toolFamily || typeof m.toolFamily !== "string") {
    errors.push("toolFamily: required (catalogue family §8 A–T)");
  }

  // inputDetectors[] — the field that makes omnibox routing DATA-DRIVEN.
  // CI rule: every entry compiles AND carries at least one passing example.
  if (!Array.isArray(m.inputDetectors) || m.inputDetectors.length === 0) {
    errors.push("inputDetectors[]: required, >=1 ordered matcher (drives omnibox routing)");
  } else {
    m.inputDetectors.forEach((d, i) => {
      const at = `inputDetectors[${i}]`;
      if (!DETECTOR_KINDS.includes(d?.kind)) {
        errors.push(`${at}.kind: must be one of ${DETECTOR_KINDS.join("|")}`);
      }
      if (typeof d?.example !== "string" || d.example.length === 0) {
        errors.push(`${at}.example: required (>=1 example per detector)`);
        return;
      }
      // "compiles AND the example passes": for regex detectors we actually
      // compile the pattern and assert it matches its own example.
      if (d.kind === "regex") {
        let re;
        try {
          re = new RegExp(d.pattern);
        } catch {
          errors.push(`${at}.pattern: regex does not compile`);
          return;
        }
        if (!re.test(d.example)) {
          errors.push(`${at}: example "${d.example}" does not match its own pattern`);
        }
      }
      // format/heuristic detectors carry a named handler at runtime; here we
      // only require the example to be present (handler resolution is the
      // registry's job, exercised by the golden vectors).
    });
  }

  // -- Capability & execution -----------------------------------------------
  // CI rule: every tool declares a capabilityBadge AND an executionClass.
  if (!CAPABILITY_BADGES.includes(m.capabilityBadge)) {
    errors.push(`capabilityBadge: required, one of ${CAPABILITY_BADGES.join("|")}`);
  }
  const execClasses = Array.isArray(m.executionClass) ? m.executionClass : [m.executionClass];
  if (execClasses.length === 0 || !execClasses.every((c) => EXECUTION_CLASSES.includes(c))) {
    errors.push(`executionClass: required, each of ${EXECUTION_CLASSES.join("|")}`);
  }
  if (m.apiCapabilityClass !== undefined && !API_CAPABILITY_CLASSES.includes(m.apiCapabilityClass)) {
    errors.push(`apiCapabilityClass: if set, one of ${API_CAPABILITY_CLASSES.join("|")}`);
  }

  const isNetworkEgress = execClasses.includes("networkEgress");
  const isSensitive = execClasses.includes("sensitiveArtifact");

  // -- Correctness & security -----------------------------------------------
  // CI rule: goldenVectors resolves to an existing vector set.
  if (!m.goldenVectors || typeof m.goldenVectors !== "string") {
    errors.push("goldenVectors: required (binds D1 correctness to the manifest)");
  } else if (knownVectorSets.size > 0 && !knownVectorSets.has(m.goldenVectors)) {
    errors.push(`goldenVectors "${m.goldenVectors}": does not resolve to an existing vector set`);
  }

  // CI rule: every networkEgress tool declares dangerousInputHandling
  //          INCLUDING the SSRF posture.
  if (isNetworkEgress) {
    const dih = Array.isArray(m.dangerousInputHandling) ? m.dangerousInputHandling : [];
    if (!dih.includes("ssrf-denylist-resolved-ip")) {
      errors.push("dangerousInputHandling: networkEgress tool MUST declare 'ssrf-denylist-resolved-ip' (RB-02)");
    }
  }
  // Any declared posture must be from the controlled vocabulary.
  if (m.dangerousInputHandling !== undefined) {
    if (!Array.isArray(m.dangerousInputHandling)) {
      errors.push("dangerousInputHandling: must be an array of postures");
    } else {
      m.dangerousInputHandling.forEach((p, i) => {
        if (!DANGEROUS_INPUT_POSTURES.includes(p)) {
          errors.push(`dangerousInputHandling[${i}] "${p}": unknown posture`);
        }
      });
    }
  }

  // CI rule: every sensitiveArtifact tool declares shareSafetyDefault
  //          'fragment' or stricter.
  if (m.shareSafetyDefault !== undefined && !SHARE_SAFETY.includes(m.shareSafetyDefault)) {
    errors.push(`shareSafetyDefault "${m.shareSafetyDefault}": must be one of ${SHARE_SAFETY.join("|")}`);
  }
  if (isSensitive) {
    if (!SHARE_SAFETY_FRAGMENT_OR_STRICTER.includes(m.shareSafetyDefault)) {
      errors.push("shareSafetyDefault: sensitiveArtifact tool MUST be 'fragment' or stricter");
    }
  }

  // -- Provenance: sources / credits / license ------------------------------
  // All metadata is text-only; links must be safe https. (RB-01/RB-05)
  if (m.sources !== undefined) {
    if (!Array.isArray(m.sources)) {
      errors.push("sources: must be an array");
    } else {
      m.sources.forEach((s, i) => {
        const at = `sources[${i}]`;
        if (!s?.id) errors.push(`${at}.id: required`);
        if (s?.type && !SOURCE_TYPES.includes(s.type)) errors.push(`${at}.type "${s.type}": unknown source type`);
        if (s?.url !== undefined && !isSafeHttpsUrl(s.url)) {
          errors.push(`${at}.url "${s.url}": must be a safe https:// URL`);
        }
      });
    }
  }
  if (m.credits !== undefined && Array.isArray(m.credits)) {
    m.credits.forEach((c, i) => {
      if (c?.profile_url !== undefined && !isSafeHttpsUrl(c.profile_url)) {
        errors.push(`credits[${i}].profile_url "${c.profile_url}": must be a safe https:// URL`);
      }
    });
  }

  // -- Cross-cutting: NO raw HTML anywhere in the manifest -------------------
  collectRawHtmlViolations(m, "manifest", errors);

  return { ok: errors.length === 0, errors };
}

// Exposed for the host boundary and tests: the same safety primitives netcore
// uses internally, so Services can reuse one definition of "safe URL".
export const _security = Object.freeze({ isSafeHttpsUrl, containsRawHtml });
