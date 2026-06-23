// ============================================================================
// netcore/src/tools/cidr/compute.mjs
// ----------------------------------------------------------------------------
// THE DETERMINISTIC CIDR TOOL  (the reference tool for Seam 1, C-04)
//
// WHY: Seam 1 must prove ONE deterministic tool runs both in-browser and behind
// a hosted endpoint with IDENTICAL golden-vector output. CIDR is chosen because
// it is pure arithmetic over a 32-bit space — no clock, no network, no entropy —
// so any divergence between the two run sites is a real architectural defect,
// not noise. This module is `executionClass: localOnly`: it never touches the
// network and is safe to ship as the in-browser embeddable module (C-68).
//
// Correctness is bound to RFC 4632 (CIDR) and the dotted-quad conventions; the
// golden vectors in ./golden-vectors.mjs are the executable contract (D-1/D-49).
// ============================================================================

/**
 * Parse a dotted-quad IPv4 string into an unsigned 32-bit integer.
 * WHY a helper: we validate each octet is 0–255 and reject malformed input
 * early, because a security tool must never silently coerce bad input.
 *
 * @param {string} ip e.g. "192.168.1.10"
 * @returns {number} unsigned 32-bit integer
 * @throws {Error} on malformed input
 */
export function ipv4ToInt(ip) {
  if (typeof ip !== "string") throw new Error("ip must be a string");
  const parts = ip.trim().split(".");
  if (parts.length !== 4) throw new Error(`malformed IPv4 (need 4 octets): "${ip}"`);
  let acc = 0;
  for (const p of parts) {
    // Reject empties, signs, non-digits, and out-of-range octets explicitly.
    if (!/^\d{1,3}$/.test(p)) throw new Error(`malformed octet "${p}" in "${ip}"`);
    const n = Number(p);
    if (n > 255) throw new Error(`octet ${n} > 255 in "${ip}"`);
    // `>>> 0` keeps the running value in the unsigned 32-bit domain.
    acc = ((acc << 8) | n) >>> 0;
  }
  return acc >>> 0;
}

/**
 * Render an unsigned 32-bit integer back to dotted-quad.
 * @param {number} int unsigned 32-bit integer
 * @returns {string} dotted-quad IPv4
 */
export function intToIpv4(int) {
  const u = int >>> 0; // force unsigned interpretation
  return [(u >>> 24) & 0xff, (u >>> 16) & 0xff, (u >>> 8) & 0xff, u & 0xff].join(".");
}

/**
 * computeCidr — the deterministic core.
 *
 * Given "A.B.C.D/P" returns the network address, broadcast address, usable
 * host range, host count, and netmask/wildcard. This is the single function
 * the in-browser build and the hosted endpoint both call, guaranteeing
 * identical output (the Seam-1 invariant).
 *
 * @param {string} cidr e.g. "192.168.1.0/24"
 * @returns {object} a flat, JSON-serializable result (stable key order)
 * @throws {Error} on malformed input or out-of-range prefix
 */
export function computeCidr(cidr) {
  if (typeof cidr !== "string") throw new Error("cidr must be a string");
  const [addr, prefixStr] = cidr.trim().split("/");
  if (prefixStr === undefined) throw new Error(`missing prefix length in "${cidr}"`);
  if (!/^\d{1,2}$/.test(prefixStr)) throw new Error(`malformed prefix "/${prefixStr}"`);

  const prefix = Number(prefixStr);
  if (prefix < 0 || prefix > 32) throw new Error(`prefix /${prefix} out of range (0–32)`);

  const ipInt = ipv4ToInt(addr);

  // Netmask: top `prefix` bits set. /0 is the special case (mask = 0) because
  // a 32-bit left shift by 32 is undefined in JS; we guard it deliberately.
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcard = (~mask) >>> 0;

  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;

  // Usable-host accounting follows the classic convention: /31 and /32 have no
  // separate network/broadcast pair, so they expose their addresses directly.
  const totalAddresses = prefix === 0 ? 4294967296 : (wildcard + 1);
  let firstHost, lastHost, usableHosts;
  if (prefix >= 31) {
    firstHost = intToIpv4(network);
    lastHost = intToIpv4(broadcast);
    usableHosts = prefix === 32 ? 1 : 2; // /32 = single host; /31 = point-to-point pair
  } else {
    firstHost = intToIpv4((network + 1) >>> 0);
    lastHost = intToIpv4((broadcast - 1) >>> 0);
    usableHosts = totalAddresses - 2;
  }

  // Stable key order so the serialized string is byte-identical across run
  // sites — the golden-vector comparison depends on this.
  return {
    input: `${intToIpv4(ipInt)}/${prefix}`,
    network: intToIpv4(network),
    broadcast: intToIpv4(broadcast),
    netmask: intToIpv4(mask),
    wildcard: intToIpv4(wildcard),
    firstHost,
    lastHost,
    totalAddresses,
    usableHosts,
  };
}
