// ============================================================================
// netcore/src/tools/cidr/golden-vectors.mjs
// ----------------------------------------------------------------------------
// GOLDEN VECTORS for the CIDR tool  (the D-1 / D-49 correctness contract)
//
// WHY: "It runs" is not "it is correct" (Protocol §10.13.2). No tool is PRESENT
// in the Conformance Manifest unless its golden-vector set EXISTS and PASSES in
// CI. These vectors are hand-derived from RFC 4632 + the standard dotted-quad
// host-accounting conventions, including the /31 (RFC 3021) and /32 edge cases
// that are the usual source of off-by-one bugs.
//
// The set id below ("cidr.rfc4632.v1") is what the manifest's `goldenVectors`
// field must reference; the manifest validator checks that linkage.
// ============================================================================

export const GOLDEN_VECTOR_SET_ID = "cidr.rfc4632.v1";

// Each case: input → the exact expected flat result. Kept small but covering
// the boundaries: a /24, a host-bit-bearing address, /0, /31, /32, and a /30.
export const CIDR_GOLDEN_VECTORS = Object.freeze([
  {
    name: "/24 typical",
    input: "192.168.1.0/24",
    expect: {
      input: "192.168.1.0/24",
      network: "192.168.1.0",
      broadcast: "192.168.1.255",
      netmask: "255.255.255.0",
      wildcard: "0.0.0.255",
      firstHost: "192.168.1.1",
      lastHost: "192.168.1.254",
      totalAddresses: 256,
      usableHosts: 254,
    },
  },
  {
    name: "/24 with host bits set (must mask to network)",
    input: "192.168.1.10/24",
    expect: {
      input: "192.168.1.10/24",
      network: "192.168.1.0",
      broadcast: "192.168.1.255",
      netmask: "255.255.255.0",
      wildcard: "0.0.0.255",
      firstHost: "192.168.1.1",
      lastHost: "192.168.1.254",
      totalAddresses: 256,
      usableHosts: 254,
    },
  },
  {
    name: "/30 point-to-point block",
    input: "10.0.0.0/30",
    expect: {
      input: "10.0.0.0/30",
      network: "10.0.0.0",
      broadcast: "10.0.0.3",
      netmask: "255.255.255.252",
      wildcard: "0.0.0.3",
      firstHost: "10.0.0.1",
      lastHost: "10.0.0.2",
      totalAddresses: 4,
      usableHosts: 2,
    },
  },
  {
    name: "/31 RFC 3021 pair (no network/broadcast waste)",
    input: "10.0.0.0/31",
    expect: {
      input: "10.0.0.0/31",
      network: "10.0.0.0",
      broadcast: "10.0.0.1",
      netmask: "255.255.255.254",
      wildcard: "0.0.0.1",
      firstHost: "10.0.0.0",
      lastHost: "10.0.0.1",
      totalAddresses: 2,
      usableHosts: 2,
    },
  },
  {
    name: "/32 single host",
    input: "172.16.5.4/32",
    expect: {
      input: "172.16.5.4/32",
      network: "172.16.5.4",
      broadcast: "172.16.5.4",
      netmask: "255.255.255.255",
      wildcard: "0.0.0.0",
      firstHost: "172.16.5.4",
      lastHost: "172.16.5.4",
      totalAddresses: 1,
      usableHosts: 1,
    },
  },
  {
    name: "/0 entire IPv4 space",
    input: "0.0.0.0/0",
    expect: {
      input: "0.0.0.0/0",
      network: "0.0.0.0",
      broadcast: "255.255.255.255",
      netmask: "0.0.0.0",
      wildcard: "255.255.255.255",
      firstHost: "0.0.0.1",
      lastHost: "255.255.255.254",
      totalAddresses: 4294967296,
      usableHosts: 4294967294,
    },
  },
]);

// Inputs that MUST throw — a security tool rejects malformed input loudly.
export const CIDR_REJECT_VECTORS = Object.freeze([
  "192.168.1.0/33",   // prefix out of range
  "256.1.1.1/24",     // octet > 255
  "192.168.1/24",     // too few octets
  "192.168.1.0",      // missing prefix
  "10.0.0.0/-1",      // negative prefix (regex-rejected)
]);
