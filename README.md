# @ronutz/netcore

**The brand-blind Engine of [ronutz.com](https://ronutz.com) (codename ARSENAL):** deterministic, privacy-first network / security / identity tools, plus the declarative tool-module manifest contract they share.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

> **Status:** early development (`0.1.0`). The API surface is still settling.

## What this is

`netcore` is the open-core **computation layer** behind ronutz.com. It is deliberately *brand-blind*: it knows about tools, inputs, and correctness — never about branding, domains, themes, or locale. Those live in a separate presentation layer. That separation is what lets the same Engine power a web UI, a CLI, embeds, and white-label instances without rewrites.

Everything here runs **locally and deterministically** wherever possible: a given input always produces the same output, and pure-computation tools never touch the network. Correctness is bound to published standards (RFCs, IANA, IEEE) through executable **golden vectors** that run in CI.

## What's in it today

- **A CIDR / subnet tool** — the reference tool: parse `A.B.C.D/P`, get the network/broadcast addresses, usable host range, host count, and netmask/wildcard. Handles the `/31` (RFC 3021) and `/32` edge cases correctly.
- **The tool-module manifest contract** — each tool carries one declarative manifest describing how to detect its input (for omnibox routing), its execution/privacy class, its golden-vector set, its share-safety posture, and its sources/credits/license. A machine-checkable schema validates all of it.
- **A tool registry** — loads tools declaratively and routes pasted input to the right tool from manifest data, not hardcoded logic.
- **A Bring-Your-Own-AI adapter** — an *optional* assist layer that is provider-agnostic and never authoritative: it can annotate a result but can never change the deterministic answer, and your API key never reaches this Engine.
- **Schema migrations** — versioned, immutable, last-known-good migration scaffolding so persisted data evolves safely.

## Open-core boundary

This repository is **public and Apache-2.0 licensed**. It is the open foundation; the application and hosted services that build on it are maintained separately. A hard rule governs the relationship: **`netcore` never depends on any private/closed package.** The open Engine stands entirely on its own.

## Usage

`netcore` is pure ESM and has **no runtime dependencies**.

```js
import * as cidr from "@ronutz/netcore/tools/cidr";

const result = cidr.run("192.168.1.0/24");
console.log(result.network);      // "192.168.1.0"
console.log(result.broadcast);    // "192.168.1.255"
console.log(result.usableHosts);  // 254
```

Validating a tool manifest:

```js
import { validateManifest } from "@ronutz/netcore/manifest-schema";

const { ok, errors } = validateManifest(myToolManifest);
```

## Development

Requires **Node.js 18+**. There is nothing to install — the package is dependency-free.

```bash
npm test            # full test suite
npm run ci:golden   # golden-vector correctness gate
npm run ci:manifest # tool-manifest (D-49) lint
```

All three also run automatically on every push and pull request via GitHub Actions.

## Contributing

Contributions are welcome. Because this is an open-core project, contributors are asked to sign a Contributor License Agreement (the CLA assistant will prompt you automatically on your first pull request). Every tool must ship with passing golden vectors and a valid manifest — the CI gates enforce this.

## License

[Apache License 2.0](./LICENSE). See [`NOTICE`](./NOTICE) for attribution and trademark terms. The license covers the *software*; it does not grant rights to the "ronutz", "ARSENAL", "netcore", or "CONCORD" names or marks.
