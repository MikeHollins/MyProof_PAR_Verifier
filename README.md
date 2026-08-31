# MyProof PAR verifier

[`@myproof/par-verifier`](https://github.com/MikeHollins/MyProof_PAR_Verifier) is a read-only verifier for coherence among published MyProof PAR records, signed receipts, and signed status credentials. The package is intended for public npm distribution as version `0.1.0`.

The product surface is intentionally narrow:

- `myproof-par verify <asset-id> [--require-active] [--json]`
- `myproof-par mcp`
- one stdio MCP tool, `verify_proof_asset_record`

The MCP server exposes no resources or prompts. The package root and the explicit `./contracts` subpath share the same contract exports; internal implementation modules are not public export-map entrypoints.

## Install and use

```sh
npm install @myproof/par-verifier
npx myproof-par verify <asset-id> --json
npx myproof-par verify <asset-id> --require-active
```

`<asset-id>` must be the canonical lowercase UUID of a public PAR asset. The verifier accepts no caller-selected origin, JWKS URL, status URL, credential, bearer token, proof URI, or raw proof bytes. It performs bounded read-only requests to the canonical PAR origin and requires the packaged release trust manifest to intersect the fetched receipt JWKS.

To launch the MCP server for a local stdio host:

```sh
npx myproof-par mcp
```

The MCP launcher is local stdio only; it does not expose a remote MCP endpoint.

## Report and exit codes

JSON output and MCP results are the same canonical `myproof.par.public-record-coherence.v1` report. They contain normalized states, finite check reason codes, verification methods, authorities, warnings, errors, and limitations—not raw JWS/JWK material, status URLs, remote prose, or provider payloads.

The report establishes only published-record coherence and cryptographic binding. It does not rerun the underlying proof, establish a predicate from private inputs, authenticate a current presenter, make a merchant acceptance decision, or turn PAR-reported assertions into source-signed or independently proven assertions. Audit/transparency material is outside the v1 assurance boundary.

| Exit code | Meaning                                                             |
| --------: | ------------------------------------------------------------------- |
|       `0` | Coherent; active when active status was requested                   |
|      `10` | Coherent but inactive with `--require-active`                       |
|      `20` | Contradictory signed/public evidence                                |
|      `21` | Indeterminate, unavailable, malformed, stale, or untrusted evidence |
|      `64` | Invocation or input error                                           |
|      `70` | Internal invariant failure                                          |

## Supported environments

The supported Node.js policy is `^22.19.0 || ^24.0.0`. The release CI matrix currently covers Ubuntu 24.04 and macOS 14 on those Node.js lines. Windows and other operating-system/runner combinations are not currently claimed as supported. Dependency versions are exact-pinned in `package.json` and `package-lock.json`.

## Development

```sh
npm ci
npm run schema:check
npm run check
npm test
npm run test:all
npm run build
npm run lint
npm run format:check
```

`npm test` runs the deterministic unit and in-process suites used by the quality matrix. `npm run test:all` additionally runs the real stdio, Inspector, and official conformance suites used by the release lane. These local commands do not by themselves certify remote CI, deployment, live-origin behavior, or release completion.

The CI package/release-evidence job also runs `node scripts/ci/origin-evidence.mjs`. That check is intentionally live-network evidence for the fixed canonical PAR origin; it is not part of the deterministic quality test contract.

Repository, issue tracker, and release source are maintained at [github.com/MikeHollins/MyProof_PAR_Verifier](https://github.com/MikeHollins/MyProof_PAR_Verifier). The package is MIT-licensed and publishes with public access for its scoped npm name.
