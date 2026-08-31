# Checkpoint 1 contracts/provider evidence

Status: local checkpoint evidence only; not release evidence.

Collected in `/private/tmp/MyProof_PAR_Verifier-20260830` on 2026-08-30. The
immutable authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0`,
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository. This record covers only the standalone contracts, generated
schemas, provider fixture, provider tests, and public-surface tests. It does
not certify the core, CLI, MCP, PAR, website, CI, packaging, deployment, or
live-origin lanes.

## Producer artifact identity

The standalone fixture
`test/fixtures/provider/producer-omit-wire.json` is copied byte-for-byte from
PAR's checked-in
`/private/tmp/par-verifier-par-20260830/server/fixtures/public-verification-audit-omit.v1.json`.
The copy is 4,857 bytes.

| Representation                                               | SHA-256                                                            | Evidence                     |
| ------------------------------------------------------------ | ------------------------------------------------------------------ | ---------------------------- |
| Producer fixture file bytes                                  | `4b765d27c75606c03da3fdd4d47fa2605e1f2117ebb96a97076ca453cb78fa88` | `shasum -a 256` and `cmp -s` |
| Compact Express JSON wire, `JSON.stringify(JSON.parse(raw))` | `ff7043feb3cf7c646adce0695468d6d2978a402474599198e4335de4e7483404` | provider hash test           |

The raw-file hash protects the producer's checked-in bytes. The compact-wire
hash protects the response representation emitted after JSON serialization;
they are intentionally recorded separately. The provider positive test parses
this exact artifact through the strict bundle and evidence schemas, preserves
the producer fields, pins `checkedAt=2026-08-30T20:00:00.000Z` and
`statusListIndex=7`, and verifies that separately fetched JWKS material is not
replaced by the embedded receipt key. The embedded key and structural status
credential are not treated as trust roots or proof of a coherent result.

## Requirement mapping

| Immutable contract requirement                                                      | Local evidence                                                                                                                        | Status and boundary                                                                                                                                                   |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §5.1 narrow public surface; no extra contract exports                               | `test/contracts/public-surface.test.ts`; post-build dynamic imports of `@myproof/par-verifier` and `@myproof/par-verifier/contracts`  | PASS locally for package metadata/export-map assertions and identical 65-key runtime surfaces; npm pack and empty-consumer execution are not proven here              |
| §5.2 canonical report and finite checks                                             | `test/contracts/contracts.test.ts`; Ajv 2020 and Zod adversarial corpus                                                               | PASS locally; this does not certify adapter, CI, or release behavior                                                                                                  |
| §6 fixed origin, finite paths, read-only transport, limits, and fail-closed parsing | `test/provider/http.test.ts`                                                                                                          | PASS locally for deterministic URL, content-type, redirect, byte, timeout, abort, concurrency, and mutation cases; DNS/TLS and canonical live behavior are not proven |
| §7.1 standalone foundation and generated schemas                                    | `src/contracts/**`, generated `schemas/*.json`, `npm run schema:check`                                                                | PASS locally; schema artifacts retain `$ref`/`$defs` and explicitly declare an object root                                                                            |
| §7.1 / §9 producer-owned public wire compatibility                                  | exact fixture identity above; provider round-trip and mutation gates                                                                  | PASS for this checked-in PAR artifact and standalone copy; production deployment/query evidence remains outside this record                                           |
| §9 strict input and Ajv/Zod parity                                                  | `npm exec vitest run test/contracts test/provider/http.test.ts`                                                                       | PASS locally, including unknown-field, required-field, ordering, status, assurance, and bound adversaries                                                             |
| §9 independent cryptographic mutation coverage                                      | provider JWKS algorithm, private-key, duplicate-key, coordinate, base64url, and size mutations remain in `test/provider/http.test.ts` | PASS for provider pre-core key-ring shape coverage; independent core receipt/status crypto and trust-rotation gates are not certified by this lane                    |
| §10 durable evidence                                                                | this file plus fixture README and mutation matrix                                                                                     | PARTIAL: records local commands, hashes, and boundaries; it intentionally omits release, deployment, CI, Inspector, conformance, and live claims                      |

## Reproducible local commands

Run from the standalone worktree:

```text
shasum -a 256 /private/tmp/par-verifier-par-20260830/server/fixtures/public-verification-audit-omit.v1.json test/fixtures/provider/producer-omit-wire.json
cmp -s /private/tmp/par-verifier-par-20260830/server/fixtures/public-verification-audit-omit.v1.json test/fixtures/provider/producer-omit-wire.json
npm run check
npm run build
npm run schema:check
npm run lint
npm exec vitest run test/contracts test/provider/http.test.ts
node --input-type=module -e 'const root=await import("@myproof/par-verifier"); const contracts=await import("@myproof/par-verifier/contracts"); const rootKeys=Object.keys(root).sort(); const contractKeys=Object.keys(contracts).sort(); if (JSON.stringify(rootKeys)!==JSON.stringify(contractKeys)) process.exit(1); console.log(JSON.stringify({rootKeyCount:rootKeys.length,contractsKeyCount:contractKeys.length,identical:true}));'
node -e 'const fs=require("node:fs"); const p=require("./package.json"); const names=Object.keys(p.exports).filter((name)=>name.startsWith("./schemas/")); const schemas=names.map((name)=>{const value=JSON.parse(fs.readFileSync(name.slice(2),"utf8")); return {name,type:value.type,ref:value.$ref,defs:Object.keys(value.$defs||{}).length};}); if (names.length!==3 || schemas.some((schema)=>schema.type!=="object" || typeof schema.ref!=="string")) process.exit(1); console.log(JSON.stringify({schemaExportCount:names.length,schemas}));'
npx prettier --check test/provider/http.test.ts test/provider/MUTATION_MATRIX.md test/fixtures/provider/README.md src/contracts schemas README.md package.json
```

Observed results:

- source/copy SHA-256 values match exactly; `cmp`: PASS;
- `npm run check`: PASS;
- `npm run build`: PASS;
- `npm run schema:check`: PASS;
- `npm run lint`: PASS;
- targeted contracts/provider tests: 4 files, 143 tests passed;
- built package root and explicit `./contracts` subpath dynamic imports: 65
  exported keys each, identical: PASS;
- package export map and generated schema artifacts: 3 explicit schema exports,
  each with an object root and `$ref`/`$defs`: PASS;
- current cross-lane MCP handoff: scoped MCP suite, 5 files and 28 tests:
  PASS;
- current cross-lane package handoff: package-smoke `ok=true` for
  `@myproof/par-verifier@0.1.0`, 144 packed files, 125,355-byte tarball, and
  SHA-256
  `b6756af9845676eb9758b31a7c1992deb0be07eba8ae40483407251519f2b3ec`:
  PASS;
- current root-level aggregate handoff: `npm run test:all`, 20 files and 296
  tests passed; this is cross-lane local evidence, not a contracts/provider
  result or release evidence;
- settled workflow-contract handoff: `ok=true`, with pull-request, push,
  merge-queue, and manual-dispatch coverage and no path filters: PASS;
- owned-path Prettier check: PASS.

The cross-lane MCP, package-smoke, and workflow-contract results are local
handoffs recorded by their owning lanes; they do not convert this contracts /
provider record into release evidence.

## Explicitly not proven

This checkpoint is not a release sign-off. It does not independently prove a
full-repository `npm run test:all` or remote CI result from the contracts /
provider lane; the current root-level aggregate handoff is recorded above for
cross-lane orientation only. The owning MCP lane separately records its
scoped Inspector/conformance suite and the package lane separately records
package-smoke; those local handoffs do not substitute for remote enforcement,
published-artifact provenance, SBOM and security review, PAR runtime/query
non-invocation evidence, website deployment state, canonical live probes,
key-rotation release evidence, rollback, or independent audit disposition.
None of those release gates may be inferred from the local green
contracts/provider gates.
