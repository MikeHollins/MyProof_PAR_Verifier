# PAR verifier foundation contract

This document records the standalone foundation seam for the MyProof PAR verifier. The immutable execution contract remains authoritative; this document records only the implementation choices in this worktree and the handoff obligations for later lanes.

## Scope and ownership

The foundation owns package metadata, the lockfile, compiler/test/lint configuration, `src/contracts/**`, generated `schemas/**`, contract fixtures/tests, and this maintenance note. It does not own verification semantics, cryptography, network transport, CLI parsing, MCP serving, PAR production code, or website code.

## Canonical boundaries

`src/contracts/index.ts` is the sole public contract barrel for the operation input, check, report, and typed verifier facade. The package root and its explicit `./contracts` subpath re-export that same narrow module; they do not define compatibility aliases or a second facade. Provider evidence schemas remain internal in `src/contracts/input.ts` because raw PAR/JWS/JWK transport shapes are an implementation trust boundary, not a supported consumer API. The report is a strict, normalized conclusion document: it contains finite status/conclusion fields and check metadata only. It deliberately has no raw JWS, public key, status URL, digest, commitment, policy CID/hash, circuit identifier, remote prose, or arbitrary evidence map.

The executable operation surface is limited to `myproof-par verify <asset-id> [--require-active] [--json]` and `myproof-par mcp`. The stdio MCP server registers exactly `verify_proof_asset_record`; it exposes zero resources and zero prompts. Internal `src/`, `dist/`, core, provider, crypto, and MCP implementation paths are not package export-map entrypoints.

Provider/core evidence is a separate strict input boundary. It models the frozen public bundle (`ok`, `schemaVersion`, `asset`, `receipt`, required status projection, optional signed status credential, provenance, and assurance) and accepts only the producer's bounded `audit: null` plus `checks: { auditAnchor: "omitted", auditInclusion: "omitted", epochSignature: "omitted" }` placeholders from `audit=omit`. Status references are limited to the two canonical PAR status-list paths, signed values are compact JWSes, receipt keys are ES256 P-256 public keys, and assurance projections enforce their producer-declared ordering/completeness relationships. Those placeholders are compatibility transport fields, never v1 assurance checks. A non-null audit payload is rejected.

The caller can supply only a canonical lower-case UUID and `require_active`; `parseVerifyProofAssetInput` materializes the omitted flag as `false` exactly once. The provider must construct the fixed HTTPS origin and finite paths itself. The current receipt key route is `/api/public/receipts/jwks.json`; the verifier must not silently substitute the well-known alias.

## Output budget

The canonical report cap is `MAX_REPORT_BYTES` (96 KiB). MCP returns the report as both text and structured content, so the cap is shared rather than redefined by an adapter. `MAX_STDIO_MESSAGE_BYTES` is 512 KiB. The Zod parser and final serializer enforce the report cap; MCP must import the same constant and reject any report that exceeds it.

## Exact dependency freeze

The freeze is recorded in both `package.json` and `package-lock.json`:

| Dependency                          | Version | Role                                       |
| ----------------------------------- | ------: | ------------------------------------------ |
| `@modelcontextprotocol/server`      |   2.0.0 | official MCP v2 server/runtime             |
| `@modelcontextprotocol/inspector`   |   2.4.0 | stdio protocol inspection                  |
| `@modelcontextprotocol/conformance` |  0.1.16 | applicable MCP conformance tooling         |
| `zod`                               |   4.5.4 | runtime schemas and JSON Schema generation |
| `typescript`                        |   6.0.3 | strict ESM compilation                     |

Development tooling is exact-pinned as well. The runtime engine policy is `^22.19.0 || ^24.0.0`, matching the supported LTS lines required by the Inspector freeze. `npm ci` is the reproducible installation command.

## Generated artifacts and maintenance

Run `npm run schema:generate` after changing a contract and commit the resulting files under `schemas/`. Each generated document retains its `$ref`/`$defs` structure and explicitly declares an object root so raw MCP `tools/list` output is byte-identical to the package artifact. CI and local verification run `npm run schema:check` so a stale artifact cannot pass. Contract tests cover strict caller input, finite checks, report privacy, UUID and key bounds, exact `audit=omit` placeholders, assurance invariants, duplicate-check rejection, Ajv/Zod adversarial parity, and the canonical PAR route.

## Handoff seams

Later adapters/core work must:

1. import public operation/report contracts from `src/contracts/index.ts` and internal provider evidence contracts directly from `src/contracts/input.ts`;
2. return the exact parsed report type from the facade, with no adapter-local report/check schema;
3. map all check outcomes to the finite `id`, `state`, `reason_code`, `verification_method`, `authority`, and `required` fields;
4. keep `acceptance_decision`, `underlying_proof_verification`, and `predicate_assurance` at their literal boundary values;
5. omit audit/transparency, remote prose, identifiers, tokens, key IDs, and raw evidence from reports; and
6. use the shared report serializer/budget before CLI or MCP output.

Downstream adapter and runtime integration are tracked by their own tests and evidence records; this foundation note does not certify CLI, MCP, packaging, deployment, or release completion.
