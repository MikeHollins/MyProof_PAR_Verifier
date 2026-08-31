# Checkpoint 1 MCP evidence

Status: local checkpoint evidence only; not a release sign-off.

This record was captured in `/private/tmp/MyProof_PAR_Verifier-20260830` on
2026-08-30 local time (latest MCP-suite command timestamp:
`2026-08-31T03:43:51Z`). The
immutable authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0`,
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository. This document covers the standalone MCP adapter, its test-only
harnesses, and the observed package-smoke handoff. It does not certify PAR,
website, provider, core, CI enforcement, deployment, or live-origin state.

## Surface and schema authority

The production MCP surface is implemented by `src/mcp/index.ts` and
`src/mcp/stdio.ts`:

- one tool: `verify_proof_asset_record`;
- zero resources and zero prompts;
- caller input is the shared `VerifyProofAssetInput` (`asset_id` plus optional
  `require_active`), with no origin, URL, credential, raw evidence, or
  provider-selected key;
- the callback invokes the exact shared verifier facade and forwards the MCP
  request `AbortSignal`;
- domain outcomes are `isError: false` structured results; protocol and
  verifier-invariant failures are tool errors;
- output is the shared report, duplicated only as canonical text and
  `structuredContent`, with no legacy `{ result: report }` wrapper;
- diagnostics are stderr-only and shutdown handles EOF, signals, transport
  close, and external abort.

`fromJsonSchema` receives the generated contract documents loaded relative to
the module, not from the caller's working directory. `tools/list` is compared
to the committed `schemas/myproof.par.public-record-input.v1.json` and
`schemas/myproof.par.public-record-coherence.v1.json` without schema
normalization. The adapter test also compiles both the canonical and advertised
report schemas with Ajv 2020 and requires identical results for valid and
adversarial reports (wrong check tuples/order, required unknowns, invalid
coherence states, limitation ordering, boundary-check escalation, and unknown
fields).

Evidence: `test/mcp/adapter.test.ts` and the first two cases in
`test/mcp/stdio.integration.test.ts`.

## CLI/MCP parity and claim boundaries

`test/mcp/parity.test.ts` exercises the real `createVerifierServiceForTests`
facade/core path, then sends the same report through the CLI JSON formatter and
the MCP server. Its table covers coherent active, coherent revoked/inactive,
coherent suspended/inactive, contradictory public binding, unavailable provider,
and malformed provider outcomes. Each row asserts the shared report fields,
reason codes, CLI exit code, MCP `isError: false`, direct structured content,
and canonical text byte-for-byte. The valid signed fixture proves that the
signed JWS may contain `jti` while the public claims projection omits it; the
result remains `COHERENT` with `SATISFIED` active status. CLI JSON, MCP
`structuredContent`, and MCP text parse to the same report.

The second parity case parses the exact producer `audit=omit` artifact at
`test/fixtures/provider/producer-omit-wire.json`, uses separately fetched
JWKS/status transport fixtures, and invokes the real service. Its separately
held release trust intentionally does not intersect the fetched key, so the
facade truthfully returns `INDETERMINATE`; the test does not fabricate a
coherent producer result. It verifies that:

- the signed artifact payload's `jti` is not required in the public projection;
- the embedded receipt JWK/header are not trust inputs;
- removing those embedded fields leaves the report unchanged;
- CLI exit/report JSON and raw MCP `structuredContent`/text are identical;
- no JWK, `jti`, or protocol wrapper enters the public report.

The MCP adapter uses the shared input-aware report parser and serializer after
the facade call, so asset binding and `require_active` intent cannot diverge
between CLI and MCP.

Cancellation is tested separately as a non-domain terminal path: the CLI
returns its safe cancellation exit/diagnostic with no JSON report, while MCP
propagates `notifications/cancelled`, emits no response/content for the
cancelled request, and remains healthy for a subsequent discovery request.

## Real stdio lifecycle

`test/mcp/stdio.integration.test.ts` launches the exact package bin entry
`bin/myproof-par.js` after one bounded build, with a genuinely empty working
directory. It does not run `npm pack`, `npm install`, or create a second npm
consumer. The test proves:

- legacy `2025-11-25` initialize and raw `tools/list` schema equality;
- exactly one tool and method-not-found behavior for resources/prompts;
- a real shared provider/core call returning a structured domain report;
- malformed input as a tool error without remote-detail leakage;
- process stdout contains only JSON-RPC messages;
- a fast cancellation race does not poison the server;
- EOF closes with exit code `0` and no signal.

The separate delayed test-only harness launches `createMcpServer` in a real
child process, emits a stderr start barrier, sends
`notifications/cancelled`, waits for the verifier's stderr abort marker, and
proves that no response is emitted for the cancelled request. It then performs
`tools/list` and another call successfully before clean EOF/exit. This is the
deterministic negative control for protocol cancellation propagation; it is not
presented as the packaged consumer install test.

The actual `npm pack` plus empty-consumer installation is intentionally owned by
the existing CLI/CI `scripts/ci/package-smoke.mjs` job. The current local
handoff artifact at
`/private/tmp/myproof-par-checkpoint1.8MiqvG/package-smoke.json` reports a
successful run:

```text
package-smoke: ok=true
package: @myproof/par-verifier@0.1.0
tarball: 125355 bytes, sha256=b6756af9845676eb9758b31a7c1992deb0be07eba8ae40483407251519f2b3ec
files: 144
installed trust loader: authenticated, compiled digest pin matched
consumer public import: true; consumer bin --help: true
```

That package-smoke result proves packed/install/export-map/bin-help behavior;
the MCP test proves the compiled bin's real stdio protocol behavior from an
empty cwd. Neither result is a production deployment or live PAR probe.

## Inspector eras

`test/mcp/inspector.test.ts` uses the pinned `@modelcontextprotocol/inspector`
2.4.0 launcher:

- legacy: strict stdio `tools/list` succeeds and finds exactly
  `verify_proof_asset_record`;
- modern: Inspector negotiates `protocolVersion: 2026-07-28` through
  `server/discover`, then strict `tools/list` succeeds on the same stdio
  binary.

The modern 2026 evidence is separate from legacy 2025 compatibility and does
not imply that the older official conformance runner supports the modern
protocol version.

## Official conformance applicability

`test/mcp/conformance.test.ts` pins
`@modelcontextprotocol/conformance` `0.1.16` and records the exact server
catalog for spec `2025-11-25`. A test-only loopback HTTP adapter is used solely
because this runner's official server mode requires a URL transport; the
production surface remains stdio-only.

Applicable scenarios all passed (`1/1`, `0 failed`):

- `server-initialize`;
- `ping`;
- `tools-list`.

The following are intentionally not applicable, not expected failures:

- `json-schema-2020-12`, because the runner requires a second tool named
  `json_schema_2020_12_tool`, which would violate the exact one-tool product
  contract;
- resources and prompts, because the product exposes zero of each;
- image/audio/embedded-resource/mixed-content scenarios, because the tool is
  text-only;
- sampling, elicitation, completion, logging, progress, subscriptions, and
  SSE scenarios, because those capabilities/transports are intentionally absent
  from this narrow stdio product.

No conformance failure is hidden by an expected-failure baseline.

## Reproducible commands and observed results

Run from the standalone worktree:

```text
npm run build
npm run schema:check
npx prettier --check src/mcp test/mcp test/harness/mcp
npx eslint src/mcp test/mcp test/harness/mcp
npx vitest run test/mcp/adapter.test.ts test/mcp/parity.test.ts test/mcp/stdio.integration.test.ts test/mcp/inspector.test.ts test/mcp/conformance.test.ts --reporter=dot
env CI=true CI_EVIDENCE_DIR=/tmp/myproof-par-mcp-package-evidence-20260831 node scripts/ci/package-smoke.mjs
```

Observed on the settled local candidate:

- build: PASS;
- schema freshness: PASS;
- scoped Prettier and ESLint: PASS;
- MCP suite: 5 files, 28 tests passed;
- package-smoke: PASS as recorded above.

An earlier WIP aggregate typecheck observation reported unrelated concurrent
crypto-test `exactOptionalPropertyTypes` diagnostics against evolving
`JsonWebKeyLike` types; that observation is historical, not a current MCP
result. The later root-level checkpoint `npm run test:all` handoff completed
with 20 files and 296 tests passed. That cross-lane test result does not prove
full-repository typecheck or release health, and this record does not relabel
the historical diagnostics as MCP failures.

## Remaining release-only gaps

This is not release evidence. The following remain outside this MCP checkpoint
or require later integration evidence:

- parent/core/provider/crypto full-suite and strict-typecheck health;
- remote CI trigger/enforcement truth and all supported-platform cells;
- final package provenance, SBOM, dependency/license review, and published
  artifact verification;
- PAR historical-key retention and `audit=omit` runtime/query non-invocation
  evidence;
- website canonical-origin configuration and immutable deployment revision;
- bounded canonical live probe, production deployment, rollback rehearsal, and
  cross-repository compatibility evidence;
- final independent audit disposition and the contract's release score gate.

MCP lane self-score: 99/100. No MCP-owned blocker or high finding is known;
overall completion remains partial until the release-only gates above and
cross-lane health are independently satisfied.
