# Checkpoint 1 service-facade evidence

Status: local checkpoint evidence only; not release evidence.

Initial local evidence was captured in `/private/tmp/MyProof_PAR_Verifier-20260830`
on 2026-08-30; the live compatibility section was updated on 2026-08-31. The
immutable authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0`,
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository. This record covers only the standalone verifier service facade
and its focused tests. It does not certify PAR, the website, deployment,
remote CI, release packaging, or live-origin behavior.

## Facade boundary

`src/service/verify-proof-asset-record.ts` is the sole service operation. The
focused suite uses its test-only dependency factory to inject a provider, core
trust material, and deterministic clock; it does not import or exercise CLI or
MCP adapters. Every returned value is parsed again with the shared
`PublicRecordCoherenceReportSchema`, so the test proves report-contract
semantics rather than a test-only object shape.

The valid control case delegates the one shared evidence envelope to the pure
core and returns `COHERENT` / `ACTIVE` / `SATISFIED`, with the fixed claim
boundaries `NOT_PERFORMED` and `PAR_REPORTED_ONLY`. Malformed evidence remains
a canonical `INDETERMINATE` report with `BUNDLE_MALFORMED`; it is not promoted
to a transport success or an exception.

The local rotation control also proves that the facade preserves both an old
and a newer receipt while both keys are trusted, then reports an unknown live
key and an indeterminate active condition when the old key is removed from the
live JWKS.

## Provider failure mapping

The table is an executable `it.each` matrix in
`test/service/verify-proof-asset-record.test.ts`. Each row injects the stated
`ParProviderError` and asserts a schema-valid `INDETERMINATE` report, one
`PUBLIC_RECORD_INDETERMINATE` warning, the mapped error, and the canonical
`bundle_structure` check. Provider error text, URLs, and status values never
enter the report.

| Provider code                  | Resource in mapping test | Canonical report error         |
| ------------------------------ | ------------------------ | ------------------------------ |
| `INVALID_ASSET_ID`             | `input`                  | `PUBLIC_RECORD_UNAVAILABLE`    |
| `INVALID_STATUS_REFERENCE`     | `status`                 | `PUBLIC_RECORD_UNAVAILABLE`    |
| `UNSAFE_URL`                   | `input`                  | `NETWORK_ORIGIN_REJECTED`      |
| `FETCH_FAILED`                 | `bundle`                 | `PUBLIC_RECORD_UNAVAILABLE`    |
| `ABORTED`                      | `bundle`                 | `NETWORK_ABORTED`              |
| `TIMEOUT`                      | `bundle`                 | `NETWORK_TIMEOUT`              |
| `REDIRECT_REJECTED`            | `bundle`                 | `NETWORK_REDIRECT_REJECTED`    |
| `HTTP_STATUS`                  | `bundle`                 | `PUBLIC_RECORD_UNAVAILABLE`    |
| `CONTENT_TYPE_MISMATCH`        | `bundle`                 | `NETWORK_CONTENT_TYPE_INVALID` |
| `CONTENT_ENCODING_UNSUPPORTED` | `bundle`                 | `NETWORK_CONTENT_TYPE_INVALID` |
| `CONTENT_LENGTH_INVALID`       | `bundle`                 | `PUBLIC_RECORD_UNAVAILABLE`    |
| `BODY_TOO_LARGE`               | `bundle`                 | `NETWORK_RESPONSE_TOO_LARGE`   |
| `INVALID_TEXT`                 | `bundle`                 | `PUBLIC_RECORD_MALFORMED`      |
| `INVALID_JSON`                 | `bundle`                 | `PUBLIC_RECORD_MALFORMED`      |
| `INVALID_RESPONSE`             | `bundle`                 | `PUBLIC_RECORD_MALFORMED`      |

An additional multi-document test uses the real `ParPublicProvider`: the
canonical bundle and JWKS GETs succeed, then only the canonical status GET
fails with a private transport error. The service returns
`PUBLIC_RECORD_UNAVAILABLE`, `INDETERMINATE`, and an indeterminate active
condition for `require_active=true`; the status URL and private error text are
absent from serialized output. The provider performs fixed-origin, bounded
validation in this test, rather than the test bypassing it with a raw fetch.

## Cancellation, input, and invariant coverage

- A caller signal is forwarded unchanged to the provider and is never
  serialized into the report.
- A signal already aborted before provider work, or aborted immediately after
  provider completion, remains the caller's cancellation exception rather than
  becoming a domain report.
- Invalid caller input is rejected before provider I/O, including an unknown
  caller URL field; no provider call is made.
- Invalid service clocks (`NaN`, negative, non-finite, and fractional values)
  fail with `INTERNAL_INVARIANT_FAILURE` before provider I/O.
- Clock dependency exceptions and unknown provider exceptions are rethrown
  unchanged; the facade does not invent a report for an internal failure.
- Malformed evidence is normalized by the core into the shared report, and
  hostile provider/error strings are checked for absence from serialized
  output.

## Reproducible local commands and results

Run from the standalone worktree:

```text
npx vitest run test/service/verify-proof-asset-record.test.ts --reporter=verbose
npx vitest run test/service/verify-proof-asset-record.test.ts test/provider/http.test.ts
npm test
npm run check
npm run build
npm run lint
npx eslint test/service/verify-proof-asset-record.test.ts
npx prettier --check test/service
```

Observed results for the focused service/provider commands in this checkpoint:

- focused service suite: 1 file, 30 tests passed;
- focused service + provider suites: 2 files, 148 tests passed;
- service-inclusive `npm test`: 17 files, 291 tests passed;
- typecheck, build, repository lint, focused ESLint, and focused Prettier:
  PASS at the service/provider checkpoint run.

An earlier WIP aggregate `npm run test:all` invocation reached 19 files and
295 passing tests before one unrelated failure in
`test/mcp/conformance.test.ts`: the sandbox denied its test-only loopback
listener (`listen EPERM: operation not permitted 127.0.0.1`). That observation
is historical, not a current service result, and was not a service-facade
failure. The later root-level checkpoint aggregate completed with 20 files and
296 tests passed. That cross-lane result does not expand this record's focused
service/provider scope. The immutable core fixture and the provider fixture
were not changed by this lane.

## Evidence boundary

The control signed evidence is generated by local test fixtures with a fixed
test clock and ephemeral test keys. The status-only case stubs `globalThis.fetch`
with canonical local bundle/JWKS responses and a local status transport failure
while running the real provider pipeline; it does not prove DNS, TLS,
deployment, PAR query behavior, or a live-origin response. The 148-test result
is therefore local fixture/provider evidence, not production or release
evidence.

## Current canonical-origin compatibility probe

The opt-in live gate was run with the real `ParPublicProvider` against the
canonical receipt-key endpoint:

```text
MYPROOF_PAR_LIVE_PROVIDER=1 npx vitest run test/provider/http.test.ts
```

The explicitly enabled run passed: 1 file, 118 tests. The default sandboxed
attempt could not reach the network and returned the provider's redacted
`FETCH_FAILED`; an approved read-only network run passed. The live test itself
does not print key IDs, asset IDs, credentials, or response bodies.

A separate read-only probe exercised both canonical JWKS and status retrieval
through `createParPublicProvider` (not raw `fetch`). It requested only the
canonical status path with a bounded reference and emitted hashes/counts rather
than key IDs or credential contents. The redacted result was:

```text
npx tsx --eval 'import { createHash } from "node:crypto"; import { createParPublicProvider, ParProviderError } from "./src/provider/http.ts"; void (async () => { const provider = createParPublicProvider({ timeoutMs: 8000, maxJwksBytes: 256 * 1024, maxStatusBytes: 24 * 1024 * 1024 }); try { const jwks = await provider.fetchReceiptJwks(); const status = await provider.fetchStatusCredential({ statusListUrl: "https://par.myproof.ai/status/revocation/default", statusListIndex: "0", statusPurpose: "revocation" }); const keyIdsDigest = createHash("sha256").update(jwks.keys.map((key) => key.kid).sort().join("\n"), "utf8").digest("hex"); const credentialDigest = createHash("sha256").update(status.credential, "utf8").digest("hex"); console.log(JSON.stringify({ ok: true, jwks: { keyCount: jwks.keys.length, keyIdsSha256: keyIdsDigest }, status: { contentType: status.contentType, credentialBytes: Buffer.byteLength(status.credential, "utf8"), credentialSha256: credentialDigest, path: "/status/revocation/default" }, activeRequests: provider.activeRequests })); } catch (error) { console.log(JSON.stringify({ ok: false, errorCode: error instanceof ParProviderError ? error.code : "UNEXPECTED" })); process.exitCode = 1; } })();'
```

```json
{
  "ok": true,
  "jwks": {
    "keyCount": 1,
    "keyIdsSha256": "07ba263229cdedad9cd6ade954d9ed0da27d91b4c90ce078037538fa891ca3c4"
  },
  "status": {
    "contentType": "application/vc+jwt",
    "credentialBytes": 887,
    "credentialSha256": "fa1dc90c989dede69640e355b1ca35c6c27a90d59f63432233d8af53a65befb5",
    "path": "/status/revocation/default"
  },
  "activeRequests": 0
}
```

This is WIP compatibility evidence for the live observation on 2026-08-31,
not a release pin or a claim that the live credential is cryptographically
trusted by the local release manifest. It does not prove the bundle route,
asset-specific behavior, DNS/TLS stability, deployment state, PAR query
non-invocation, key-rotation policy, or remote CI enforcement. No unsafe route
was queried and no remote state was mutated.

Beyond the narrowly scoped compatibility observation above, this checkpoint
makes no claim about live provider reliability, release-trust publication,
remote CI enforcement, package installation, website state, deployment state,
or independent audit acceptance. Those gates remain owned by their respective
lanes.
