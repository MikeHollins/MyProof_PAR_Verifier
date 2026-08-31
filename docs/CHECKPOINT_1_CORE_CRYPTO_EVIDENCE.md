# Checkpoint 1 core and cryptography evidence

Status: local checkpoint evidence only; not release evidence.

Captured in `/private/tmp/MyProof_PAR_Verifier-20260830` on 2026-08-30. The
immutable authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0`,
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository. This record covers the standalone deterministic core, receipt and
status cryptography, release/live key intersection, service facade, and their
privacy-safe local fixtures. It does not certify PAR deployment, the website,
remote CI, package publication, or a live-origin release.

## Authority and claim boundary

The signed receipt is the cryptographic authority for the asset identifier,
policy/constraint references, proof digest and commitment fields, status
reference, audience, issuer, time window, and protected key identifier. The
signed VC-JWT status credential is authoritative for the status-list bit after
its issuer, subject, purpose, validity window, encoding, and index are checked.
The release trust manifest and the separately fetched live JWKS must intersect
on the same complete public key; neither an embedded bundle key nor live JWKS
alone is sufficient.

The pure core is synchronous, deterministic, and network-free. It consumes one
strict provider evidence envelope and emits the shared canonical report. PAR
bundle, status-check, provenance, and receipt-claim fields are projections:
they may establish coherence only when bound to verified signed values. The
`audit: null`/`omitted` representation is accepted as transport compatibility
and discarded; this v1 core makes no epoch, Merkle, transparency, or audit
inclusion claim. The report boundary remains explicit:
`acceptance_decision=NOT_PERFORMED`,
`underlying_proof_verification=NOT_PERFORMED`, and
`predicate_assurance=PAR_REPORTED_ONLY`.

Only an authenticated signed assertion can produce a contradiction. A valid
signature with an incompatible issuer, audience, subject, status reference,
purpose, or public projection is a required `FAIL` and therefore
`CONTRADICTORY`. Missing, malformed, unsupported, stale, tampered, unknown-kid,
untrusted, or otherwise unavailable evidence remains `UNKNOWN` and therefore
`INDETERMINATE`; it is never treated as a signed assertion of the opposite
state.

## Immutable signed vector

The fixed vector is under
`test/fixtures/core/immutable/`. Its receipt and VC-JWT were generated once by
the independent Node.js `node:crypto` ECDSA P-256 signing oracle described in
`PROVENANCE.json`; no private key was persisted and the production verifier was
not used to create the signed bytes. The fixed verification clock is
`1733616000000` (`2024-12-08T00:00:00.000Z`). The signed receipt retains its
required `jti`, while the public `receipt.claims` projection omits `jti`.

The immutable test checks all seven artifact hashes, parses the exact provider
shape through the strict input schema, verifies the recorded coherent active
report, and mutates the fixed projection to prove that a leaked `jti` is a
contradiction. `expected-report.json` is a byte-pinned contract snapshot; the
executable mutation suites are the semantic regression oracle.

| Artifact               | SHA-256                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| `input.json`           | `77201c1af2422f3f6f1dbbd078e2308795652a34deff901e8a9b82ba9652cf89` |
| `bundle.json`          | `d204ec3fc140487a11d314e30c66decd16ec000754960fc9dbe95a2ae57cb7d3` |
| `jwks.json`            | `893e7268f329a5743828e6761e004869ab8b2675c16e1c56535d522d39755b5c` |
| `status.vc-jwt`        | `81271c1c6332f1d0920fe389dec9adba5945f63d9cf7e817d1a42c26eeabb5fe` |
| `manifest.json`        | `4f69b9e68bbb8f857cc81aa84e71904b8d1680608d016463d3cc67189e7bd5bb` |
| `expected-report.json` | `b967f34f9749ae3a70920cc76941f5aa893e4f79dec2b349af5457b57b7fb106` |
| `PROVENANCE.json`      | `96a5390d1f12fe414607ee2989bc01ad931395b7b93bf8cb0351d571b9f9df0e` |

## Executable invariant coverage

The dedicated tests cover the following claims using real ES256 signatures,
strict schemas, and single-field mutations:

- `test/core/verify.test.ts` proves coherent active evidence, signed-only
  `jti` privacy, direct and nested digest-prefix binding, circuit-version
  equality/mismatch and honest legacy `NOT_ASSESSED`, policy TTL and expiry
  binding, projected receipt header/JWK binding, trusted re-signed receipt and
  status contradictions, tampered signatures as indeterminate, deterministic
  expiry boundaries, and `require_active` metamorphic behavior.
- The same core suite proves a signed suspension bit yields
  `COHERENT / SUSPENDED / NOT_SATISFIED`. A compact but malformed status token
  yields `INDETERMINATE` with `STATUS_CREDENTIAL_MALFORMED`; the token is not
  copied into the report.
- The same suite exercises a real old/current two-key release/live overlap:
  an old protected-kid receipt passes while the current key is also present,
  a newer receipt remains valid when only the current key remains, and old-key
  removal or an unknown protected kid fails closed with `RECEIPT_KEY_UNKNOWN`.
  The service suite repeats the old/new/removal path through the provider
  envelope and canonical report parser.
- `test/crypto/jws.test.ts` covers ES256/typ/kid/critical-header/content-type
  constraints, compact-format and signature-width failures, public-only P-256
  key validation, private-material rejection, thumbprints, and rotation.
- `test/crypto/receipt.test.ts` covers complete signed claims including
  required `jti`, missing-claim failures, the rejected legacy status path,
  trusted audience/issuer/subject conflicts, signature tampering, unknown
  kids, and the exact clock tolerance boundaries.
- `test/crypto/status.test.ts` covers signed active status, trusted issuer,
  subject, identifier, and purpose conflicts, tampered and unknown keys,
  validity windows, canonical indexes, bounded gzip encoding, and range
  failures.
- `test/crypto/trust.test.ts` covers strict top-level, retention, live-JWKS,
  and JWK fields; required `ext=true`; private-material rejection; digest
  pinning; key-order canonicalization; historical overlap; same-kid/different
  key conflict; and empty/missing independent pins.
- `test/service/verify-proof-asset-record.test.ts` proves lossless provider
  delegation, canonical mapping for unavailable/malformed/timeout/abort
  outcomes, caller cancellation preservation, invalid-input and clock guards,
  redaction of provider error text, and the rotation path above.

The core and service tests parse returned reports through the shared report
schema. No test relies on a fake literal signature for a positive case, and no
pure-core test performs network I/O.

## Commands and observed results

Run from the standalone worktree:

```text
npm run check -- --pretty false
npm run build
npm run lint -- --no-warn-ignored
npm run format:check
npm run test:unit -- --reporter=dot
npx vitest run test/core test/crypto test/service test/mcp/parity.test.ts --reporter=dot
npx vitest run test/core/immutable-fixture.test.ts --reporter=verbose
```

Observed results for this checkpoint:

- strict typecheck: PASS;
- build: PASS;
- ESLint with warnings disallowed: PASS;
- repository Prettier check: PASS;
- enforced unit suite: 17 files, 291 tests passed;
- core/crypto/service plus MCP parity focus: 8 files, 79 tests passed;
- immutable vector gate: 1 file, 2 tests passed, with all 7 artifact hashes
  matching `SHA256SUMS`.

## Evidence boundary and remaining gates

There is no known core/crypto/service semantic failure in the local suites
listed above. The old/current rotation test uses runtime-generated ephemeral
test keys as supplemental cryptographic coverage; the one-key immutable vector
is the fixed byte oracle. This proves consumer behavior but does not prove
that deployed PAR retains historical keys for the full receipt-validity and
rollback horizons.

The following are release-only or cross-lane gates and remain unclaimed here:

- PAR historical-key publication/retention and runtime `audit=omit` non-
  invocation evidence;
- canonical website origin configuration and immutable deployment revisions;
- remote CI enforcement, supported-platform matrix, package tarball and empty
  consumer installation, provenance/SBOM/license evidence, and publication;
- live canonical-origin verification, DNS/TLS behavior, and production status
  or bundle compatibility;
- MCP Inspector/official conformance and final CLI/MCP release evidence; and
- independent final audit disposition and the contract score gate of at least
  97/100.

No production data, credentials, signing private keys, network state, or
source-control history was changed for this evidence record.
