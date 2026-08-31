# Provider fixtures

`producer-omit-wire.json` is a byte-for-byte copy of PAR's checked-in
`server/fixtures/public-verification-audit-omit.v1.json`. Its producer-file
SHA-256 is
`4b765d27c75606c03da3fdd4d47fa2605e1f2117ebb96a97076ca453cb78fa88`.
The corresponding compact Express JSON wire (`JSON.stringify(JSON.parse(raw))`)
SHA-256 is
`ff7043feb3cf7c646adce0695468d6d2978a402474599198e4335de4e7483404`.
The provider gate pins both hashes, while the end-to-end provider test is the
single positive semantic-preservation check at the shared seam. The fixture
itself must not be reserialized or locally reconstructed.

The exact bundle is producer-authoritative for transport shape and field
preservation, but its embedded `receipt.publicJwk` is not a trust root. The
provider fetches receipt keys separately and tests that the separately fetched
JWKS is not silently replaced by the embedded key. The receipt signature and
status credential in this fixture are structural values; this fixture must not
be used as proof of a `COHERENT` result.

`structural-receipt-jwks.json` and `structural-status.vc-jwt` remain bounded
transport fixtures for response-shape tests, not signed golden evidence.
Signed golden fixtures and private test-key custody belong to the core and
cross-boundary fixture lane.

The provider tests pin the public wire paths observed in the PAR source:

- receipt keys: `/api/public/receipts/jwks.json`;
- verification bundle: `/api/public/proof-assets/{asset-id}/verification-bundle?audit=omit`;
- status list: `/status/{revocation|suspension}/default`.

The provider's fixed host (`https://par.myproof.ai`), HTTPS requirement, and
exact response URL check establish an application-level origin invariant:
callers cannot select a host, scheme, port, credentials, redirect target, or
alternate path. They do not independently prove DNS resolution or the
certificate chain; those properties remain the responsibility of the
platform TLS stack and the bounded canonical live probe.
