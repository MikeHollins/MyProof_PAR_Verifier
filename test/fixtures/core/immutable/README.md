# Immutable signed core fixture

These files are a fixed, independently recorded wire vector for the pure verifier. The signed receipt and VC-JWT were generated once with v22.22.3's built-in `node:crypto` ECDSA P-256 signer using an ephemeral key; the private key was not persisted. The fixed verification clock is 2024-12-08T00:00:00.000Z (1733616000000). The signed receipt contains a `jti`, while the public `receipt.claims` projection intentionally omits it.

The vector is producer-shaped (`audit: null`, finite omitted audit markers, exact status projection, provenance and metadata). `expected-report.json` is a byte-pinned contract snapshot; executable core tests independently mutate the fixed bytes and verify the resulting classifications. No network or production credentials are involved.

Generator metadata is in [PROVENANCE.json](./PROVENANCE.json). Verify every artifact with [SHA256SUMS](./SHA256SUMS).
