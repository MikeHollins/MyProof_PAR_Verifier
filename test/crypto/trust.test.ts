import { describe, expect, it } from "vitest";
import {
  createIndependentPublicJwk,
  createSignedFixture,
} from "../fixtures/core/signed-fixtures.js";
import {
  computeManifestDigest,
  intersectReceiptTrust,
  parseReceiptJwks,
  validateReleaseTrustManifest,
  type JsonWebKeyLike,
  type ReleaseTrustManifest,
} from "../../src/crypto/trust.js";

function validTrust() {
  const trust = createSignedFixture().trust;
  return {
    manifest: trust.manifest as ReleaseTrustManifest,
    expected_manifest_digest: trust.expected_manifest_digest,
  };
}

function repin(
  payload: Omit<ReleaseTrustManifest, "manifest_digest" | "authenticated">,
): ReleaseTrustManifest {
  return {
    ...payload,
    manifest_digest: computeManifestDigest(payload),
    authenticated: true,
  };
}

describe("strict release trust artifact", () => {
  it("accepts the exact authenticated artifact and live key intersection", () => {
    const trust = validTrust();
    expect(validateReleaseTrustManifest(trust.manifest, trust.expected_manifest_digest)).toEqual({
      ok: true,
      manifest: trust.manifest,
    });
    expect(
      intersectReceiptTrust(
        trust.manifest,
        { keys: trust.manifest.receipt_keys },
        { expectedManifestDigest: trust.expected_manifest_digest },
      ).ok,
    ).toBe(true);
  });

  it("rejects unsigned unknown fields at every authenticated manifest boundary", () => {
    const trust = validTrust();
    const topLevel = { ...trust.manifest, alternate_origin: "https://evil.example" };
    const nestedRetention = {
      ...trust.manifest,
      key_retention: {
        ...trust.manifest.key_retention,
        alternate_origin: "https://evil.example",
      },
    };
    const [firstKey, ...remainingKeys] = trust.manifest.receipt_keys;
    expect(firstKey).toBeDefined();
    const nestedJwk = {
      ...trust.manifest,
      receipt_keys: [{ ...firstKey, x5u: "https://evil.example/key" }, ...remainingKeys],
    };

    for (const candidate of [topLevel, nestedRetention, nestedJwk]) {
      expect(validateReleaseTrustManifest(candidate, trust.expected_manifest_digest)).toMatchObject(
        {
          ok: false,
        },
      );
    }
  });

  it("requires the complete retention contract and exact public JWK shape", () => {
    const trust = validTrust();
    const withoutRetention = { ...trust.manifest } as Partial<ReleaseTrustManifest>;
    delete withoutRetention.key_retention;
    expect(
      validateReleaseTrustManifest(withoutRetention, trust.expected_manifest_digest),
    ).toMatchObject({ ok: false, code: "TRUST_MANIFEST_SCHEMA_INVALID" });

    const key = trust.manifest.receipt_keys[0]!;
    const withoutExt = { ...key };
    delete withoutExt.ext;
    const unsigned = {
      schema_version: trust.manifest.schema_version,
      canonical_origin: trust.manifest.canonical_origin,
      receipt_issuer: trust.manifest.receipt_issuer,
      receipt_keys: [withoutExt as JsonWebKeyLike],
      key_retention: trust.manifest.key_retention,
    };
    const repinned = repin(unsigned);
    expect(validateReleaseTrustManifest(repinned, repinned.manifest_digest)).toMatchObject({
      ok: false,
      code: "TRUST_MANIFEST_KEYS_INVALID",
    });
  });

  it("rejects additive JWKS fields even when the exact keys remain valid", () => {
    const trust = validTrust();
    expect(
      parseReceiptJwks({
        keys: trust.manifest.receipt_keys,
        alternate_origin: "https://evil.example",
      }),
    ).toMatchObject({ ok: false, code: "LIVE_JWKS_INVALID" });
  });

  it("accepts a producer JWKS that omits optional ext without weakening key validation", () => {
    const trust = validTrust();
    const key = trust.manifest.receipt_keys[0]!;
    const withoutExt = { ...key };
    delete withoutExt.ext;

    expect(parseReceiptJwks({ keys: [withoutExt] })).toEqual({ keys: [withoutExt] });
    expect(
      intersectReceiptTrust(
        trust.manifest,
        { keys: [withoutExt] },
        { expectedManifestDigest: trust.expected_manifest_digest },
      ),
    ).toMatchObject({
      ok: true,
      manifestKeyCount: 1,
      liveKeyCount: 1,
      intersectionKids: [key.kid],
    });

    expect(parseReceiptJwks({ keys: [{ ...withoutExt, ext: false }] })).toMatchObject({
      ok: false,
      code: "LIVE_JWKS_KEY_INVALID",
    });
  });

  it("canonicalizes harmless JSON member ordering but not semantic changes", () => {
    const trust = validTrust();
    const key = trust.manifest.receipt_keys[0]!;
    const reorderedKey: JsonWebKeyLike = {
      ext: true,
      key_ops: ["verify"],
      use: "sig",
      alg: "ES256",
      kid: String(key.kid),
      y: String(key.y),
      x: String(key.x),
      crv: "P-256",
      kty: "EC",
    };
    const reordered = repin({
      key_retention: {
        historical_keys_required: trust.manifest.key_retention.historical_keys_required,
        rollback_horizon_seconds: trust.manifest.key_retention.rollback_horizon_seconds,
        receipt_validity_horizon_seconds:
          trust.manifest.key_retention.receipt_validity_horizon_seconds,
      },
      receipt_keys: [reorderedKey],
      receipt_issuer: trust.manifest.receipt_issuer,
      canonical_origin: trust.manifest.canonical_origin,
      schema_version: trust.manifest.schema_version,
    });
    expect(reordered.manifest_digest).toBe(trust.expected_manifest_digest);
    expect(validateReleaseTrustManifest(reordered, trust.expected_manifest_digest).ok).toBe(true);
  });

  it("retains historical keys only through an overlapping release/live intersection", () => {
    const trust = validTrust();
    const current = trust.manifest.receipt_keys[0]!;
    const historical = createIndependentPublicJwk("fixture-historical-es256");
    const rotated = repin({
      schema_version: trust.manifest.schema_version,
      canonical_origin: trust.manifest.canonical_origin,
      receipt_issuer: trust.manifest.receipt_issuer,
      receipt_keys: [current, historical],
      key_retention: trust.manifest.key_retention,
    });
    const intersection = intersectReceiptTrust(
      rotated,
      { keys: [historical, current] },
      { expectedManifestDigest: rotated.manifest_digest },
    );
    expect(intersection).toMatchObject({
      ok: true,
      intersectionKids: ["fixture-historical-es256", current.kid],
    });
  });

  it("rejects same-kid key replacement, even when the replacement is valid P-256", () => {
    const trust = validTrust();
    const current = trust.manifest.receipt_keys[0]!;
    const replacement = createIndependentPublicJwk(String(current.kid));
    expect(
      intersectReceiptTrust(
        trust.manifest,
        { keys: [replacement] },
        { expectedManifestDigest: trust.expected_manifest_digest },
      ),
    ).toMatchObject({ ok: false, code: "TRUST_KEY_INTERSECTION_CONFLICT" });

    const rehashedReplacement = repin({
      schema_version: trust.manifest.schema_version,
      canonical_origin: trust.manifest.canonical_origin,
      receipt_issuer: trust.manifest.receipt_issuer,
      receipt_keys: [replacement],
      key_retention: trust.manifest.key_retention,
    });
    expect(
      validateReleaseTrustManifest(rehashedReplacement, trust.expected_manifest_digest),
    ).toMatchObject({ ok: false, code: "TRUST_MANIFEST_DIGEST_MISMATCH" });
  });

  it("rejects private material and missing independent digest pins", () => {
    const trust = validTrust();
    const key = trust.manifest.receipt_keys[0]!;
    const privateKeyManifest = repin({
      schema_version: trust.manifest.schema_version,
      canonical_origin: trust.manifest.canonical_origin,
      receipt_keys: [{ ...key, d: "not-public" }],
      receipt_issuer: trust.manifest.receipt_issuer,
      key_retention: trust.manifest.key_retention,
    });
    expect(
      validateReleaseTrustManifest(privateKeyManifest, privateKeyManifest.manifest_digest),
    ).toMatchObject({ ok: false, code: "TRUST_MANIFEST_KEYS_INVALID" });
    expect(validateReleaseTrustManifest(trust.manifest, "")).toMatchObject({
      ok: false,
      code: "TRUST_MANIFEST_DIGEST_INVALID",
    });
  });
});
