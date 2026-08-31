import { createHash, timingSafeEqual } from "node:crypto";
import { importVerificationKey, publicJwkThumbprint, type JsonWebKeyLike } from "./jws.js";

export type { JsonWebKeyLike } from "./jws.js";

export const CANONICAL_PAR_ORIGIN = "https://par.myproof.ai" as const;
export const CANONICAL_RECEIPT_ISSUER = "did:web:par.myproof.ai" as const;
export const TRUST_MANIFEST_SCHEMA = "myproof.par.release-trust-manifest.v1" as const;

/** Retention assertions are package metadata, never a source of trust. */
export interface ReleaseTrustKeyRetention {
  receipt_validity_horizon_seconds: number;
  rollback_horizon_seconds: number;
  historical_keys_required: boolean;
}

export interface ReceiptJwks {
  keys: readonly JsonWebKeyLike[];
}

/**
 * The release manifest is generated and pinned by the release/configuration
 * lane.  `authenticated` is an explicit boundary: the pure core never
 * fetches or discovers trust material.  `manifest_digest` lets the release
 * loader provide an immutable content digest, and `expectedManifestDigest`
 * below lets a caller prove that it loaded the exact release artifact.
 */
export interface ReleaseTrustManifest {
  schema_version: typeof TRUST_MANIFEST_SCHEMA;
  canonical_origin: typeof CANONICAL_PAR_ORIGIN;
  receipt_issuer: typeof CANONICAL_RECEIPT_ISSUER;
  receipt_keys: readonly JsonWebKeyLike[];
  manifest_digest: string;
  key_retention: ReleaseTrustKeyRetention;
  authenticated: true;
}

export type TrustFailureCode =
  | "TRUST_MANIFEST_MISSING"
  | "TRUST_MANIFEST_UNAUTHENTICATED"
  | "TRUST_MANIFEST_SCHEMA_INVALID"
  | "TRUST_MANIFEST_ORIGIN_INVALID"
  | "TRUST_MANIFEST_ISSUER_INVALID"
  | "TRUST_MANIFEST_DIGEST_INVALID"
  | "TRUST_MANIFEST_DIGEST_MISMATCH"
  | "TRUST_MANIFEST_KEYS_INVALID"
  | "LIVE_JWKS_INVALID"
  | "LIVE_JWKS_DUPLICATE_KID"
  | "LIVE_JWKS_KEY_INVALID"
  | "TRUST_KEY_INTERSECTION_EMPTY"
  | "TRUST_KEY_INTERSECTION_CONFLICT";

export interface TrustIntersectionSuccess {
  ok: true;
  /** Only keys present in both the release manifest and the live JWKS. */
  keys: readonly JsonWebKeyLike[];
  manifestKeyCount: number;
  liveKeyCount: number;
  intersectionKids: readonly string[];
}

export interface TrustIntersectionFailure {
  ok: false;
  code: TrustFailureCode;
  reason: string;
}

export type TrustIntersectionResult = TrustIntersectionSuccess | TrustIntersectionFailure;

export interface TrustIntersectionOptions {
  /** Digest pinned by the release artifact, not supplied by remote input. */
  expectedManifestDigest: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonicalExpected = [...expected].sort();
  return (
    actual.length === canonicalExpected.length &&
    actual.every((key, index) => key === canonicalExpected[index])
  );
}

function digestBytes(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function digestEquals(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(actual) || !/^[a-f0-9]{64}$/.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "ascii"), Buffer.from(expected, "ascii"));
}

/** Stable JSON for the release-manifest integrity field only. */
export function canonicalizeManifest(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("TRUST_MANIFEST_DIGEST_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeManifest).join(",")}]`;
  if (!isRecord(value)) throw new Error("TRUST_MANIFEST_DIGEST_INVALID");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeManifest(value[key])}`)
    .join(",")}}`;
}

export function computeManifestDigest(
  manifest: Omit<ReleaseTrustManifest, "manifest_digest" | "authenticated">,
): string {
  return digestBytes(canonicalizeManifest(manifest));
}

function parseRetention(value: unknown): ReleaseTrustKeyRetention | undefined {
  if (!isRecord(value)) return undefined;
  if (
    !hasExactKeys(value, [
      "receipt_validity_horizon_seconds",
      "rollback_horizon_seconds",
      "historical_keys_required",
    ])
  ) {
    return undefined;
  }
  if (
    !Number.isSafeInteger(value.receipt_validity_horizon_seconds) ||
    Number(value.receipt_validity_horizon_seconds) <= 0 ||
    !Number.isSafeInteger(value.rollback_horizon_seconds) ||
    Number(value.rollback_horizon_seconds) <= 0 ||
    typeof value.historical_keys_required !== "boolean"
  )
    return undefined;
  return {
    receipt_validity_horizon_seconds: Number(value.receipt_validity_horizon_seconds),
    rollback_horizon_seconds: Number(value.rollback_horizon_seconds),
    historical_keys_required: value.historical_keys_required,
  };
}

function parseKeyRing(
  value: unknown,
  duplicateCode: TrustFailureCode,
  requireExt: boolean,
): { ok: true; keys: JsonWebKeyLike[] } | { ok: false; code: TrustFailureCode; reason: string } {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    return {
      ok: false,
      code:
        duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
          ? "LIVE_JWKS_INVALID"
          : "TRUST_MANIFEST_KEYS_INVALID",
      reason: "A non-empty bounded key ring is required",
    };
  }
  const byKid = new Map<string, JsonWebKeyLike>();
  for (const candidate of value) {
    if (
      !isRecord(candidate) ||
      typeof candidate.kid !== "string" ||
      candidate.kid.length === 0 ||
      candidate.kid.length > 256
    ) {
      return {
        ok: false,
        code:
          duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
            ? "LIVE_JWKS_KEY_INVALID"
            : "TRUST_MANIFEST_KEYS_INVALID",
        reason: "Every public key must have a bounded kid",
      };
    }
    const requiredFields = ["kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"];
    const exactShape = requireExt
      ? hasExactKeys(candidate, [...requiredFields, "ext"])
      : hasExactKeys(candidate, requiredFields) ||
        hasExactKeys(candidate, [...requiredFields, "ext"]);
    if (!exactShape) {
      return {
        ok: false,
        code:
          duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
            ? "LIVE_JWKS_KEY_INVALID"
            : "TRUST_MANIFEST_KEYS_INVALID",
        reason: "Every public key must use the exact release JWK shape",
      };
    }
    if (candidate.ext !== undefined && candidate.ext !== true) {
      return {
        ok: false,
        code:
          duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
            ? "LIVE_JWKS_KEY_INVALID"
            : "TRUST_MANIFEST_KEYS_INVALID",
        reason: "Every release/live key must declare ext=true when ext is present",
      };
    }
    // A release/live public key ring must never carry private EC material,
    // even as an ignored extension. This keeps the trust seam one-way.
    for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
      if (privateField in candidate) {
        return {
          ok: false,
          code:
            duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
              ? "LIVE_JWKS_KEY_INVALID"
              : "TRUST_MANIFEST_KEYS_INVALID",
          reason: "Private key material is not accepted",
        };
      }
    }
    try {
      importVerificationKey(candidate as JsonWebKeyLike);
    } catch {
      return {
        ok: false,
        code:
          duplicateCode === "LIVE_JWKS_DUPLICATE_KID"
            ? "LIVE_JWKS_KEY_INVALID"
            : "TRUST_MANIFEST_KEYS_INVALID",
        reason: "Every key must be an ES256 P-256 verification key",
      };
    }
    if (byKid.has(candidate.kid)) {
      return { ok: false, code: duplicateCode, reason: `Duplicate key id ${candidate.kid}` };
    }
    byKid.set(candidate.kid, candidate as JsonWebKeyLike);
  }
  return { ok: true, keys: [...byKid.values()] };
}

export function parseReceiptJwks(value: unknown): ReceiptJwks | TrustIntersectionFailure {
  if (!isRecord(value))
    return { ok: false, code: "LIVE_JWKS_INVALID", reason: "JWKS must be an object" };
  if (!hasExactKeys(value, ["keys"])) {
    return {
      ok: false,
      code: "LIVE_JWKS_INVALID",
      reason: "JWKS must contain only the public key ring",
    };
  }
  // `ext` is optional JWK metadata in the producer-owned public JWKS.  Keep
  // the live-key parser aligned with that wire contract while retaining the
  // strict value check whenever the member is present.
  const parsed = parseKeyRing(value.keys, "LIVE_JWKS_DUPLICATE_KID", false);
  if (!parsed.ok) return parsed;
  return { keys: parsed.keys };
}

export function validateReleaseTrustManifest(
  manifest: unknown,
  expectedManifestDigest: string,
): TrustIntersectionFailure | { ok: true; manifest: ReleaseTrustManifest } {
  if (!isRecord(manifest))
    return {
      ok: false,
      code: "TRUST_MANIFEST_MISSING",
      reason: "A release trust manifest is required",
    };
  if (
    !hasExactKeys(manifest, [
      "schema_version",
      "canonical_origin",
      "receipt_issuer",
      "receipt_keys",
      "manifest_digest",
      "key_retention",
      "authenticated",
    ])
  ) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_SCHEMA_INVALID",
      reason: "Release trust manifest has an unexpected shape",
    };
  }
  if (
    typeof expectedManifestDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(expectedManifestDigest)
  ) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_DIGEST_INVALID",
      reason: "A release-pinned trust manifest digest is required",
    };
  }
  if (manifest.authenticated !== true)
    return {
      ok: false,
      code: "TRUST_MANIFEST_UNAUTHENTICATED",
      reason: "Only an authenticated release trust manifest is accepted",
    };
  if (manifest.schema_version !== TRUST_MANIFEST_SCHEMA)
    return {
      ok: false,
      code: "TRUST_MANIFEST_SCHEMA_INVALID",
      reason: "Unsupported release trust manifest schema",
    };
  if (manifest.canonical_origin !== CANONICAL_PAR_ORIGIN)
    return {
      ok: false,
      code: "TRUST_MANIFEST_ORIGIN_INVALID",
      reason: "Release trust origin is not the canonical PAR origin",
    };
  if (manifest.receipt_issuer !== CANONICAL_RECEIPT_ISSUER)
    return {
      ok: false,
      code: "TRUST_MANIFEST_ISSUER_INVALID",
      reason: "Release receipt issuer is not canonical",
    };
  if (
    typeof manifest.manifest_digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(manifest.manifest_digest)
  ) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_DIGEST_INVALID",
      reason: "Release trust manifest digest is invalid",
    };
  }
  const keys = parseKeyRing(manifest.receipt_keys, "TRUST_KEY_INTERSECTION_CONFLICT", true);
  if (!keys.ok) return keys;
  const retention = parseRetention(manifest.key_retention);
  if (retention === undefined) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_SCHEMA_INVALID",
      reason: "Release key-retention metadata is invalid",
    };
  }
  const payload = {
    schema_version: TRUST_MANIFEST_SCHEMA,
    canonical_origin: CANONICAL_PAR_ORIGIN,
    receipt_issuer: CANONICAL_RECEIPT_ISSUER,
    receipt_keys: keys.keys,
    key_retention: retention,
  } satisfies Omit<ReleaseTrustManifest, "manifest_digest" | "authenticated">;
  const computed = computeManifestDigest(payload);
  if (!digestEquals(computed, manifest.manifest_digest)) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_DIGEST_MISMATCH",
      reason: "Release trust manifest content digest does not match",
    };
  }
  if (!digestEquals(manifest.manifest_digest, expectedManifestDigest)) {
    return {
      ok: false,
      code: "TRUST_MANIFEST_DIGEST_MISMATCH",
      reason: "Release trust manifest is not the pinned artifact",
    };
  }
  return {
    ok: true,
    manifest: {
      schema_version: TRUST_MANIFEST_SCHEMA,
      canonical_origin: CANONICAL_PAR_ORIGIN,
      receipt_issuer: CANONICAL_RECEIPT_ISSUER,
      receipt_keys: keys.keys,
      manifest_digest: manifest.manifest_digest,
      key_retention: retention,
      authenticated: true,
    },
  };
}

export function intersectReceiptTrust(
  manifestInput: unknown,
  liveJwksInput: unknown,
  options: TrustIntersectionOptions,
): TrustIntersectionResult {
  const manifestResult = validateReleaseTrustManifest(
    manifestInput,
    options.expectedManifestDigest,
  );
  if (!manifestResult.ok) return manifestResult;
  const jwksResult = parseReceiptJwks(liveJwksInput);
  if (!("keys" in jwksResult)) return jwksResult;

  const liveByKid = new Map(jwksResult.keys.map((key) => [key.kid as string, key]));
  const matches: JsonWebKeyLike[] = [];
  for (const manifestKey of manifestResult.manifest.receipt_keys) {
    const liveKey = liveByKid.get(manifestKey.kid as string);
    if (!liveKey) continue;
    let sameKey: boolean;
    try {
      sameKey = publicJwkThumbprint(manifestKey) === publicJwkThumbprint(liveKey);
    } catch {
      return {
        ok: false,
        code: "TRUST_KEY_INTERSECTION_CONFLICT",
        reason: "A matching kid does not contain the same public key",
      };
    }
    if (!sameKey)
      return {
        ok: false,
        code: "TRUST_KEY_INTERSECTION_CONFLICT",
        reason: "A matching kid does not contain the same public key",
      };
    matches.push(liveKey);
  }
  if (matches.length === 0)
    return {
      ok: false,
      code: "TRUST_KEY_INTERSECTION_EMPTY",
      reason: "The live receipt JWKS has no release-trusted key",
    };
  return {
    ok: true,
    keys: matches,
    manifestKeyCount: manifestResult.manifest.receipt_keys.length,
    liveKeyCount: jwksResult.keys.length,
    intersectionKids: matches.map((key) => key.kid as string).sort(),
  };
}

export function keyForProtectedKid(
  keys: readonly JsonWebKeyLike[],
  kid: unknown,
): JsonWebKeyLike | null {
  return typeof kid === "string" ? (keys.find((key) => key.kid === kid) ?? null) : null;
}
