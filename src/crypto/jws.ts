import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import { decodeBase64Url, decodeBase64UrlJson, encodeBase64Url } from "./base64url.js";

export const ES256_ALGORITHM = "ES256" as const;

export interface JsonWebKeyLike {
  kty?: string | undefined;
  crv?: string | undefined;
  x?: string | undefined;
  y?: string | undefined;
  d?: string | undefined;
  alg?: string | undefined;
  kid?: string | undefined;
  use?: string | undefined;
  key_ops?: string[] | undefined;
  ext?: boolean | undefined;
  [key: string]: unknown;
}

export interface CompactJws {
  readonly encodedHeader: string;
  readonly encodedPayload: string;
  readonly encodedSignature: string;
  readonly signingInput: string;
  readonly header: Record<string, unknown>;
  readonly payloadBytes: Uint8Array;
  readonly payload: unknown;
  readonly signature: Uint8Array;
}

const MAX_COMPACT_JWS_BYTES = 1_048_576;
const ALLOWED_HEADER_NAMES = new Set(["alg", "typ", "kid", "cty"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse a compact JWS without interpreting any claims as trusted. */
export function parseCompactJws(token: unknown, expectedTyp?: string): CompactJws {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_COMPACT_JWS_BYTES) {
    throw new Error("INVALID_JWS_FORMAT");
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("INVALID_JWS_FORMAT");
  }
  const encodedHeader = parts[0]!;
  const encodedPayload = parts[1]!;
  const encodedSignature = parts[2]!;
  const headerValue = decodeBase64UrlJson(encodedHeader, "jws_header");
  if (!isRecord(headerValue)) throw new Error("INVALID_JWS_HEADER");

  for (const key of Object.keys(headerValue)) {
    if (!ALLOWED_HEADER_NAMES.has(key)) throw new Error("UNSUPPORTED_JWS_HEADER");
  }
  if (headerValue.alg !== ES256_ALGORITHM) throw new Error("UNSUPPORTED_JWS_ALGORITHM");
  if (expectedTyp !== undefined && headerValue.typ !== expectedTyp) {
    throw new Error("JWS_TYPE_MISMATCH");
  }
  if (
    typeof headerValue.kid !== "string" ||
    headerValue.kid.length === 0 ||
    headerValue.kid.length > 256
  ) {
    throw new Error("JWS_KID_REQUIRED");
  }
  if (headerValue.cty !== undefined && typeof headerValue.cty !== "string") {
    throw new Error("INVALID_JWS_CONTENT_TYPE");
  }

  const payloadBytes = decodeBase64Url(encodedPayload, "jws_payload");
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    throw new Error("INVALID_JWS_PAYLOAD");
  }
  const signature = decodeBase64Url(encodedSignature, "jws_signature");
  // ES256 JWS signatures are the fixed-width IEEE P1363 r || s form.
  if (signature.length !== 64) throw new Error("INVALID_ES256_SIGNATURE_LENGTH");

  return {
    encodedHeader,
    encodedPayload,
    encodedSignature,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    header: headerValue,
    payloadBytes,
    payload,
    signature,
  };
}

/**
 * Validate and import a public P-256 JWK.  The returned KeyObject is only
 * usable for signature verification; private material and caller-selected
 * key types are rejected.
 */
export function importVerificationKey(jwk: JsonWebKeyLike): KeyObject {
  if (!isRecord(jwk)) throw new Error("INVALID_VERIFICATION_KEY");
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new Error("INVALID_ES256_VERIFICATION_KEY");
  }
  for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
    if (privateField in jwk) throw new Error("PRIVATE_KEY_NOT_ALLOWED");
  }
  if (jwk.alg !== undefined && jwk.alg !== ES256_ALGORITHM)
    throw new Error("VERIFICATION_KEY_ALGORITHM_MISMATCH");
  if (jwk.use !== undefined && jwk.use !== "sig") throw new Error("VERIFICATION_KEY_USE_MISMATCH");
  if (jwk.ext !== undefined && jwk.ext !== true) throw new Error("VERIFICATION_KEY_EXT_MISMATCH");
  if (
    jwk.key_ops !== undefined &&
    (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify"))
  ) {
    throw new Error("VERIFICATION_KEY_OPERATION_MISMATCH");
  }
  // Validate coordinates as canonical base64url and expected P-256 width.
  if (
    decodeBase64Url(jwk.x, "jwk_x").length !== 32 ||
    decodeBase64Url(jwk.y, "jwk_y").length !== 32
  ) {
    throw new Error("INVALID_P256_COORDINATE_LENGTH");
  }
  try {
    return createPublicKey({ key: jwk as unknown as JsonWebKey, format: "jwk" });
  } catch {
    throw new Error("INVALID_ES256_VERIFICATION_KEY");
  }
}

export function verifyCompactJwsSignature(jws: CompactJws, jwk: JsonWebKeyLike): boolean {
  const key = importVerificationKey(jwk);
  return verifySignature(
    "sha256",
    Buffer.from(jws.signingInput, "ascii"),
    { key, dsaEncoding: "ieee-p1363" },
    Buffer.from(jws.signature),
  );
}

/**
 * RFC 7638-style public-key thumbprint for an EC P-256 key.  This is used for
 * trust-manifest/live-JWKS intersection and deliberately excludes metadata
 * such as `kid`, `use`, or `alg`.
 */
export function publicJwkThumbprint(jwk: JsonWebKeyLike): string {
  const key = importVerificationKey(jwk);
  // createPublicKey verifies the structure, while the raw coordinates below
  // remain the canonical RFC 7638 members for an EC key.
  void key;
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return encodeBase64Url(new Uint8Array(createHash("sha256").update(canonical, "utf8").digest()));
}
