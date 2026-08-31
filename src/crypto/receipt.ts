import { keyForProtectedKid } from "./trust.js";
import { parseCompactJws, verifyCompactJwsSignature, type JsonWebKeyLike } from "./jws.js";
import { CANONICAL_PAR_ORIGIN, CANONICAL_RECEIPT_ISSUER } from "./trust.js";

export const RECEIPT_AUDIENCE = "myproof-proof-asset" as const;
export const RECEIPT_JWS_TYPE = "JWT" as const;
export const RECEIPT_CLOCK_TOLERANCE_SECONDS = 60;

export interface ReceiptStatusRef {
  statusListUrl: string;
  statusListIndex: string;
  statusPurpose: "revocation" | "suspension";
}

export interface ReceiptClaims {
  proof_digest: string;
  policy_hash: string;
  constraint_hash: string;
  status_ref: ReceiptStatusRef;
  jti: string;
  aud: string;
  exp: number;
  nbf: number;
  iat?: number;
  iss?: string;
  sub?: string;
  proof_asset_commitment?: string;
  policy_cid?: string;
  circuit_or_schema_id?: string;
  circuit_version?: number;
  audit_event_id?: string;
  audit_event_hash?: string;
  upstream_receipt_hash?: string;
  created_at?: string;
  environment?: "sandbox" | "production";
  configuration_revision?: number;
  policy_ttl_seconds?: number;
  proof_expires_at?: string;
  freshness_source?: "policy";
  nonce?: string;
  [key: string]: unknown;
}

export type ReceiptReasonCode =
  | "RECEIPT_REQUIRED"
  | "RECEIPT_FORMAT_INVALID"
  | "RECEIPT_HEADER_INVALID"
  | "RECEIPT_KID_UNTRUSTED"
  | "RECEIPT_SIGNATURE_INVALID"
  | "RECEIPT_KEY_INVALID"
  | "RECEIPT_PAYLOAD_INVALID"
  | "RECEIPT_CLAIM_MISSING"
  | "RECEIPT_CLAIM_TYPE_INVALID"
  | "RECEIPT_ALGORITHM_INVALID"
  | "RECEIPT_AUDIENCE_MISMATCH"
  | "RECEIPT_ISSUER_MISMATCH"
  | "RECEIPT_SUBJECT_MISSING"
  | "RECEIPT_SUBJECT_MISMATCH"
  | "RECEIPT_TIME_INVALID"
  | "RECEIPT_NOT_YET_VALID"
  | "RECEIPT_EXPIRED"
  | "RECEIPT_STATUS_REF_INVALID"
  | "RECEIPT_POLICY_FRESHNESS_INVALID"
  | "RECEIPT_PROVENANCE_INVALID";

export interface ReceiptVerificationSuccess {
  ok: true;
  header: { alg: "ES256"; typ: "JWT"; kid: string };
  claims: ReceiptClaims;
}

export interface ReceiptVerificationFailure {
  ok: false;
  code: ReceiptReasonCode;
  reason: string;
  /** Internal classification hint; never serialized in the public report. */
  signature_verified?: boolean;
}

export type ReceiptVerificationResult = ReceiptVerificationSuccess | ReceiptVerificationFailure;

export interface ReceiptVerificationOptions {
  nowSeconds: number;
  expectedAssetId?: string;
  expectedAudience?: string;
  expectedIssuer?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringClaim(
  payload: Record<string, unknown>,
  name: string,
  required = false,
): string | undefined {
  const value = payload[name];
  if (value === undefined) {
    if (!required) return undefined;
    throw failure("RECEIPT_CLAIM_MISSING", `Receipt claim ${name} is required`);
  }
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
    throw failure(
      "RECEIPT_CLAIM_TYPE_INVALID",
      `Receipt claim ${name} must be a bounded non-empty string`,
    );
  }
  return value;
}

function integerClaim(
  payload: Record<string, unknown>,
  name: string,
  required = false,
): number | undefined {
  const value = payload[name];
  if (value === undefined) {
    if (!required) return undefined;
    throw failure("RECEIPT_CLAIM_MISSING", `Receipt claim ${name} is required`);
  }
  if (!Number.isSafeInteger(value)) {
    throw failure("RECEIPT_CLAIM_TYPE_INVALID", `Receipt claim ${name} must be a safe integer`);
  }
  return Number(value);
}

function parseCanonicalStatusUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048)
    throw failure("RECEIPT_STATUS_REF_INVALID", "Receipt status URL is invalid");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw failure("RECEIPT_STATUS_REF_INVALID", "Receipt status URL is invalid");
  }
  if (
    parsed.origin !== CANONICAL_PAR_ORIGIN ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.search ||
    parsed.hash ||
    // The v1 producer has one canonical status list per purpose.  In
    // particular, do not accept the historical `/status/lists/...` route or
    // caller-selected list identifiers as equivalent trust surfaces.
    !/^\/status\/(?:revocation|suspension)\/default$/.test(parsed.pathname)
  ) {
    throw failure(
      "RECEIPT_STATUS_REF_INVALID",
      "Receipt status URL is outside the canonical PAR status surface",
    );
  }
  return parsed.toString();
}

function normalizeClaims(
  payloadValue: unknown,
  options: ReceiptVerificationOptions,
): ReceiptClaims {
  if (!isRecord(payloadValue))
    throw failure("RECEIPT_PAYLOAD_INVALID", "Receipt payload must be a JSON object");
  const proof_digest = stringClaim(payloadValue, "proof_digest", true)!;
  const policy_hash = stringClaim(payloadValue, "policy_hash", true)!;
  const constraint_hash = stringClaim(payloadValue, "constraint_hash", true)!;
  const jti = stringClaim(payloadValue, "jti", true)!;
  const aud = stringClaim(payloadValue, "aud", true)!;
  const exp = integerClaim(payloadValue, "exp", true)!;
  const nbf = integerClaim(payloadValue, "nbf", true)!;
  const iat = integerClaim(payloadValue, "iat");
  const iss = stringClaim(payloadValue, "iss");
  const sub = stringClaim(payloadValue, "sub", true);
  const proof_asset_commitment = stringClaim(payloadValue, "proof_asset_commitment", true);
  const policy_cid = stringClaim(payloadValue, "policy_cid", true);

  if (aud !== (options.expectedAudience ?? RECEIPT_AUDIENCE)) {
    throw failure("RECEIPT_AUDIENCE_MISMATCH", "Receipt audience is not the public asset audience");
  }
  if (options.expectedIssuer !== undefined && iss !== options.expectedIssuer) {
    throw failure(
      "RECEIPT_ISSUER_MISMATCH",
      "Receipt issuer does not match the canonical release issuer",
    );
  }
  if (options.expectedAssetId !== undefined && sub !== options.expectedAssetId) {
    throw failure(
      "RECEIPT_SUBJECT_MISMATCH",
      "Receipt subject does not match the requested asset identifier",
    );
  }
  if (exp <= nbf) throw failure("RECEIPT_TIME_INVALID", "Receipt expiry must be after not-before");
  if (iat !== undefined && (iat > exp || iat < nbf - RECEIPT_CLOCK_TOLERANCE_SECONDS)) {
    throw failure(
      "RECEIPT_TIME_INVALID",
      "Receipt issued-at time is outside its validity interval",
    );
  }
  if (options.nowSeconds < nbf - RECEIPT_CLOCK_TOLERANCE_SECONDS) {
    throw failure("RECEIPT_NOT_YET_VALID", "Receipt is not yet valid at the verification clock");
  }
  if (options.nowSeconds > exp + RECEIPT_CLOCK_TOLERANCE_SECONDS) {
    throw failure("RECEIPT_EXPIRED", "Receipt is expired at the verification clock");
  }

  const statusRef = payloadValue.status_ref;
  if (!isRecord(statusRef))
    throw failure("RECEIPT_STATUS_REF_INVALID", "Receipt status_ref is required");
  const statusListUrl = parseCanonicalStatusUrl(statusRef.statusListUrl);
  if (
    typeof statusRef.statusListIndex !== "string" ||
    !/^(?:0|[1-9]\d*)$/.test(statusRef.statusListIndex)
  ) {
    throw failure(
      "RECEIPT_STATUS_REF_INVALID",
      "Receipt status index must be a canonical decimal string",
    );
  }
  const statusIndex = Number(statusRef.statusListIndex);
  if (!Number.isSafeInteger(statusIndex))
    throw failure("RECEIPT_STATUS_REF_INVALID", "Receipt status index is out of range");
  if (statusRef.statusPurpose !== "revocation" && statusRef.statusPurpose !== "suspension") {
    throw failure("RECEIPT_STATUS_REF_INVALID", "Receipt status purpose is invalid");
  }

  const environment = payloadValue.environment;
  const configuration_revision = payloadValue.configuration_revision;
  if ((environment === undefined) !== (configuration_revision === undefined)) {
    throw failure(
      "RECEIPT_PROVENANCE_INVALID",
      "Receipt environment and configuration revision must be paired",
    );
  }
  if (environment !== undefined && environment !== "sandbox" && environment !== "production") {
    throw failure("RECEIPT_PROVENANCE_INVALID", "Receipt environment is invalid");
  }
  if (
    configuration_revision !== undefined &&
    (!Number.isSafeInteger(configuration_revision) || Number(configuration_revision) < 0)
  ) {
    throw failure("RECEIPT_PROVENANCE_INVALID", "Receipt configuration revision is invalid");
  }

  const policy_ttl_seconds = integerClaim(payloadValue, "policy_ttl_seconds");
  const proof_expires_at = stringClaim(payloadValue, "proof_expires_at");
  const freshness_source = stringClaim(payloadValue, "freshness_source");
  const circuit_or_schema_id = stringClaim(payloadValue, "circuit_or_schema_id");
  const circuit_version = integerClaim(payloadValue, "circuit_version");
  const audit_event_id = stringClaim(payloadValue, "audit_event_id");
  const audit_event_hash = stringClaim(payloadValue, "audit_event_hash");
  const upstream_receipt_hash = stringClaim(payloadValue, "upstream_receipt_hash");
  const created_at = stringClaim(payloadValue, "created_at");
  const nonce = stringClaim(payloadValue, "nonce");
  const freshnessCount = [policy_ttl_seconds, proof_expires_at, freshness_source].filter(
    (value) => value !== undefined,
  ).length;
  if (freshnessCount !== 0 && freshnessCount !== 3)
    throw failure(
      "RECEIPT_POLICY_FRESHNESS_INVALID",
      "Receipt policy freshness claims must be complete",
    );
  if (policy_ttl_seconds !== undefined && policy_ttl_seconds <= 0)
    throw failure("RECEIPT_POLICY_FRESHNESS_INVALID", "Receipt policy TTL must be positive");
  if (proof_expires_at !== undefined && !Number.isFinite(Date.parse(proof_expires_at)))
    throw failure("RECEIPT_POLICY_FRESHNESS_INVALID", "Receipt policy expiry is invalid");
  if (freshness_source !== undefined && freshness_source !== "policy")
    throw failure("RECEIPT_POLICY_FRESHNESS_INVALID", "Receipt freshness source is invalid");

  return {
    proof_digest,
    policy_hash,
    constraint_hash,
    status_ref: {
      statusListUrl,
      statusListIndex: statusRef.statusListIndex,
      statusPurpose: statusRef.statusPurpose,
    },
    jti,
    aud,
    exp,
    nbf,
    ...(iat === undefined ? {} : { iat }),
    ...(iss === undefined ? {} : { iss }),
    ...(sub === undefined ? {} : { sub }),
    ...(proof_asset_commitment === undefined ? {} : { proof_asset_commitment }),
    ...(policy_cid === undefined ? {} : { policy_cid }),
    ...(circuit_or_schema_id === undefined ? {} : { circuit_or_schema_id }),
    ...(circuit_version === undefined ? {} : { circuit_version }),
    ...(audit_event_id === undefined ? {} : { audit_event_id }),
    ...(audit_event_hash === undefined ? {} : { audit_event_hash }),
    ...(upstream_receipt_hash === undefined ? {} : { upstream_receipt_hash }),
    ...(created_at === undefined ? {} : { created_at }),
    ...(environment === undefined ? {} : { environment: environment as "sandbox" | "production" }),
    ...(configuration_revision === undefined
      ? {}
      : { configuration_revision: Number(configuration_revision) }),
    ...(policy_ttl_seconds === undefined ? {} : { policy_ttl_seconds }),
    ...(proof_expires_at === undefined ? {} : { proof_expires_at }),
    ...(freshness_source === undefined ? {} : { freshness_source: "policy" as const }),
    ...(nonce === undefined ? {} : { nonce }),
  };
}

function failure(code: ReceiptReasonCode, reason: string): ReceiptVerificationFailure {
  return { ok: false, code, reason };
}

function mapJwsError(error: unknown): ReceiptVerificationFailure {
  const reason = error instanceof Error ? error.message : String(error);
  if (reason === "UNSUPPORTED_JWS_ALGORITHM")
    return failure("RECEIPT_ALGORITHM_INVALID", "Receipt algorithm is not ES256");
  if (
    reason === "JWS_TYPE_MISMATCH" ||
    reason === "JWS_KID_REQUIRED" ||
    reason === "UNSUPPORTED_JWS_HEADER"
  )
    return failure(
      "RECEIPT_HEADER_INVALID",
      "Receipt JOSE header is not an allowed asset-receipt header",
    );
  if (reason.includes("KEY"))
    return failure("RECEIPT_KEY_INVALID", "Receipt verification key is invalid");
  return failure("RECEIPT_FORMAT_INVALID", "Receipt is not a valid compact JWS");
}

export function verifyReceiptJws(
  token: unknown,
  trustedLiveKeys: readonly JsonWebKeyLike[],
  options: ReceiptVerificationOptions,
): ReceiptVerificationResult {
  if (typeof token !== "string" || token.length === 0)
    return failure("RECEIPT_REQUIRED", "A signed asset receipt is required");
  if (!Number.isSafeInteger(options.nowSeconds) || options.nowSeconds < 0)
    return failure(
      "RECEIPT_TIME_INVALID",
      "Verification clock must be a non-negative safe integer",
    );
  let jws;
  try {
    jws = parseCompactJws(token, RECEIPT_JWS_TYPE);
  } catch (error) {
    return mapJwsError(error);
  }
  const kid = jws.header.kid;
  const key = keyForProtectedKid(trustedLiveKeys, kid);
  if (!key)
    return failure(
      "RECEIPT_KID_UNTRUSTED",
      "Receipt protected kid is not present in the trusted live key intersection",
    );
  try {
    if (!verifyCompactJwsSignature(jws, key))
      return failure("RECEIPT_SIGNATURE_INVALID", "Receipt signature does not verify");
  } catch (error) {
    return error instanceof Error && error.message.includes("VERIFICATION_KEY")
      ? failure("RECEIPT_KEY_INVALID", "Receipt verification key is invalid")
      : failure("RECEIPT_SIGNATURE_INVALID", "Receipt signature does not verify");
  }
  try {
    const claims = normalizeClaims(jws.payload, {
      ...options,
      expectedAudience: options.expectedAudience ?? RECEIPT_AUDIENCE,
      expectedIssuer: options.expectedIssuer ?? CANONICAL_RECEIPT_ISSUER,
    });
    return {
      ok: true,
      header: { alg: "ES256", typ: "JWT", kid: kid as string },
      claims,
    };
  } catch (error) {
    if (isReceiptFailure(error)) return { ...error, signature_verified: true };
    return failure("RECEIPT_PAYLOAD_INVALID", "Receipt claims could not be validated");
  }
}

function isReceiptFailure(value: unknown): value is ReceiptVerificationFailure {
  return (
    isRecord(value) &&
    value.ok === false &&
    typeof value.code === "string" &&
    typeof value.reason === "string"
  );
}
