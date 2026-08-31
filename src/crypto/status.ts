import { gunzipSync } from "node:zlib";
import { keyForProtectedKid } from "./trust.js";
import { parseCompactJws, verifyCompactJwsSignature, type JsonWebKeyLike } from "./jws.js";
import { CANONICAL_RECEIPT_ISSUER } from "./trust.js";

export const STATUS_JWS_TYPE = "vc+jwt" as const;
export const STATUS_JWS_CONTENT_TYPE = "vc" as const;
export const STATUS_CONTEXT = "https://www.w3.org/ns/credentials/v2" as const;
export const STATUS_CLOCK_TOLERANCE_MS = 60_000;
export const STATUS_MIN_BYTES = 16 * 1024;
export const STATUS_MAX_BYTES = 16 * 1024 * 1024;

export type StatusPurpose = "revocation" | "suspension";
export type RegistryStatus = "ACTIVE" | "REVOKED" | "SUSPENDED" | "UNKNOWN";

export interface SignedStatusCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id: string;
    type: "BitstringStatusList";
    statusPurpose: StatusPurpose;
    encodedList: string;
  };
}

export type StatusReasonCode =
  | "STATUS_CREDENTIAL_REQUIRED"
  | "STATUS_FORMAT_INVALID"
  | "STATUS_HEADER_INVALID"
  | "STATUS_KID_UNTRUSTED"
  | "STATUS_SIGNATURE_INVALID"
  | "STATUS_KEY_INVALID"
  | "STATUS_PAYLOAD_INVALID"
  | "STATUS_ID_MISMATCH"
  | "STATUS_ISSUER_MISMATCH"
  | "STATUS_SUBJECT_MISMATCH"
  | "STATUS_PURPOSE_MISMATCH"
  | "STATUS_NOT_YET_VALID"
  | "STATUS_EXPIRED"
  | "STATUS_ENCODING_INVALID"
  | "STATUS_INDEX_INVALID"
  | "STATUS_INDEX_OUT_OF_RANGE";

export interface StatusVerificationSuccess {
  ok: true;
  header: { alg: "ES256"; typ: "vc+jwt"; cty: "vc"; kid: string };
  credential: SignedStatusCredential;
  bit: 0 | 1;
  registryStatus: Exclude<RegistryStatus, "UNKNOWN">;
}

export interface StatusVerificationFailure {
  ok: false;
  code: StatusReasonCode;
  reason: string;
  /** Internal classification hint; never serialized in the public report. */
  signature_verified?: boolean;
}

export type StatusVerificationResult = StatusVerificationSuccess | StatusVerificationFailure;

export interface StatusVerificationOptions {
  nowMs: number;
  expectedId: string;
  expectedPurpose: StatusPurpose;
  expectedIssuer?: string;
  statusListIndex: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strictDate(value: unknown, code: StatusReasonCode): number {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  ) {
    throw failure(code, "Status credential date-time is invalid");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw failure(code, "Status credential date-time is invalid");
  return parsed;
}

function decodeStatusList(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 32 * 1024 * 1024 ||
    !/^u[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw failure(
      "STATUS_ENCODING_INVALID",
      "Status encodedList must be a bounded multibase base64url value",
    );
  }
  const encoded = value.slice(1);
  const compressed = Buffer.from(encoded, "base64url");
  if (
    compressed.length === 0 ||
    compressed.toString("base64url") !== encoded ||
    compressed[0] !== 0x1f ||
    compressed[1] !== 0x8b
  ) {
    throw failure("STATUS_ENCODING_INVALID", "Status encodedList is not canonical gzip data");
  }
  let expanded: Buffer;
  try {
    expanded = gunzipSync(compressed, { maxOutputLength: STATUS_MAX_BYTES });
  } catch {
    throw failure("STATUS_ENCODING_INVALID", "Status encodedList gzip data is invalid");
  }
  if (expanded.length < STATUS_MIN_BYTES || expanded.length > STATUS_MAX_BYTES) {
    throw failure(
      "STATUS_ENCODING_INVALID",
      "Status encodedList size is outside the bounded policy",
    );
  }
  return new Uint8Array(expanded);
}

function statusBit(bytes: Uint8Array, index: string): 0 | 1 {
  if (typeof index !== "string" || !/^(?:0|[1-9]\d*)$/.test(index))
    throw failure("STATUS_INDEX_INVALID", "Status index is not a canonical decimal string");
  const parsed = Number(index);
  if (!Number.isSafeInteger(parsed))
    throw failure("STATUS_INDEX_INVALID", "Status index is out of range");
  const byteIndex = Math.floor(parsed / 8);
  if (byteIndex >= bytes.length)
    throw failure("STATUS_INDEX_OUT_OF_RANGE", "Status index is outside the published bitstring");
  const byte = bytes[byteIndex];
  if (byte === undefined)
    throw failure("STATUS_INDEX_OUT_OF_RANGE", "Status index is outside the published bitstring");
  return (byte & (1 << (7 - (parsed % 8)))) === 0 ? 0 : 1;
}

function failure(code: StatusReasonCode, reason: string): StatusVerificationFailure {
  return { ok: false, code, reason };
}

function mapJwsError(error: unknown): StatusVerificationFailure {
  const reason = error instanceof Error ? error.message : String(error);
  if (reason === "UNSUPPORTED_JWS_ALGORITHM")
    return failure("STATUS_HEADER_INVALID", "Status credential algorithm is not ES256");
  if (
    reason === "JWS_TYPE_MISMATCH" ||
    reason === "JWS_KID_REQUIRED" ||
    reason === "UNSUPPORTED_JWS_HEADER" ||
    reason === "INVALID_JWS_CONTENT_TYPE"
  )
    return failure("STATUS_HEADER_INVALID", "Status credential JOSE header is not allowed");
  return failure("STATUS_FORMAT_INVALID", "Status credential is not a valid compact JWS");
}

export function verifySignedStatusCredential(
  token: unknown,
  trustedLiveKeys: readonly JsonWebKeyLike[],
  options: StatusVerificationOptions,
): StatusVerificationResult {
  if (typeof token !== "string" || token.length === 0)
    return failure(
      "STATUS_CREDENTIAL_REQUIRED",
      "A signed application/vc+jwt status credential is required",
    );
  if (!Number.isSafeInteger(options.nowMs) || options.nowMs < 0)
    return failure("STATUS_PAYLOAD_INVALID", "Status verification clock is invalid");
  let jws;
  try {
    jws = parseCompactJws(token, STATUS_JWS_TYPE);
  } catch (error) {
    return mapJwsError(error);
  }
  if (jws.header.cty !== STATUS_JWS_CONTENT_TYPE)
    return failure("STATUS_HEADER_INVALID", "Status credential cty must be vc");
  const kid = jws.header.kid;
  const key = keyForProtectedKid(trustedLiveKeys, kid);
  if (!key)
    return failure("STATUS_KID_UNTRUSTED", "Status credential protected kid is not trusted");
  try {
    if (!verifyCompactJwsSignature(jws, key))
      return failure("STATUS_SIGNATURE_INVALID", "Status credential signature does not verify");
  } catch (error) {
    return error instanceof Error && error.message.includes("VERIFICATION_KEY")
      ? failure("STATUS_KEY_INVALID", "Status credential verification key is invalid")
      : failure("STATUS_SIGNATURE_INVALID", "Status credential signature does not verify");
  }

  try {
    const payload = jws.payload;
    if (!isRecord(payload))
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential payload must be an object");
    if (
      !Array.isArray(payload["@context"]) ||
      !(payload["@context"] as unknown[]).includes(STATUS_CONTEXT)
    )
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential context is invalid");
    if (
      !Array.isArray(payload.type) ||
      !(payload.type as unknown[]).includes("VerifiableCredential") ||
      !(payload.type as unknown[]).includes("BitstringStatusListCredential")
    )
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential type is invalid");
    if (payload.id !== options.expectedId)
      throw failure(
        "STATUS_ID_MISMATCH",
        "Status credential id does not match the receipt status reference",
      );
    const expectedIssuer = options.expectedIssuer ?? CANONICAL_RECEIPT_ISSUER;
    if (payload.issuer !== expectedIssuer)
      throw failure("STATUS_ISSUER_MISMATCH", "Status credential issuer is not canonical");
    const validFrom = strictDate(payload.validFrom, "STATUS_PAYLOAD_INVALID");
    const validUntil =
      payload.validUntil === undefined
        ? undefined
        : strictDate(payload.validUntil, "STATUS_PAYLOAD_INVALID");
    if (validUntil !== undefined && validUntil < validFrom)
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential validUntil precedes validFrom");
    if (validFrom > options.nowMs + STATUS_CLOCK_TOLERANCE_MS)
      throw failure(
        "STATUS_NOT_YET_VALID",
        "Status credential is not yet valid at the verification clock",
      );
    if (validUntil !== undefined && validUntil < options.nowMs - STATUS_CLOCK_TOLERANCE_MS)
      throw failure("STATUS_EXPIRED", "Status credential is expired at the verification clock");
    if (!isRecord(payload.credentialSubject))
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential subject is invalid");
    const subject = payload.credentialSubject;
    if (subject.id !== `${options.expectedId}#list`)
      throw failure(
        "STATUS_SUBJECT_MISMATCH",
        "Status credential subject id does not match the status reference",
      );
    if (subject.type !== "BitstringStatusList")
      throw failure("STATUS_PAYLOAD_INVALID", "Status credential subject type is invalid");
    if (subject.statusPurpose !== options.expectedPurpose)
      throw failure(
        "STATUS_PURPOSE_MISMATCH",
        "Status credential purpose does not match the receipt",
      );
    const bytes = decodeStatusList(subject.encodedList);
    const bit = statusBit(bytes, options.statusListIndex);
    const registryStatus =
      bit === 0 ? "ACTIVE" : options.expectedPurpose === "suspension" ? "SUSPENDED" : "REVOKED";
    return {
      ok: true,
      header: { alg: "ES256", typ: "vc+jwt", cty: "vc", kid: kid as string },
      credential: payload as unknown as SignedStatusCredential,
      bit,
      registryStatus,
    };
  } catch (error) {
    if (isStatusFailure(error)) return { ...error, signature_verified: true };
    return failure("STATUS_PAYLOAD_INVALID", "Status credential payload could not be validated");
  }
}

function isStatusFailure(value: unknown): value is StatusVerificationFailure {
  return (
    isRecord(value) &&
    value.ok === false &&
    typeof value.code === "string" &&
    typeof value.reason === "string"
  );
}
