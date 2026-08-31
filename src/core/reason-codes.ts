import type { CheckId, ReasonCode } from "../contracts/index.js";

/**
 * Human text is kept local and finite. Remote PAR text, identifiers, token
 * fragments, and upstream exception strings are never copied into reports.
 */
export const REASON_DETAIL: Readonly<Record<ReasonCode, string>> = {
  CHECK_PASSED: "The check passed.",
  CHECK_FAILED: "The check failed.",
  CHECK_UNKNOWN: "The check could not be established.",
  CHECK_NOT_ASSESSED: "The check was not assessed.",
  CHECK_NOT_PERFORMED: "The check was not performed by this verifier.",
  INPUT_ASSET_ID_INVALID: "The asset identifier is invalid.",
  BUNDLE_SCHEMA_VALID: "The public verification bundle has the expected schema.",
  BUNDLE_MALFORMED: "The public verification bundle is malformed.",
  BUNDLE_ASSET_ID_MISMATCH: "The bundle asset identifier does not match the requested identifier.",
  PUBLIC_RECORD_AVAILABLE: "The public PAR record is available.",
  PUBLIC_RECORD_UNAVAILABLE: "The public PAR record is unavailable.",
  PUBLIC_RECORD_MALFORMED: "The public PAR record is malformed.",
  PUBLIC_RECORD_CONTRADICTION: "The public PAR record contains contradictory evidence.",
  PUBLIC_RECORD_INDETERMINATE: "The public PAR record does not establish a determinate result.",
  RECEIPT_PRESENT: "A signed asset receipt is present.",
  RECEIPT_MISSING: "The signed asset receipt is missing.",
  RECEIPT_MALFORMED: "The signed asset receipt is malformed.",
  RECEIPT_SIGNATURE_VALID: "The asset receipt has a valid ES256 signature.",
  RECEIPT_SIGNATURE_INVALID: "The asset receipt signature is invalid.",
  RECEIPT_KEY_TRUSTED: "The receipt key is in the release-trusted live key intersection.",
  RECEIPT_KEY_UNKNOWN: "The receipt protected key id is not trusted.",
  RECEIPT_KEY_CONFLICT: "The receipt key id maps to conflicting public key material.",
  RECEIPT_ALGORITHM_UNSUPPORTED: "The receipt algorithm is not allowed.",
  RECEIPT_TYPE_INVALID: "The receipt JOSE type is not allowed.",
  RECEIPT_CRITICAL_HEADER_UNSUPPORTED: "The receipt uses unsupported critical JOSE headers.",
  RECEIPT_CLAIMS_VALID: "The receipt contains the required valid claims.",
  RECEIPT_CLAIMS_MISSING: "Required receipt claims are missing.",
  RECEIPT_CLAIMS_EXPIRED: "The receipt is expired at the deterministic verification clock.",
  RECEIPT_CLAIMS_NOT_YET_VALID:
    "The receipt is not yet valid at the deterministic verification clock.",
  RECEIPT_AUDIENCE_MISMATCH: "The receipt audience is not the public asset audience.",
  RECEIPT_ISSUER_MISMATCH: "The receipt issuer is not the canonical PAR issuer.",
  ASSET_BINDING_VALID: "The signed receipt is bound to the requested public asset.",
  ASSET_BINDING_MISMATCH: "The signed receipt is not bound to the requested public asset.",
  ASSET_COMMITMENT_MATCH: "The signed receipt commitment matches the public asset commitment.",
  ASSET_COMMITMENT_MISMATCH:
    "The signed receipt commitment does not match the public asset commitment.",
  POLICY_BINDING_MATCH: "The signed policy hash and policy CID match the public asset.",
  POLICY_BINDING_MISMATCH: "The signed policy binding does not match the public asset.",
  CONSTRAINT_BINDING_MATCH: "The signed constraint binding matches the public asset.",
  CONSTRAINT_BINDING_MISMATCH: "The signed constraint binding does not match the public asset.",
  CIRCUIT_BINDING_MATCH: "The signed circuit/schema binding matches the public asset.",
  CIRCUIT_BINDING_MISMATCH: "The signed circuit/schema binding does not match the public asset.",
  STATUS_REFERENCE_MATCH: "The signed status reference matches the public record.",
  STATUS_REFERENCE_MISMATCH: "The signed status reference does not match the public record.",
  STATUS_PROJECTION_MATCH: "The public status projection matches the signed status evidence.",
  STATUS_PROJECTION_MISMATCH:
    "The public status projection contradicts the signed status evidence.",
  TRUST_MANIFEST_VALID: "The pinned release trust manifest is valid.",
  TRUST_MANIFEST_MISSING: "The pinned release trust manifest is missing.",
  TRUST_MANIFEST_UNAUTHENTICATED: "The release trust manifest is not authenticated.",
  TRUST_MANIFEST_SCHEMA_INVALID: "The release trust manifest schema is invalid.",
  TRUST_MANIFEST_TAMPERED: "The release trust manifest failed its pinned integrity check.",
  TRUST_KEY_INTERSECTION_EMPTY:
    "No release-trusted receipt key is present in the canonical live JWKS.",
  TRUST_KEY_INTERSECTION_CONFLICT:
    "A receipt key id has conflicting release and live public key material.",
  STATUS_CREDENTIAL_SIGNATURE_VALID: "The signed status credential has a valid ES256 signature.",
  STATUS_CREDENTIAL_SIGNATURE_INVALID: "The signed status credential signature is invalid.",
  STATUS_CREDENTIAL_MISSING: "A signed application/vc+jwt status credential is missing.",
  STATUS_CREDENTIAL_MALFORMED: "The signed status credential is malformed.",
  STATUS_CREDENTIAL_EXPIRED: "The signed status credential is expired.",
  STATUS_CREDENTIAL_NOT_YET_VALID: "The signed status credential is not yet valid.",
  STATUS_ACTIVE: "The signed status-list bit is clear; the registry status is active.",
  STATUS_REVOKED: "The signed revocation-list bit is set; the registry status is revoked.",
  STATUS_SUSPENDED: "The signed suspension-list bit is set; the registry status is suspended.",
  STATUS_UNKNOWN: "No signed status evidence established the registry status.",
  STATUS_INDEX_INVALID: "The status-list index is invalid.",
  STATUS_INDEX_OUT_OF_RANGE: "The status-list index is outside the published bitstring.",
  FRESHNESS_ADVISORY: "Freshness metadata is advisory and is not a cryptographic proof.",
  FRESHNESS_EXPIRED: "The public asset freshness boundary is expired.",
  PREDICATE_REPORTED_ONLY: "The predicate is PAR-reported only.",
  PROOF_VERIFICATION_NOT_PERFORMED: "The underlying proof was not independently verified.",
  ACCEPTANCE_NOT_PERFORMED: "No merchant acceptance decision was performed.",
  NETWORK_ABORTED: "The network operation was aborted.",
  NETWORK_TIMEOUT: "The network operation timed out.",
  NETWORK_RESPONSE_TOO_LARGE: "The network response exceeded its bounded limit.",
  NETWORK_REDIRECT_REJECTED: "The network redirect was rejected.",
  NETWORK_ORIGIN_REJECTED: "The network origin was rejected.",
  NETWORK_CONTENT_TYPE_INVALID: "The network content type was invalid.",
  INTERNAL_INVARIANT_FAILURE: "The verifier encountered an internal invariant failure.",
};

export function checkDetail(code: ReasonCode): string {
  return REASON_DETAIL[code];
}

export function isContradictoryReason(code: ReasonCode): boolean {
  return new Set<ReasonCode>([
    "BUNDLE_ASSET_ID_MISMATCH",
    "PUBLIC_RECORD_CONTRADICTION",
    "RECEIPT_SIGNATURE_INVALID",
    "RECEIPT_AUDIENCE_MISMATCH",
    "RECEIPT_ISSUER_MISMATCH",
    "ASSET_BINDING_MISMATCH",
    "ASSET_COMMITMENT_MISMATCH",
    "POLICY_BINDING_MISMATCH",
    "CONSTRAINT_BINDING_MISMATCH",
    "CIRCUIT_BINDING_MISMATCH",
    "STATUS_REFERENCE_MISMATCH",
    "TRUST_KEY_INTERSECTION_CONFLICT",
    "STATUS_CREDENTIAL_SIGNATURE_INVALID",
  ]).has(code);
}

/** Check identifiers whose absence prevents a coherence assertion. */
export function isRequiredCheck(id: CheckId): boolean {
  return !new Set<CheckId>([
    "acceptance_decision",
    "underlying_proof_verification",
    "predicate_assurance",
  ]).has(id);
}
