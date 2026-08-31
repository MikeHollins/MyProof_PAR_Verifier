import {
  LIMITATION_CODES,
  PublicRecordCoherenceReportSchema,
  REPORT_CONTRACT_ID,
  REPORT_SCHEMA_VERSION,
  type PublicRecordCoherenceReport,
} from "../../../src/contracts/index.js";

export const MCP_FIXTURE_ASSET_ID = "11111111-1111-4111-8111-111111111111" as const;

export type CanonicalReportOutcome =
  "coherent-active" | "coherent-inactive" | "contradictory" | "indeterminate";

export interface CanonicalReportFixtureOptions {
  readonly assetId?: string;
  readonly outcome?: CanonicalReportOutcome;
  readonly requireActive?: boolean;
}

/**
 * One MCP test fixture factory. Every returned value is parsed by the shared
 * report schema before it crosses the adapter, so lifecycle tests cannot
 * silently grow a second report vocabulary.
 */
export function canonicalReport(
  options: CanonicalReportFixtureOptions = {},
): PublicRecordCoherenceReport {
  const assetId = options.assetId ?? MCP_FIXTURE_ASSET_ID;
  const outcome = options.outcome ?? "coherent-active";
  const requireActive = options.requireActive ?? false;
  const contradictory = outcome === "contradictory";
  const indeterminate = outcome === "indeterminate";
  const inactive = outcome === "coherent-inactive";
  const registryStatus =
    contradictory || indeterminate ? "UNKNOWN" : inactive ? "REVOKED" : "ACTIVE";
  const registryActiveCondition = !requireActive
    ? "NOT_REQUESTED"
    : contradictory || indeterminate
      ? "INDETERMINATE"
      : inactive
        ? "NOT_SATISFIED"
        : "SATISFIED";
  const receiptState = contradictory || indeterminate ? "UNKNOWN" : "PASS";
  const receiptReason =
    contradictory || indeterminate ? "RECEIPT_SIGNATURE_INVALID" : "RECEIPT_SIGNATURE_VALID";

  const checks: PublicRecordCoherenceReport["checks"] = [
    {
      id: "bundle_structure",
      state: contradictory ? "FAIL" : indeterminate ? "UNKNOWN" : "PASS",
      reason_code: contradictory
        ? "PUBLIC_RECORD_CONTRADICTION"
        : indeterminate
          ? "BUNDLE_MALFORMED"
          : "BUNDLE_SCHEMA_VALID",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    },
    {
      id: "asset_record",
      state: indeterminate ? "UNKNOWN" : "PASS",
      reason_code: indeterminate ? "PUBLIC_RECORD_UNAVAILABLE" : "PUBLIC_RECORD_AVAILABLE",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    },
    {
      id: "trust_manifest",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "TRUST_MANIFEST_MISSING" : "TRUST_MANIFEST_VALID",
      verification_method: "KEY_RING_INTERSECTION",
      authority: "RELEASE_TRUST_MANIFEST",
      required: true,
    },
    {
      id: "live_key_intersection",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "TRUST_KEY_INTERSECTION_EMPTY" : "RECEIPT_KEY_TRUSTED",
      verification_method: "KEY_RING_INTERSECTION",
      authority: "RELEASE_TRUST_MANIFEST",
      required: true,
    },
    {
      id: "receipt_presence",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code: contradictory || indeterminate ? "RECEIPT_MISSING" : "RECEIPT_PRESENT",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    },
    {
      id: "receipt_structure",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code: contradictory || indeterminate ? "RECEIPT_MALFORMED" : "RECEIPT_PRESENT",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    },
    {
      id: "receipt_signature",
      state: receiptState,
      reason_code: receiptReason,
      verification_method: "JWS_SIGNATURE",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    },
    {
      id: "receipt_claims",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "RECEIPT_CLAIMS_MISSING" : "RECEIPT_CLAIMS_VALID",
      verification_method: "CLOCK_VALIDATION",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    },
    {
      id: "asset_identifier",
      state: contradictory ? "FAIL" : indeterminate ? "UNKNOWN" : "PASS",
      reason_code: contradictory
        ? "BUNDLE_ASSET_ID_MISMATCH"
        : indeterminate
          ? "CHECK_UNKNOWN"
          : "ASSET_BINDING_VALID",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    },
    {
      id: "asset_commitment",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "ASSET_COMMITMENT_MISMATCH" : "ASSET_COMMITMENT_MATCH",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    },
    {
      id: "proof_digest_binding",
      state: contradictory || indeterminate ? "NOT_ASSESSED" : "PASS",
      reason_code: contradictory || indeterminate ? "CHECK_NOT_ASSESSED" : "ASSET_BINDING_VALID",
      verification_method: "PREFIX_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: contradictory || indeterminate ? false : true,
    },
    {
      id: "policy_binding",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "POLICY_BINDING_MISMATCH" : "POLICY_BINDING_MATCH",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    },
    {
      id: "constraint_binding",
      state: "NOT_ASSESSED",
      reason_code: "CHECK_NOT_ASSESSED",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: false,
    },
    {
      id: "circuit_binding",
      state: contradictory || indeterminate ? "NOT_ASSESSED" : "PASS",
      reason_code: contradictory || indeterminate ? "CHECK_NOT_ASSESSED" : "CIRCUIT_BINDING_MATCH",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: contradictory || indeterminate ? false : true,
    },
    {
      id: "status_reference_binding",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate ? "STATUS_REFERENCE_MISMATCH" : "STATUS_REFERENCE_MATCH",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_STATUS_CREDENTIAL",
      required: true,
    },
    {
      id: "status_check_projection",
      state: contradictory || indeterminate ? "NOT_ASSESSED" : "PASS",
      reason_code:
        contradictory || indeterminate ? "CHECK_NOT_ASSESSED" : "STATUS_PROJECTION_MATCH",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: contradictory || indeterminate ? false : true,
    },
    {
      id: "provenance_binding",
      state: "NOT_ASSESSED",
      reason_code: "CHECK_NOT_ASSESSED",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: false,
    },
    {
      id: "policy_freshness_binding",
      state: "NOT_ASSESSED",
      reason_code: "CHECK_NOT_ASSESSED",
      verification_method: "CLOCK_VALIDATION",
      authority: "PAR_SIGNED_RECEIPT",
      required: false,
    },
    {
      id: "signed_status",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate
          ? "STATUS_CREDENTIAL_MISSING"
          : "STATUS_CREDENTIAL_SIGNATURE_VALID",
      verification_method: "JWS_SIGNATURE",
      authority: "PAR_SIGNED_STATUS_CREDENTIAL",
      required: true,
    },
    {
      id: "registry_status",
      state: contradictory || indeterminate ? "UNKNOWN" : "PASS",
      reason_code:
        contradictory || indeterminate
          ? "STATUS_UNKNOWN"
          : inactive
            ? "STATUS_REVOKED"
            : "STATUS_ACTIVE",
      verification_method: "STATUS_BIT_EVALUATION",
      authority: "PAR_SIGNED_STATUS_CREDENTIAL",
      required: true,
    },
    {
      id: "acceptance_decision",
      state: "NOT_ASSESSED",
      reason_code: "ACCEPTANCE_NOT_PERFORMED",
      verification_method: "NOT_PERFORMED",
      authority: "NONE",
      required: false,
    },
    {
      id: "underlying_proof_verification",
      state: "NOT_ASSESSED",
      reason_code: "PROOF_VERIFICATION_NOT_PERFORMED",
      verification_method: "NOT_PERFORMED",
      authority: "NONE",
      required: false,
    },
    {
      id: "predicate_assurance",
      state: "NOT_ASSESSED",
      reason_code: "PREDICATE_REPORTED_ONLY",
      verification_method: "NOT_PERFORMED",
      authority: "NONE",
      required: false,
    },
  ];

  return PublicRecordCoherenceReportSchema.parse({
    schema_version: REPORT_SCHEMA_VERSION,
    contract_id: REPORT_CONTRACT_ID,
    asset_id: assetId,
    evaluated_at: "2026-08-30T00:00:00.000Z",
    record_coherence: contradictory
      ? "CONTRADICTORY"
      : indeterminate
        ? "INDETERMINATE"
        : "COHERENT",
    registry_status: registryStatus,
    registry_active_condition: registryActiveCondition,
    acceptance_decision: "NOT_PERFORMED",
    underlying_proof_verification: "NOT_PERFORMED",
    predicate_assurance: "PAR_REPORTED_ONLY",
    checks,
    warnings: [],
    errors: [],
    limitations: [...LIMITATION_CODES],
  });
}
