import {
  AssetIdSchema,
  PublicAssetRecordInputSchema,
  PublicRecordEvidenceInputSchema,
} from "../contracts/input.js";
import { PublicRecordCoherenceReportSchema } from "../contracts/report.js";
import type {
  Check,
  CheckAuthority,
  CheckId,
  CheckState,
  PublicRecordCoherenceReport,
  ReasonCode,
  VerificationMethod,
  VerifyProofAssetInput,
} from "../contracts/index.js";
import { parseCompactJws, type JsonWebKeyLike } from "../crypto/jws.js";
import {
  verifyReceiptJws,
  type ReceiptClaims,
  type ReceiptVerificationFailure,
} from "../crypto/receipt.js";
import {
  intersectReceiptTrust,
  parseReceiptJwks,
  validateReleaseTrustManifest,
} from "../crypto/trust.js";
import { verifySignedStatusCredential, type StatusVerificationFailure } from "../crypto/status.js";
import { checkDetail } from "./reason-codes.js";
import type { CoreEvidenceEnvelope, CoreTrustMaterial } from "./evidence.js";

const BUNDLE_SCHEMA_VERSION = "myproof.public-verification-bundle.v1" as const;
const CANONICAL_RECEIPT_ISSUER = "did:web:par.myproof.ai" as const;
const LIMITATIONS = [
  "UNDERLYING_PROOF_NOT_PERFORMED",
  "PREDICATE_PAR_REPORTED_ONLY",
  "CURRENT_PRESENTER_NOT_AUTHENTICATED",
  "PROOF_COMMITMENT_NOT_RECOMPUTABLE",
  "STATUS_TRUST_ROOT_CANONICAL_ORIGIN",
  "FULL_DIGEST_NOT_PUBLIC",
] as const;

type RegistryStatus = "ACTIVE" | "REVOKED" | "SUSPENDED" | "UNKNOWN";

interface ParsedEvidence {
  readonly asset: Record<string, unknown>;
  readonly receipt: Record<string, unknown> | null;
  readonly receiptJws: string | null;
  readonly receiptHeader: Record<string, unknown> | null;
  readonly receiptPublicJwk: Record<string, unknown> | null;
  readonly receiptClaimsProjection: Record<string, unknown> | null;
  readonly receiptJwks: unknown;
  readonly statusCredential: string | null;
  readonly statusContentType: string | null;
  readonly statusUrl: string | null;
  readonly statusCheck: Record<string, unknown> | null;
  readonly bundleChecksStatus: string | null;
  readonly provenance: Record<string, unknown> | null;
  readonly freshness: Record<string, unknown> | null;
  readonly bundleSchemaVersion: string | null;
}

interface EvidenceParseFailure {
  readonly ok: false;
  readonly reasonCode: ReasonCode;
}

interface EvidenceParseSuccess {
  readonly ok: true;
  readonly value: ParsedEvidence;
}

type EvidenceParseResult = EvidenceParseFailure | EvidenceParseSuccess;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 16_777_216 ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

/**
 * Normalize only the fields the core understands. Audit/transparency fields
 * are deliberately discarded and cannot become a v1 epoch/Merkle claim.
 */
function parseEvidence(evidence: unknown): EvidenceParseResult {
  if (!isRecord(evidence)) return { ok: false, reasonCode: "BUNDLE_MALFORMED" };
  const parsed = PublicRecordEvidenceInputSchema.safeParse(evidence);
  if (!parsed.success) return { ok: false, reasonCode: "BUNDLE_MALFORMED" };
  const envelope = parsed.data;
  const bundle = envelope.bundle;
  const asset = bundle.asset;
  const receipt = bundle.receipt;
  const status = envelope.status_credential ?? bundle.statusCredential;
  const statusUrl = boundedString(envelope.status_url);
  return {
    ok: true,
    value: {
      asset,
      receipt,
      receiptJws: boundedString(receipt?.jws),
      receiptHeader: asRecord(receipt?.header),
      receiptPublicJwk: asRecord(receipt?.publicJwk),
      receiptClaimsProjection: asRecord(receipt?.claims),
      receiptJwks: envelope.receipt_jwks,
      statusCredential: boundedString(status?.credential),
      statusContentType: boundedString(status?.content_type),
      statusUrl,
      statusCheck: bundle.statusCheck,
      bundleChecksStatus: boundedString(bundle.checks.status),
      provenance: bundle.provenance,
      // The signed expiry is compared to the producer's public asset expiry;
      // `_freshness` remains an advisory display projection only.
      freshness: asset,
      bundleSchemaVersion: boundedString(bundle.schemaVersion),
    },
  };
}

function detail(code: ReasonCode): string {
  return checkDetail(code);
}

function makeCheck(
  id: CheckId,
  state: CheckState,
  reason_code: ReasonCode,
  verification_method: VerificationMethod,
  authority: CheckAuthority,
  required = true,
): Check {
  // Exercise the reviewed finite catalogue without exposing prose or remote
  // values in the report.
  void detail(reason_code);
  return { id, state, reason_code, verification_method, authority, required };
}

function setCheck(checks: Check[], id: CheckId, next: Check): void {
  const index = checks.findIndex((check) => check.id === id);
  if (index < 0) throw new Error("INTERNAL_INVARIANT_FAILURE");
  checks[index] = next;
}

function checkMap(checks: readonly Check[]): Map<CheckId, Check> {
  return new Map(checks.map((check) => [check.id, check]));
}

function uniqueCodes(values: readonly ReasonCode[]): ReasonCode[] {
  return [...new Set(values)];
}

function report(
  request: VerifyProofAssetInput,
  nowMs: number,
  checks: Check[],
  registryStatus: RegistryStatus,
  warnings: ReasonCode[] = [],
  errors: ReasonCode[] = [],
): PublicRecordCoherenceReport {
  const mapped = checkMap(checks);
  // A FAIL only contradicts a claim when the corresponding required evidence
  // was established. Malformed, stale, unknown, and unsupported evidence stay
  // UNKNOWN and therefore classify as INDETERMINATE.
  const hasFailure = checks.some((check) => check.required && check.state === "FAIL");
  const hasUnknownRequired = checks.some(
    (check) => check.required && (check.state === "UNKNOWN" || check.state === "NOT_ASSESSED"),
  );
  const recordCoherence = hasFailure
    ? "CONTRADICTORY"
    : hasUnknownRequired
      ? "INDETERMINATE"
      : "COHERENT";
  const registryActiveCondition = !request.require_active
    ? "NOT_REQUESTED"
    : recordCoherence !== "COHERENT" || registryStatus === "UNKNOWN"
      ? "INDETERMINATE"
      : registryStatus === "ACTIVE"
        ? "SATISFIED"
        : "NOT_SATISFIED";

  if (
    !mapped.has("acceptance_decision") ||
    !mapped.has("underlying_proof_verification") ||
    !mapped.has("predicate_assurance")
  ) {
    throw new Error("INTERNAL_INVARIANT_FAILURE");
  }

  const value = {
    schema_version: 1 as const,
    contract_id: "myproof.par.public-record-coherence.v1" as const,
    asset_id: request.asset_id,
    evaluated_at: new Date(nowMs).toISOString(),
    record_coherence: recordCoherence,
    registry_status: registryStatus,
    registry_active_condition: registryActiveCondition,
    acceptance_decision: "NOT_PERFORMED" as const,
    underlying_proof_verification: "NOT_PERFORMED" as const,
    predicate_assurance: "PAR_REPORTED_ONLY" as const,
    checks,
    warnings: uniqueCodes(warnings),
    errors: uniqueCodes(errors),
    limitations: [...LIMITATIONS],
  } satisfies PublicRecordCoherenceReport;
  return PublicRecordCoherenceReportSchema.parse(value);
}

/**
 * Checks start in a non-assertive state. Individual checks are upgraded only
 * after the corresponding evidence has been parsed and, where applicable,
 * cryptographically verified. This also keeps unavailable/malformed paths
 * from inheriting a misleading signed-evidence tuple.
 */
function baseChecks(): Check[] {
  return [
    makeCheck(
      "bundle_structure",
      "UNKNOWN",
      "BUNDLE_MALFORMED",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
    makeCheck(
      "asset_record",
      "UNKNOWN",
      "PUBLIC_RECORD_UNAVAILABLE",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
    makeCheck(
      "trust_manifest",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "KEY_RING_INTERSECTION",
      "RELEASE_TRUST_MANIFEST",
    ),
    makeCheck(
      "live_key_intersection",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "KEY_RING_INTERSECTION",
      "RELEASE_TRUST_MANIFEST",
    ),
    makeCheck(
      "receipt_presence",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
    makeCheck(
      "receipt_structure",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
    makeCheck(
      "receipt_signature",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "JWS_SIGNATURE",
      "PAR_SIGNED_RECEIPT",
    ),
    makeCheck(
      "receipt_claims",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "STRUCTURAL_VALIDATION",
      "PAR_SIGNED_RECEIPT",
    ),
    makeCheck(
      "asset_identifier",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "EXACT_FIELD_BINDING",
      "PAR_PUBLIC_EVIDENCE",
    ),
    makeCheck(
      "asset_commitment",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
    ),
    makeCheck(
      "proof_digest_binding",
      "NOT_ASSESSED",
      "CHECK_NOT_ASSESSED",
      "PREFIX_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
      false,
    ),
    makeCheck(
      "policy_binding",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
    ),
    makeCheck(
      "constraint_binding",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
    ),
    makeCheck(
      "circuit_binding",
      "NOT_ASSESSED",
      "CHECK_NOT_ASSESSED",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
      false,
    ),
    makeCheck(
      "status_reference_binding",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_STATUS_CREDENTIAL",
    ),
    makeCheck(
      "status_check_projection",
      "NOT_ASSESSED",
      "CHECK_NOT_ASSESSED",
      "EXACT_FIELD_BINDING",
      "PAR_PUBLIC_EVIDENCE",
      false,
    ),
    makeCheck(
      "provenance_binding",
      "NOT_ASSESSED",
      "CHECK_NOT_ASSESSED",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
      false,
    ),
    makeCheck(
      "policy_freshness_binding",
      "NOT_ASSESSED",
      "CHECK_NOT_ASSESSED",
      "CLOCK_VALIDATION",
      "PAR_SIGNED_RECEIPT",
      false,
    ),
    makeCheck(
      "signed_status",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "JWS_SIGNATURE",
      "PAR_SIGNED_STATUS_CREDENTIAL",
    ),
    makeCheck(
      "registry_status",
      "UNKNOWN",
      "CHECK_UNKNOWN",
      "STATUS_BIT_EVALUATION",
      "PAR_SIGNED_STATUS_CREDENTIAL",
    ),
    makeCheck(
      "acceptance_decision",
      "NOT_ASSESSED",
      "ACCEPTANCE_NOT_PERFORMED",
      "NOT_PERFORMED",
      "NONE",
      false,
    ),
    makeCheck(
      "underlying_proof_verification",
      "NOT_ASSESSED",
      "PROOF_VERIFICATION_NOT_PERFORMED",
      "NOT_PERFORMED",
      "NONE",
      false,
    ),
    makeCheck(
      "predicate_assurance",
      "NOT_ASSESSED",
      "PREDICATE_REPORTED_ONLY",
      "NOT_PERFORMED",
      "NONE",
      false,
    ),
  ];
}

function mapReceiptStructureFailure(failure: ReceiptVerificationFailure): ReasonCode {
  switch (failure.code) {
    case "RECEIPT_ALGORITHM_INVALID":
      return "RECEIPT_ALGORITHM_UNSUPPORTED";
    case "RECEIPT_HEADER_INVALID":
      return "RECEIPT_TYPE_INVALID";
    case "RECEIPT_FORMAT_INVALID":
      return "RECEIPT_MALFORMED";
    case "RECEIPT_KEY_INVALID":
      return "RECEIPT_KEY_CONFLICT";
    default:
      return "RECEIPT_MALFORMED";
  }
}

function mapReceiptClaimsFailure(failure: ReceiptVerificationFailure): ReasonCode {
  switch (failure.code) {
    case "RECEIPT_EXPIRED":
      return "RECEIPT_CLAIMS_EXPIRED";
    case "RECEIPT_NOT_YET_VALID":
      return "RECEIPT_CLAIMS_NOT_YET_VALID";
    case "RECEIPT_AUDIENCE_MISMATCH":
      return "RECEIPT_AUDIENCE_MISMATCH";
    case "RECEIPT_ISSUER_MISMATCH":
      return "RECEIPT_ISSUER_MISMATCH";
    case "RECEIPT_SUBJECT_MISMATCH":
      return "BUNDLE_ASSET_ID_MISMATCH";
    default:
      return failure.code === "RECEIPT_REQUIRED" ? "RECEIPT_MISSING" : "RECEIPT_CLAIMS_MISSING";
  }
}

function receiptFailureState(failure: ReceiptVerificationFailure): CheckState {
  switch (failure.code) {
    // No incompatible signed fact exists for these cases.
    case "RECEIPT_REQUIRED":
    case "RECEIPT_KID_UNTRUSTED":
    case "RECEIPT_KEY_INVALID":
    case "RECEIPT_EXPIRED":
    case "RECEIPT_NOT_YET_VALID":
    case "RECEIPT_TIME_INVALID":
    case "RECEIPT_STATUS_REF_INVALID":
    case "RECEIPT_POLICY_FRESHNESS_INVALID":
    case "RECEIPT_FORMAT_INVALID":
    case "RECEIPT_HEADER_INVALID":
    case "RECEIPT_ALGORITHM_INVALID":
    case "RECEIPT_CLAIM_MISSING":
    case "RECEIPT_CLAIM_TYPE_INVALID":
    case "RECEIPT_PAYLOAD_INVALID":
    case "RECEIPT_PROVENANCE_INVALID":
      return "UNKNOWN";
    // A trusted key produced a valid signature over an incompatible claim.
    case "RECEIPT_AUDIENCE_MISMATCH":
    case "RECEIPT_ISSUER_MISMATCH":
    case "RECEIPT_SUBJECT_MISMATCH":
      return "FAIL";
    case "RECEIPT_SIGNATURE_INVALID":
      return "UNKNOWN";
    default:
      return "UNKNOWN";
  }
}

function mapStatusFailure(failure: StatusVerificationFailure): ReasonCode {
  switch (failure.code) {
    case "STATUS_CREDENTIAL_REQUIRED":
      return "STATUS_CREDENTIAL_MISSING";
    case "STATUS_KID_UNTRUSTED":
      return "RECEIPT_KEY_UNKNOWN";
    case "STATUS_ID_MISMATCH":
    case "STATUS_ISSUER_MISMATCH":
    case "STATUS_SUBJECT_MISMATCH":
    case "STATUS_PURPOSE_MISMATCH":
      return "STATUS_REFERENCE_MISMATCH";
    case "STATUS_NOT_YET_VALID":
      return "STATUS_CREDENTIAL_NOT_YET_VALID";
    case "STATUS_EXPIRED":
      return "STATUS_CREDENTIAL_EXPIRED";
    case "STATUS_INDEX_INVALID":
      return "STATUS_INDEX_INVALID";
    case "STATUS_INDEX_OUT_OF_RANGE":
      return "STATUS_INDEX_OUT_OF_RANGE";
    default:
      return failure.code === "STATUS_SIGNATURE_INVALID"
        ? "STATUS_CREDENTIAL_SIGNATURE_INVALID"
        : "STATUS_CREDENTIAL_MALFORMED";
  }
}

function statusFailureState(failure: StatusVerificationFailure): CheckState {
  switch (failure.code) {
    case "STATUS_ID_MISMATCH":
    case "STATUS_ISSUER_MISMATCH":
    case "STATUS_SUBJECT_MISMATCH":
    case "STATUS_PURPOSE_MISMATCH":
      return "FAIL";
    // Malformed, stale, unknown, and invalidly signed status is unavailable;
    // it is not a signed assertion of the opposite registry state.
    default:
      return "UNKNOWN";
  }
}

function trustFailureReason(code: string): ReasonCode {
  switch (code) {
    case "TRUST_MANIFEST_MISSING":
      return "TRUST_MANIFEST_MISSING";
    case "TRUST_MANIFEST_UNAUTHENTICATED":
      return "TRUST_MANIFEST_UNAUTHENTICATED";
    case "TRUST_MANIFEST_SCHEMA_INVALID":
    case "TRUST_MANIFEST_ORIGIN_INVALID":
    case "TRUST_MANIFEST_ISSUER_INVALID":
    case "TRUST_MANIFEST_KEYS_INVALID":
      return "TRUST_MANIFEST_SCHEMA_INVALID";
    case "TRUST_MANIFEST_DIGEST_INVALID":
    case "TRUST_MANIFEST_DIGEST_MISMATCH":
      return "TRUST_MANIFEST_TAMPERED";
    case "TRUST_KEY_INTERSECTION_CONFLICT":
      return "TRUST_KEY_INTERSECTION_CONFLICT";
    case "TRUST_KEY_INTERSECTION_EMPTY":
    case "LIVE_JWKS_INVALID":
    case "LIVE_JWKS_DUPLICATE_KID":
    case "LIVE_JWKS_KEY_INVALID":
      return "TRUST_KEY_INTERSECTION_EMPTY";
    default:
      return "TRUST_MANIFEST_TAMPERED";
  }
}

function normalizeClaimProjectionValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeClaimProjectionValue);
  if (!isRecord(value)) return value;
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort())
    output[key] = normalizeClaimProjectionValue(value[key]);
  return output;
}

/** Compare the untrusted bundle projection to claims after JWS validation. */
type ReceiptProjectionResult = "MATCH" | "MISSING" | "MISMATCH";

function receiptProjectionResult(
  projection: Record<string, unknown> | null,
  claims: ReceiptClaims,
): ReceiptProjectionResult {
  if (!projection) return "MISSING";
  const expected: Record<string, unknown> = {
    proof_digest: claims.proof_digest,
    policy_hash: claims.policy_hash,
    constraint_hash: claims.constraint_hash,
    status_ref: claims.status_ref,
    aud: claims.aud,
    exp: claims.exp,
    nbf: claims.nbf,
    ...(claims.iat === undefined ? {} : { iat: claims.iat }),
    ...(claims.iss === undefined ? {} : { iss: claims.iss }),
    ...(claims.sub === undefined ? {} : { sub: claims.sub }),
    ...(claims.proof_asset_commitment === undefined
      ? {}
      : { proof_asset_commitment: claims.proof_asset_commitment }),
    ...(claims.policy_cid === undefined ? {} : { policy_cid: claims.policy_cid }),
    ...(claims.circuit_or_schema_id === undefined
      ? {}
      : { circuit_or_schema_id: claims.circuit_or_schema_id }),
    ...(claims.circuit_version === undefined ? {} : { circuit_version: claims.circuit_version }),
    ...(claims.audit_event_id === undefined ? {} : { audit_event_id: claims.audit_event_id }),
    ...(claims.audit_event_hash === undefined ? {} : { audit_event_hash: claims.audit_event_hash }),
    ...(claims.upstream_receipt_hash === undefined
      ? {}
      : { upstream_receipt_hash: claims.upstream_receipt_hash }),
    ...(claims.created_at === undefined ? {} : { created_at: claims.created_at }),
  };
  // `jti` is required inside the signed JWS for replay identity but is
  // intentionally omitted from PAR's public projection. If a producer ever
  // leaks it, treat the projection as incompatible rather than making the
  // privacy-sensitive field part of the expected public wire.
  if ("jti" in projection) return "MISMATCH";
  let found = 0;
  for (const [key, value] of Object.entries(expected)) {
    if (!(key in projection) || projection[key] === undefined) continue;
    found += 1;
    if (
      JSON.stringify(normalizeClaimProjectionValue(projection[key])) !==
      JSON.stringify(normalizeClaimProjectionValue(value))
    )
      return "MISMATCH";
  }
  // These claims are not currently emitted by the frozen producer projection,
  // but if a compatible producer includes them they must still agree with the
  // signed receipt. They are never required merely because they are signed.
  for (const key of [
    "environment",
    "configuration_revision",
    "policy_ttl_seconds",
    "proof_expires_at",
    "freshness_source",
  ] as const) {
    if (!(key in projection) || projection[key] === undefined) continue;
    if (
      claims[key] === undefined ||
      JSON.stringify(normalizeClaimProjectionValue(projection[key])) !==
        JSON.stringify(normalizeClaimProjectionValue(claims[key]))
    )
      return "MISMATCH";
  }
  return found === Object.keys(expected).length ? "MATCH" : "MISSING";
}

function setAssetBindings(
  checks: Check[],
  evidence: ParsedEvidence,
  request: VerifyProofAssetInput,
  claims: ReceiptClaims,
): void {
  const asset = evidence.asset;

  const assetId = boundedString(asset.proofAssetId);
  const idAvailable = assetId !== null && claims.sub !== undefined;
  const idMatch = idAvailable && assetId === request.asset_id && claims.sub === request.asset_id;
  setCheck(
    checks,
    "asset_identifier",
    makeCheck(
      "asset_identifier",
      !idAvailable ? "UNKNOWN" : idMatch ? "PASS" : "FAIL",
      !idAvailable ? "CHECK_UNKNOWN" : idMatch ? "ASSET_BINDING_VALID" : "BUNDLE_ASSET_ID_MISMATCH",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
    ),
  );

  const commitment = boundedString(asset.proofAssetCommitment);
  const signedCommitment = boundedString(claims.proof_asset_commitment);
  const commitmentAvailable = commitment !== null && signedCommitment !== null;
  setCheck(
    checks,
    "asset_commitment",
    makeCheck(
      "asset_commitment",
      !commitmentAvailable ? "NOT_ASSESSED" : commitment === signedCommitment ? "PASS" : "FAIL",
      !commitmentAvailable
        ? "CHECK_NOT_ASSESSED"
        : commitment === signedCommitment
          ? "ASSET_COMMITMENT_MATCH"
          : "ASSET_COMMITMENT_MISMATCH",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
      commitmentAvailable,
    ),
  );

  const metadata = asRecord(asset.verificationMetadata);
  const digestPrefixes = [
    boundedString(asset.proofDigestPrefix),
    boundedString(metadata?.proof_digest_prefix),
  ].filter((value): value is string => value !== null);
  const distinctDigestPrefixes = [...new Set(digestPrefixes)];
  if (distinctDigestPrefixes.length === 0) {
    setCheck(
      checks,
      "proof_digest_binding",
      makeCheck(
        "proof_digest_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "PREFIX_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  } else {
    const match =
      distinctDigestPrefixes.length === 1 &&
      distinctDigestPrefixes.every((prefix) => claims.proof_digest.startsWith(prefix));
    setCheck(
      checks,
      "proof_digest_binding",
      makeCheck(
        "proof_digest_binding",
        match ? "PASS" : "FAIL",
        match ? "ASSET_BINDING_VALID" : "ASSET_BINDING_MISMATCH",
        "PREFIX_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  }

  const policyHash = boundedString(asset.policyHash);
  const policyCid = boundedString(asset.policyCid);
  const policyAvailable = policyHash !== null && policyCid !== null;
  const policyMatch =
    policyAvailable && policyHash === claims.policy_hash && policyCid === claims.policy_cid;
  setCheck(
    checks,
    "policy_binding",
    makeCheck(
      "policy_binding",
      !policyAvailable ? "UNKNOWN" : policyMatch ? "PASS" : "FAIL",
      !policyAvailable
        ? "CHECK_UNKNOWN"
        : policyMatch
          ? "POLICY_BINDING_MATCH"
          : "POLICY_BINDING_MISMATCH",
      "EXACT_FIELD_BINDING",
      "PAR_SIGNED_RECEIPT",
    ),
  );

  const constraintHash = boundedString(asset.constraintHash);
  const constraintCid = boundedString(asset.constraintCid);
  if (constraintHash !== null) {
    const match = constraintHash === claims.constraint_hash;
    setCheck(
      checks,
      "constraint_binding",
      makeCheck(
        "constraint_binding",
        match ? "PASS" : "FAIL",
        match ? "CONSTRAINT_BINDING_MATCH" : "CONSTRAINT_BINDING_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  } else if (constraintCid !== null) {
    // A CID and a signed constraint hash are different namespaces. The
    // current public view has no independent comparator, so this optional
    // check remains explicit NOT_ASSESSED rather than overclaiming equality.
    setCheck(
      checks,
      "constraint_binding",
      makeCheck(
        "constraint_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  } else {
    setCheck(
      checks,
      "constraint_binding",
      makeCheck(
        "constraint_binding",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  }

  const circuitId = boundedString(asset.circuitOrSchemaId);
  const signedCircuitId = boundedString(claims.circuit_or_schema_id);
  const circuitVersion = metadata?.circuit_version;
  const signedCircuitVersion = claims.circuit_version;
  const circuitComparisons: boolean[] = [];
  if (circuitId !== null && signedCircuitId !== null)
    circuitComparisons.push(circuitId === signedCircuitId);
  if (circuitVersion !== undefined && signedCircuitVersion !== undefined)
    circuitComparisons.push(circuitVersion === signedCircuitVersion);
  if (circuitComparisons.length > 0) {
    const match = circuitComparisons.every(Boolean);
    setCheck(
      checks,
      "circuit_binding",
      makeCheck(
        "circuit_binding",
        match ? "PASS" : "FAIL",
        match ? "CIRCUIT_BINDING_MATCH" : "CIRCUIT_BINDING_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  } else {
    setCheck(
      checks,
      "circuit_binding",
      makeCheck(
        "circuit_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  }

  if (evidence.statusCheck) {
    const projectionUrl = evidence.statusCheck.statusListUrl;
    const projectionIndex = evidence.statusCheck.statusListIndex;
    const projectionPurpose = evidence.statusCheck.statusPurpose ?? evidence.statusCheck.purpose;
    const match =
      evidence.statusCheck.statusListUrl === claims.status_ref.statusListUrl &&
      projectionIndex === claims.status_ref.statusListIndex &&
      projectionPurpose === claims.status_ref.statusPurpose &&
      projectionUrl === claims.status_ref.statusListUrl;
    setCheck(
      checks,
      "status_check_projection",
      makeCheck(
        "status_check_projection",
        match ? "PASS" : "FAIL",
        match ? "STATUS_PROJECTION_MATCH" : "STATUS_PROJECTION_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
  }

  const provenance = evidence.provenance;
  const provenanceEnvironment = boundedString(provenance?.environment);
  const provenanceRevision =
    provenance?.configurationRevision ?? provenance?.configuration_revision;
  const provenanceBinding = provenance?.binding;
  if (
    provenanceBinding === "legacy_unavailable" ||
    provenanceEnvironment === null ||
    !Number.isSafeInteger(provenanceRevision)
  ) {
    setCheck(
      checks,
      "provenance_binding",
      makeCheck(
        "provenance_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  } else if (claims.environment !== undefined && claims.configuration_revision !== undefined) {
    const match =
      provenanceEnvironment === claims.environment &&
      provenanceRevision === claims.configuration_revision;
    setCheck(
      checks,
      "provenance_binding",
      makeCheck(
        "provenance_binding",
        match ? "PASS" : "FAIL",
        match ? "CHECK_PASSED" : "PUBLIC_RECORD_CONTRADICTION",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  } else {
    // A producer projection without a signed counterpart is useful metadata,
    // not an assertion that can be made independently by this verifier.
    setCheck(
      checks,
      "provenance_binding",
      makeCheck(
        "provenance_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  }

  const freshness = evidence.freshness;
  const freshnessComparisons: boolean[] = [];
  const freshnessExpiry = boundedString(freshness?.expiresAt);
  if (freshnessExpiry !== null && claims.proof_expires_at !== undefined)
    freshnessComparisons.push(freshnessExpiry === claims.proof_expires_at);
  const assetTtl = freshness?.ttlSeconds;
  if (typeof assetTtl === "number" && claims.policy_ttl_seconds !== undefined)
    freshnessComparisons.push(assetTtl === claims.policy_ttl_seconds);
  if (freshnessComparisons.length > 0) {
    const match = freshnessComparisons.every(Boolean);
    setCheck(
      checks,
      "policy_freshness_binding",
      makeCheck(
        "policy_freshness_binding",
        match ? "PASS" : "FAIL",
        match ? "CHECK_PASSED" : "PUBLIC_RECORD_CONTRADICTION",
        "CLOCK_VALIDATION",
        "PAR_SIGNED_RECEIPT",
      ),
    );
  } else {
    // `_freshness` (age/isAdvisoryExpired) is a display hint and has no
    // independently comparable signed value. Keep the check explicitly
    // optional rather than turning producer metadata into UNKNOWN evidence.
    setCheck(
      checks,
      "policy_freshness_binding",
      makeCheck(
        "policy_freshness_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "CLOCK_VALIDATION",
        "PAR_SIGNED_RECEIPT",
        false,
      ),
    );
  }
}

function setStatusProjectionResult(
  checks: Check[],
  projection: Record<string, unknown> | null,
  bundleChecksStatus: string | null,
  registryStatus: RegistryStatus,
): void {
  if (!projection || typeof projection.state !== "string") return;
  // A public projection cannot establish a registry state when the signed
  // status credential was unavailable. Leave the projection result alone so
  // the required signed-status checks classify the report INDETERMINATE.
  if (registryStatus === "UNKNOWN") return;
  const expected =
    projection.state === "active"
      ? "ACTIVE"
      : projection.state === "revoked"
        ? "REVOKED"
        : projection.state === "suspended"
          ? "SUSPENDED"
          : "UNKNOWN";
  // `checks.status` is another producer projection. It is intentionally
  // compared only after the signed status credential established a registry
  // state; an inconsistent public pair without trusted status evidence is
  // unavailable, not a contradiction.
  const checksMatch =
    bundleChecksStatus === null ||
    (bundleChecksStatus === "active" && projection.state === "active") ||
    (bundleChecksStatus === "revoked" && projection.state === "revoked") ||
    (bundleChecksStatus === "suspended" && projection.state === "suspended") ||
    (bundleChecksStatus === "unavailable" && projection.state === "unavailable");
  if (expected !== registryStatus || !checksMatch)
    setCheck(
      checks,
      "status_check_projection",
      makeCheck(
        "status_check_projection",
        "FAIL",
        "STATUS_PROJECTION_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
}

function setStatusReferenceResult(
  checks: Check[],
  claims: ReceiptClaims,
  statusCredentialValid: boolean,
  failure?: StatusVerificationFailure,
  fetchedStatusUrl?: string | null,
): void {
  if (statusCredentialValid) {
    const fetchedMatches =
      fetchedStatusUrl === null ||
      fetchedStatusUrl === undefined ||
      fetchedStatusUrl === claims.status_ref.statusListUrl;
    setCheck(
      checks,
      "status_reference_binding",
      makeCheck(
        "status_reference_binding",
        fetchedMatches ? "PASS" : "FAIL",
        fetchedMatches ? "STATUS_REFERENCE_MATCH" : "STATUS_REFERENCE_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
  } else if (
    failure?.code === "STATUS_ID_MISMATCH" ||
    failure?.code === "STATUS_ISSUER_MISMATCH" ||
    failure?.code === "STATUS_SUBJECT_MISMATCH" ||
    failure?.code === "STATUS_PURPOSE_MISMATCH"
  ) {
    setCheck(
      checks,
      "status_reference_binding",
      makeCheck(
        "status_reference_binding",
        "FAIL",
        "STATUS_REFERENCE_MISMATCH",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
  } else if (!claims.status_ref.statusListUrl) {
    throw new Error("INTERNAL_INVARIANT_FAILURE");
  }
}

function setReceiptProjectionResult(
  checks: Check[],
  projection: Record<string, unknown> | null,
  claims: ReceiptClaims,
): void {
  const result = receiptProjectionResult(projection, claims);
  if (result === "MISMATCH") {
    setCheck(
      checks,
      "bundle_structure",
      makeCheck(
        "bundle_structure",
        "FAIL",
        "PUBLIC_RECORD_CONTRADICTION",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
  } else if (result === "MISSING") {
    setCheck(
      checks,
      "bundle_structure",
      makeCheck(
        "bundle_structure",
        "UNKNOWN",
        "BUNDLE_MALFORMED",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
  }
}

function sameNormalizedValue(left: unknown, right: unknown): boolean {
  return (
    JSON.stringify(normalizeClaimProjectionValue(left)) ===
    JSON.stringify(normalizeClaimProjectionValue(right))
  );
}

/**
 * Embedded receipt provenance is a projection, never a trust root. When PAR
 * supplies it, bind every supplied JWK member to the selected key from the
 * separately fetched release/live intersection. Comparing only `kid` would
 * allow a valid but unrelated public key to be displayed beside a valid JWS.
 */
function sameProjectedPublicJwk(
  projected: Record<string, unknown>,
  selected: JsonWebKeyLike,
): boolean {
  // PAR may omit optional JWK metadata from the embedded projection even
  // when the fetched JWKS enriches the same key with it. The cryptographic
  // identity and protected-key algorithm remain mandatory comparisons; an
  // optional member is checked when present, never required merely because
  // the live representation contains it.
  for (const field of ["kty", "crv", "x", "y", "kid"] as const) {
    if (!sameNormalizedValue(projected[field], selected[field])) return false;
  }
  if (projected.alg !== undefined && !sameNormalizedValue(projected.alg, selected.alg)) {
    return false;
  }
  return true;
}

function setReceiptProjectionKeyBinding(
  checks: Check[],
  evidence: ParsedEvidence,
  verifiedHeader: { readonly alg: "ES256"; readonly typ: "JWT"; readonly kid: string },
  trustedKeys: readonly JsonWebKeyLike[],
): void {
  const projectedHeader = evidence.receiptHeader;
  const projectedJwk = evidence.receiptPublicJwk;
  if (projectedHeader === null && projectedJwk === null) return;

  const headerMatches =
    projectedHeader === null ||
    (projectedHeader.alg === verifiedHeader.alg &&
      projectedHeader.kid === verifiedHeader.kid &&
      (projectedHeader.typ === undefined || projectedHeader.typ === verifiedHeader.typ));
  const selected = trustedKeys.find((key) => key.kid === verifiedHeader.kid);
  const jwkMatches =
    projectedJwk === null ||
    (selected !== undefined && sameProjectedPublicJwk(projectedJwk, selected));
  if (headerMatches && jwkMatches) return;

  setCheck(
    checks,
    "bundle_structure",
    makeCheck(
      "bundle_structure",
      "FAIL",
      "PUBLIC_RECORD_CONTRADICTION",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );
}

function requiredFailures(checks: readonly Check[]): ReasonCode[] {
  return checks
    .filter((check) => check.required && check.state === "FAIL")
    .map((check) => check.reason_code);
}

/** Build a canonical non-throwing result when the provider could not obtain evidence. */
export function unavailableReport(
  request: VerifyProofAssetInput,
  nowMs: number,
  reason: ReasonCode = "PUBLIC_RECORD_UNAVAILABLE",
): PublicRecordCoherenceReport {
  const parsedInput = AssetIdSchema.safeParse(request.asset_id);
  const validClock = Number.isSafeInteger(nowMs) && nowMs >= 0 && nowMs <= 8_640_000_000_000_000;
  const checks = baseChecks();
  if (!parsedInput.success || !validClock) {
    setCheck(
      checks,
      "asset_identifier",
      makeCheck(
        "asset_identifier",
        "FAIL",
        "INPUT_ASSET_ID_INVALID",
        "STRUCTURAL_VALIDATION",
        "LOCAL_VERIFIER_POLICY",
      ),
    );
    return report(
      {
        ...request,
        asset_id: parsedInput.success ? request.asset_id : "00000000-0000-4000-8000-000000000001",
      },
      validClock ? nowMs : 0,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      ["INPUT_ASSET_ID_INVALID"],
    );
  }
  setCheck(
    checks,
    "bundle_structure",
    makeCheck(
      "bundle_structure",
      "UNKNOWN",
      reason,
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );
  return report(request, nowMs, checks, "UNKNOWN", ["PUBLIC_RECORD_INDETERMINATE"], [reason]);
}

/**
 * Verify a provider-fetched public PAR evidence envelope. Provider/service
 * own all I/O; this function is synchronous, deterministic, and network-free.
 */
export function verifyEvidence(
  request: VerifyProofAssetInput,
  evidence: CoreEvidenceEnvelope,
  trust: CoreTrustMaterial,
  nowMs: number,
): PublicRecordCoherenceReport {
  const parsedInput = AssetIdSchema.safeParse(request.asset_id);
  const validClock = Number.isSafeInteger(nowMs) && nowMs >= 0 && nowMs <= 8_640_000_000_000_000;
  const checks = baseChecks();
  if (!parsedInput.success || !validClock) {
    setCheck(
      checks,
      "asset_identifier",
      makeCheck(
        "asset_identifier",
        "FAIL",
        "INPUT_ASSET_ID_INVALID",
        "STRUCTURAL_VALIDATION",
        "LOCAL_VERIFIER_POLICY",
      ),
    );
    return report(
      {
        ...request,
        asset_id: parsedInput.success ? request.asset_id : "00000000-0000-4000-8000-000000000001",
      },
      validClock ? nowMs : 0,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      ["INPUT_ASSET_ID_INVALID"],
    );
  }

  const parsed = parseEvidence(evidence);
  if (!parsed.ok) {
    setCheck(
      checks,
      "bundle_structure",
      makeCheck(
        "bundle_structure",
        "UNKNOWN",
        parsed.reasonCode,
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
    return report(request, nowMs, checks, "UNKNOWN", ["PUBLIC_RECORD_INDETERMINATE"]);
  }
  const value = parsed.value;
  const schemaValid = value.bundleSchemaVersion === BUNDLE_SCHEMA_VERSION;
  const hasReceiptObject = value.receipt !== null && value.receiptClaimsProjection !== null;
  setCheck(
    checks,
    "bundle_structure",
    makeCheck(
      "bundle_structure",
      schemaValid && hasReceiptObject ? "PASS" : "UNKNOWN",
      schemaValid && hasReceiptObject ? "BUNDLE_SCHEMA_VALID" : "BUNDLE_MALFORMED",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );

  const assetValidation = PublicAssetRecordInputSchema.safeParse(value.asset);
  setCheck(
    checks,
    "asset_record",
    makeCheck(
      "asset_record",
      assetValidation.success ? "PASS" : "UNKNOWN",
      assetValidation.success ? "PUBLIC_RECORD_AVAILABLE" : "PUBLIC_RECORD_MALFORMED",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );
  const assetId = boundedString(value.asset.proofAssetId);
  setCheck(
    checks,
    "asset_identifier",
    makeCheck(
      "asset_identifier",
      assetId === request.asset_id ? "PASS" : assetId === null ? "UNKNOWN" : "FAIL",
      assetId === request.asset_id
        ? "ASSET_BINDING_VALID"
        : assetId === null
          ? "CHECK_UNKNOWN"
          : "BUNDLE_ASSET_ID_MISMATCH",
      "EXACT_FIELD_BINDING",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );
  setCheck(
    checks,
    "receipt_presence",
    makeCheck(
      "receipt_presence",
      value.receiptJws !== null ? "PASS" : "UNKNOWN",
      value.receiptJws !== null ? "RECEIPT_PRESENT" : "RECEIPT_MISSING",
      "STRUCTURAL_VALIDATION",
      "PAR_PUBLIC_EVIDENCE",
    ),
  );

  const manifestResult = validateReleaseTrustManifest(
    trust.manifest,
    trust.expected_manifest_digest,
  );
  if (!manifestResult.ok) {
    const reason = trustFailureReason(manifestResult.code);
    setCheck(
      checks,
      "trust_manifest",
      makeCheck(
        "trust_manifest",
        "UNKNOWN",
        reason,
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
      ),
    );
    setCheck(
      checks,
      "live_key_intersection",
      makeCheck(
        "live_key_intersection",
        "UNKNOWN",
        reason === "TRUST_KEY_INTERSECTION_CONFLICT" ? reason : "TRUST_KEY_INTERSECTION_EMPTY",
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  }
  setCheck(
    checks,
    "trust_manifest",
    makeCheck(
      "trust_manifest",
      "PASS",
      "TRUST_MANIFEST_VALID",
      "KEY_RING_INTERSECTION",
      "RELEASE_TRUST_MANIFEST",
    ),
  );

  const liveResult = parseReceiptJwks(value.receiptJwks);
  if (!("keys" in liveResult)) {
    const reason = trustFailureReason(liveResult.code);
    setCheck(
      checks,
      "live_key_intersection",
      makeCheck(
        "live_key_intersection",
        "UNKNOWN",
        reason,
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  }
  const intersection = intersectReceiptTrust(manifestResult.manifest, liveResult, {
    expectedManifestDigest: trust.expected_manifest_digest,
  });
  if (!intersection.ok) {
    const reason = trustFailureReason(intersection.code);
    setCheck(
      checks,
      "live_key_intersection",
      makeCheck(
        "live_key_intersection",
        "UNKNOWN",
        reason,
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  }
  setCheck(
    checks,
    "live_key_intersection",
    makeCheck(
      "live_key_intersection",
      "PASS",
      "RECEIPT_KEY_TRUSTED",
      "KEY_RING_INTERSECTION",
      "RELEASE_TRUST_MANIFEST",
    ),
  );

  if (value.receiptJws === null)
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  try {
    parseCompactJws(value.receiptJws, "JWT");
    setCheck(
      checks,
      "receipt_structure",
      makeCheck(
        "receipt_structure",
        "PASS",
        "RECEIPT_PRESENT",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
  } catch (error) {
    const reason = error instanceof Error ? error.message : "";
    const code: ReasonCode =
      reason === "UNSUPPORTED_JWS_ALGORITHM"
        ? "RECEIPT_ALGORITHM_UNSUPPORTED"
        : reason === "JWS_TYPE_MISMATCH"
          ? "RECEIPT_TYPE_INVALID"
          : reason === "UNSUPPORTED_JWS_HEADER"
            ? "RECEIPT_CRITICAL_HEADER_UNSUPPORTED"
            : "RECEIPT_MALFORMED";
    setCheck(
      checks,
      "receipt_structure",
      makeCheck(
        "receipt_structure",
        "UNKNOWN",
        code,
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  }

  const receiptResult = verifyReceiptJws(value.receiptJws, intersection.keys, {
    nowSeconds: Math.floor(nowMs / 1000),
    expectedAssetId: request.asset_id,
  });
  if (!receiptResult.ok) {
    const failure = receiptResult;
    const state = receiptFailureState(failure);
    if (failure.code === "RECEIPT_KID_UNTRUSTED")
      setCheck(
        checks,
        "live_key_intersection",
        makeCheck(
          "live_key_intersection",
          "UNKNOWN",
          "RECEIPT_KEY_UNKNOWN",
          "KEY_RING_INTERSECTION",
          "RELEASE_TRUST_MANIFEST",
        ),
      );
    if (failure.signature_verified)
      setCheck(
        checks,
        "receipt_signature",
        makeCheck(
          "receipt_signature",
          "PASS",
          "RECEIPT_SIGNATURE_VALID",
          "JWS_SIGNATURE",
          "PAR_SIGNED_RECEIPT",
        ),
      );
    else
      setCheck(
        checks,
        "receipt_signature",
        makeCheck(
          "receipt_signature",
          state,
          failure.code === "RECEIPT_SIGNATURE_INVALID"
            ? "RECEIPT_SIGNATURE_INVALID"
            : mapReceiptStructureFailure(failure),
          "JWS_SIGNATURE",
          "PAR_SIGNED_RECEIPT",
        ),
      );
    setCheck(
      checks,
      "receipt_claims",
      makeCheck(
        "receipt_claims",
        state,
        mapReceiptClaimsFailure(failure),
        "CLOCK_VALIDATION",
        "PAR_SIGNED_RECEIPT",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      [state === "FAIL" ? "PUBLIC_RECORD_CONTRADICTION" : "PUBLIC_RECORD_INDETERMINATE"],
      state === "FAIL" ? [mapReceiptClaimsFailure(failure)] : [],
    );
  }

  setCheck(
    checks,
    "receipt_signature",
    makeCheck(
      "receipt_signature",
      "PASS",
      "RECEIPT_SIGNATURE_VALID",
      "JWS_SIGNATURE",
      "PAR_SIGNED_RECEIPT",
    ),
  );
  setCheck(
    checks,
    "receipt_claims",
    makeCheck(
      "receipt_claims",
      "PASS",
      "RECEIPT_CLAIMS_VALID",
      "CLOCK_VALIDATION",
      "PAR_SIGNED_RECEIPT",
    ),
  );
  setReceiptProjectionResult(checks, value.receiptClaimsProjection, receiptResult.claims);
  setReceiptProjectionKeyBinding(checks, value, receiptResult.header, intersection.keys);
  setAssetBindings(checks, value, request, receiptResult.claims);

  if (value.statusCredential === null || value.statusContentType !== "application/vc+jwt") {
    setCheck(
      checks,
      "signed_status",
      makeCheck(
        "signed_status",
        "UNKNOWN",
        "STATUS_CREDENTIAL_MISSING",
        "JWS_SIGNATURE",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
    return report(
      request,
      nowMs,
      checks,
      "UNKNOWN",
      ["PUBLIC_RECORD_INDETERMINATE"],
      requiredFailures(checks),
    );
  }

  const statusResult = verifySignedStatusCredential(value.statusCredential, intersection.keys, {
    nowMs,
    expectedId: receiptResult.claims.status_ref.statusListUrl,
    expectedPurpose: receiptResult.claims.status_ref.statusPurpose,
    statusListIndex: receiptResult.claims.status_ref.statusListIndex,
    expectedIssuer: CANONICAL_RECEIPT_ISSUER,
  });
  let registryStatus: RegistryStatus = "UNKNOWN";
  if (!statusResult.ok) {
    const failure = statusResult;
    const code = mapStatusFailure(failure);
    const state = statusFailureState(failure);
    setCheck(
      checks,
      "signed_status",
      makeCheck("signed_status", state, code, "JWS_SIGNATURE", "PAR_SIGNED_STATUS_CREDENTIAL"),
    );
    setStatusReferenceResult(checks, receiptResult.claims, false, failure, value.statusUrl);
    setCheck(
      checks,
      "registry_status",
      makeCheck(
        "registry_status",
        "UNKNOWN",
        code === "STATUS_INDEX_INVALID" || code === "STATUS_INDEX_OUT_OF_RANGE"
          ? code
          : "STATUS_UNKNOWN",
        "STATUS_BIT_EVALUATION",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
  } else {
    registryStatus = statusResult.registryStatus;
    setCheck(
      checks,
      "signed_status",
      makeCheck(
        "signed_status",
        "PASS",
        "STATUS_CREDENTIAL_SIGNATURE_VALID",
        "JWS_SIGNATURE",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
    setStatusReferenceResult(checks, receiptResult.claims, true, undefined, value.statusUrl);
    const statusReason: ReasonCode =
      registryStatus === "ACTIVE"
        ? "STATUS_ACTIVE"
        : registryStatus === "REVOKED"
          ? "STATUS_REVOKED"
          : "STATUS_SUSPENDED";
    setCheck(
      checks,
      "registry_status",
      makeCheck(
        "registry_status",
        "PASS",
        statusReason,
        "STATUS_BIT_EVALUATION",
        "PAR_SIGNED_STATUS_CREDENTIAL",
      ),
    );
  }
  setStatusProjectionResult(checks, value.statusCheck, value.bundleChecksStatus, registryStatus);

  const warnings: ReasonCode[] = ["FRESHNESS_ADVISORY"];
  if (
    value.asset._freshness &&
    isRecord(value.asset._freshness) &&
    value.asset._freshness.isAdvisoryExpired === true
  )
    warnings.push("FRESHNESS_EXPIRED");
  return report(request, nowMs, checks, registryStatus, warnings, requiredFailures(checks));
}

export const verifyPublicRecord = verifyEvidence;
