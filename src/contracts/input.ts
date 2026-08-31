import { z } from "zod";

import {
  ASSURANCE_COMPLETENESS_EXCEPTION_VALUES,
  CANONICAL_PAR_ORIGIN,
  CANONICAL_RECEIPT_JWKS_PATH,
  MAX_EVIDENCE_BYTES,
  MAX_STATUS_CREDENTIAL_BYTES,
  REPORT_CONTRACT_ID,
  REPORT_SCHEMA_VERSION,
  STATUS_PURPOSE_VALUES,
  STATUS_CREDENTIAL_MEDIA_TYPE,
} from "./constants.js";

/** Canonical lower-case UUID shape used by the public PAR routes. */
export const AssetIdSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    "asset_id must be a canonical lower-case UUID",
  )
  .meta({
    title: "PAR proof asset identifier",
    description: "A canonical lower-case UUID identifying one public PAR record.",
    examples: ["00000000-0000-4000-8000-000000000001"],
  });

/** RFC 3339 date-time with seconds, an explicit offset, and a real calendar date. */
const RFC3339DateTimePattern =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

export function isValidRFC3339DateTime(value: string): boolean {
  const match = RFC3339DateTimePattern.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === undefined ? 0 : Number(match[8]);
  const offsetMinute = match[9] === undefined ? 0 : Number(match[9]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth =
    [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ?? 0;
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    offsetHour <= 23 &&
    offsetMinute <= 59
  );
}

export const RFC3339DateTimeInputSchema = z
  .string()
  .regex(
    RFC3339DateTimePattern,
    "must be an RFC 3339 date-time with seconds and an explicit offset",
  )
  .superRefine((value, context) => {
    if (!isValidRFC3339DateTime(value)) {
      context.addIssue({
        code: "custom",
        message: "must contain a valid calendar date and time",
      });
    }
  });

const BoundedTextSchema = (max: number) => z.string().min(1).max(max);
const NullableBoundedTextSchema = (max: number) => BoundedTextSchema(max).nullable().optional();
const BoundedDecimalStringSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "must be a canonical non-negative decimal string")
  .max(20);
const COMPACT_JWS_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const P256_COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const CANONICAL_STATUS_URL_PATTERN =
  /^https:\/\/par\.myproof\.ai\/status\/(revocation|suspension)\/default$/;

/** The only status URLs that can be fetched by the provider. */
export const CanonicalStatusUrlSchema = z
  .string()
  .regex(CANONICAL_STATUS_URL_PATTERN, "status URL must be a canonical PAR status-list URL")
  .meta({
    title: "Canonical PAR status-list URL",
    description: "A finite HTTPS status-list path under the canonical PAR origin.",
    examples: ["https://par.myproof.ai/status/revocation/default"],
  });

/** A bounded compact JWS; the provider still performs transport-level checks. */
const CompactJwsSchema = (max: number) =>
  z
    .string()
    .min(8)
    .max(max)
    .regex(COMPACT_JWS_PATTERN, "must be a compact JWS with three base64url segments");

/**
 * PAR intentionally permits a closed set of predicate names at its own
 * producer boundary.  The verifier does not need to know those names to
 * establish record coherence, but it must consume the exact JSON value
 * without turning it into an unbounded `unknown` passthrough.  Keep this
 * transport-only value bounded and discard it before report construction.
 */
const PredicateResultInputSchema = z
  .record(
    z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_.:-]+$/),
    z.union([z.boolean(), z.string().max(512)]),
  )
  .superRefine((value, context) => {
    if (Object.keys(value).length > 64) {
      context.addIssue({
        code: "too_big",
        maximum: 64,
        inclusive: true,
        origin: "record",
        message: "predicate_result contains too many entries",
      });
    }
  });

const AssuranceHexSchema = z.string().regex(/^[0-9a-f]{64}$/);
const AssuranceNullableHexSchema = AssuranceHexSchema.nullable();
const AssuranceExceptionSchema = z.enum(ASSURANCE_COMPLETENESS_EXCEPTION_VALUES);
const AssuranceOrderedPredicateSchema = z.strictObject({
  index: z.number().int().min(0).max(7),
  outcome: z.enum(["pass", "fail"]),
  provenance: z.literal("exact_journal"),
  policy_cid: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  verifier_binding_hash: AssuranceHexSchema,
});

/**
 * Exact bounded public assurance projection emitted by PAR.  It is accepted
 * only at the transport seam and is never copied into the normalized v1
 * report; in particular, none of these values are an independent proof or
 * predicate result for this verifier.
 */
export const PublicAssurancePayloadInputSchema = z
  .strictObject({
    submission_mode: z.literal("direct"),
    provenance: z.literal("exact_journal"),
    completeness: z.enum(["incomplete", "complete"]),
    completeness_exceptions: z.array(AssuranceExceptionSchema).max(16),
    circuit_version: z.literal(6),
    journal_version: z.literal(16),
    image_id_digest: AssuranceHexSchema,
    verifier_artifact_digest: AssuranceNullableHexSchema,
    proof_digest: AssuranceHexSchema,
    receipt_digest: AssuranceHexSchema,
    policy_version: z.string().min(1).max(64).nullable(),
    policy_cid: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    policy_hash: AssuranceHexSchema,
    ordered_predicates: z.array(AssuranceOrderedPredicateSchema).min(1).max(8),
    holder_evidence_root: AssuranceHexSchema,
    assurance_profile_hash: AssuranceHexSchema,
    assurance_profile_version: z.literal(1),
    assurance_decision: z.literal(true),
    component_provenance: z.literal("aggregate_proven"),
    face_match_required: z.literal(true),
    face_match_pass: z.literal(true),
    face_threshold_q16: z.literal(49_152),
    face_consensus_count: z.number().int().min(0).max(0xffff_ffff).nullable(),
    face_frame_count: z.number().int().min(3).max(0xffff_ffff).nullable(),
    face_required_count: z.number().int().min(1).max(0xffff_ffff).nullable(),
    credential_kind: z.enum(["passport", "dl", "other_supported"]).nullable(),
    credential_auth_class: z.number().int().min(1).max(3),
    portrait_source: z.null(),
    document_authentication: z.null(),
    liveness: z.literal("pass"),
    texture: z.literal("pass"),
    depth: z.literal("not_applicable"),
    continuous_presence: z.literal("pass"),
    challenge: z.literal("pass"),
    app_attest: z.literal("pass"),
    app_attest_counter: z.literal("pass"),
    capture_ms: z.number().int().min(1).max(600_000),
    prove_ms: z.null(),
    finalize_ms: z.null(),
    server_git_sha: z
      .string()
      .regex(/^[0-9a-f]{7,64}$/)
      .nullable(),
    deployment_region: z
      .string()
      .regex(/^[a-z0-9_-]{1,64}$/)
      .nullable(),
    app_clip_git_sha: z
      .string()
      .regex(/^[0-9a-f]{40}$/)
      .nullable(),
    app_clip_build: z
      .string()
      .regex(/^(?:0|[1-9][0-9]{0,9})$/)
      .nullable(),
  })
  .superRefine((value, context) => {
    const exceptions = new Set(value.completeness_exceptions);
    if (exceptions.size !== value.completeness_exceptions.length) {
      context.addIssue({
        code: "custom",
        path: ["completeness_exceptions"],
        message: "completeness exceptions must be unique",
      });
    }

    const isComplete = value.completeness_exceptions.length === 0;
    if ((value.completeness === "complete") !== isComplete) {
      context.addIssue({
        code: "custom",
        path: ["completeness"],
        message: "completeness must match the exception set",
      });
    }

    const policyHash = value.policy_cid.slice("sha256:".length);
    if (policyHash !== value.policy_hash) {
      context.addIssue({
        code: "custom",
        path: ["policy_hash"],
        message: "policy_hash must match the policy_cid digest",
      });
    }

    for (const [index, predicate] of value.ordered_predicates.entries()) {
      if (predicate.index !== index) {
        context.addIssue({
          code: "custom",
          path: ["ordered_predicates", index, "index"],
          message: "ordered predicate indexes must be contiguous and canonical",
        });
      }
      if (predicate.policy_cid !== value.policy_cid) {
        context.addIssue({
          code: "custom",
          path: ["ordered_predicates", index, "policy_cid"],
          message: "ordered predicate policy_cid must match the payload policy_cid",
        });
      }
    }

    const verifierUnavailable = exceptions.has("VERIFIER_ARTIFACT_DIGEST_UNAVAILABLE");
    if ((value.verifier_artifact_digest === null) !== verifierUnavailable) {
      context.addIssue({
        code: "custom",
        path: ["verifier_artifact_digest"],
        message: "verifier artifact digest must match its completeness exception",
      });
    }

    const mobileUnavailable = exceptions.has("MOBILE_M3_BINDING_UNAVAILABLE");
    const mobileValues = [value.app_clip_git_sha, value.app_clip_build];
    const mobileMissing = mobileValues.some((item) => item === null);
    if (
      mobileMissing !== mobileUnavailable ||
      mobileMissing !== mobileValues.every((item) => item === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["app_clip_git_sha"],
        message: "mobile provenance fields must be jointly present or absent",
      });
    }

    const countsUnavailable = exceptions.has("CONSENSUS_COUNTS_UNAVAILABLE");
    const counts = [value.face_consensus_count, value.face_frame_count, value.face_required_count];
    const countsMissing = counts.some((item) => item === null);
    if (
      countsMissing !== countsUnavailable ||
      countsMissing !== counts.every((item) => item === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["face_consensus_count"],
        message: "consensus counts must be jointly present or absent",
      });
    } else if (!countsMissing) {
      const frameCount = value.face_frame_count as number;
      const expectedRequired = Math.floor((2 * frameCount + 2) / 3);
      if (
        value.face_required_count !== expectedRequired ||
        (value.face_consensus_count as number) < expectedRequired ||
        (value.face_consensus_count as number) > frameCount
      ) {
        context.addIssue({
          code: "custom",
          path: ["face_required_count"],
          message: "consensus counts do not satisfy the canonical threshold",
        });
      }
    }
  });

export const PublicAssuranceEvidenceInputSchema = z.strictObject({
  payloadHash: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  projectedAt: RFC3339DateTimeInputSchema,
  decisionStatus: z.literal("verified"),
  validation: z.literal("ingestion_validated"),
  payload: PublicAssurancePayloadInputSchema,
});

export type PublicAssurancePayloadInput = z.infer<typeof PublicAssurancePayloadInputSchema>;
export type PublicAssuranceEvidenceInput = z.infer<typeof PublicAssuranceEvidenceInputSchema>;

/**
 * The only caller-controlled input in v1. In particular, this does not
 * accept a URL, receipt, key, credential, proof bytes, status reference, or
 * arbitrary options object.
 */
export const VerifyProofAssetInputSchema = z
  .strictObject({
    asset_id: AssetIdSchema,
    // The wire operation argument is optional and normalizes to false. Keep
    // `.optional()` after `.default()` so generated JSON Schema advertises
    // the actual accepted caller shape instead of falsely requiring it.
    require_active: z.boolean().default(false).optional().meta({
      description: "Require the published registry status to be active.",
      default: false,
    }),
  })
  .meta({
    id: "myproof.par.public-record-input.v1",
    title: "MyProof PAR public-record verification input",
    description:
      "Strict input for verify_proof_asset_record. No caller-selected network or evidence source is accepted.",
    x_contract_id: REPORT_CONTRACT_ID,
    x_schema_version: REPORT_SCHEMA_VERSION,
    x_canonical_origin: CANONICAL_PAR_ORIGIN,
  });

/** Normalized facade input after the schema default has been applied. */
export type VerifyProofAssetInput = {
  readonly asset_id: z.infer<typeof AssetIdSchema>;
  readonly require_active: boolean;
};
/**
 * Normalize caller arguments once at the shared facade boundary. Keeping this
 * separate from the advertised input schema lets JSON Schema accurately show
 * that `require_active` may be omitted while core/service types remain total.
 */
export function parseVerifyProofAssetInput(value: unknown): VerifyProofAssetInput {
  const parsed = VerifyProofAssetInputSchema.parse(value);
  return {
    asset_id: parsed.asset_id,
    require_active: parsed.require_active ?? false,
  };
}

/**
 * Public PAR asset fields actually emitted by `publicProofAssetView` plus the
 * status projection fields needed for receipt↔asset comparisons. This is a
 * strict allowlist: raw database rows, proof bytes, partner identifiers,
 * subject bindings, and arbitrary metadata cannot cross the provider seam.
 */
export const PublicAssetRecordInputSchema = z
  .strictObject({
    proofAssetId: AssetIdSchema,
    proofAssetCommitment: BoundedTextSchema(512).optional(),
    proofFormat: BoundedTextSchema(64).optional(),
    proofDigestPrefix: BoundedTextSchema(128).nullable().optional(),
    digestAlg: BoundedTextSchema(64).optional(),
    constraintCid: NullableBoundedTextSchema(512),
    /** Optional because the frozen public view does not currently expose it. */
    constraintHash: NullableBoundedTextSchema(512),
    policyHash: NullableBoundedTextSchema(512),
    policyCid: NullableBoundedTextSchema(512),
    circuitOrSchemaId: NullableBoundedTextSchema(256),
    circuitCid: NullableBoundedTextSchema(512),
    schemaCid: NullableBoundedTextSchema(512),
    contentCids: z.array(BoundedTextSchema(512)).max(64).nullable().optional(),
    auditCid: NullableBoundedTextSchema(512),
    verificationStatus: NullableBoundedTextSchema(64),
    verificationAlgorithm: NullableBoundedTextSchema(128),
    verificationTimestamp: RFC3339DateTimeInputSchema.nullable().optional(),
    verificationMetadata: z
      .strictObject({
        circuit_version: z.number().int().nonnegative().max(1_000_000).optional(),
        predicate_result: PredicateResultInputSchema.nullable().optional(),
        proof_digest_prefix: BoundedTextSchema(128).optional(),
        proof_format: BoundedTextSchema(64).optional(),
        digest_alg: BoundedTextSchema(64).optional(),
      })
      .nullable()
      .optional(),
    statusListUrl: CanonicalStatusUrlSchema.optional(),
    statusListIndex: BoundedDecimalStringSchema.optional(),
    statusPurpose: z.enum(STATUS_PURPOSE_VALUES).optional(),
    status: z
      .strictObject({
        purpose: z.enum(STATUS_PURPOSE_VALUES),
        verificationStatus: BoundedTextSchema(64),
      })
      .optional(),
    ttlSeconds: z.number().int().nonnegative().max(31_536_000).nullable().optional(),
    expiresAt: RFC3339DateTimeInputSchema.nullable().optional(),
    createdAt: RFC3339DateTimeInputSchema.optional(),
    _freshness: z
      .strictObject({
        ageSeconds: z.number().int().nonnegative().max(31_536_000),
        isAdvisoryExpired: z.boolean(),
      })
      .optional(),
  })
  .superRefine((value, context) => {
    const directStatus = value.statusListUrl;
    if (
      directStatus !== undefined &&
      value.statusPurpose !== undefined &&
      !directStatus.endsWith(`/status/${value.statusPurpose}/default`)
    ) {
      context.addIssue({
        code: "custom",
        path: ["statusPurpose"],
        message: "status purpose must match the canonical status URL",
      });
    }
    if (
      value.status !== undefined &&
      value.statusListUrl !== undefined &&
      !value.statusListUrl.endsWith(`/status/${value.status.purpose}/default`)
    ) {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "status purpose must match the canonical status URL",
      });
    }
    if (
      value.status !== undefined &&
      value.statusPurpose !== undefined &&
      value.status.purpose !== value.statusPurpose
    ) {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "status projection purposes must agree",
      });
    }
  });

export type PublicAssetRecordInput = z.infer<typeof PublicAssetRecordInputSchema>;

/** The exact status reference projection needed for binding checks. */
export const StatusReferenceInputSchema = z
  .strictObject({
    statusListUrl: CanonicalStatusUrlSchema,
    statusListIndex: BoundedDecimalStringSchema,
    statusPurpose: z.enum(STATUS_PURPOSE_VALUES),
  })
  .superRefine((value, context) => {
    if (!value.statusListUrl.endsWith(`/status/${value.statusPurpose}/default`)) {
      context.addIssue({
        code: "custom",
        path: ["statusPurpose"],
        message: "status purpose must match the canonical status URL",
      });
    }
  });

export type StatusReferenceInput = z.infer<typeof StatusReferenceInputSchema>;

/**
 * Receipt claims are allowlisted rather than represented as a record of
 * unknown values. Audit/transparency claims may be parsed for compatibility,
 * but no v1 check or report field exposes or verifies them.
 */
export const ReceiptClaimsInputSchema = z.strictObject({
  /** These projections may be omitted by the route; the signed JWS is authoritative. */
  proof_digest: BoundedTextSchema(4_096).optional(),
  policy_hash: BoundedTextSchema(4_096).optional(),
  constraint_hash: BoundedTextSchema(4_096).optional(),
  status_ref: StatusReferenceInputSchema.optional(),
  jti: BoundedTextSchema(4_096).optional(),
  aud: BoundedTextSchema(512).optional(),
  exp: z.number().int().nonnegative().max(9_999_999_999).optional(),
  nbf: z.number().int().nonnegative().max(9_999_999_999).optional(),
  iat: z.number().int().nonnegative().max(9_999_999_999).optional(),
  iss: BoundedTextSchema(512).optional(),
  sub: AssetIdSchema.optional(),
  proof_asset_commitment: BoundedTextSchema(512).optional(),
  policy_cid: BoundedTextSchema(512).optional(),
  circuit_or_schema_id: BoundedTextSchema(256).optional(),
  circuit_version: z.number().int().nonnegative().max(1_000_000).optional(),
  audit_event_id: BoundedTextSchema(512).optional(),
  audit_event_hash: BoundedTextSchema(512).optional(),
  upstream_receipt_hash: BoundedTextSchema(512).optional(),
  created_at: RFC3339DateTimeInputSchema.optional(),
  environment: z.enum(["sandbox", "production"]).optional(),
  configuration_revision: z.number().int().nonnegative().max(1_000_000_000).optional(),
  policy_ttl_seconds: z.number().int().positive().max(31_536_000).optional(),
  proof_expires_at: RFC3339DateTimeInputSchema.optional(),
  freshness_source: z.literal("policy").optional(),
  nonce: BoundedTextSchema(512).optional(),
});

export type ReceiptClaimsInput = z.infer<typeof ReceiptClaimsInputSchema>;

export const ReceiptJwkInputSchema = z.strictObject({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  x: z.string().regex(P256_COORDINATE_PATTERN, "x must be a 32-byte base64url coordinate"),
  y: z.string().regex(P256_COORDINATE_PATTERN, "y must be a 32-byte base64url coordinate"),
  kid: z.string().regex(KEY_ID_PATTERN, "kid must use the bounded canonical key-id syntax"),
  alg: z.literal("ES256").optional(),
  use: z.literal("sig").optional(),
  key_ops: z.array(z.literal("verify")).min(1).max(4).optional(),
  /** The canonical public JWKS currently emits this explicit capability. */
  ext: z.literal(true).optional(),
});

export type ReceiptJwkInput = z.infer<typeof ReceiptJwkInputSchema>;

export const ReceiptHeaderInputSchema = z.strictObject({
  alg: z.literal("ES256"),
  kid: z.string().regex(KEY_ID_PATTERN, "kid must use the bounded canonical key-id syntax"),
  typ: z.literal("JWT").optional(),
});

export type ReceiptHeaderInput = z.infer<typeof ReceiptHeaderInputSchema>;

export const ReceiptEvidenceInputSchema = z.strictObject({
  type: z.literal("asset").optional(),
  jws: CompactJwsSchema(MAX_EVIDENCE_BYTES),
  jwksUri: z.literal(CANONICAL_RECEIPT_JWKS_PATH).optional(),
  publicJwk: ReceiptJwkInputSchema.optional(),
  header: ReceiptHeaderInputSchema.optional(),
  claims: ReceiptClaimsInputSchema,
});

export type ReceiptEvidenceInput = z.infer<typeof ReceiptEvidenceInputSchema>;

export const ReceiptJwksInputSchema = z
  .strictObject({
    keys: z.array(ReceiptJwkInputSchema).min(1).max(32),
  })
  .superRefine((value, context) => {
    const kids = new Set<string>();
    for (const [index, key] of value.keys.entries()) {
      if (kids.has(key.kid)) {
        context.addIssue({
          code: "custom",
          path: ["keys", index, "kid"],
          message: "receipt JWKS key ids must be unique",
        });
      }
      kids.add(key.kid);
    }
  });

export type ReceiptJwksInput = z.infer<typeof ReceiptJwksInputSchema>;

/** Exact status-check projection emitted by the public verification-bundle route. */
export const StatusCheckInputSchema = z
  .strictObject({
    state: z.enum(["active", "revoked", "suspended", "unavailable"]),
    purpose: z.enum(STATUS_PURPOSE_VALUES),
    checkedAt: RFC3339DateTimeInputSchema,
    statusListUrl: CanonicalStatusUrlSchema,
    statusListIndex: BoundedDecimalStringSchema,
  })
  .superRefine((value, context) => {
    if (!value.statusListUrl.endsWith(`/status/${value.purpose}/default`)) {
      context.addIssue({
        code: "custom",
        path: ["purpose"],
        message: "status purpose must match the canonical status URL",
      });
    }
  });

export type StatusCheckInput = z.infer<typeof StatusCheckInputSchema>;

export const ProvenanceInputSchema = z.strictObject({
  environment: z.enum(["sandbox", "production"]).nullable(),
  configurationRevision: z.number().int().nonnegative().max(1_000_000_000).nullable(),
  binding: z.enum(["asset_receipt", "authorized_mint_record", "legacy_unavailable"]),
});

export type ProvenanceInput = z.infer<typeof ProvenanceInputSchema>;

export const StatusCredentialEvidenceInputSchema = z.strictObject({
  credential: CompactJwsSchema(MAX_STATUS_CREDENTIAL_BYTES),
  content_type: z.literal(STATUS_CREDENTIAL_MEDIA_TYPE),
});

export type StatusCredentialEvidenceInput = z.infer<typeof StatusCredentialEvidenceInputSchema>;

/**
 * The producer includes a complete checks projection even when audit data is
 * omitted.  The audit-related values are accepted as finite transport
 * markers only; v1 never turns them into an assurance check or conclusion.
 */
export const BundleChecksInputSchema = z.strictObject({
  receiptSignature: z.literal("verified"),
  assetBinding: z.literal("verified"),
  audienceBinding: z.literal("verified"),
  status: z.enum(["active", "revoked", "suspended", "unavailable"]),
  auditAnchor: z.literal("omitted"),
  auditInclusion: z.literal("omitted"),
  epochSignature: z.literal("omitted"),
  authorizedMintRecord: z.enum(["verified", "unavailable"]),
  assuranceBinding: z.enum(["ingestion_validated", "unavailable"]),
});

export type BundleChecksInput = z.infer<typeof BundleChecksInputSchema>;

/**
 * The frozen public bundle wire shape. The verifier requests the additive
 * `audit=omit` mode and accepts only the producer's bounded null/omitted
 * placeholders; it rejects an unbounded audit/transparency payload instead of
 * making a v1 assurance claim.
 */
export const PublicVerificationBundleInputSchema = z.strictObject({
  ok: z.literal(true),
  schemaVersion: z.literal("myproof.public-verification-bundle.v1"),
  generatedAt: RFC3339DateTimeInputSchema,
  asset: PublicAssetRecordInputSchema,
  receipt: ReceiptEvidenceInputSchema,
  statusCheck: StatusCheckInputSchema,
  statusCredential: StatusCredentialEvidenceInputSchema.optional(),
  provenance: ProvenanceInputSchema,
  assurance: z.union([z.null(), PublicAssuranceEvidenceInputSchema]),
  /**
   * `audit=omit` is shape-preserving in the producer: it returns a null
   * placeholder and finite omission markers. These fields are transport
   * compatibility only and are deliberately not part of any report check.
   */
  audit: z.null(),
  checks: BundleChecksInputSchema,
});

/**
 * Cross-object comparisons intentionally do not live in the transport
 * schema. They require trusted signed evidence to distinguish a public
 * projection contradiction from merely unavailable or malformed evidence.
 * The core performs these comparisons after receipt/status verification and
 * emits the stable check/reason classification. The nested strict schemas
 * above still enforce types, bounds, canonical URLs, and unknown-field
 * rejection before any value reaches the provider seam.
 */

export type PublicVerificationBundleInput = z.infer<typeof PublicVerificationBundleInputSchema>;

/**
 * Normalized provider-to-core evidence. Raw signed material is accepted here
 * only because the core must verify it; report schemas never carry it.
 */
export const PublicRecordEvidenceInputSchema = z.strictObject({
  bundle: PublicVerificationBundleInputSchema,
  receipt_jwks: ReceiptJwksInputSchema,
  status_credential: StatusCredentialEvidenceInputSchema.optional(),
  /** Exact URL used for the fetched signed status credential. */
  status_url: CanonicalStatusUrlSchema,
});

export type PublicRecordEvidenceInput = z.infer<typeof PublicRecordEvidenceInputSchema>;
