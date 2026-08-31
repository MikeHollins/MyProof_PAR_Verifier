/**
 * Versioned values that form the public semantic contract.
 *
 * Keep this module dependency-free. Adapters may import these constants, but
 * the values must not be inferred from CLI text, MCP annotations, or remote
 * PAR data.
 */

export const REPORT_SCHEMA_VERSION = 1 as const;
/** The canonical schema identifier carried by the report contract. */
export const REPORT_CONTRACT_ID = "myproof.par.public-record-coherence.v1" as const;
export const CANONICAL_PAR_ORIGIN = "https://par.myproof.ai" as const;
/** Current PAR public route; the well-known alias is not the verifier route. */
export const CANONICAL_RECEIPT_JWKS_PATH = "/api/public/receipts/jwks.json" as const;
export const VERIFICATION_BUNDLE_PATH_TEMPLATE =
  "/api/public/proof-assets/{asset_id}/verification-bundle" as const;
export const STATUS_CREDENTIAL_MEDIA_TYPE = "application/vc+jwt" as const;

/** Bounded wire budgets shared by the provider, core, CLI, and MCP adapter. */
/**
 * The report is repeated as MCP text and structured content. Keep the one
 * canonical report below 96 KiB so the duplicated JSON plus JSON-RPC framing
 * remains comfortably below the 512 KiB stdio message budget.
 */
export const MAX_REPORT_BYTES = 98_304 as const;
export const MAX_STDIO_MESSAGE_BYTES = 524_288 as const;
export const MAX_EVIDENCE_BYTES = 1_048_576 as const;
export const MAX_STATUS_CREDENTIAL_BYTES = 25_165_824 as const;
export const MAX_REPORT_CHECKS = 64 as const;
export const MAX_REPORT_REASONS = 32 as const;
export const MAX_REPORT_LIMITATIONS = 16 as const;

/** Stable process exit values used by the CLI adapter. */
export const EXIT_CODES = {
  OK: 0,
  COHERENT_BUT_INACTIVE: 10,
  CONTRADICTORY: 20,
  INDETERMINATE: 21,
  USAGE_ERROR: 64,
  INTERNAL_ERROR: 70,
} as const;

export const RECORD_COHERENCE_VALUES = ["COHERENT", "CONTRADICTORY", "INDETERMINATE"] as const;

export const REGISTRY_STATUS_VALUES = ["ACTIVE", "REVOKED", "SUSPENDED", "UNKNOWN"] as const;

export const REGISTRY_ACTIVE_CONDITION_VALUES = [
  "NOT_REQUESTED",
  "SATISFIED",
  "NOT_SATISFIED",
  "INDETERMINATE",
] as const;

/** Public status-list purposes emitted by the PAR bundle and receipt. */
export const STATUS_PURPOSE_VALUES = ["revocation", "suspension"] as const;

/**
 * Completeness exceptions accepted by the PAR assurance projection.  This is
 * intentionally a closed set copied from the producer contract; accepting
 * arbitrary exception text would make the projection an unbounded assertion
 * channel.
 */
export const ASSURANCE_COMPLETENESS_EXCEPTION_VALUES = [
  "MOBILE_M3_BINDING_UNAVAILABLE",
  "PAR_LINKAGE_PENDING",
  "CONSENSUS_COUNTS_UNAVAILABLE",
  "VERIFIER_ARTIFACT_DIGEST_UNAVAILABLE",
] as const;

export const CHECK_STATE_VALUES = ["PASS", "FAIL", "UNKNOWN", "NOT_ASSESSED"] as const;

export const VERIFICATION_METHOD_VALUES = [
  "STRUCTURAL_VALIDATION",
  "JWS_SIGNATURE",
  "KEY_RING_INTERSECTION",
  "EXACT_FIELD_BINDING",
  "PREFIX_FIELD_BINDING",
  "STATUS_BIT_EVALUATION",
  "CLOCK_VALIDATION",
  "NOT_PERFORMED",
] as const;

export const CHECK_AUTHORITY_VALUES = [
  "PAR_PUBLIC_EVIDENCE",
  "PAR_SIGNED_RECEIPT",
  "PAR_SIGNED_STATUS_CREDENTIAL",
  "RELEASE_TRUST_MANIFEST",
  "CANONICAL_ORIGIN_TLS",
  "LOCAL_VERIFIER_POLICY",
  "NONE",
] as const;

/**
 * Check identifiers are finite and normalized. A new semantic check must be
 * added here and to the compatibility fixtures instead of silently becoming
 * an adapter-specific field.
 */
export const CHECK_IDS = [
  "bundle_structure",
  "asset_record",
  "trust_manifest",
  "live_key_intersection",
  "receipt_presence",
  "receipt_structure",
  "receipt_signature",
  "receipt_claims",
  "asset_identifier",
  "asset_commitment",
  "proof_digest_binding",
  "policy_binding",
  "constraint_binding",
  "circuit_binding",
  "status_reference_binding",
  "status_check_projection",
  "provenance_binding",
  "policy_freshness_binding",
  "signed_status",
  "registry_status",
  "acceptance_decision",
  "underlying_proof_verification",
  "predicate_assurance",
] as const;

export type CanonicalCheckId = (typeof CHECK_IDS)[number];

export type CanonicalCheckDefinition = {
  readonly verification_methods: readonly (typeof VERIFICATION_METHOD_VALUES)[number][];
  readonly authorities: readonly (typeof CHECK_AUTHORITY_VALUES)[number][];
  readonly required: readonly boolean[];
};

/**
 * Cross-lane check metadata. Adapters and the verification core must use
 * this catalog rather than inventing per-lane method/authority combinations.
 * A check may be optional when the corresponding public field is unavailable;
 * that variation is represented explicitly in `required`.
 */
export const CHECK_DEFINITIONS = {
  bundle_structure: {
    verification_methods: ["STRUCTURAL_VALIDATION"],
    authorities: ["PAR_PUBLIC_EVIDENCE"],
    required: [true],
  },
  asset_record: {
    verification_methods: ["STRUCTURAL_VALIDATION"],
    authorities: ["PAR_PUBLIC_EVIDENCE"],
    required: [true],
  },
  trust_manifest: {
    verification_methods: ["KEY_RING_INTERSECTION"],
    authorities: ["RELEASE_TRUST_MANIFEST"],
    required: [true],
  },
  live_key_intersection: {
    verification_methods: ["KEY_RING_INTERSECTION"],
    authorities: ["RELEASE_TRUST_MANIFEST"],
    required: [true],
  },
  receipt_presence: {
    verification_methods: ["STRUCTURAL_VALIDATION"],
    authorities: ["PAR_PUBLIC_EVIDENCE"],
    required: [true],
  },
  receipt_structure: {
    verification_methods: ["STRUCTURAL_VALIDATION"],
    authorities: ["PAR_PUBLIC_EVIDENCE"],
    required: [true],
  },
  receipt_signature: {
    verification_methods: ["JWS_SIGNATURE"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true],
  },
  receipt_claims: {
    verification_methods: ["STRUCTURAL_VALIDATION", "CLOCK_VALIDATION"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true],
  },
  asset_identifier: {
    verification_methods: ["EXACT_FIELD_BINDING", "STRUCTURAL_VALIDATION"],
    authorities: ["PAR_SIGNED_RECEIPT", "PAR_PUBLIC_EVIDENCE", "LOCAL_VERIFIER_POLICY"],
    required: [true],
  },
  asset_commitment: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  proof_digest_binding: {
    verification_methods: ["PREFIX_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  policy_binding: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true],
  },
  constraint_binding: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  circuit_binding: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  status_reference_binding: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_STATUS_CREDENTIAL"],
    required: [true],
  },
  status_check_projection: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_PUBLIC_EVIDENCE"],
    required: [true, false],
  },
  provenance_binding: {
    verification_methods: ["EXACT_FIELD_BINDING"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  policy_freshness_binding: {
    verification_methods: ["CLOCK_VALIDATION"],
    authorities: ["PAR_SIGNED_RECEIPT"],
    required: [true, false],
  },
  signed_status: {
    verification_methods: ["JWS_SIGNATURE"],
    authorities: ["PAR_SIGNED_STATUS_CREDENTIAL"],
    required: [true],
  },
  registry_status: {
    verification_methods: ["STATUS_BIT_EVALUATION"],
    authorities: ["PAR_SIGNED_STATUS_CREDENTIAL"],
    required: [true],
  },
  acceptance_decision: {
    verification_methods: ["NOT_PERFORMED"],
    authorities: ["NONE"],
    required: [false],
  },
  underlying_proof_verification: {
    verification_methods: ["NOT_PERFORMED"],
    authorities: ["NONE"],
    required: [false],
  },
  predicate_assurance: {
    verification_methods: ["NOT_PERFORMED"],
    authorities: ["NONE"],
    required: [false],
  },
} as const satisfies Record<CanonicalCheckId, CanonicalCheckDefinition>;

/** Universal state meanings for generic reason codes. Domain reasons remain
 * intentionally open to avoid claiming more than the producer semantics. */
export const GENERIC_REASON_STATES = {
  CHECK_PASSED: ["PASS"],
  CHECK_FAILED: ["FAIL"],
  CHECK_UNKNOWN: ["UNKNOWN"],
  CHECK_NOT_ASSESSED: ["NOT_ASSESSED"],
  CHECK_NOT_PERFORMED: ["NOT_ASSESSED"],
} as const;

/**
 * Stable reason codes are deliberately not human prose. Remote text must
 * never be copied into a report or used as a routing instruction.
 */
export const REASON_CODES = [
  "CHECK_PASSED",
  "CHECK_FAILED",
  "CHECK_UNKNOWN",
  "CHECK_NOT_ASSESSED",
  "CHECK_NOT_PERFORMED",
  "INPUT_ASSET_ID_INVALID",
  "BUNDLE_SCHEMA_VALID",
  "BUNDLE_MALFORMED",
  "BUNDLE_ASSET_ID_MISMATCH",
  "PUBLIC_RECORD_AVAILABLE",
  "PUBLIC_RECORD_UNAVAILABLE",
  "PUBLIC_RECORD_MALFORMED",
  "PUBLIC_RECORD_CONTRADICTION",
  "PUBLIC_RECORD_INDETERMINATE",
  "RECEIPT_PRESENT",
  "RECEIPT_MISSING",
  "RECEIPT_MALFORMED",
  "RECEIPT_SIGNATURE_VALID",
  "RECEIPT_SIGNATURE_INVALID",
  "RECEIPT_KEY_TRUSTED",
  "RECEIPT_KEY_UNKNOWN",
  "RECEIPT_KEY_CONFLICT",
  "RECEIPT_ALGORITHM_UNSUPPORTED",
  "RECEIPT_TYPE_INVALID",
  "RECEIPT_CRITICAL_HEADER_UNSUPPORTED",
  "RECEIPT_CLAIMS_VALID",
  "RECEIPT_CLAIMS_MISSING",
  "RECEIPT_CLAIMS_EXPIRED",
  "RECEIPT_CLAIMS_NOT_YET_VALID",
  "RECEIPT_AUDIENCE_MISMATCH",
  "RECEIPT_ISSUER_MISMATCH",
  "ASSET_BINDING_VALID",
  "ASSET_BINDING_MISMATCH",
  "ASSET_COMMITMENT_MATCH",
  "ASSET_COMMITMENT_MISMATCH",
  "POLICY_BINDING_MATCH",
  "POLICY_BINDING_MISMATCH",
  "CONSTRAINT_BINDING_MATCH",
  "CONSTRAINT_BINDING_MISMATCH",
  "CIRCUIT_BINDING_MATCH",
  "CIRCUIT_BINDING_MISMATCH",
  "STATUS_REFERENCE_MATCH",
  "STATUS_REFERENCE_MISMATCH",
  "STATUS_PROJECTION_MATCH",
  "STATUS_PROJECTION_MISMATCH",
  "TRUST_MANIFEST_VALID",
  "TRUST_MANIFEST_MISSING",
  "TRUST_MANIFEST_UNAUTHENTICATED",
  "TRUST_MANIFEST_SCHEMA_INVALID",
  "TRUST_MANIFEST_TAMPERED",
  "TRUST_KEY_INTERSECTION_EMPTY",
  "TRUST_KEY_INTERSECTION_CONFLICT",
  "STATUS_CREDENTIAL_SIGNATURE_VALID",
  "STATUS_CREDENTIAL_SIGNATURE_INVALID",
  "STATUS_CREDENTIAL_MISSING",
  "STATUS_CREDENTIAL_MALFORMED",
  "STATUS_CREDENTIAL_EXPIRED",
  "STATUS_CREDENTIAL_NOT_YET_VALID",
  "STATUS_ACTIVE",
  "STATUS_REVOKED",
  "STATUS_SUSPENDED",
  "STATUS_UNKNOWN",
  "STATUS_INDEX_INVALID",
  "STATUS_INDEX_OUT_OF_RANGE",
  "FRESHNESS_ADVISORY",
  "FRESHNESS_EXPIRED",
  "PREDICATE_REPORTED_ONLY",
  "PROOF_VERIFICATION_NOT_PERFORMED",
  "ACCEPTANCE_NOT_PERFORMED",
  "NETWORK_ABORTED",
  "NETWORK_TIMEOUT",
  "NETWORK_RESPONSE_TOO_LARGE",
  "NETWORK_REDIRECT_REJECTED",
  "NETWORK_ORIGIN_REJECTED",
  "NETWORK_CONTENT_TYPE_INVALID",
  "INTERNAL_INVARIANT_FAILURE",
] as const;

export type CanonicalCheckVariant = {
  readonly id: CanonicalCheckId;
  readonly state: (typeof CHECK_STATE_VALUES)[number];
  readonly reason_code: (typeof REASON_CODES)[number];
  readonly verification_method: (typeof VERIFICATION_METHOD_VALUES)[number];
  readonly authority: (typeof CHECK_AUTHORITY_VALUES)[number];
  readonly required: boolean;
};

type StateReasonPair = readonly [
  (typeof CHECK_STATE_VALUES)[number],
  (typeof REASON_CODES)[number],
];

function variants(
  id: CanonicalCheckId,
  verification_method: (typeof VERIFICATION_METHOD_VALUES)[number],
  authority: (typeof CHECK_AUTHORITY_VALUES)[number],
  required: boolean,
  pairs: readonly StateReasonPair[],
): readonly CanonicalCheckVariant[] {
  return pairs.map(([state, reason_code]) => ({
    id,
    state,
    reason_code,
    verification_method,
    authority,
    required,
  }));
}

/**
 * Finite, producer-aligned check tuples. This is deliberately expanded at
 * runtime rather than represented as independent field sets: a report cannot
 * combine a valid state with another check's reason, method, authority, or
 * requiredness. The core should construct checks through
 * `createCanonicalCheck`; the report schema uses the same tuple table.
 */
export const CHECK_VARIANTS = {
  bundle_structure: [
    ...variants("bundle_structure", "STRUCTURAL_VALIDATION", "PAR_PUBLIC_EVIDENCE", true, [
      ["PASS", "BUNDLE_SCHEMA_VALID"],
      ["UNKNOWN", "BUNDLE_MALFORMED"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "PUBLIC_RECORD_UNAVAILABLE"],
      ["UNKNOWN", "PUBLIC_RECORD_MALFORMED"],
      ["UNKNOWN", "PUBLIC_RECORD_INDETERMINATE"],
      ["UNKNOWN", "NETWORK_ABORTED"],
      ["UNKNOWN", "NETWORK_TIMEOUT"],
      ["UNKNOWN", "NETWORK_RESPONSE_TOO_LARGE"],
      ["UNKNOWN", "NETWORK_REDIRECT_REJECTED"],
      ["UNKNOWN", "NETWORK_ORIGIN_REJECTED"],
      ["UNKNOWN", "NETWORK_CONTENT_TYPE_INVALID"],
      ["FAIL", "PUBLIC_RECORD_CONTRADICTION"],
    ]),
  ],
  asset_record: variants("asset_record", "STRUCTURAL_VALIDATION", "PAR_PUBLIC_EVIDENCE", true, [
    ["PASS", "PUBLIC_RECORD_AVAILABLE"],
    ["UNKNOWN", "CHECK_UNKNOWN"],
    ["UNKNOWN", "PUBLIC_RECORD_UNAVAILABLE"],
    ["UNKNOWN", "PUBLIC_RECORD_MALFORMED"],
  ]),
  trust_manifest: variants(
    "trust_manifest",
    "KEY_RING_INTERSECTION",
    "RELEASE_TRUST_MANIFEST",
    true,
    [
      ["PASS", "TRUST_MANIFEST_VALID"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "TRUST_MANIFEST_MISSING"],
      ["UNKNOWN", "TRUST_MANIFEST_UNAUTHENTICATED"],
      ["UNKNOWN", "TRUST_MANIFEST_SCHEMA_INVALID"],
      ["UNKNOWN", "TRUST_MANIFEST_TAMPERED"],
      ["UNKNOWN", "TRUST_KEY_INTERSECTION_EMPTY"],
      ["UNKNOWN", "TRUST_KEY_INTERSECTION_CONFLICT"],
    ],
  ),
  live_key_intersection: variants(
    "live_key_intersection",
    "KEY_RING_INTERSECTION",
    "RELEASE_TRUST_MANIFEST",
    true,
    [
      ["PASS", "RECEIPT_KEY_TRUSTED"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "TRUST_MANIFEST_MISSING"],
      ["UNKNOWN", "TRUST_MANIFEST_UNAUTHENTICATED"],
      ["UNKNOWN", "TRUST_MANIFEST_SCHEMA_INVALID"],
      ["UNKNOWN", "TRUST_MANIFEST_TAMPERED"],
      ["UNKNOWN", "TRUST_KEY_INTERSECTION_EMPTY"],
      ["UNKNOWN", "TRUST_KEY_INTERSECTION_CONFLICT"],
      ["UNKNOWN", "RECEIPT_KEY_UNKNOWN"],
    ],
  ),
  receipt_presence: variants(
    "receipt_presence",
    "STRUCTURAL_VALIDATION",
    "PAR_PUBLIC_EVIDENCE",
    true,
    [
      ["PASS", "RECEIPT_PRESENT"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "RECEIPT_MISSING"],
    ],
  ),
  receipt_structure: variants(
    "receipt_structure",
    "STRUCTURAL_VALIDATION",
    "PAR_PUBLIC_EVIDENCE",
    true,
    [
      ["PASS", "RECEIPT_PRESENT"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "RECEIPT_MALFORMED"],
      ["UNKNOWN", "RECEIPT_ALGORITHM_UNSUPPORTED"],
      ["UNKNOWN", "RECEIPT_TYPE_INVALID"],
      ["UNKNOWN", "RECEIPT_CRITICAL_HEADER_UNSUPPORTED"],
    ],
  ),
  receipt_signature: variants("receipt_signature", "JWS_SIGNATURE", "PAR_SIGNED_RECEIPT", true, [
    ["PASS", "RECEIPT_SIGNATURE_VALID"],
    ["UNKNOWN", "CHECK_UNKNOWN"],
    ["UNKNOWN", "RECEIPT_SIGNATURE_INVALID"],
    ["UNKNOWN", "RECEIPT_MALFORMED"],
    ["UNKNOWN", "RECEIPT_KEY_CONFLICT"],
    ["UNKNOWN", "RECEIPT_ALGORITHM_UNSUPPORTED"],
    ["UNKNOWN", "RECEIPT_TYPE_INVALID"],
    ["UNKNOWN", "RECEIPT_CRITICAL_HEADER_UNSUPPORTED"],
  ]),
  receipt_claims: [
    ...variants("receipt_claims", "STRUCTURAL_VALIDATION", "PAR_SIGNED_RECEIPT", true, [
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "RECEIPT_CLAIMS_MISSING"],
    ]),
    ...variants("receipt_claims", "CLOCK_VALIDATION", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "RECEIPT_CLAIMS_VALID"],
      ["UNKNOWN", "RECEIPT_CLAIMS_MISSING"],
      ["UNKNOWN", "RECEIPT_CLAIMS_EXPIRED"],
      ["UNKNOWN", "RECEIPT_CLAIMS_NOT_YET_VALID"],
      ["UNKNOWN", "RECEIPT_MALFORMED"],
      ["FAIL", "RECEIPT_AUDIENCE_MISMATCH"],
      ["FAIL", "RECEIPT_ISSUER_MISMATCH"],
      ["FAIL", "BUNDLE_ASSET_ID_MISMATCH"],
    ]),
  ],
  asset_identifier: [
    ...variants("asset_identifier", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "CHECK_PASSED"],
      ["PASS", "ASSET_BINDING_VALID"],
      ["FAIL", "BUNDLE_ASSET_ID_MISMATCH"],
      ["FAIL", "ASSET_BINDING_MISMATCH"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
    ]),
    ...variants("asset_identifier", "EXACT_FIELD_BINDING", "PAR_PUBLIC_EVIDENCE", true, [
      ["PASS", "ASSET_BINDING_VALID"],
      ["FAIL", "BUNDLE_ASSET_ID_MISMATCH"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
    ]),
    ...variants("asset_identifier", "STRUCTURAL_VALIDATION", "LOCAL_VERIFIER_POLICY", true, [
      ["FAIL", "INPUT_ASSET_ID_INVALID"],
    ]),
  ],
  asset_commitment: [
    ...variants("asset_commitment", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("asset_commitment", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["PASS", "ASSET_COMMITMENT_MATCH"],
      ["FAIL", "ASSET_COMMITMENT_MISMATCH"],
      ["UNKNOWN", "ASSET_COMMITMENT_MISMATCH"],
    ]),
  ],
  proof_digest_binding: [
    ...variants("proof_digest_binding", "PREFIX_FIELD_BINDING", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("proof_digest_binding", "PREFIX_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "ASSET_BINDING_VALID"],
      ["FAIL", "ASSET_BINDING_MISMATCH"],
    ]),
  ],
  policy_binding: variants("policy_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
    ["PASS", "POLICY_BINDING_MATCH"],
    ["FAIL", "POLICY_BINDING_MISMATCH"],
    ["UNKNOWN", "POLICY_BINDING_MISMATCH"],
    ["UNKNOWN", "CHECK_UNKNOWN"],
  ]),
  constraint_binding: [
    ...variants("constraint_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("constraint_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "CONSTRAINT_BINDING_MATCH"],
      ["FAIL", "CONSTRAINT_BINDING_MISMATCH"],
      ["UNKNOWN", "CONSTRAINT_BINDING_MISMATCH"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
    ]),
  ],
  circuit_binding: [
    ...variants("circuit_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("circuit_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "CIRCUIT_BINDING_MATCH"],
      ["FAIL", "CIRCUIT_BINDING_MISMATCH"],
    ]),
  ],
  status_reference_binding: variants(
    "status_reference_binding",
    "EXACT_FIELD_BINDING",
    "PAR_SIGNED_STATUS_CREDENTIAL",
    true,
    [
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["PASS", "STATUS_REFERENCE_MATCH"],
      ["FAIL", "STATUS_REFERENCE_MISMATCH"],
      ["UNKNOWN", "STATUS_REFERENCE_MISMATCH"],
    ],
  ),
  status_check_projection: [
    ...variants("status_check_projection", "EXACT_FIELD_BINDING", "PAR_PUBLIC_EVIDENCE", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("status_check_projection", "EXACT_FIELD_BINDING", "PAR_PUBLIC_EVIDENCE", true, [
      ["PASS", "STATUS_PROJECTION_MATCH"],
      ["FAIL", "STATUS_PROJECTION_MISMATCH"],
    ]),
  ],
  provenance_binding: [
    ...variants("provenance_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("provenance_binding", "EXACT_FIELD_BINDING", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "CHECK_PASSED"],
      ["FAIL", "PUBLIC_RECORD_CONTRADICTION"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
    ]),
  ],
  policy_freshness_binding: [
    ...variants("policy_freshness_binding", "CLOCK_VALIDATION", "PAR_SIGNED_RECEIPT", false, [
      ["NOT_ASSESSED", "CHECK_NOT_ASSESSED"],
    ]),
    ...variants("policy_freshness_binding", "CLOCK_VALIDATION", "PAR_SIGNED_RECEIPT", true, [
      ["PASS", "CHECK_PASSED"],
      ["FAIL", "PUBLIC_RECORD_CONTRADICTION"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
    ]),
  ],
  signed_status: variants("signed_status", "JWS_SIGNATURE", "PAR_SIGNED_STATUS_CREDENTIAL", true, [
    ["PASS", "STATUS_CREDENTIAL_SIGNATURE_VALID"],
    ["UNKNOWN", "CHECK_UNKNOWN"],
    ["UNKNOWN", "STATUS_CREDENTIAL_MISSING"],
    ["UNKNOWN", "STATUS_CREDENTIAL_SIGNATURE_INVALID"],
    ["UNKNOWN", "STATUS_CREDENTIAL_MALFORMED"],
    ["UNKNOWN", "STATUS_CREDENTIAL_EXPIRED"],
    ["UNKNOWN", "STATUS_CREDENTIAL_NOT_YET_VALID"],
    ["UNKNOWN", "RECEIPT_KEY_UNKNOWN"],
    ["UNKNOWN", "STATUS_INDEX_INVALID"],
    ["UNKNOWN", "STATUS_INDEX_OUT_OF_RANGE"],
    ["FAIL", "STATUS_REFERENCE_MISMATCH"],
  ]),
  registry_status: variants(
    "registry_status",
    "STATUS_BIT_EVALUATION",
    "PAR_SIGNED_STATUS_CREDENTIAL",
    true,
    [
      ["PASS", "STATUS_ACTIVE"],
      ["PASS", "STATUS_REVOKED"],
      ["PASS", "STATUS_SUSPENDED"],
      ["UNKNOWN", "CHECK_UNKNOWN"],
      ["UNKNOWN", "STATUS_UNKNOWN"],
      ["UNKNOWN", "STATUS_INDEX_INVALID"],
      ["UNKNOWN", "STATUS_INDEX_OUT_OF_RANGE"],
    ],
  ),
  acceptance_decision: variants("acceptance_decision", "NOT_PERFORMED", "NONE", false, [
    ["NOT_ASSESSED", "ACCEPTANCE_NOT_PERFORMED"],
  ]),
  underlying_proof_verification: variants(
    "underlying_proof_verification",
    "NOT_PERFORMED",
    "NONE",
    false,
    [["NOT_ASSESSED", "PROOF_VERIFICATION_NOT_PERFORMED"]],
  ),
  predicate_assurance: variants("predicate_assurance", "NOT_PERFORMED", "NONE", false, [
    ["NOT_ASSESSED", "PREDICATE_REPORTED_ONLY"],
  ]),
} as const satisfies Record<CanonicalCheckId, readonly CanonicalCheckVariant[]>;

/** Construct a check only when the exact tuple is in the canonical catalog. */
export function createCanonicalCheck(
  id: CanonicalCheckId,
  state: (typeof CHECK_STATE_VALUES)[number],
  reason_code: (typeof REASON_CODES)[number],
  selection?: Partial<
    Pick<CanonicalCheckVariant, "verification_method" | "authority" | "required">
  >,
): CanonicalCheckVariant {
  const candidates = CHECK_VARIANTS[id].filter(
    (variant) => variant.state === state && variant.reason_code === reason_code,
  );
  const selected = candidates.find(
    (variant) =>
      (selection?.verification_method === undefined ||
        variant.verification_method === selection.verification_method) &&
      (selection?.authority === undefined || variant.authority === selection.authority) &&
      (selection?.required === undefined || variant.required === selection.required),
  );
  if (!selected) throw new Error("INTERNAL_INVARIANT_FAILURE");
  return selected;
}

export const LIMITATION_CODES = [
  "UNDERLYING_PROOF_NOT_PERFORMED",
  "PREDICATE_PAR_REPORTED_ONLY",
  "CURRENT_PRESENTER_NOT_AUTHENTICATED",
  "PROOF_COMMITMENT_NOT_RECOMPUTABLE",
  "STATUS_TRUST_ROOT_CANONICAL_ORIGIN",
  "FULL_DIGEST_NOT_PUBLIC",
] as const;
