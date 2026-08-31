import { describe, expect, it } from "vitest";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";

import {
  AssetIdSchema,
  assertPublicRecordReportBytes,
  CHECK_IDS,
  CheckSchema,
  PublicRecordCoherenceReportSchema,
  REPORT_CONTRACT_ID,
  VerifyProofAssetInputSchema,
  parsePublicRecordCoherenceReportForInput,
  serializePublicRecordCoherenceReport,
} from "../../src/contracts/index.js";
import { CHECK_VARIANTS, MAX_REPORT_BYTES } from "../../src/contracts/constants.js";
import {
  CanonicalStatusUrlSchema,
  PublicAssuranceEvidenceInputSchema,
  PublicRecordEvidenceInputSchema,
  PublicVerificationBundleInputSchema,
  RFC3339DateTimeInputSchema,
  ReceiptJwksInputSchema,
  StatusCredentialEvidenceInputSchema,
  StatusReferenceInputSchema,
  StatusCheckInputSchema,
  isValidRFC3339DateTime,
  type PublicVerificationBundleInput,
} from "../../src/contracts/input.js";

const ASSET_ID = "550e8400-e29b-41d4-a716-446655440000";

const validCheck = {
  id: "bundle_structure" as const,
  state: "PASS" as const,
  reason_code: "BUNDLE_SCHEMA_VALID" as const,
  verification_method: "STRUCTURAL_VALIDATION" as const,
  authority: "PAR_PUBLIC_EVIDENCE" as const,
  required: true,
};

const boundaryChecks = [
  {
    id: "acceptance_decision" as const,
    state: "NOT_ASSESSED" as const,
    reason_code: "ACCEPTANCE_NOT_PERFORMED" as const,
    verification_method: "NOT_PERFORMED" as const,
    authority: "NONE" as const,
    required: false,
  },
  {
    id: "underlying_proof_verification" as const,
    state: "NOT_ASSESSED" as const,
    reason_code: "PROOF_VERIFICATION_NOT_PERFORMED" as const,
    verification_method: "NOT_PERFORMED" as const,
    authority: "NONE" as const,
    required: false,
  },
  {
    id: "predicate_assurance" as const,
    state: "NOT_ASSESSED" as const,
    reason_code: "PREDICATE_REPORTED_ONLY" as const,
    verification_method: "NOT_PERFORMED" as const,
    authority: "NONE" as const,
    required: false,
  },
];

const canonicalEvidenceChecks = CHECK_IDS.filter(
  (id) =>
    id !== "acceptance_decision" &&
    id !== "underlying_proof_verification" &&
    id !== "predicate_assurance",
).map((id) => CHECK_VARIANTS[id].find((check) => check.state === "PASS") ?? CHECK_VARIANTS[id][0]);

const validReport = {
  schema_version: 1 as const,
  contract_id: REPORT_CONTRACT_ID,
  asset_id: ASSET_ID,
  evaluated_at: "2026-08-30T00:00:00.000Z",
  record_coherence: "COHERENT" as const,
  registry_status: "ACTIVE" as const,
  registry_active_condition: "SATISFIED" as const,
  acceptance_decision: "NOT_PERFORMED" as const,
  underlying_proof_verification: "NOT_PERFORMED" as const,
  predicate_assurance: "PAR_REPORTED_ONLY" as const,
  checks: [...canonicalEvidenceChecks, ...boundaryChecks],
  warnings: [],
  errors: [],
  limitations: [
    "UNDERLYING_PROOF_NOT_PERFORMED" as const,
    "PREDICATE_PAR_REPORTED_ONLY" as const,
    "CURRENT_PRESENTER_NOT_AUTHENTICATED" as const,
    "PROOF_COMMITMENT_NOT_RECOMPUTABLE" as const,
    "STATUS_TRUST_ROOT_CANONICAL_ORIGIN" as const,
    "FULL_DIGEST_NOT_PUBLIC" as const,
  ],
};

const inputJsonSchema = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-input.v1.json", import.meta.url),
    "utf8",
  ),
);
const reportJsonSchema = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-coherence.v1.json", import.meta.url),
    "utf8",
  ),
);
const checkJsonSchema = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-check.v1.json", import.meta.url),
    "utf8",
  ),
);
const installFormats = addFormats as unknown as (ajv: Ajv2020) => Ajv2020;

type JsonSchemaObject = Record<string, unknown>;

function resolveLocalDefinition(
  document: JsonSchemaObject,
  ref: unknown,
): JsonSchemaObject | undefined {
  if (typeof ref !== "string" || !ref.startsWith("#/$defs/")) return undefined;
  const defs = document.$defs;
  if (!defs || typeof defs !== "object" || Array.isArray(defs)) return undefined;
  const definition = (defs as Record<string, unknown>)[ref.slice("#/$defs/".length)];
  if (!definition || typeof definition !== "object" || Array.isArray(definition)) return undefined;
  return definition as JsonSchemaObject;
}

function resolveRootDefinition(
  document: JsonSchemaObject,
): { ref: string; definition: JsonSchemaObject } | undefined {
  if (typeof document.$ref !== "string") return undefined;
  const definition = resolveLocalDefinition(document, document.$ref);
  return definition ? { ref: document.$ref, definition } : undefined;
}

function withBundleStructureCheck(replacement: object) {
  return validReport.checks.map((check) =>
    check?.id === "bundle_structure" ? replacement : check,
  );
}

const validBundle = {
  ok: true as const,
  schemaVersion: "myproof.public-verification-bundle.v1" as const,
  generatedAt: "2026-08-30T00:00:00.000Z",
  asset: {
    proofAssetId: ASSET_ID,
    proofAssetCommitment: "commitment-is-provider-only",
    proofFormat: "ZK_PROOF",
    proofDigestPrefix: "digest-prefix-is-provider-only",
    digestAlg: "sha2-256",
    policyHash: "policy-hash-is-provider-only",
    policyCid: "policy-cid-is-provider-only",
    constraintHash: "constraint-hash-is-provider-only",
    circuitOrSchemaId: "circuit-is-provider-only",
    verificationStatus: "verified",
    statusListUrl: "https://par.myproof.ai/status/revocation/default",
    statusListIndex: "0",
    statusPurpose: "revocation" as const,
    status: { purpose: "revocation" as const, verificationStatus: "verified" },
    createdAt: "2026-08-29T00:00:00.000Z",
  },
  receipt: {
    type: "asset" as const,
    jws: "header.payload.signature",
    jwksUri: "/api/public/receipts/jwks.json" as const,
    publicJwk: {
      kty: "EC" as const,
      crv: "P-256" as const,
      x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      kid: "receipt-fixture",
      alg: "ES256" as const,
      use: "sig" as const,
      key_ops: ["verify" as const],
    },
    header: { alg: "ES256" as const, kid: "receipt-fixture", typ: "JWT" as const },
    claims: {
      proof_digest: "proof-digest-is-provider-only",
      policy_hash: "policy-hash-is-provider-only",
      constraint_hash: "constraint-hash-is-provider-only",
      status_ref: {
        statusListUrl: "https://par.myproof.ai/status/revocation/default",
        statusListIndex: "0",
        statusPurpose: "revocation" as const,
      },
      jti: "receipt-jti-is-provider-only",
      aud: "myproof-proof-asset",
      exp: 1_798_056_000,
      nbf: 1_798_000_000,
      sub: ASSET_ID,
      proof_asset_commitment: "commitment-is-provider-only",
      policy_cid: "policy-cid-is-provider-only",
      circuit_or_schema_id: "circuit-is-provider-only",
    },
  },
  statusCheck: {
    state: "active" as const,
    purpose: "revocation" as const,
    checkedAt: "2026-08-30T00:00:00.000Z",
    statusListUrl: "https://par.myproof.ai/status/revocation/default",
    statusListIndex: "0",
  },
  provenance: {
    environment: "production" as const,
    configurationRevision: 7,
    binding: "asset_receipt" as const,
  },
  assurance: null,
  audit: null,
  checks: {
    receiptSignature: "verified" as const,
    assetBinding: "verified" as const,
    audienceBinding: "verified" as const,
    status: "active" as const,
    auditAnchor: "omitted" as const,
    auditInclusion: "omitted" as const,
    epochSignature: "omitted" as const,
    authorizedMintRecord: "unavailable" as const,
    assuranceBinding: "unavailable" as const,
  },
};

describe("canonical public-record contracts", () => {
  it("accepts only the two caller fields and defaults require_active", () => {
    expect(VerifyProofAssetInputSchema.parse({ asset_id: ASSET_ID })).toEqual({
      asset_id: ASSET_ID,
      require_active: false,
    });
    expect(
      VerifyProofAssetInputSchema.safeParse({
        asset_id: ASSET_ID,
        origin: "https://attacker.invalid",
      }).success,
    ).toBe(false);
    expect(
      VerifyProofAssetInputSchema.safeParse({ asset_id: ASSET_ID, require_active: true }).success,
    ).toBe(true);
  });

  it("keeps the advertised JSON Schemas aligned with structural Zod acceptance", () => {
    expect(inputJsonSchema).toMatchObject({ type: "object" });
    expect(checkJsonSchema).toMatchObject({ type: "object" });
    expect(reportJsonSchema).toMatchObject({
      type: "object",
      $ref: "#/$defs/myproof.par.public-record-coherence.v1",
    });
    const ajv = new Ajv2020({ strict: false });
    installFormats(ajv);
    const validateInput = ajv.compile(inputJsonSchema);
    const validateReport = ajv.compile(reportJsonSchema);
    const validateCheck = ajv.compile(checkJsonSchema);

    const omittedRequireActive = { asset_id: ASSET_ID };
    expect(validateInput(omittedRequireActive)).toBe(true);
    expect(VerifyProofAssetInputSchema.safeParse(omittedRequireActive).success).toBe(true);
    const inputWithUnknown = { ...omittedRequireActive, origin: "https://attacker.invalid" };
    expect(validateInput(inputWithUnknown)).toBe(false);
    expect(VerifyProofAssetInputSchema.safeParse(inputWithUnknown).success).toBe(false);

    expect(validateReport(validReport)).toBe(true);
    expect(PublicRecordCoherenceReportSchema.safeParse(validReport).success).toBe(true);
    expect(validateCheck(validCheck)).toBe(true);
    expect(validateCheck({ ...validCheck, reason_code: "CHECK_FAILED" })).toBe(false);
    expect(CheckSchema.safeParse({ ...validCheck, reason_code: "CHECK_FAILED" }).success).toBe(
      false,
    );
    for (const checks of [
      validReport.checks.slice(0, -1),
      [...validReport.checks, validReport.checks[0]],
    ]) {
      expect(validateReport({ ...validReport, checks })).toBe(false);
      expect(PublicRecordCoherenceReportSchema.safeParse({ ...validReport, checks }).success).toBe(
        false,
      );
    }
  });

  it("resolves canonical roots and shares the exact check definition", () => {
    const inputRoot = resolveRootDefinition(inputJsonSchema);
    const checkRoot = resolveRootDefinition(checkJsonSchema);
    const reportRoot = resolveRootDefinition(reportJsonSchema);

    expect(inputJsonSchema).toMatchObject({
      type: "object",
      $ref: "#/$defs/myproof.par.public-record-input.v1",
    });
    expect(checkJsonSchema).toMatchObject({
      type: "object",
      $ref: "#/$defs/myproof.par.public-record-check.v1",
    });
    expect(reportJsonSchema).toMatchObject({
      type: "object",
      $ref: "#/$defs/myproof.par.public-record-coherence.v1",
    });
    expect(inputRoot?.definition).toMatchObject({
      type: "object",
      required: ["asset_id"],
      additionalProperties: false,
    });
    expect(checkRoot?.definition).toMatchObject({ oneOf: expect.any(Array) });
    expect(reportRoot?.definition).toMatchObject({
      type: "object",
      required: expect.arrayContaining(["checks"]),
      additionalProperties: false,
    });

    const reportProperties = reportRoot?.definition.properties as JsonSchemaObject | undefined;
    const checksProperty = reportProperties?.checks as JsonSchemaObject | undefined;
    const checksArray = checksProperty
      ? resolveLocalDefinition(reportJsonSchema, checksProperty.$ref)
      : undefined;
    const checkItem = checksArray?.items as JsonSchemaObject | undefined;
    expect(checksArray).toBeDefined();
    expect(checkItem?.$ref).toBe(checkRoot?.ref);

    const checkId = checkRoot?.ref.slice("#/$defs/".length);
    expect(checkId).toBe("myproof.par.public-record-check.v1");
    expect(reportJsonSchema.$defs?.[checkId ?? ""]).toEqual(checkJsonSchema.$defs?.[checkId ?? ""]);
  });

  it("rejects the same adversarial report corpus through Ajv and Zod", () => {
    const ajv = new Ajv2020({ strict: false });
    installFormats(ajv);
    const validateReport = ajv.compile(reportJsonSchema);
    const requiredUnknown = {
      ...validCheck,
      state: "UNKNOWN" as const,
      reason_code: "BUNDLE_MALFORMED" as const,
    };
    const requiredFailure = {
      ...validCheck,
      state: "FAIL" as const,
      reason_code: "PUBLIC_RECORD_CONTRADICTION" as const,
    };
    const corpus: Array<[string, object]> = [
      [
        "wrong domain tuple",
        {
          ...validReport,
          checks: withBundleStructureCheck({ ...validCheck, reason_code: "CHECK_FAILED" }),
        },
      ],
      [
        "wrong canonical order",
        {
          ...validReport,
          checks: [validReport.checks[1], validReport.checks[0], ...validReport.checks.slice(2)],
        },
      ],
      [
        "coherent with required unknown",
        {
          ...validReport,
          registry_active_condition: "INDETERMINATE",
          checks: withBundleStructureCheck(requiredUnknown),
        },
      ],
      [
        "contradictory without required failure",
        {
          ...validReport,
          record_coherence: "CONTRADICTORY",
          registry_active_condition: "INDETERMINATE",
        },
      ],
      [
        "indeterminate without required unknown",
        {
          ...validReport,
          record_coherence: "INDETERMINATE",
          registry_active_condition: "INDETERMINATE",
        },
      ],
      [
        "contradictory with satisfied active condition",
        {
          ...validReport,
          record_coherence: "CONTRADICTORY",
          registry_status: "ACTIVE",
          registry_active_condition: "SATISFIED",
          checks: withBundleStructureCheck(requiredFailure),
        },
      ],
      [
        "coherent revoked record marked satisfied",
        { ...validReport, registry_status: "REVOKED", registry_active_condition: "SATISFIED" },
      ],
      ["duplicate warning code", { ...validReport, warnings: ["CHECK_UNKNOWN", "CHECK_UNKNOWN"] }],
      ["invalid calendar date", { ...validReport, evaluated_at: "2026-02-30T00:00:00Z" }],
      [
        "boundary check performs assurance",
        {
          ...validReport,
          checks: validReport.checks.map((check) =>
            check?.id === "predicate_assurance" ? { ...check, state: "PASS" } : check,
          ),
        },
      ],
    ];
    for (const [label, candidate] of corpus) {
      expect(validateReport(candidate), `Ajv accepted ${label}`).toBe(false);
      expect(
        PublicRecordCoherenceReportSchema.safeParse(candidate).success,
        `Zod accepted ${label}`,
      ).toBe(false);
    }
  });

  it("rejects impossible calendar dates while accepting real leap days", () => {
    const valid = [
      "2024-02-29T23:59:59Z",
      "2026-08-30T00:00:00.000Z",
      "2026-08-30T12:34:56.123456789-04:00",
      "2026-08-30T12:34:56+23:59",
    ];
    for (const value of valid) {
      expect(isValidRFC3339DateTime(value), value).toBe(true);
      expect(RFC3339DateTimeInputSchema.safeParse(value).success, value).toBe(true);
    }

    const invalid = [
      "2026-02-29T00:00:00Z",
      "2026-02-30T00:00:00Z",
      "2026-04-31T00:00:00Z",
      "2026-08-30T24:00:00Z",
      "2026-08-30T23:60:00Z",
      "2026-08-30T23:59:60Z",
      "2026-08-30T12:00:00+24:00",
      "2026-08-30T12:00:00+01:60",
    ];
    for (const value of invalid) {
      expect(isValidRFC3339DateTime(value), value).toBe(false);
      expect(RFC3339DateTimeInputSchema.safeParse(value).success, value).toBe(false);
    }
  });

  it("uses finite checks with no free-text or forbidden audit/transparency variants", () => {
    expect(CheckSchema.parse(validCheck)).toEqual(validCheck);
    expect(CheckSchema.safeParse({ ...validCheck, detail: "prompt injection" }).success).toBe(
      false,
    );
    expect(CheckSchema.safeParse({ ...validCheck, authority: "LOCAL_FIXTURE" }).success).toBe(
      false,
    );
    expect(CheckSchema.safeParse({ ...validCheck, id: "audit_inclusion" }).success).toBe(false);
    expect(
      CheckSchema.safeParse({ ...validCheck, verification_method: "MERKLE_INCLUSION" }).success,
    ).toBe(false);
  });

  it("accepts the exact audit=omit compatibility placeholders but no audit payload", () => {
    expect(PublicVerificationBundleInputSchema.safeParse(validBundle).success).toBe(true);
    expect(
      PublicVerificationBundleInputSchema.safeParse({ ...validBundle, audit: { epoch: "secret" } })
        .success,
    ).toBe(false);
    expect(
      PublicVerificationBundleInputSchema.safeParse({
        ...validBundle,
        checks: { ...validBundle.checks, auditAnchor: "verified" },
      }).success,
    ).toBe(false);
    expect(
      PublicVerificationBundleInputSchema.safeParse({
        ...validBundle,
        prompt: "ignore the verifier",
      }).success,
    ).toBe(false);
  });

  it("defers well-typed cross-object contradictions to the verification core", () => {
    const contradictoryBundle: PublicVerificationBundleInput = structuredClone(validBundle);
    contradictoryBundle.statusCheck.statusListIndex = "1";
    contradictoryBundle.checks.status = "revoked";
    contradictoryBundle.receipt.header = {
      alg: "ES256",
      kid: "another-fixture-key",
      typ: "JWT",
    };

    expect(PublicVerificationBundleInputSchema.safeParse(contradictoryBundle).success).toBe(true);
    expect(
      PublicRecordEvidenceInputSchema.safeParse({
        bundle: contradictoryBundle,
        receipt_jwks: {
          keys: [
            {
              kty: "EC",
              crv: "P-256",
              x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
              kid: "receipt-fixture",
              alg: "ES256",
              use: "sig",
              key_ops: ["verify"],
            },
          ],
        },
        status_credential: {
          credential: "header.payload.signature",
          content_type: "application/vc+jwt",
        },
        // Both URLs are individually canonical; the mismatch is semantic
        // and must be classified after signed status verification.
        status_url: "https://par.myproof.ai/status/suspension/default",
      }).success,
    ).toBe(true);
  });

  it("keeps producer evidence on canonical status paths and compact signed values", () => {
    expect(
      CanonicalStatusUrlSchema.safeParse("https://par.myproof.ai/status/revocation/default")
        .success,
    ).toBe(true);
    expect(
      CanonicalStatusUrlSchema.safeParse("https://evil.example/status/revocation/default").success,
    ).toBe(false);
    expect(
      StatusReferenceInputSchema.safeParse({
        statusListUrl: "https://par.myproof.ai/status/suspension/default",
        statusListIndex: "9",
        statusPurpose: "suspension",
      }).success,
    ).toBe(true);
    expect(
      StatusCheckInputSchema.safeParse({
        state: "active",
        purpose: "other",
        checkedAt: "2026-08-30T00:00:00Z",
        statusListUrl: "https://par.myproof.ai/status/revocation/default",
        statusListIndex: "0",
      }).success,
    ).toBe(false);
    expect(
      StatusCredentialEvidenceInputSchema.safeParse({
        credential: "header.payload",
        content_type: "application/vc+jwt",
      }).success,
    ).toBe(false);
    expect(
      PublicRecordEvidenceInputSchema.safeParse({
        bundle: validBundle,
        receipt_jwks: {
          keys: [
            {
              kty: "EC",
              crv: "P-256",
              x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
              kid: "receipt-fixture",
              alg: "ES256",
              use: "sig",
              key_ops: ["verify"],
            },
          ],
        },
        status_credential: {
          credential: "header.payload.signature",
          content_type: "application/vc+jwt",
        },
        status_url: "https://par.myproof.ai/status/revocation/default",
      }).success,
    ).toBe(true);
    expect(
      PublicRecordEvidenceInputSchema.safeParse({
        bundle: validBundle,
        receipt_jwks: {
          keys: [
            {
              kty: "EC",
              crv: "P-256",
              x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
              kid: "receipt-fixture",
            },
          ],
        },
        status_credential: {
          credential: "header.payload.signature",
          content_type: "application/vc+jwt",
        },
        status_url: "https://evil.example/status/revocation/default",
      }).success,
    ).toBe(false);
  });

  it("enforces assurance completeness, policy, ordering, and consensus invariants", () => {
    const policyHash = "a".repeat(64);
    const policyCid = `sha256:${policyHash}`;
    const assurance = {
      payloadHash: "A".repeat(43),
      projectedAt: "2026-08-30T00:00:00Z",
      decisionStatus: "verified" as const,
      validation: "ingestion_validated" as const,
      payload: {
        submission_mode: "direct" as const,
        provenance: "exact_journal" as const,
        completeness: "incomplete" as const,
        completeness_exceptions: [
          "MOBILE_M3_BINDING_UNAVAILABLE" as const,
          "CONSENSUS_COUNTS_UNAVAILABLE" as const,
          "VERIFIER_ARTIFACT_DIGEST_UNAVAILABLE" as const,
        ],
        circuit_version: 6 as const,
        journal_version: 16 as const,
        image_id_digest: "b".repeat(64),
        verifier_artifact_digest: null,
        proof_digest: "c".repeat(64),
        receipt_digest: "d".repeat(64),
        policy_version: null,
        policy_cid: policyCid,
        policy_hash: policyHash,
        ordered_predicates: [
          {
            index: 0,
            outcome: "pass" as const,
            provenance: "exact_journal" as const,
            policy_cid: policyCid,
            verifier_binding_hash: "e".repeat(64),
          },
        ],
        holder_evidence_root: "f".repeat(64),
        assurance_profile_hash: "0".repeat(64),
        assurance_profile_version: 1 as const,
        assurance_decision: true as const,
        component_provenance: "aggregate_proven" as const,
        face_match_required: true as const,
        face_match_pass: true as const,
        face_threshold_q16: 49_152 as const,
        face_consensus_count: null,
        face_frame_count: null,
        face_required_count: null,
        credential_kind: null,
        credential_auth_class: 1,
        portrait_source: null,
        document_authentication: null,
        liveness: "pass" as const,
        texture: "pass" as const,
        depth: "not_applicable" as const,
        continuous_presence: "pass" as const,
        challenge: "pass" as const,
        app_attest: "pass" as const,
        app_attest_counter: "pass" as const,
        capture_ms: 1,
        prove_ms: null,
        finalize_ms: null,
        server_git_sha: null,
        deployment_region: null,
        app_clip_git_sha: null,
        app_clip_build: null,
      },
    };
    expect(PublicAssuranceEvidenceInputSchema.safeParse(assurance).success).toBe(true);
    expect(
      PublicAssuranceEvidenceInputSchema.safeParse({
        ...assurance,
        payload: {
          ...assurance.payload,
          completeness: "complete",
          completeness_exceptions: [],
          verifier_artifact_digest: "1".repeat(64),
          face_consensus_count: 2,
          face_frame_count: 3,
          face_required_count: 2,
          app_clip_git_sha: "2".repeat(40),
          app_clip_build: "1",
        },
      }).success,
    ).toBe(true);
    expect(
      PublicAssuranceEvidenceInputSchema.safeParse({
        ...assurance,
        payload: {
          ...assurance.payload,
          policy_hash: "1".repeat(64),
        },
      }).success,
    ).toBe(false);
    expect(
      PublicAssuranceEvidenceInputSchema.safeParse({
        ...assurance,
        payload: {
          ...assurance.payload,
          ordered_predicates: [{ ...assurance.payload.ordered_predicates[0], index: 1 }],
        },
      }).success,
    ).toBe(false);
    expect(
      PublicAssuranceEvidenceInputSchema.safeParse({
        ...assurance,
        payload: {
          ...assurance.payload,
          completeness_exceptions: [
            ...assurance.payload.completeness_exceptions,
            "MOBILE_M3_BINDING_UNAVAILABLE",
          ],
        },
      }).success,
    ).toBe(false);
    expect(
      PublicAssuranceEvidenceInputSchema.safeParse({
        ...assurance,
        payload: {
          ...assurance.payload,
          completeness_exceptions: ["MOBILE_M3_BINDING_UNAVAILABLE"],
          app_clip_git_sha: "a".repeat(40),
          app_clip_build: "1",
        },
      }).success,
    ).toBe(false);
  });

  it("keeps remote correlation material out of the canonical report", () => {
    const parsed = PublicRecordCoherenceReportSchema.parse(validReport);
    const serialized = serializePublicRecordCoherenceReport(parsed);
    expect(Buffer.byteLength(serialized)).toBeLessThanOrEqual(MAX_REPORT_BYTES);
    expect(serialized).not.toContain("commitment-is-provider-only");
    expect(serialized).not.toContain("policy-hash-is-provider-only");
    expect(serialized).not.toContain("prompt injection");
    expect(serialized).not.toContain("audit_inclusion");
    expect(serialized).not.toContain("MERKLE");
    expect(serialized).not.toContain("epoch");
  });

  it("rejects duplicate checks and additive unknown output fields", () => {
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        checks: [validCheck, validCheck],
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        checks: [validReport.checks[1], validReport.checks[0], ...validReport.checks.slice(2)],
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({ ...validReport, remote: "secret" }).success,
    ).toBe(false);
  });

  it("requires unique warnings/errors and the complete ordered limitation set", () => {
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        warnings: ["CHECK_UNKNOWN", "CHECK_UNKNOWN"],
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        errors: ["CHECK_FAILED", "CHECK_FAILED"],
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        limitations: validReport.limitations.slice(0, -1),
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        limitations: [...validReport.limitations].reverse(),
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        limitations: [...validReport.limitations.slice(0, -1), "UNDERLYING_PROOF_NOT_PERFORMED"],
      }).success,
    ).toBe(false);
  });

  it("rejects a report made only of claim-boundary checks", () => {
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        checks: boundaryChecks,
      }).success,
    ).toBe(false);
  });

  it("rejects universally impossible generic state/reason pairs", () => {
    expect(
      CheckSchema.safeParse({
        ...validCheck,
        state: "PASS",
        reason_code: "CHECK_FAILED",
      }).success,
    ).toBe(false);
    expect(
      CheckSchema.safeParse({
        ...validCheck,
        state: "FAIL",
        reason_code: "CHECK_PASSED",
      }).success,
    ).toBe(false);
    expect(
      CheckSchema.safeParse({
        ...validCheck,
        state: "UNKNOWN",
        reason_code: "CHECK_NOT_ASSESSED",
      }).success,
    ).toBe(false);
  });

  it("rejects domain reason/state and claim-boundary tuple swaps", () => {
    const receiptSignature = CHECK_VARIANTS.receipt_signature[0];
    expect(
      CheckSchema.safeParse({
        ...receiptSignature,
        state: "PASS",
        reason_code: "RECEIPT_SIGNATURE_INVALID",
      }).success,
    ).toBe(false);
    expect(
      CheckSchema.safeParse({
        ...receiptSignature,
        verification_method: "NOT_PERFORMED",
        authority: "NONE",
      }).success,
    ).toBe(false);
    expect(
      CheckSchema.safeParse({
        ...boundaryChecks[0],
        id: "receipt_signature",
      }).success,
    ).toBe(false);
  });

  it("accepts the explicit optional asset-commitment tuple", () => {
    const optionalCommitment = CHECK_VARIANTS.asset_commitment.find(
      (check) => check.required === false && check.state === "NOT_ASSESSED",
    );
    expect(optionalCommitment).toEqual({
      id: "asset_commitment",
      state: "NOT_ASSESSED",
      reason_code: "CHECK_NOT_ASSESSED",
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: false,
    });
    expect(CheckSchema.safeParse(optionalCommitment).success).toBe(true);
  });

  it("enforces the one-byte report boundary through the shared budget helper", () => {
    expect(() => assertPublicRecordReportBytes("x".repeat(MAX_REPORT_BYTES))).not.toThrow();
    expect(() => assertPublicRecordReportBytes("x".repeat(MAX_REPORT_BYTES + 1))).toThrow(
      "canonical report exceeds its bounded output size",
    );
  });

  it("rejects impossible coherence classifications", () => {
    const requiredUnknown = {
      ...validCheck,
      state: "UNKNOWN" as const,
      reason_code: "BUNDLE_MALFORMED" as const,
    };
    const requiredFail = {
      ...validCheck,
      state: "FAIL" as const,
      reason_code: "PUBLIC_RECORD_CONTRADICTION" as const,
    };
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "COHERENT",
        checks: withBundleStructureCheck(requiredUnknown),
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "CONTRADICTORY",
        checks: validReport.checks,
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "INDETERMINATE",
        checks: validReport.checks,
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "CONTRADICTORY",
        registry_active_condition: "INDETERMINATE",
        checks: withBundleStructureCheck(requiredFail),
      }).success,
    ).toBe(true);
  });

  it("keeps active-status classification aligned with coherence and registry status", () => {
    const coherent = (
      registry_status: "ACTIVE" | "REVOKED" | "SUSPENDED" | "UNKNOWN",
      registry_active_condition: "NOT_REQUESTED" | "SATISFIED" | "NOT_SATISFIED" | "INDETERMINATE",
    ) =>
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        registry_status,
        registry_active_condition,
      }).success;

    expect(coherent("ACTIVE", "SATISFIED")).toBe(true);
    expect(coherent("REVOKED", "NOT_SATISFIED")).toBe(true);
    expect(coherent("SUSPENDED", "NOT_SATISFIED")).toBe(true);
    expect(coherent("UNKNOWN", "INDETERMINATE")).toBe(true);
    expect(coherent("REVOKED", "SATISFIED")).toBe(false);
    expect(coherent("ACTIVE", "NOT_SATISFIED")).toBe(false);
    expect(coherent("ACTIVE", "INDETERMINATE")).toBe(false);

    const contradictoryChecks = withBundleStructureCheck({
      ...validCheck,
      state: "FAIL" as const,
      reason_code: "PUBLIC_RECORD_CONTRADICTION" as const,
    });
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "CONTRADICTORY",
        registry_status: "ACTIVE",
        registry_active_condition: "INDETERMINATE",
        checks: contradictoryChecks,
      }).success,
    ).toBe(true);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "CONTRADICTORY",
        registry_status: "ACTIVE",
        registry_active_condition: "SATISFIED",
        checks: contradictoryChecks,
      }).success,
    ).toBe(false);

    const indeterminateChecks = withBundleStructureCheck({
      ...validCheck,
      state: "UNKNOWN" as const,
      reason_code: "BUNDLE_MALFORMED" as const,
    });
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "INDETERMINATE",
        registry_status: "ACTIVE",
        registry_active_condition: "INDETERMINATE",
        checks: indeterminateChecks,
      }).success,
    ).toBe(true);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        record_coherence: "INDETERMINATE",
        registry_status: "UNKNOWN",
        registry_active_condition: "SATISFIED",
        checks: indeterminateChecks,
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        registry_status: "UNKNOWN",
        registry_active_condition: "NOT_REQUESTED",
      }).success,
    ).toBe(true);
  });

  it("binds report asset and active intent once for CLI and MCP", () => {
    expect(
      parsePublicRecordCoherenceReportForInput(validReport, {
        asset_id: ASSET_ID,
        require_active: true,
      }),
    ).toEqual(validReport);
    expect(() =>
      parsePublicRecordCoherenceReportForInput(validReport, {
        asset_id: ASSET_ID,
        require_active: false,
      }),
    ).toThrow("NOT_REQUESTED");
    expect(() =>
      parsePublicRecordCoherenceReportForInput(
        { ...validReport, asset_id: "550e8400-e29b-41d4-a716-446655440001" },
        { asset_id: ASSET_ID, require_active: true },
      ),
    ).toThrow("asset_id");
    expect(() =>
      parsePublicRecordCoherenceReportForInput(
        { ...validReport, registry_active_condition: "NOT_REQUESTED" },
        { asset_id: ASSET_ID, require_active: true },
      ),
    ).toThrow("active condition");
  });

  it("enforces literal non-assurance boundary checks", () => {
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        checks: [validCheck, { ...boundaryChecks[0], state: "PASS" }, ...boundaryChecks.slice(1)],
      }).success,
    ).toBe(false);
    expect(
      PublicRecordCoherenceReportSchema.safeParse({
        ...validReport,
        checks: [
          validCheck,
          { ...boundaryChecks[2], authority: "PAR_PUBLIC_EVIDENCE" },
          ...boundaryChecks.slice(0, 2),
        ],
      }).success,
    ).toBe(false);
  });

  it("requires canonical UUIDs and bounded receipt key sets", () => {
    expect(AssetIdSchema.safeParse(ASSET_ID).success).toBe(true);
    expect(AssetIdSchema.safeParse("ASSET-ID-SENTINEL").success).toBe(false);
    expect(AssetIdSchema.safeParse("550e8400-e29b-01d4-a716-446655440000").success).toBe(false);
    expect(AssetIdSchema.safeParse("550e8400-e29b-41d4-7716-446655440000").success).toBe(false);
    expect(
      ReceiptJwksInputSchema.safeParse({
        keys: Array.from({ length: 33 }, (_, index) => ({
          kty: "EC",
          crv: "P-256",
          x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          kid: `key-${index}`,
        })),
      }).success,
    ).toBe(false);
    expect(
      ReceiptJwksInputSchema.safeParse({
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            kid: "key-1",
            ext: true,
          },
        ],
      }).success,
    ).toBe(true);
    expect(
      ReceiptJwksInputSchema.safeParse({
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            kid: "key-1",
            ext: false,
          },
        ],
      }).success,
    ).toBe(false);
    expect(
      ReceiptJwksInputSchema.safeParse({
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "x",
            y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            kid: "key-1",
          },
        ],
      }).success,
    ).toBe(false);
    expect(
      ReceiptJwksInputSchema.safeParse({
        keys: [
          {
            kty: "EC",
            crv: "P-256",
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            kid: "key-1",
            key_ops: [],
          },
        ],
      }).success,
    ).toBe(false);
  });
});
