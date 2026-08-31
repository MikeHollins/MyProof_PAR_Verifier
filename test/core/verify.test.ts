import { describe, expect, it } from "vitest";

import type { Check, CheckId } from "../../src/contracts/index.js";
import { PublicRecordEvidenceInputSchema } from "../../src/contracts/input.js";
import { unavailableReport, verifyEvidence } from "../../src/core/verify.js";
import type { CoreEvidenceEnvelope } from "../../src/core/evidence.js";
import {
  createIndependentPublicJwk,
  createSignedFixture,
  createRotatedSignedFixtures,
  FIXTURE_ASSET_ID,
  FIXTURE_NOW_MS,
  resignReceipt,
  resignStatus,
} from "../fixtures/core/signed-fixtures.js";

function check(report: ReturnType<typeof verifyEvidence>, id: CheckId): Check {
  const found = report.checks.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`missing check ${id}`);
  return found;
}

function cloneEvidence(fixture: ReturnType<typeof createSignedFixture>): CoreEvidenceEnvelope {
  return structuredClone(fixture.evidence);
}

function tamperSignature(token: string): string {
  const parts = token.split(".");
  const header = parts[0];
  const payload = parts[1];
  const signature = parts[2];
  if (header === undefined || payload === undefined || signature === undefined) {
    throw new Error("fixture token is not compact JWS");
  }
  const first = signature.charAt(0);
  return `${header}.${payload}.${first === "A" ? "B" : "A"}${signature.slice(1)}`;
}

function recordWithReceiptClaims(
  fixture: ReturnType<typeof createSignedFixture>,
  claims: Record<string, unknown>,
): CoreEvidenceEnvelope {
  const evidence = cloneEvidence(fixture);
  evidence.bundle.receipt.jws = resignReceipt(fixture, claims);
  return evidence;
}

function recordWithStatusPayload(
  fixture: ReturnType<typeof createSignedFixture>,
  payload: Record<string, unknown>,
): CoreEvidenceEnvelope {
  const evidence = cloneEvidence(fixture);
  evidence.status_credential = {
    credential: resignStatus(fixture, payload),
    content_type: "application/vc+jwt",
  };
  return evidence;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("pure verification core", () => {
  it("accepts an independently signed active producer-shaped record", () => {
    const fixture = createSignedFixture({
      requireActive: true,
      includeConstraintHash: true,
      includeProvenance: true,
    });
    const report = verifyEvidence(fixture.request, fixture.evidence, fixture.trust, FIXTURE_NOW_MS);

    expect(report.record_coherence).toBe("COHERENT");
    expect(report.registry_status).toBe("ACTIVE");
    expect(report.registry_active_condition).toBe("SATISFIED");
    expect(check(report, "proof_digest_binding")).toMatchObject({ state: "PASS" });
    expect(check(report, "circuit_binding")).toMatchObject({ state: "PASS" });
    expect(check(report, "policy_freshness_binding")).toMatchObject({ state: "PASS" });
    expect(check(report, "status_check_projection")).toMatchObject({ state: "PASS" });
    expect(JSON.stringify(report)).not.toContain("fixture-receipt-0001");
    expect(JSON.stringify(report)).not.toContain(fixture.publicJwk.kid);
    expect(report.acceptance_decision).toBe("NOT_PERFORMED");
    expect(report.underlying_proof_verification).toBe("NOT_PERFORMED");
    expect(report.predicate_assurance).toBe("PAR_REPORTED_ONLY");
  });

  it("keeps receipt jti signed-only while accepting the public projection", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    expect("jti" in fixture.evidence.bundle.receipt.claims).toBe(false);
    const report = verifyEvidence(fixture.request, fixture.evidence, fixture.trust, FIXTURE_NOW_MS);
    expect(report.record_coherence).toBe("COHERENT");

    const leaked = cloneEvidence(fixture);
    leaked.bundle.receipt.claims.jti = "fixture-receipt-0001";
    const leakedReport = verifyEvidence(fixture.request, leaked, fixture.trust, FIXTURE_NOW_MS);
    expect(leakedReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(leakedReport, "bundle_structure")).toMatchObject({
      state: "FAIL",
      reason_code: "PUBLIC_RECORD_CONTRADICTION",
    });
  });

  it("binds both direct and nested digest prefixes to the signed digest", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true });
    const nestedMismatch = cloneEvidence(fixture);
    if (!nestedMismatch.bundle.asset.verificationMetadata) throw new Error("missing metadata");
    nestedMismatch.bundle.asset.verificationMetadata.proof_digest_prefix =
      "sha256:" + "b".repeat(16);
    const nestedReport = verifyEvidence(
      fixture.request,
      nestedMismatch,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(nestedReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(nestedReport, "proof_digest_binding")).toMatchObject({
      state: "FAIL",
      reason_code: "ASSET_BINDING_MISMATCH",
    });

    const directMismatch = cloneEvidence(fixture);
    directMismatch.bundle.asset.proofDigestPrefix = "sha256:" + "b".repeat(16);
    const directReport = verifyEvidence(
      fixture.request,
      directMismatch,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(directReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(directReport, "proof_digest_binding").state).toBe("FAIL");
  });

  it("binds circuit version and leaves a legacy absence explicitly unassessed", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true });
    const mismatch = cloneEvidence(fixture);
    if (!mismatch.bundle.asset.verificationMetadata) throw new Error("missing metadata");
    mismatch.bundle.asset.verificationMetadata.circuit_version = 2;
    const mismatchReport = verifyEvidence(fixture.request, mismatch, fixture.trust, FIXTURE_NOW_MS);
    expect(mismatchReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(mismatchReport, "circuit_binding")).toMatchObject({
      state: "FAIL",
      reason_code: "CIRCUIT_BINDING_MISMATCH",
    });

    const legacy = cloneEvidence(fixture);
    const claims = { ...fixture.receiptClaims };
    delete claims.circuit_or_schema_id;
    delete claims.circuit_version;
    legacy.bundle.receipt.jws = resignReceipt(fixture, claims);
    delete legacy.bundle.receipt.claims.circuit_or_schema_id;
    delete legacy.bundle.receipt.claims.circuit_version;
    delete legacy.bundle.asset.circuitOrSchemaId;
    if (legacy.bundle.asset.verificationMetadata)
      delete legacy.bundle.asset.verificationMetadata.circuit_version;
    const legacyReport = verifyEvidence(fixture.request, legacy, fixture.trust, FIXTURE_NOW_MS);
    expect(legacyReport.record_coherence).toBe("COHERENT");
    expect(check(legacyReport, "circuit_binding")).toMatchObject({
      state: "NOT_ASSESSED",
      required: false,
    });
  });

  it("binds signed policy TTL and public expiry when present", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true, includeProvenance: true });
    const ttlMismatch = cloneEvidence(fixture);
    ttlMismatch.bundle.asset.ttlSeconds = 1;
    const ttlReport = verifyEvidence(fixture.request, ttlMismatch, fixture.trust, FIXTURE_NOW_MS);
    expect(ttlReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(ttlReport, "policy_freshness_binding")).toMatchObject({
      state: "FAIL",
      reason_code: "PUBLIC_RECORD_CONTRADICTION",
    });

    const expiryMismatch = cloneEvidence(fixture);
    expiryMismatch.bundle.asset.expiresAt = "2024-12-14T00:00:00Z";
    const expiryReport = verifyEvidence(
      fixture.request,
      expiryMismatch,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(expiryReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(expiryReport, "policy_freshness_binding").state).toBe("FAIL");

    const legacy = createSignedFixture({ includeConstraintHash: true });
    const legacyReport = verifyEvidence(
      legacy.request,
      legacy.evidence,
      legacy.trust,
      FIXTURE_NOW_MS,
    );
    expect(check(legacyReport, "policy_freshness_binding")).toMatchObject({
      state: "NOT_ASSESSED",
      required: false,
    });
  });

  it.each([
    {
      name: "asset commitment",
      checkId: "asset_commitment" as const,
      reasonCode: "ASSET_COMMITMENT_MISMATCH" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.asset.proofAssetCommitment = "sha256:" + "e".repeat(64);
      },
    },
    {
      name: "policy hash",
      checkId: "policy_binding" as const,
      reasonCode: "POLICY_BINDING_MISMATCH" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.asset.policyHash = "sha256:" + "e".repeat(64);
      },
    },
    {
      name: "policy CID",
      checkId: "policy_binding" as const,
      reasonCode: "POLICY_BINDING_MISMATCH" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.asset.policyCid = "bafybeidifferentpolicycid";
      },
    },
    {
      name: "constraint hash",
      checkId: "constraint_binding" as const,
      reasonCode: "CONSTRAINT_BINDING_MISMATCH" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.asset.constraintHash = "sha256:" + "e".repeat(64);
      },
    },
    {
      name: "provenance environment",
      checkId: "provenance_binding" as const,
      reasonCode: "PUBLIC_RECORD_CONTRADICTION" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.provenance.environment = "sandbox";
      },
    },
    {
      name: "provenance revision",
      checkId: "provenance_binding" as const,
      reasonCode: "PUBLIC_RECORD_CONTRADICTION" as const,
      mutate: (evidence: CoreEvidenceEnvelope) => {
        evidence.bundle.provenance.configurationRevision = 8;
      },
    },
  ])("classifies a signed $name contradiction in the core", ({ checkId, reasonCode, mutate }) => {
    const fixture = createSignedFixture({
      requireActive: true,
      includeConstraintHash: true,
      includeProvenance: true,
    });
    const evidence = cloneEvidence(fixture);
    mutate(evidence);

    const report = verifyEvidence(fixture.request, evidence, fixture.trust, FIXTURE_NOW_MS);

    expect(report.record_coherence).toBe("CONTRADICTORY");
    expect(report.registry_status).toBe("ACTIVE");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(check(report, "trust_manifest").state).toBe("PASS");
    expect(check(report, "live_key_intersection").state).toBe("PASS");
    expect(check(report, "receipt_signature").state).toBe("PASS");
    expect(check(report, "receipt_claims").state).toBe("PASS");
    expect(check(report, "signed_status").state).toBe("PASS");
    expect(check(report, checkId)).toEqual({
      id: checkId,
      state: "FAIL",
      reason_code: reasonCode,
      verification_method: "EXACT_FIELD_BINDING",
      authority: "PAR_SIGNED_RECEIPT",
      required: true,
    });
    expect(report.errors).toContain(reasonCode);
  });

  it("binds projected receipt header and full public JWK to the verified key", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true });
    const jwkOnly = cloneEvidence(fixture);
    delete jwkOnly.bundle.receipt.header;
    const jwkOnlyReport = verifyEvidence(fixture.request, jwkOnly, fixture.trust, FIXTURE_NOW_MS);
    expect(jwkOnlyReport.record_coherence).toBe("COHERENT");

    const sparseJwk = cloneEvidence(fixture);
    if (!sparseJwk.bundle.receipt.publicJwk) throw new Error("missing public JWK");
    // The fixture intentionally shares this object with the live JWKS. Detach
    // the embedded projection before exercising producer-omitted metadata.
    sparseJwk.bundle.receipt.publicJwk = { ...sparseJwk.bundle.receipt.publicJwk };
    delete sparseJwk.bundle.receipt.publicJwk.alg;
    delete sparseJwk.bundle.receipt.publicJwk.use;
    delete sparseJwk.bundle.receipt.publicJwk.key_ops;
    delete sparseJwk.bundle.receipt.publicJwk.ext;
    const sparseReport = verifyEvidence(fixture.request, sparseJwk, fixture.trust, FIXTURE_NOW_MS);
    expect(sparseReport.record_coherence).toBe("COHERENT");

    const headerOnly = cloneEvidence(fixture);
    delete headerOnly.bundle.receipt.publicJwk;
    const headerOnlyReport = verifyEvidence(
      fixture.request,
      headerOnly,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(headerOnlyReport.record_coherence).toBe("COHERENT");

    const neither = cloneEvidence(fixture);
    delete neither.bundle.receipt.header;
    delete neither.bundle.receipt.publicJwk;
    const neitherReport = verifyEvidence(fixture.request, neither, fixture.trust, FIXTURE_NOW_MS);
    expect(neitherReport.record_coherence).toBe("COHERENT");

    const alternate = cloneEvidence(fixture);
    alternate.bundle.receipt.publicJwk = createIndependentPublicJwk(fixture.publicJwk.kid);
    const alternateReport = verifyEvidence(
      fixture.request,
      alternate,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(alternateReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(alternateReport, "bundle_structure")).toMatchObject({
      state: "FAIL",
      reason_code: "PUBLIC_RECORD_CONTRADICTION",
    });

    const headerMismatch = cloneEvidence(fixture);
    headerMismatch.bundle.receipt.header = {
      alg: "ES256",
      kid: "fixture-other-es256-key",
      typ: "JWT",
    };
    headerMismatch.bundle.receipt.publicJwk = createIndependentPublicJwk("fixture-other-es256-key");
    const headerReport = verifyEvidence(
      fixture.request,
      headerMismatch,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(headerReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(headerReport, "bundle_structure").state).toBe("FAIL");
  });

  it("classifies trusted re-signed incompatible receipt claims as contradiction", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true });
    const wrongIssuer = { ...fixture.receiptClaims, iss: "did:web:evil.example" };
    const issuerEvidence = recordWithReceiptClaims(fixture, wrongIssuer);
    issuerEvidence.bundle.receipt.claims.iss = "did:web:evil.example";
    const issuerReport = verifyEvidence(
      fixture.request,
      issuerEvidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(issuerReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(issuerReport, "receipt_signature").state).toBe("PASS");
    expect(check(issuerReport, "receipt_claims")).toMatchObject({
      state: "FAIL",
      reason_code: "RECEIPT_ISSUER_MISMATCH",
    });

    const wrongSubject = {
      ...fixture.receiptClaims,
      sub: "00000000-0000-4000-8000-000000000002",
    };
    const subjectEvidence = recordWithReceiptClaims(fixture, wrongSubject);
    subjectEvidence.bundle.receipt.claims.sub = wrongSubject.sub;
    const subjectReport = verifyEvidence(
      fixture.request,
      subjectEvidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(subjectReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(subjectReport, "receipt_claims")).toMatchObject({
      state: "FAIL",
      reason_code: "BUNDLE_ASSET_ID_MISMATCH",
    });
  });

  it("keeps a tampered receipt signature indeterminate", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    const evidence = cloneEvidence(fixture);
    evidence.bundle.receipt.jws = tamperSignature(evidence.bundle.receipt.jws);
    const report = verifyEvidence(fixture.request, evidence, fixture.trust, FIXTURE_NOW_MS);
    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(check(report, "receipt_signature")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "RECEIPT_SIGNATURE_INVALID",
    });
  });

  it("classifies trusted re-signed status issuer and subject conflicts as contradiction", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    const wrongIssuerPayload = structuredClone(fixture.statusPayload);
    wrongIssuerPayload.issuer = "did:web:evil.example";
    const issuerEvidence = recordWithStatusPayload(fixture, wrongIssuerPayload);
    const issuerReport = verifyEvidence(
      fixture.request,
      issuerEvidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(issuerReport.record_coherence).toBe("CONTRADICTORY");
    expect(issuerReport.registry_status).toBe("UNKNOWN");
    expect(issuerReport.registry_active_condition).toBe("INDETERMINATE");
    expect(check(issuerReport, "signed_status")).toMatchObject({
      state: "FAIL",
      reason_code: "STATUS_REFERENCE_MISMATCH",
    });

    const wrongSubjectPayload = structuredClone(fixture.statusPayload);
    if (!isRecord(wrongSubjectPayload.credentialSubject)) throw new Error("missing status subject");
    wrongSubjectPayload.credentialSubject.id = `${fixture.statusPayload.id}#other`;
    const subjectEvidence = recordWithStatusPayload(fixture, wrongSubjectPayload);
    const subjectReport = verifyEvidence(
      fixture.request,
      subjectEvidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(subjectReport.record_coherence).toBe("CONTRADICTORY");
    expect(check(subjectReport, "signed_status")).toMatchObject({
      state: "FAIL",
      reason_code: "STATUS_REFERENCE_MISMATCH",
    });
  });

  it("classifies producer cross-field projection contradictions in the core", () => {
    const fixture = createSignedFixture({
      requireActive: true,
      includeConstraintHash: true,
      includeProvenance: true,
    });
    const cases = [
      {
        mutate: (evidence: CoreEvidenceEnvelope) => {
          evidence.bundle.statusCheck.statusListIndex = "10";
        },
        checkId: "status_check_projection" as const,
        reason: "STATUS_PROJECTION_MISMATCH" as const,
      },
      {
        mutate: (evidence: CoreEvidenceEnvelope) => {
          evidence.bundle.checks.status = "revoked";
        },
        checkId: "status_check_projection" as const,
        reason: "STATUS_PROJECTION_MISMATCH" as const,
      },
      {
        mutate: (evidence: CoreEvidenceEnvelope) => {
          evidence.status_url = "https://par.myproof.ai/status/suspension/default";
        },
        checkId: "status_reference_binding" as const,
        reason: "STATUS_REFERENCE_MISMATCH" as const,
      },
      {
        mutate: (evidence: CoreEvidenceEnvelope) => {
          evidence.bundle.receipt.header = {
            alg: "ES256",
            kid: "another-fixture-key",
            typ: "JWT",
          };
        },
        checkId: "bundle_structure" as const,
        reason: "PUBLIC_RECORD_CONTRADICTION" as const,
      },
    ];

    for (const candidate of cases) {
      const evidence = cloneEvidence(fixture);
      candidate.mutate(evidence);
      expect(PublicRecordEvidenceInputSchema.safeParse(evidence).success).toBe(true);

      const report = verifyEvidence(fixture.request, evidence, fixture.trust, FIXTURE_NOW_MS);
      expect(report.record_coherence).toBe("CONTRADICTORY");
      expect(check(report, candidate.checkId)).toMatchObject({
        state: "FAIL",
        reason_code: candidate.reason,
      });
    }
  });

  it("keeps a tampered status signature indeterminate", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    const evidence = cloneEvidence(fixture);
    if (!evidence.status_credential) throw new Error("missing status credential");
    evidence.status_credential.credential = tamperSignature(evidence.status_credential.credential);
    const report = verifyEvidence(fixture.request, evidence, fixture.trust, FIXTURE_NOW_MS);
    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(check(report, "signed_status")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "STATUS_CREDENTIAL_SIGNATURE_INVALID",
    });
  });

  it("accepts a signed suspension bit and satisfies no active requirement", () => {
    const fixture = createSignedFixture({
      requireActive: true,
      statusPurpose: "suspension",
      statusBit: 1,
      includeConstraintHash: true,
    });
    const report = verifyEvidence(fixture.request, fixture.evidence, fixture.trust, FIXTURE_NOW_MS);

    expect(report.record_coherence).toBe("COHERENT");
    expect(report.registry_status).toBe("SUSPENDED");
    expect(report.registry_active_condition).toBe("NOT_SATISFIED");
    expect(check(report, "signed_status")).toMatchObject({
      state: "PASS",
      reason_code: "STATUS_CREDENTIAL_SIGNATURE_VALID",
    });
    expect(check(report, "registry_status")).toMatchObject({
      state: "PASS",
      reason_code: "STATUS_SUSPENDED",
    });
  });

  it("keeps a malformed compact status credential indeterminate", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    const evidence = cloneEvidence(fixture);
    if (!evidence.status_credential) throw new Error("missing status credential");
    evidence.status_credential.credential = "AAAA.AAAA.AAAA";

    const report = verifyEvidence(fixture.request, evidence, fixture.trust, FIXTURE_NOW_MS);

    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(check(report, "signed_status")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "STATUS_CREDENTIAL_MALFORMED",
    });
    expect(JSON.stringify(report)).not.toContain("AAAA.AAAA.AAAA");
  });

  it("uses non-assertive tuples for every unavailable check", () => {
    const report = unavailableReport(
      { asset_id: FIXTURE_ASSET_ID, require_active: true },
      FIXTURE_NOW_MS,
    );

    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(
      report.checks.map((item) => [
        item.id,
        item.state,
        item.reason_code,
        item.verification_method,
        item.authority,
        item.required,
      ]),
    ).toEqual([
      [
        "bundle_structure",
        "UNKNOWN",
        "PUBLIC_RECORD_UNAVAILABLE",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
        true,
      ],
      [
        "asset_record",
        "UNKNOWN",
        "PUBLIC_RECORD_UNAVAILABLE",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
        true,
      ],
      [
        "trust_manifest",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
        true,
      ],
      [
        "live_key_intersection",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "KEY_RING_INTERSECTION",
        "RELEASE_TRUST_MANIFEST",
        true,
      ],
      [
        "receipt_presence",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
        true,
      ],
      [
        "receipt_structure",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "STRUCTURAL_VALIDATION",
        "PAR_PUBLIC_EVIDENCE",
        true,
      ],
      [
        "receipt_signature",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "JWS_SIGNATURE",
        "PAR_SIGNED_RECEIPT",
        true,
      ],
      [
        "receipt_claims",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "STRUCTURAL_VALIDATION",
        "PAR_SIGNED_RECEIPT",
        true,
      ],
      [
        "asset_identifier",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_PUBLIC_EVIDENCE",
        true,
      ],
      [
        "asset_commitment",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        true,
      ],
      [
        "proof_digest_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "PREFIX_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ],
      [
        "policy_binding",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        true,
      ],
      [
        "constraint_binding",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        true,
      ],
      [
        "circuit_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ],
      [
        "status_reference_binding",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_STATUS_CREDENTIAL",
        true,
      ],
      [
        "status_check_projection",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_PUBLIC_EVIDENCE",
        false,
      ],
      [
        "provenance_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "EXACT_FIELD_BINDING",
        "PAR_SIGNED_RECEIPT",
        false,
      ],
      [
        "policy_freshness_binding",
        "NOT_ASSESSED",
        "CHECK_NOT_ASSESSED",
        "CLOCK_VALIDATION",
        "PAR_SIGNED_RECEIPT",
        false,
      ],
      [
        "signed_status",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "JWS_SIGNATURE",
        "PAR_SIGNED_STATUS_CREDENTIAL",
        true,
      ],
      [
        "registry_status",
        "UNKNOWN",
        "CHECK_UNKNOWN",
        "STATUS_BIT_EVALUATION",
        "PAR_SIGNED_STATUS_CREDENTIAL",
        true,
      ],
      [
        "acceptance_decision",
        "NOT_ASSESSED",
        "ACCEPTANCE_NOT_PERFORMED",
        "NOT_PERFORMED",
        "NONE",
        false,
      ],
      [
        "underlying_proof_verification",
        "NOT_ASSESSED",
        "PROOF_VERIFICATION_NOT_PERFORMED",
        "NOT_PERFORMED",
        "NONE",
        false,
      ],
      [
        "predicate_assurance",
        "NOT_ASSESSED",
        "PREDICATE_REPORTED_ONLY",
        "NOT_PERFORMED",
        "NONE",
        false,
      ],
    ]);
  });

  it("honors deterministic receipt clock tolerance and fails closed after expiry", () => {
    const fixture = createSignedFixture({ includeConstraintHash: true });
    const exp = Number(fixture.receiptClaims.exp);
    const withinTolerance = verifyEvidence(
      fixture.request,
      fixture.evidence,
      fixture.trust,
      (exp + 60) * 1000,
    );
    expect(withinTolerance.checks.find((item) => item.id === "receipt_claims")?.state).toBe("PASS");

    const expired = verifyEvidence(
      fixture.request,
      fixture.evidence,
      fixture.trust,
      (exp + 61) * 1000,
    );
    expect(expired.record_coherence).toBe("INDETERMINATE");
    expect(check(expired, "receipt_claims")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "RECEIPT_CLAIMS_EXPIRED",
    });
  });

  it("changes only the active condition when require_active is toggled", () => {
    const fixture = createSignedFixture({ requireActive: true, includeConstraintHash: true });
    const requested = verifyEvidence(
      fixture.request,
      fixture.evidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    const notRequested = verifyEvidence(
      { ...fixture.request, require_active: false },
      fixture.evidence,
      fixture.trust,
      FIXTURE_NOW_MS,
    );
    expect(requested.record_coherence).toBe("COHERENT");
    expect(notRequested.record_coherence).toBe("COHERENT");
    expect(requested.registry_active_condition).toBe("SATISFIED");
    expect(notRequested.registry_active_condition).toBe("NOT_REQUESTED");
    expect(requested.checks).toEqual(notRequested.checks);

    const inactive = createSignedFixture({
      requireActive: true,
      statusBit: 1,
      includeConstraintHash: true,
    });
    const inactiveReport = verifyEvidence(
      inactive.request,
      inactive.evidence,
      inactive.trust,
      FIXTURE_NOW_MS,
    );
    expect(inactiveReport.record_coherence).toBe("COHERENT");
    expect(inactiveReport.registry_status).toBe("REVOKED");
    expect(inactiveReport.registry_active_condition).toBe("NOT_SATISFIED");
  });

  it("verifies old and current receipts across key rotation and fails closed after removal", () => {
    const rotated = createRotatedSignedFixtures();

    const oldReport = verifyEvidence(
      rotated.old.request,
      rotated.oldEvidence,
      rotated.trust,
      FIXTURE_NOW_MS,
    );
    expect(oldReport.record_coherence).toBe("COHERENT");
    expect(oldReport.registry_status).toBe("ACTIVE");
    expect(oldReport.registry_active_condition).toBe("SATISFIED");

    const currentReport = verifyEvidence(
      rotated.current.request,
      rotated.currentEvidence,
      rotated.trust,
      FIXTURE_NOW_MS,
    );
    expect(currentReport.record_coherence).toBe("COHERENT");
    expect(currentReport.registry_status).toBe("ACTIVE");

    const currentOnly = structuredClone(rotated.currentEvidence);
    currentOnly.receipt_jwks = { keys: [rotated.current.publicJwk] };
    const preservedNewer = verifyEvidence(
      rotated.current.request,
      currentOnly,
      rotated.trust,
      FIXTURE_NOW_MS,
    );
    expect(preservedNewer.record_coherence).toBe("COHERENT");

    const oldAfterRemoval = structuredClone(rotated.oldEvidence);
    oldAfterRemoval.receipt_jwks = { keys: [rotated.current.publicJwk] };
    const removedOld = verifyEvidence(
      rotated.old.request,
      oldAfterRemoval,
      rotated.trust,
      FIXTURE_NOW_MS,
    );
    expect(removedOld.record_coherence).toBe("INDETERMINATE");
    expect(removedOld.registry_active_condition).toBe("INDETERMINATE");
    expect(check(removedOld, "live_key_intersection")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "RECEIPT_KEY_UNKNOWN",
    });

    const unknown = createSignedFixture({
      kid: "fixture-rotation-unknown",
      requireActive: true,
      includeConstraintHash: true,
      includeProvenance: true,
    });
    const unknownReport = verifyEvidence(
      unknown.request,
      { ...unknown.evidence, receipt_jwks: rotated.liveJwks },
      rotated.trust,
      FIXTURE_NOW_MS,
    );
    expect(unknownReport.record_coherence).toBe("INDETERMINATE");
    expect(check(unknownReport, "live_key_intersection")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "RECEIPT_KEY_UNKNOWN",
    });
  });
});
