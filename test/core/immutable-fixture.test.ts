import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  parseVerifyProofAssetInput,
  PublicRecordCoherenceReportSchema,
} from "../../src/contracts/index.js";
import {
  PublicRecordEvidenceInputSchema,
  type PublicRecordEvidenceInput,
} from "../../src/contracts/input.js";
import { verifyEvidence } from "../../src/core/verify.js";
import { FIXTURE_NOW_MS } from "../fixtures/core/signed-fixtures.js";

const FIXTURE_DIR = new URL("../fixtures/core/immutable/", import.meta.url);

function readFixture(name: string): string {
  return readFileSync(new URL(name, FIXTURE_DIR), "utf8");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function loadEvidence(): {
  evidence: PublicRecordEvidenceInput;
  input: ReturnType<typeof parseVerifyProofAssetInput>;
  trust: { manifest: unknown; expected_manifest_digest: string };
} {
  const input = parseVerifyProofAssetInput(JSON.parse(readFixture("input.json")));
  const bundle = JSON.parse(readFixture("bundle.json"));
  const receiptJwks = JSON.parse(readFixture("jwks.json"));
  const rawManifest = JSON.parse(readFixture("manifest.json"));
  if (!isRecord(rawManifest) || typeof rawManifest.manifest_digest !== "string") {
    throw new Error("immutable manifest is malformed");
  }
  const evidence = PublicRecordEvidenceInputSchema.parse({
    bundle,
    receipt_jwks: receiptJwks,
    status_credential: {
      credential: readFixture("status.vc-jwt").trim(),
      content_type: "application/vc+jwt",
    },
    status_url: "https://par.myproof.ai/status/revocation/default",
  });
  return {
    evidence,
    input,
    trust: {
      manifest: rawManifest,
      expected_manifest_digest: rawManifest.manifest_digest,
    },
  };
}

describe("immutable independently signed core vector", () => {
  it("matches every recorded artifact hash and the fixed expected report", () => {
    const sums = readFixture("SHA256SUMS").trim().split("\n");
    for (const line of sums) {
      const separator = line.indexOf("  ");
      if (separator < 0) throw new Error("invalid SHA256SUMS line");
      const expected = line.slice(0, separator);
      const name = line.slice(separator + 2);
      expect(createHash("sha256").update(readFixture(name), "utf8").digest("hex")).toBe(expected);
    }

    const { evidence, input, trust } = loadEvidence();
    const expected = PublicRecordCoherenceReportSchema.parse(
      JSON.parse(readFixture("expected-report.json")),
    );
    const actual = verifyEvidence(input, evidence, trust, FIXTURE_NOW_MS);
    expect(actual).toEqual(expected);
    expect(actual.record_coherence).toBe("COHERENT");
    expect(actual.registry_status).toBe("ACTIVE");
    expect(actual.registry_active_condition).toBe("SATISFIED");
    expect("jti" in evidence.bundle.receipt.claims).toBe(false);
    expect(JSON.stringify(actual)).not.toContain("fixture-receipt-0001");
  });

  it("uses the fixed bytes as the mutation source for a privacy regression", () => {
    const { evidence, input, trust } = loadEvidence();
    const leaked = structuredClone(evidence);
    leaked.bundle.receipt.claims.jti = "fixture-receipt-0001";
    const report = verifyEvidence(input, leaked, trust, FIXTURE_NOW_MS);
    expect(report.record_coherence).toBe("CONTRADICTORY");
    expect(report.checks[0]).toMatchObject({
      id: "bundle_structure",
      state: "FAIL",
      reason_code: "PUBLIC_RECORD_CONTRADICTION",
    });
  });
});
