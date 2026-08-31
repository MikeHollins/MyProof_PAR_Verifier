import { describe, expect, it } from "vitest";

import { verifySignedStatusCredential } from "../../src/crypto/status.js";
import { CANONICAL_RECEIPT_ISSUER } from "../../src/crypto/trust.js";
import { createSignedFixture, resignStatus } from "../fixtures/core/signed-fixtures.js";

const STATUS_URL = "https://par.myproof.ai/status/revocation/default";
const NOW_MS = 1_733_616_000_000;

function verifyFixture(
  fixture: ReturnType<typeof createSignedFixture>,
  token = fixture.statusJws,
  overrides: Partial<Parameters<typeof verifySignedStatusCredential>[2]> = {},
) {
  return verifySignedStatusCredential(token, fixture.evidence.receipt_jwks.keys, {
    nowMs: NOW_MS,
    expectedId: STATUS_URL,
    expectedPurpose: "revocation",
    statusListIndex: "9",
    expectedIssuer: CANONICAL_RECEIPT_ISSUER,
    ...overrides,
  });
}

function tamperSignature(token: string): string {
  const parts = token.split(".");
  const signature = parts[2];
  if (parts[0] === undefined || parts[1] === undefined || signature === undefined)
    throw new Error("invalid fixture token");
  const first = signature.charAt(0);
  return `${parts[0]}.${parts[1]}.${first === "A" ? "B" : "A"}${signature.slice(1)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("signed status credential verification", () => {
  it("verifies an ES256 bitstring status credential and evaluates its bit", () => {
    const fixture = createSignedFixture();
    const result = verifyFixture(fixture);
    expect(result).toMatchObject({ ok: true, bit: 0, registryStatus: "ACTIVE" });
  });

  it("treats trusted signed issuer, subject, id, and purpose conflicts as explicit failures", () => {
    const fixture = createSignedFixture();

    const wrongIssuer = structuredClone(fixture.statusPayload);
    wrongIssuer.issuer = "did:web:evil.example";
    expect(verifyFixture(fixture, resignStatus(fixture, wrongIssuer))).toMatchObject({
      ok: false,
      code: "STATUS_ISSUER_MISMATCH",
      signature_verified: true,
    });

    const wrongSubject = structuredClone(fixture.statusPayload);
    const subject = wrongSubject.credentialSubject;
    if (!isRecord(subject)) throw new Error("missing credential subject");
    subject.id = `${STATUS_URL}#other`;
    expect(verifyFixture(fixture, resignStatus(fixture, wrongSubject))).toMatchObject({
      ok: false,
      code: "STATUS_SUBJECT_MISMATCH",
      signature_verified: true,
    });

    const wrongId = {
      ...fixture.statusPayload,
      id: "https://par.myproof.ai/status/revocation/other",
    };
    expect(verifyFixture(fixture, resignStatus(fixture, wrongId))).toMatchObject({
      ok: false,
      code: "STATUS_ID_MISMATCH",
      signature_verified: true,
    });

    const wrongPurpose = structuredClone(fixture.statusPayload);
    if (!isRecord(wrongPurpose.credentialSubject)) throw new Error("missing credential subject");
    wrongPurpose.credentialSubject.statusPurpose = "suspension";
    expect(verifyFixture(fixture, resignStatus(fixture, wrongPurpose))).toMatchObject({
      ok: false,
      code: "STATUS_PURPOSE_MISMATCH",
      signature_verified: true,
    });
  });

  it("keeps untrusted keys and invalid signatures indeterminate", () => {
    const fixture = createSignedFixture();
    const tampered = tamperSignature(fixture.statusJws);
    expect(verifyFixture(fixture, tampered)).toMatchObject({
      ok: false,
      code: "STATUS_SIGNATURE_INVALID",
    });

    const parts = fixture.statusJws.split(".");
    const payload = parts[1];
    const signature = parts[2];
    if (payload === undefined || signature === undefined) throw new Error("invalid fixture token");
    const unknownKidHeader = Buffer.from(
      JSON.stringify({ alg: "ES256", typ: "vc+jwt", cty: "vc", kid: "status-unknown-key" }),
    ).toString("base64url");
    expect(verifyFixture(fixture, `${unknownKidHeader}.${payload}.${signature}`)).toMatchObject({
      ok: false,
      code: "STATUS_KID_UNTRUSTED",
    });
  });

  it("enforces status validity windows, canonical indexes, and bounded gzip lists", () => {
    const fixture = createSignedFixture();

    const expired = { ...fixture.statusPayload, validUntil: "2024-12-07T23:58:59Z" };
    expect(verifyFixture(fixture, resignStatus(fixture, expired))).toMatchObject({
      ok: false,
      code: "STATUS_EXPIRED",
      signature_verified: true,
    });

    const notYet = { ...fixture.statusPayload, validFrom: "2024-12-09T00:00:00Z" };
    expect(verifyFixture(fixture, resignStatus(fixture, notYet))).toMatchObject({
      ok: false,
      code: "STATUS_NOT_YET_VALID",
      signature_verified: true,
    });

    expect(verifyFixture(fixture, fixture.statusJws, { statusListIndex: "09" })).toMatchObject({
      ok: false,
      code: "STATUS_INDEX_INVALID",
    });
    expect(verifyFixture(fixture, fixture.statusJws, { statusListIndex: "131072" })).toMatchObject({
      ok: false,
      code: "STATUS_INDEX_OUT_OF_RANGE",
    });

    const malformedEncoding = structuredClone(fixture.statusPayload);
    if (!isRecord(malformedEncoding.credentialSubject))
      throw new Error("missing credential subject");
    malformedEncoding.credentialSubject.encodedList = "uAAAA";
    expect(verifyFixture(fixture, resignStatus(fixture, malformedEncoding))).toMatchObject({
      ok: false,
      code: "STATUS_ENCODING_INVALID",
      signature_verified: true,
    });
  });
});
