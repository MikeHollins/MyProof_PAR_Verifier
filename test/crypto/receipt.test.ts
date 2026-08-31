import { describe, expect, it } from "vitest";

import { encodeBase64Url } from "../../src/crypto/base64url.js";
import { verifyReceiptJws } from "../../src/crypto/receipt.js";
import { createSignedFixture, resignReceipt } from "../fixtures/core/signed-fixtures.js";

function tokenWithHeader(token: string, header: Record<string, unknown>): string {
  const parts = token.split(".");
  const payload = parts[1];
  const signature = parts[2];
  if (payload === undefined || signature === undefined) throw new Error("invalid fixture token");
  return `${encodeBase64Url(Buffer.from(JSON.stringify(header), "utf8"))}.${payload}.${signature}`;
}

function verifyFixture(
  fixture: ReturnType<typeof createSignedFixture>,
  token = fixture.receiptJws,
  nowSeconds = Math.floor(1_733_616_000_000 / 1000),
) {
  return verifyReceiptJws(token, fixture.evidence.receipt_jwks.keys, {
    nowSeconds,
    expectedAssetId: fixture.request.asset_id,
  });
}

describe("signed PAR receipt verification", () => {
  it("requires a valid ES256 signature, complete signed claims, and canonical status reference", () => {
    const fixture = createSignedFixture();
    const result = verifyFixture(fixture);
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) throw new Error("expected valid receipt");
    expect(result.claims.jti).toBe("fixture-receipt-0001");

    const missingJti = { ...fixture.receiptClaims };
    delete missingJti.jti;
    const missingResult = verifyFixture(fixture, resignReceipt(fixture, missingJti));
    expect(missingResult).toMatchObject({
      ok: false,
      code: "RECEIPT_CLAIM_MISSING",
      signature_verified: true,
    });

    const legacyPath = {
      ...fixture.receiptClaims,
      status_ref: {
        ...(fixture.receiptClaims.status_ref as Record<string, unknown>),
        statusListUrl: "https://par.myproof.ai/status/lists/revocation/default",
      },
    };
    expect(verifyFixture(fixture, resignReceipt(fixture, legacyPath))).toMatchObject({
      ok: false,
      code: "RECEIPT_STATUS_REF_INVALID",
      signature_verified: true,
    });
  });

  it("distinguishes trusted signed contradictions from untrusted or tampered evidence", () => {
    const fixture = createSignedFixture();
    const wrongAudience = { ...fixture.receiptClaims, aud: "other-audience" };
    expect(verifyFixture(fixture, resignReceipt(fixture, wrongAudience))).toMatchObject({
      ok: false,
      code: "RECEIPT_AUDIENCE_MISMATCH",
      signature_verified: true,
    });

    const wrongIssuer = { ...fixture.receiptClaims, iss: "did:web:evil.example" };
    expect(verifyFixture(fixture, resignReceipt(fixture, wrongIssuer))).toMatchObject({
      ok: false,
      code: "RECEIPT_ISSUER_MISMATCH",
      signature_verified: true,
    });

    const wrongSubject = {
      ...fixture.receiptClaims,
      sub: "00000000-0000-4000-8000-000000000002",
    };
    expect(verifyFixture(fixture, resignReceipt(fixture, wrongSubject))).toMatchObject({
      ok: false,
      code: "RECEIPT_SUBJECT_MISMATCH",
      signature_verified: true,
    });

    const tamperedParts = fixture.receiptJws.split(".");
    const tamperedSignature = tamperedParts[2];
    if (
      tamperedParts[0] === undefined ||
      tamperedParts[1] === undefined ||
      tamperedSignature === undefined
    )
      throw new Error("invalid fixture token");
    const first = tamperedSignature.charAt(0);
    const tampered = `${tamperedParts[0]}.${tamperedParts[1]}.${first === "A" ? "B" : "A"}${tamperedSignature.slice(1)}`;
    expect(verifyFixture(fixture, tampered)).toMatchObject({
      ok: false,
      code: "RECEIPT_SIGNATURE_INVALID",
    });

    const unknownKid = tokenWithHeader(fixture.receiptJws, {
      alg: "ES256",
      typ: "JWT",
      kid: "fixture-unknown-key",
    });
    expect(verifyFixture(fixture, unknownKid)).toMatchObject({
      ok: false,
      code: "RECEIPT_KID_UNTRUSTED",
    });
  });

  it("enforces deterministic clock boundaries", () => {
    const fixture = createSignedFixture();
    const exp = Number(fixture.receiptClaims.exp);
    const nbf = Number(fixture.receiptClaims.nbf);
    expect(verifyFixture(fixture, fixture.receiptJws, exp + 60)).toMatchObject({ ok: true });
    expect(verifyFixture(fixture, fixture.receiptJws, exp + 61)).toMatchObject({
      ok: false,
      code: "RECEIPT_EXPIRED",
    });
    expect(verifyFixture(fixture, fixture.receiptJws, nbf - 61)).toMatchObject({
      ok: false,
      code: "RECEIPT_NOT_YET_VALID",
    });
    expect(
      verifyReceiptJws(fixture.receiptJws, fixture.evidence.receipt_jwks.keys, {
        nowSeconds: -1,
        expectedAssetId: fixture.request.asset_id,
      }),
    ).toMatchObject({ ok: false, code: "RECEIPT_TIME_INVALID" });
  });
});
