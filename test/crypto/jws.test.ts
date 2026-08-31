import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { encodeBase64Url } from "../../src/crypto/base64url.js";
import {
  importVerificationKey,
  parseCompactJws,
  publicJwkThumbprint,
} from "../../src/crypto/jws.js";
import {
  createIndependentPublicJwk,
  createSignedFixture,
} from "../fixtures/core/signed-fixtures.js";

function tokenWithHeader(token: string, header: Record<string, unknown>): string {
  const parts = token.split(".");
  const payload = parts[1];
  const signature = parts[2];
  if (payload === undefined || signature === undefined) throw new Error("invalid fixture token");
  const encodedHeader = encodeBase64Url(Buffer.from(JSON.stringify(header), "utf8"));
  return `${encodedHeader}.${payload}.${signature}`;
}

describe("strict compact JWS primitives", () => {
  it("parses an ES256 JWT without trusting its payload", () => {
    const fixture = createSignedFixture();
    const parsed = parseCompactJws(fixture.receiptJws, "JWT");
    expect(parsed.header).toMatchObject({ alg: "ES256", typ: "JWT", kid: fixture.publicJwk.kid });
    expect(parsed.payload).toEqual(fixture.receiptClaims);
    expect(parsed.signature.byteLength).toBe(64);
  });

  it.each([
    ["wrong algorithm", { alg: "RS256", typ: "JWT", kid: "fixture" }, "UNSUPPORTED_JWS_ALGORITHM"],
    ["wrong type", { alg: "ES256", typ: "JOSE", kid: "fixture" }, "JWS_TYPE_MISMATCH"],
    [
      "critical header",
      { alg: "ES256", typ: "JWT", kid: "fixture", crit: ["exp"] },
      "UNSUPPORTED_JWS_HEADER",
    ],
    [
      "non-string content type",
      { alg: "ES256", typ: "JWT", kid: "fixture", cty: 7 },
      "INVALID_JWS_CONTENT_TYPE",
    ],
  ] as const)("rejects %s", (_label, header, reason) => {
    const fixture = createSignedFixture();
    expect(() => parseCompactJws(tokenWithHeader(fixture.receiptJws, header), "JWT")).toThrow(
      reason,
    );
  });

  it("rejects malformed and non-canonical compact segments", () => {
    const fixture = createSignedFixture();
    expect(() => parseCompactJws("not-a-jws", "JWT")).toThrow("INVALID_JWS_FORMAT");
    const parts = fixture.receiptJws.split(".");
    const payload = parts[1];
    const signature = parts[2];
    if (payload === undefined || signature === undefined) throw new Error("invalid fixture token");
    const header = parts[0];
    if (header === undefined) throw new Error("invalid fixture token");
    expect(() => parseCompactJws(`${header}=.${payload}.${signature}`, "JWT")).toThrow(
      "INVALID_JWS_HEADER_ENCODING",
    );
    expect(() => parseCompactJws(`${header}.${payload}.AA`, "JWT")).toThrow(
      "INVALID_ES256_SIGNATURE_LENGTH",
    );
  });

  it("rejects caller-supplied private or incompatible verification keys", () => {
    const fixture = createSignedFixture();
    const privateJwk = fixture.privateKey.export({ format: "jwk" });
    expect(() => importVerificationKey(privateJwk)).toThrow("PRIVATE_KEY_NOT_ALLOWED");
    expect(() => importVerificationKey({ ...fixture.publicJwk, ext: false })).toThrow(
      "VERIFICATION_KEY_EXT_MISMATCH",
    );
    expect(() => importVerificationKey({ ...fixture.publicJwk, key_ops: ["sign"] })).toThrow(
      "VERIFICATION_KEY_OPERATION_MISMATCH",
    );
  });

  it("uses only public coordinates for stable thumbprints and distinguishes rotation", () => {
    const fixture = createSignedFixture();
    const rotated = createIndependentPublicJwk(fixture.publicJwk.kid);
    expect(publicJwkThumbprint(fixture.publicJwk)).not.toBe(publicJwkThumbprint(rotated));
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const privateRotated = privateKey.export({ format: "jwk" });
    expect(() => publicJwkThumbprint(privateRotated)).toThrow("PRIVATE_KEY_NOT_ALLOWED");
  });
});
