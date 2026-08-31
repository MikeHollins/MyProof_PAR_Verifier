import { describe, expect, it } from "vitest";

import {
  CANONICAL_PAR_ORIGIN,
  CANONICAL_RECEIPT_JWKS_PATH,
  VERIFICATION_BUNDLE_PATH_TEMPLATE,
} from "../../src/contracts/constants.js";

describe("canonical PAR public routes", () => {
  it("pins the current producer routes exactly", () => {
    expect(CANONICAL_PAR_ORIGIN).toBe("https://par.myproof.ai");
    expect(CANONICAL_RECEIPT_JWKS_PATH).toBe("/api/public/receipts/jwks.json");
    expect(VERIFICATION_BUNDLE_PATH_TEMPLATE).toBe(
      "/api/public/proof-assets/{asset_id}/verification-bundle",
    );

    const jwks = new URL(CANONICAL_RECEIPT_JWKS_PATH, CANONICAL_PAR_ORIGIN);
    expect(jwks.href).toBe("https://par.myproof.ai/api/public/receipts/jwks.json");
  });

  it("can run an explicit non-mutating live route probe when requested", async () => {
    if (process.env.MYPROOF_PAR_LIVE_CONTRACT !== "1") return;

    const response = await fetch(new URL(CANONICAL_RECEIPT_JWKS_PATH, CANONICAL_PAR_ORIGIN), {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")?.split(";", 1)[0]).toBe("application/json");
  });
});
