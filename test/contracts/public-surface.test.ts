import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const packageJson = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as {
  exports?: Record<string, unknown>;
  files?: unknown[];
};

const schemaExports = [
  "./schemas/myproof.par.public-record-input.v1.json",
  "./schemas/myproof.par.public-record-check.v1.json",
  "./schemas/myproof.par.public-record-coherence.v1.json",
] as const;

const publicRuntimeExports = [
  "AssetIdSchema",
  "CheckAuthoritySchema",
  "CheckIdSchema",
  "CheckSchema",
  "CheckStateSchema",
  "CHECK_AUTHORITY_VALUES",
  "CHECK_IDS",
  "CHECK_STATE_VALUES",
  "LimitationCodeSchema",
  "LIMITATION_CODES",
  "PublicRecordCoherenceReportSchema",
  "REASON_CODES",
  "ReasonCodeSchema",
  "RecordCoherenceSchema",
  "RECORD_COHERENCE_VALUES",
  "RegistryActiveConditionSchema",
  "RegistryStatusSchema",
  "REGISTRY_ACTIVE_CONDITION_VALUES",
  "REGISTRY_STATUS_VALUES",
  "REPORT_CONTRACT_ID",
  "REPORT_SCHEMA_VERSION",
  "VerificationMethodSchema",
  "VERIFICATION_METHOD_VALUES",
  "VerifyProofAssetInputSchema",
  "assertPublicRecordReportBytes",
  "parsePublicRecordCoherenceReport",
  "parsePublicRecordCoherenceReportForInput",
  "parseVerifyProofAssetInput",
  "serializePublicRecordCoherenceReport",
] as const;

const forbiddenProviderRuntimeExports = [
  "BundleChecksInputSchema",
  "CanonicalStatusUrlSchema",
  "PublicAssetRecordInputSchema",
  "PublicAssuranceEvidenceInputSchema",
  "PublicAssurancePayloadInputSchema",
  "PublicRecordEvidenceInputSchema",
  "PublicVerificationBundleInputSchema",
  "ProvenanceInputSchema",
  "ReceiptClaimsInputSchema",
  "ReceiptEvidenceInputSchema",
  "ReceiptHeaderInputSchema",
  "ReceiptJwkInputSchema",
  "ReceiptJwksInputSchema",
  "RFC3339DateTimeInputSchema",
  "StatusCheckInputSchema",
  "StatusCredentialEvidenceInputSchema",
  "StatusReferenceInputSchema",
  "isValidRFC3339DateTime",
] as const;

describe("published package surface", () => {
  it("exports only the root contracts, explicit contracts subpath, and canonical schema artifacts", () => {
    const expectedExports = {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
      "./contracts": {
        types: "./dist/contracts/index.d.ts",
        import: "./dist/contracts/index.js",
      },
      ...Object.fromEntries(schemaExports.map((path) => [path, path])),
    };

    expect(packageJson.exports).toEqual(expectedExports);
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./schemas/*.json");
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./mcp");
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./service");
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./provider");
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./core");
    expect(Object.keys(packageJson.exports ?? {})).not.toContain("./crypto");
  });

  it("keeps root and ./contracts on one explicit runtime allowlist", async () => {
    const root = await import("../../src/index.js");
    const contracts = await import("../../src/contracts/index.js");
    const rootKeys = Object.keys(root).sort();
    const contractKeys = Object.keys(contracts).sort();
    expect(rootKeys).toEqual([...publicRuntimeExports].sort());
    expect(contractKeys).toEqual([...publicRuntimeExports].sort());
    expect(rootKeys).toEqual(contractKeys);
    for (const name of forbiddenProviderRuntimeExports) {
      expect(name in root).toBe(false);
      expect(name in contracts).toBe(false);
    }
  });

  it("ships exactly the generated schema artifacts rather than source or generator files", () => {
    const files = (packageJson.files ?? []).filter(
      (entry): entry is string => typeof entry === "string",
    );
    expect(files.filter((path) => path.startsWith("schemas/"))).toEqual(
      schemaExports.map((path) => path.slice("./".length)),
    );
    expect(files).not.toContain("schemas/generate.ts");
    expect(files).not.toContain("schemas/*.json");
  });
});
