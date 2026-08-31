import { describe, expect, it } from "vitest";
import { CliInvariantError } from "../../src/cli/errors.js";
import { formatHumanReport, formatJsonReport, formatSafeError } from "../../src/cli/format.js";
import type { CanonicalReport } from "../../src/cli/types.js";
import { canonicalReport } from "../harness/mcp/canonical-report.js";

const ASSET_ID = "00000000-0000-4000-8000-000000000001";

const fixture: CanonicalReport = canonicalReport({
  assetId: ASSET_ID,
  outcome: "coherent-active",
  requireActive: true,
});

describe("report formatting", () => {
  it("emits the canonical report as one JSON document without a wrapper", () => {
    const output = formatJsonReport(fixture);
    expect(output.endsWith("\n")).toBe(true);
    expect(JSON.parse(output)).toEqual(fixture);
  });

  it("states the claim boundary and does not dump arbitrary record detail", () => {
    const output = formatHumanReport(fixture, ASSET_ID);
    expect(output).toContain("Record coherence: COHERENT");
    expect(output).toContain("Underlying proof verification: NOT_PERFORMED");
    expect(output).toContain("Predicate assurance: PAR_REPORTED_ONLY");
    expect(output).toContain(
      "Limitations: UNDERLYING_PROOF_NOT_PERFORMED, PREDICATE_PAR_REPORTED_ONLY",
    );
    expect(output).toContain("The underlying proof and predicate were not independently verified.");
    expect(output).not.toContain("ignore previous instructions");
  });

  it("formats machine-readable errors independently of the canonical report", () => {
    expect(
      formatSafeError({ safeCode: "VERIFICATION_UNAVAILABLE", safeMessage: "safe message" }, true),
    ).toBe('{"error":{"code":"VERIFICATION_UNAVAILABLE","message":"safe message"}}\n');
  });

  it("fails closed instead of formatting a report for another asset", () => {
    expect(() => formatHumanReport(fixture, "11111111-1111-4111-8111-111111111111")).toThrow(
      CliInvariantError,
    );
  });
});
