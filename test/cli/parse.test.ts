import { describe, expect, it } from "vitest";
import { CliUsageError } from "../../src/cli/errors.js";
import { CLI_HELP, parseCliArgs, validateAssetId } from "../../src/cli/parse.js";

const ASSET_ID = "00000000-0000-4000-8000-000000000001";

describe("parseCliArgs", () => {
  it("parses the exact verify command with flags in either order", () => {
    expect(parseCliArgs(["verify", ASSET_ID, "--json", "--require-active"])).toEqual({
      kind: "verify",
      assetId: ASSET_ID,
      json: true,
      requireActive: true,
    });
    expect(parseCliArgs(["verify", ASSET_ID, "--require-active"])).toEqual({
      kind: "verify",
      assetId: ASSET_ID,
      json: false,
      requireActive: true,
    });
  });

  it("parses mcp without permitting command arguments", () => {
    expect(parseCliArgs(["mcp"])).toEqual({ kind: "mcp" });
    expect(() => parseCliArgs(["mcp", "--json"])).toThrow(CliUsageError);
  });

  it("supports help without loading verifier dependencies", () => {
    expect(parseCliArgs(["--help"])).toEqual({ kind: "help" });
    expect(CLI_HELP).toContain("myproof-par verify <asset-id>");
  });

  const malformedInvocations: readonly (readonly string[])[] = [
    [],
    ["verify"],
    ["verify", "one", "two"],
    ["verify", "--json", ASSET_ID],
    ["verify", ASSET_ID, "--json", "--json"],
    ["verify", ASSET_ID, "--require-active", "--require-active"],
    ["verify", ASSET_ID, "--unknown"],
    ["unknown", ASSET_ID],
    ["--json", "verify", ASSET_ID],
  ];
  it.each(malformedInvocations.map((argv) => ({ argv })))(
    "rejects malformed invocation %j",
    ({ argv }) => {
      expect(() => parseCliArgs(argv)).toThrow(CliUsageError);
    },
  );

  it.each([
    "../private",
    "/absolute",
    "https://example.invalid",
    "a?b",
    "a\\b",
    "-starts-with-dash",
    "a b",
    "é",
    "00000000-0000-0000-8000-000000000001",
    "00000000-0000-4000-7000-000000000001",
    "00000000-0000-4000-8000-00000000000A",
  ])("rejects unsafe or noncanonical asset-id %j", (assetId) => {
    expect(() => validateAssetId(assetId)).toThrow(CliUsageError);
  });

  it("accepts the canonical lowercase UUID", () => {
    expect(validateAssetId(ASSET_ID)).toBe(ASSET_ID);
  });

  it("keeps flags after the required positional asset identifier", () => {
    expect(() => parseCliArgs(["verify", "--require-active", ASSET_ID])).toThrow(CliUsageError);
  });
});
