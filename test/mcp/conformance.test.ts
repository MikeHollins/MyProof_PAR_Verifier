import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { VerifyProofAssetRecord } from "../../src/contracts/index.js";
import { canonicalReport } from "../harness/mcp/canonical-report.js";
import { startConformanceLoopbackServer } from "../harness/mcp/loopback-http.js";

const execFileAsync = promisify(execFile);
const CONFORMANCE_TIMEOUT_MS = 30_000;
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const CONFORMANCE_ENTRY = resolve(
  PACKAGE_ROOT,
  "node_modules/@modelcontextprotocol/conformance/dist/index.js",
);
const EXPECTED_SERVER_CATALOG = `Server scenarios (test against a server):
  - server-initialize [2025-06-18,2025-11-25]
  - logging-set-level [2025-06-18,2025-11-25]
  - ping [2025-06-18,2025-11-25]
  - completion-complete [2025-06-18,2025-11-25]
  - tools-list [2025-06-18,2025-11-25]
  - tools-call-simple-text [2025-06-18,2025-11-25]
  - tools-call-image [2025-06-18,2025-11-25]
  - tools-call-audio [2025-06-18,2025-11-25]
  - tools-call-embedded-resource [2025-06-18,2025-11-25]
  - tools-call-mixed-content [2025-06-18,2025-11-25]
  - tools-call-with-logging [2025-06-18,2025-11-25]
  - tools-call-error [2025-06-18,2025-11-25]
  - tools-call-with-progress [2025-06-18,2025-11-25]
  - tools-call-sampling [2025-06-18,2025-11-25]
  - tools-call-elicitation [2025-06-18,2025-11-25]
  - json-schema-2020-12 [2025-11-25]
  - elicitation-sep1034-defaults [2025-11-25]
  - server-sse-polling [2025-11-25]
  - server-sse-multiple-streams [2025-11-25]
  - elicitation-sep1330-enums [2025-11-25]
  - resources-list [2025-06-18,2025-11-25]
  - resources-read-text [2025-06-18,2025-11-25]
  - resources-read-binary [2025-06-18,2025-11-25]
  - resources-templates-read [2025-06-18,2025-11-25]
  - resources-subscribe [2025-06-18,2025-11-25]
  - resources-unsubscribe [2025-06-18,2025-11-25]
  - prompts-list [2025-06-18,2025-11-25]
  - prompts-get-simple [2025-06-18,2025-11-25]
  - prompts-get-with-args [2025-06-18,2025-11-25]
  - prompts-get-embedded-resource [2025-06-18,2025-11-25]
  - prompts-get-with-image [2025-06-18,2025-11-25]
  - dns-rebinding-protection [2025-11-25]
`;

describe("official MCP conformance through test-only loopback HTTP", () => {
  it("passes every applicable pinned 2025-11-25 server scenario and records intentional exclusions", async () => {
    const version = await execFileAsync(process.execPath, [CONFORMANCE_ENTRY, "--version"], {
      cwd: PACKAGE_ROOT,
      maxBuffer: 20 * 1024 * 1024,
      timeout: CONFORMANCE_TIMEOUT_MS,
      killSignal: "SIGTERM",
    });
    expect(version.stdout.trim()).toBe("0.1.16");
    const listed = await execFileAsync(
      process.execPath,
      [CONFORMANCE_ENTRY, "list", "--server", "--spec-version", "2025-11-25"],
      {
        cwd: PACKAGE_ROOT,
        maxBuffer: 20 * 1024 * 1024,
        timeout: CONFORMANCE_TIMEOUT_MS,
        killSignal: "SIGTERM",
      },
    );
    // Exact pinned discovery evidence. The runner exposes the full scenario
    // catalog; only the three below apply to this deliberately one-tool,
    // text-only, stdio-only server. The JSON-schema scenario requires a
    // second tool named `json_schema_2020_12_tool`, which would violate the
    // product's one-tool contract, so it is explicitly non-applicable rather
    // than an expected-failure baseline. Resources/prompts/media/sampling/
    // elicitation/SSE scenarios likewise require capabilities intentionally
    // absent from the production surface. No scenario failure is suppressed.
    expect(listed.stdout).toBe(EXPECTED_SERVER_CATALOG);

    const verifier: VerifyProofAssetRecord = async (input) =>
      canonicalReport({ assetId: input.asset_id });
    const server = await startConformanceLoopbackServer(verifier);
    const outputDir = await mkdtemp(join(tmpdir(), "myproof-par-conformance-"));
    try {
      const applicableScenarios = ["server-initialize", "ping", "tools-list"] as const;
      for (const scenario of applicableScenarios) {
        const result = await execFileAsync(
          process.execPath,
          [
            CONFORMANCE_ENTRY,
            "server",
            "--url",
            server.url,
            "--scenario",
            scenario,
            "--spec-version",
            "2025-11-25",
            "--output-dir",
            outputDir,
            "--verbose",
          ],
          {
            cwd: PACKAGE_ROOT,
            maxBuffer: 20 * 1024 * 1024,
            timeout: CONFORMANCE_TIMEOUT_MS,
            killSignal: "SIGTERM",
          },
        );
        expect(`${result.stdout}\n${result.stderr}`).not.toContain("FAILURE");
        expect(result.stdout).toMatch(/Passed:\s*1\/1,\s*0 failed/);
      }
    } finally {
      await server.close();
      await rm(outputDir, { recursive: true, force: true });
    }
  }, 120_000);
});
