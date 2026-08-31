/**
 * Test-only stdio lifecycle harness. It exercises the production adapter
 * with the same canonical report factory used by the in-memory and
 * conformance tests. Packaged tests launch the real shared service instead.
 */

import { runMcpStdio } from "../../../src/mcp/index.js";
import type { VerifyProofAssetRecord } from "../../../src/contracts/index.js";
import { canonicalReport } from "./canonical-report.js";

const fixtureVerifier: VerifyProofAssetRecord = async (input, options) => {
  const signal = options?.signal;
  if (!signal) throw new Error("missing cancellation signal");
  if (signal.aborted) {
    const error = new Error("cancelled");
    error.name = "AbortError";
    throw error;
  }

  if (process.env.MCP_TEST_DELAY === "1" && !delayedOnce) {
    delayedOnce = true;
    process.stderr.write("[mcp-test] verifier-started\n");
    await new Promise<void>((resolve) => {
      if (signal.aborted) return resolve();
      signal.addEventListener(
        "abort",
        () => {
          process.stderr.write("[mcp-test] verifier-aborted\n");
          resolve();
        },
        { once: true },
      );
    });
    const error = new Error("cancelled");
    error.name = "AbortError";
    throw error;
  }

  const outcome = process.env.MCP_TEST_OUTCOME;
  return canonicalReport({
    assetId: input.asset_id,
    requireActive: input.require_active,
    outcome:
      outcome === "coherent-inactive" || outcome === "contradictory" || outcome === "indeterminate"
        ? outcome
        : "coherent-active",
  });
};

let delayedOnce = false;

await runMcpStdio(fixtureVerifier);
