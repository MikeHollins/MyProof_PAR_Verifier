import { runMcpStdio } from "../mcp/stdio.js";
import { verifyProofAssetRecord } from "../service/verify-proof-asset-record.js";
import type { CliDependencies, RunMcp, VerifyAsset } from "./types.js";

/**
 * Bind the CLI to the one shared service facade. There is deliberately no
 * dynamic module probing or alternate call signature: a broken package build
 * must fail as an internal error instead of silently selecting another
 * verifier implementation.
 */
export function createDefaultCliDependencies(): CliDependencies {
  const verifyAsset: VerifyAsset = verifyProofAssetRecord;
  const runMcp: RunMcp = async (signal) => {
    await runMcpStdio(verifyProofAssetRecord, signal === undefined ? {} : { signal });
  };
  return { verifyProofAssetRecord: verifyAsset, runMcp };
}
