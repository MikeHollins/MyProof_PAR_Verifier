import type { VerifyProofAssetInput } from "./input.js";
import type { PublicRecordCoherenceReport } from "./report.js";

/** Optional transport cancellation; it is never serialized into a report. */
export interface VerifyProofAssetOptions {
  readonly signal?: AbortSignal;
}

/**
 * The one domain-to-adapter function boundary. CLI and MCP may differ in
 * transport, but both call this exact operation and receive the same parsed
 * report type. No object-method or alternate request shape is accepted.
 */
export type VerifyProofAssetRecord = (
  input: VerifyProofAssetInput,
  options?: VerifyProofAssetOptions,
) => Promise<PublicRecordCoherenceReport>;
