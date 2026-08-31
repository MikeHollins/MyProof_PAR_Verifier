import {
  PublicRecordCoherenceReportSchema,
  parseVerifyProofAssetInput,
  type PublicRecordCoherenceReport,
  type VerifyProofAssetInput,
} from "../contracts/index.js";
import { verifyEvidence, unavailableReport } from "../core/verify.js";
import type { CoreTrustMaterial } from "../core/evidence.js";
import {
  createParPublicProvider,
  ParProviderError,
  type ParPublicProvider,
} from "../provider/index.js";
import { defaultTrustMaterial } from "../config/trust.js";

/** The smallest production dependency surface; callers cannot replace it. */
export interface VerifierServiceDependencies {
  readonly provider: Pick<ParPublicProvider, "fetchPublicRecordEvidence">;
  readonly trust: CoreTrustMaterial;
  readonly nowMs: () => number;
}

type ServiceFunction = (
  input: VerifyProofAssetInput,
  options?: { readonly signal?: AbortSignal },
) => Promise<PublicRecordCoherenceReport>;

function unavailableReason(
  error: ParProviderError,
):
  | "PUBLIC_RECORD_UNAVAILABLE"
  | "PUBLIC_RECORD_MALFORMED"
  | "NETWORK_ABORTED"
  | "NETWORK_TIMEOUT"
  | "NETWORK_RESPONSE_TOO_LARGE"
  | "NETWORK_REDIRECT_REJECTED"
  | "NETWORK_ORIGIN_REJECTED"
  | "NETWORK_CONTENT_TYPE_INVALID" {
  switch (error.code) {
    case "ABORTED":
      return "NETWORK_ABORTED";
    case "TIMEOUT":
      return "NETWORK_TIMEOUT";
    case "BODY_TOO_LARGE":
      return "NETWORK_RESPONSE_TOO_LARGE";
    case "REDIRECT_REJECTED":
      return "NETWORK_REDIRECT_REJECTED";
    case "UNSAFE_URL":
      return "NETWORK_ORIGIN_REJECTED";
    case "CONTENT_TYPE_MISMATCH":
    case "CONTENT_ENCODING_UNSUPPORTED":
      return "NETWORK_CONTENT_TYPE_INVALID";
    case "INVALID_RESPONSE":
    case "INVALID_JSON":
    case "INVALID_TEXT":
      return "PUBLIC_RECORD_MALFORMED";
    default:
      return "PUBLIC_RECORD_UNAVAILABLE";
  }
}

// Keep one provider in the production process so its semaphore bounds the
// aggregate concurrency of all facade calls. Test callers still use the
// explicit dependency factory below and retain isolated provider injection.
const productionDependencies: VerifierServiceDependencies = {
  provider: createParPublicProvider(),
  trust: defaultTrustMaterial,
  nowMs: () => Date.now(),
};

function createService(dependencies: VerifierServiceDependencies): ServiceFunction {
  return async (rawInput, options = {}) => {
    const input = parseVerifyProofAssetInput(rawInput);
    const nowMs = dependencies.nowMs();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("INTERNAL_INVARIANT_FAILURE");
    if (options.signal?.aborted)
      throw options.signal.reason ?? new DOMException("The operation was aborted", "AbortError");
    try {
      const evidence = await dependencies.provider.fetchPublicRecordEvidence(
        input.asset_id,
        options.signal,
      );
      if (options.signal?.aborted)
        throw options.signal.reason ?? new DOMException("The operation was aborted", "AbortError");
      return PublicRecordCoherenceReportSchema.parse(
        verifyEvidence(input, evidence, dependencies.trust, nowMs),
      );
    } catch (error) {
      // Caller cancellation remains a cancellation (CLI maps it to its
      // cancellation result); provider/public-record failures are canonical
      // verifier outcomes so CLI and MCP cannot diverge.
      if (options.signal?.aborted) throw error;
      if (error instanceof ParProviderError)
        return unavailableReport(input, nowMs, unavailableReason(error));
      throw error;
    }
  };
}

/**
 * The sole production verification facade. Input is only an asset id and the
 * active-status policy; provider URLs, evidence, and trust material are not
 * caller-selectable.
 */
export async function verifyProofAssetRecord(
  input: VerifyProofAssetInput,
  options: { readonly signal?: AbortSignal } = {},
): Promise<PublicRecordCoherenceReport> {
  return createService(productionDependencies)(input, options);
}

/** Test-only factory; production adapters import only verifyProofAssetRecord. */
export function createVerifierServiceForTests(
  dependencies: VerifierServiceDependencies,
): ServiceFunction {
  return createService(dependencies);
}
