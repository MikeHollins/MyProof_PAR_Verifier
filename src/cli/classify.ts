import { CliInvariantError } from "./errors.js";
import { EXIT_CODES, type CliExitCode } from "./exit-codes.js";
import type { CanonicalReport } from "./types.js";
import { parsePublicRecordCoherenceReport } from "../contracts/index.js";

/** Parse through the shared contract; the CLI owns no second report schema. */
export function parseCanonicalReport(value: unknown): CanonicalReport {
  try {
    return parsePublicRecordCoherenceReport(value);
  } catch {
    // Do not expose Zod paths or remote text as process diagnostics.
    throw new CliInvariantError();
  }
}

export function assertCanonicalReport(value: unknown): asserts value is CanonicalReport {
  parseCanonicalReport(value);
}

export function exitCodeForReport(report: CanonicalReport, requireActive: boolean): CliExitCode {
  switch (report.record_coherence) {
    case "CONTRADICTORY":
      return EXIT_CODES.CONTRADICTORY;
    case "INDETERMINATE":
      return EXIT_CODES.INDETERMINATE;
    case "COHERENT":
      break;
    default:
      throw new CliInvariantError();
  }

  if (!requireActive) return EXIT_CODES.SUCCESS;
  switch (report.registry_active_condition) {
    case "SATISFIED":
      return EXIT_CODES.SUCCESS;
    case "NOT_SATISFIED":
      return EXIT_CODES.INACTIVE;
    case "NOT_REQUESTED":
    case "INDETERMINATE":
      return EXIT_CODES.INDETERMINATE;
    default:
      throw new CliInvariantError();
  }
}
