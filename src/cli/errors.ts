import { EXIT_CODES, type CliExitCode } from "./exit-codes.js";

/** An error that can safely be shown to a caller without exposing upstream data. */
export class CliSafeError extends Error {
  readonly exitCode: CliExitCode;
  readonly safeCode: string;
  readonly safeMessage: string;

  constructor(exitCode: CliExitCode, safeCode: string, safeMessage: string) {
    super(safeMessage);
    this.name = "CliSafeError";
    this.exitCode = exitCode;
    this.safeCode = safeCode;
    this.safeMessage = safeMessage;
  }
}

export class CliUsageError extends CliSafeError {
  constructor(message: string) {
    super(EXIT_CODES.USAGE, "CLI_USAGE", message);
    this.name = "CliUsageError";
  }
}

export class CliInvariantError extends CliSafeError {
  constructor(message = "the verifier returned an invalid canonical report") {
    // The detail is intentionally stable and does not include an upstream
    // message, identifier, token, or stack trace.
    super(EXIT_CODES.INTERNAL, "CLI_INVARIANT", message);
    this.name = "CliInvariantError";
  }
}

export class CliCancelledError extends CliSafeError {
  constructor() {
    super(
      EXIT_CODES.INDETERMINATE,
      "CLI_CANCELLED",
      "verification was cancelled before it completed",
    );
    this.name = "CliCancelledError";
  }
}

export function isAbortLike(error: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  if (!error || typeof error !== "object") return false;

  const candidate = error as { name?: unknown; code?: unknown };
  return candidate.name === "AbortError" || candidate.code === "ABORT_ERR";
}

/**
 * Map all non-contract exceptions to a short, non-sensitive diagnostic. Never
 * pass an upstream error message through: provider responses can contain URLs,
 * response bodies, credentials, or arbitrary remote text. The service facade
 * converts known provider/public-record failures into canonical INDETERMINATE
 * reports; a thrown verification exception therefore indicates an internal
 * implementation failure and must not be mislabeled as a domain outcome.
 */
export function safeFailure(
  error: unknown,
  phase: "verification" | "mcp",
  signal?: AbortSignal,
): CliSafeError {
  if (isAbortLike(error, signal)) return new CliCancelledError();

  if (phase === "mcp") {
    return new CliSafeError(
      EXIT_CODES.INTERNAL,
      "MCP_FAILURE",
      "the local MCP server could not start or stopped unexpectedly",
    );
  }

  return new CliSafeError(
    EXIT_CODES.INTERNAL,
    "VERIFIER_FAILURE",
    "the verifier failed internally",
  );
}
