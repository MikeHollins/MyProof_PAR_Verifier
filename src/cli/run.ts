import { exitCodeForReport } from "./classify.js";
import { createDefaultCliDependencies } from "./dependencies.js";
import {
  CliCancelledError,
  CliInvariantError,
  CliUsageError,
  isAbortLike,
  safeFailure,
} from "./errors.js";
import type { CliSafeError } from "./errors.js";
import { formatHumanReport, formatJsonReport, formatSafeError } from "./format.js";
import { CLI_HELP, parseCliArgs } from "./parse.js";
import type { CanonicalReport, CliDependencies, CliStreams, OutputSink } from "./types.js";
import { parsePublicRecordCoherenceReportForInput } from "../contracts/index.js";

export interface CliRunOptions {
  readonly dependencies?: CliDependencies;
  readonly streams?: CliStreams;
  readonly signal?: AbortSignal;
  readonly processSignals?: boolean;
  readonly processLike?: SignalProcess;
}

export interface SignalProcess {
  on(event: "SIGINT" | "SIGTERM", listener: () => void): void;
  removeListener(event: "SIGINT" | "SIGTERM", listener: () => void): void;
}

const defaultSink: OutputSink = {
  write(chunk: string): void {
    process.stdout.write(chunk);
  },
};

const defaultErrorSink: OutputSink = {
  write(chunk: string): void {
    process.stderr.write(chunk);
  },
};

function writeError(streams: CliStreams, error: CliSafeError, json: boolean): void {
  streams.stderr.write(formatSafeError(error, json));
}

function wantsJsonDiagnostics(argv: readonly string[]): boolean {
  // `--json` belongs only to the verify operation. Treating an invalid
  // `mcp --json` invocation as a JSON verify failure would blur the two
  // command surfaces and make protocol-launch errors surprising to callers.
  return Array.isArray(argv) && argv[0] === "verify" && argv.includes("--json");
}

function installCancellation(
  controller: AbortController,
  external: AbortSignal | undefined,
  processLike: SignalProcess | undefined,
): () => void {
  const onExternalAbort = (): void => controller.abort();
  const onSignal = (): void => controller.abort();

  if (external) {
    if (external.aborted) controller.abort();
    else external.addEventListener("abort", onExternalAbort, { once: true });
  }
  if (processLike) {
    processLike.on("SIGINT", onSignal);
    processLike.on("SIGTERM", onSignal);
  }

  return () => {
    external?.removeEventListener("abort", onExternalAbort);
    if (processLike) {
      processLike.removeListener("SIGINT", onSignal);
      processLike.removeListener("SIGTERM", onSignal);
    }
  };
}

function processSignalsDefault(): SignalProcess | undefined {
  // `process` is available in the shipped Node CLI; keeping this in a helper
  // makes unit tests independent of actual process signal listeners.
  return process as unknown as SignalProcess;
}

export async function runCli(
  argv: readonly string[],
  options: CliRunOptions = {},
): Promise<number> {
  const streams = options.streams ?? { stdout: defaultSink, stderr: defaultErrorSink };
  let invocation;
  try {
    invocation = parseCliArgs(argv);
  } catch (error) {
    const safe = error instanceof CliUsageError ? error : new CliUsageError("invalid command line");
    writeError(streams, safe, wantsJsonDiagnostics(argv));
    return safe.exitCode;
  }

  if (invocation.kind === "help") {
    streams.stdout.write(`${CLI_HELP}\n`);
    return 0;
  }

  const controller = new AbortController();
  const removeCancellation = installCancellation(
    controller,
    options.signal,
    options.processSignals === false ? undefined : (options.processLike ?? processSignalsDefault()),
  );

  try {
    if (controller.signal.aborted) throw new CliCancelledError();
    const dependencies = options.dependencies ?? createDefaultCliDependencies();
    if (invocation.kind === "mcp") {
      await dependencies.runMcp(controller.signal);
      if (controller.signal.aborted) throw new CliCancelledError();
      return 0;
    }

    const input = { asset_id: invocation.assetId, require_active: invocation.requireActive };
    const rawReport = await dependencies.verifyProofAssetRecord(input, {
      signal: controller.signal,
    });
    if (controller.signal.aborted) throw new CliCancelledError();
    let report: CanonicalReport;
    try {
      report = parsePublicRecordCoherenceReportForInput(rawReport, input);
    } catch {
      throw new CliInvariantError();
    }

    if (invocation.json) streams.stdout.write(formatJsonReport(report));
    else streams.stdout.write(formatHumanReport(report, invocation.assetId));
    return exitCodeForReport(report, invocation.requireActive);
  } catch (error) {
    const phase = invocation.kind === "mcp" ? "mcp" : "verification";
    const safe =
      error instanceof CliCancelledError || error instanceof CliInvariantError
        ? error
        : isAbortLike(error, controller.signal)
          ? new CliCancelledError()
          : safeFailure(error, phase, controller.signal);
    writeError(streams, safe, invocation.kind === "verify" && invocation.json);
    return safe.exitCode;
  } finally {
    removeCancellation();
  }
}
