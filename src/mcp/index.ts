/**
 * The sole MyProof PAR MCP adapter.
 *
 * This module is deliberately an adapter, not a second verifier. The
 * provider and deterministic core are owned by the shared service facade;
 * this file only validates the MCP boundary, forwards request cancellation,
 * and serializes the already-classified report.
 */

import {
  fromJsonSchema,
  McpServer,
  type JsonSchemaType,
  type ServerContext,
  type StandardSchemaWithJSON,
} from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { readFileSync } from "node:fs";
import type { Readable, Writable } from "node:stream";
import {
  VerifyProofAssetInputSchema,
  parsePublicRecordCoherenceReportForInput,
  serializePublicRecordCoherenceReport,
} from "../contracts/index.js";
import type { PublicRecordCoherenceReport, VerifyProofAssetInput } from "../contracts/index.js";
import { MAX_REPORT_BYTES, MAX_STDIO_MESSAGE_BYTES } from "../contracts/constants.js";
import type { VerifyProofAssetRecord as SharedVerifyProofAssetRecord } from "../contracts/facade.js";

export const MCP_SERVER_NAME = "myproof-par-verifier" as const;
export const MCP_TOOL_NAME = "verify_proof_asset_record" as const;

/** The shared report and stdio budgets are re-exported for adapter evidence. */
export const MCP_MAX_REPORT_BYTES = MAX_REPORT_BYTES;
/**
 * Result-envelope budget derived from the one shared report cap. The MCP
 * result contains the report twice (text plus structured content); the
 * framing margin also covers JSON string escaping and the JSON-RPC envelope.
 * This is an envelope budget, not a second report limit.
 */
export const MCP_MAX_RESULT_BYTES = MAX_REPORT_BYTES * 2 + 16_384;
export const MCP_MAX_STDIO_MESSAGE_BYTES = MAX_STDIO_MESSAGE_BYTES;
export const MCP_MAX_REQUEST_ID_BYTES = 512;

/**
 * The generated contract documents are the one wire-schema authority.  The
 * SDK's Zod conversion intentionally only understands representable Zod
 * constraints; it cannot retain the cross-field/tuple refinements that the
 * contract generator materializes in JSON Schema.  Wrap the generated
 * documents with the SDK-native `fromJsonSchema` path so tools/list exposes
 * exactly those constraints.  The handler still parses with the shared Zod
 * schema and the shared input-aware report parser before invoking/serializing
 * the verifier, so generated-schema validation does not become an adapter
 * fallback or a second verifier.
 */
const verifyProofAssetRecordInputSchema: StandardSchemaWithJSON<VerifyProofAssetInput> =
  fromJsonSchema<VerifyProofAssetInput>(
    readGeneratedSchema("myproof.par.public-record-input.v1.json"),
  );
const verifyProofAssetRecordOutputSchema: StandardSchemaWithJSON<PublicRecordCoherenceReport> =
  fromJsonSchema<PublicRecordCoherenceReport>(
    readGeneratedSchema("myproof.par.public-record-coherence.v1.json"),
  );

export { verifyProofAssetRecordOutputSchema };

export interface McpServerOptions {
  /** Version reported by initialize/discovery. */
  readonly version?: string;
  /** Diagnostic sink; never use the MCP protocol stdout for diagnostics. */
  readonly stderr?: Writable;
  /** Maximum complete JSON-RPC message accepted/emitted by this adapter. */
  readonly maxMessageBytes?: number;
}

export interface McpStdioOptions extends McpServerOptions {
  readonly stdin?: Readable;
  readonly stdout?: Writable;
  /** Process-level cancellation used by the CLI wrapper. */
  readonly signal?: AbortSignal | undefined;
}

/**
 * Build the one-tool server. Input and output are the exact shared contract
 * objects; no adapter-local fallback or passthrough schema exists. The
 * server has no resource or prompt registrations.
 */
export function createMcpServer(
  verifier: SharedVerifyProofAssetRecord,
  options: McpServerOptions = {},
): McpServer {
  const server = new McpServer(
    { name: MCP_SERVER_NAME, version: options.version ?? "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    MCP_TOOL_NAME,
    {
      title: "Verify MyProof PAR record",
      description:
        "Verify the coherence and public cryptographic bindings of one MyProof PAR record. " +
        "This is read-only evidence inspection: it never reruns the underlying proof, " +
        "authenticates a presenter, or makes a merchant acceptance decision.",
      annotations: {
        title: "Verify MyProof PAR record",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        // Verification performs bounded read-only GETs against the canonical
        // external PAR registry, so its domain is open-world under MCP's
        // annotation semantics even though the origin and paths are fixed.
        openWorldHint: true,
      },
      inputSchema: verifyProofAssetRecordInputSchema,
      outputSchema: verifyProofAssetRecordOutputSchema,
    },
    async (rawInput, context: ServerContext) =>
      // The SDK callback receives the schema's caller-facing input type (where
      // require_active is optional). Parse through the same shared schema once
      // more to materialize its canonical default before crossing the exact
      // normalized service facade; no adapter alias or alternate shape exists.
      handleToolCall(verifier, normalizeInput(rawInput), context, options),
  );

  return server;
}

/**
 * Run the official SDK stdio entry point and own process lifecycle.
 * `serveStdio` handles 2025/2026 negotiation and protocol cancellation;
 * this wrapper handles only stream/process shutdown and diagnostics.
 */
export async function runMcpStdio(
  verifier: SharedVerifyProofAssetRecord,
  options: McpStdioOptions = {},
): Promise<void> {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const maxMessageBytes = options.maxMessageBytes ?? MCP_MAX_STDIO_MESSAGE_BYTES;

  assertBoundedMessageSize(maxMessageBytes);

  let finished = false;
  let closing = false;
  let handle: { close(): Promise<void> } | undefined;
  let resolveLifecycle: (() => void) | undefined;
  let rejectLifecycle: ((error: unknown) => void) | undefined;

  const lifecycle = new Promise<void>((resolve, reject) => {
    resolveLifecycle = resolve;
    rejectLifecycle = reject;
  });

  const finish = (error?: unknown): void => {
    if (finished) return;
    finished = true;
    if (error !== undefined) rejectLifecycle?.(error);
    else resolveLifecycle?.();
  };

  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    try {
      await handle?.close();
      finish();
    } catch {
      // Keep shutdown diagnostics out of the protocol stream and avoid
      // leaking transport implementation details to a host.
      finish(new Error("MCP server shutdown failed"));
    }
  };

  const onSignal = (): void => {
    void close();
  };
  const onEnd = (): void => {
    void close();
  };
  const onExternalAbort = (): void => {
    void close();
  };

  stdin.once("end", onEnd);
  stdin.once("close", onEnd);
  options.signal?.addEventListener("abort", onExternalAbort, { once: true });
  if (stdin.readableEnded || stdin.destroyed || options.signal?.aborted) {
    void close();
  }

  // Test-created streams must not install process-global listeners. The
  // shipped CLI uses the real process streams and gets signal shutdown.
  const ownsProcessStreams = stdin === process.stdin && stdout === process.stdout;
  if (ownsProcessStreams) {
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
  }

  try {
    const transport = new StdioServerTransport(stdin, stdout, { maxBufferSize: maxMessageBytes });
    transport.onclose = onEnd;
    transport.onerror = (error) => writeDiagnostic(stderr, error);

    try {
      handle = serveStdio(() => createMcpServer(verifier, { ...options, maxMessageBytes }), {
        transport,
        // Keep 2025 compatibility; modern Inspector/conformance clients
        // still negotiate the current SDK era on the same factory.
        legacy: "serve",
        onerror: (error) => writeDiagnostic(stderr, error),
      });
    } catch (error) {
      finish(new Error("MCP server failed to start"));
      throw new Error("MCP server failed to start", { cause: error });
    }

    // EOF/abort may race with serveStdio construction. Close the newly
    // created handle before awaiting the lifecycle promise in that case.
    if (closing) await handle.close();
    await lifecycle;
  } finally {
    stdin.removeListener("end", onEnd);
    stdin.removeListener("close", onEnd);
    options.signal?.removeEventListener("abort", onExternalAbort);
    if (ownsProcessStreams) {
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
    }
    if (!finished) {
      try {
        await handle?.close();
      } catch {
        // A best-effort final close must not replace the original failure.
      }
      finish();
    }
  }
}

async function handleToolCall(
  verifier: SharedVerifyProofAssetRecord,
  input: VerifyProofAssetInput,
  context: ServerContext,
  options: McpServerOptions,
): Promise<{
  content: [{ type: "text"; text: string }];
  structuredContent: PublicRecordCoherenceReport;
  isError: false;
}> {
  const signal = context.mcpReq.signal;
  if (signal.aborted) throw abortError();

  let report: PublicRecordCoherenceReport;
  try {
    report = await verifier(input, { signal });
    if (signal.aborted) throw abortError();
    // Parse and bind through the same shared helper used by the CLI. The
    // parsed value is used for both result representations.
    report = parsePublicRecordCoherenceReportForInput(report, input);
    if (signal.aborted) throw abortError();
  } catch (error) {
    if (isAbortError(error) || signal.aborted) throw abortError();
    // Domain outcomes are reports, not exceptions. Any exception here is a
    // service invariant failure; expose only a stable protocol-safe message.
    writeDiagnostic(options.stderr, error);
    throw new Error("Verifier invariant failure", { cause: error });
  }

  try {
    return makeBoundedToolResult(report, context.mcpReq.id, options.maxMessageBytes);
  } catch (error) {
    writeDiagnostic(options.stderr, error);
    throw new Error("Verifier invariant failure", { cause: error });
  }
}

function normalizeInput(rawInput: unknown): VerifyProofAssetInput {
  const parsed = VerifyProofAssetInputSchema.parse(rawInput);
  return {
    asset_id: parsed.asset_id,
    require_active: parsed.require_active ?? false,
  };
}

function makeBoundedToolResult(
  report: PublicRecordCoherenceReport,
  requestId: unknown,
  maxMessageBytes: number = MCP_MAX_STDIO_MESSAGE_BYTES,
): {
  content: [{ type: "text"; text: string }];
  structuredContent: PublicRecordCoherenceReport;
  isError: false;
} {
  assertBoundedMessageSize(maxMessageBytes);
  // The shared serializer re-parses against the advertised schema and owns
  // the canonical report byte bound used by CLI and every other adapter.
  const serialized = serializePublicRecordCoherenceReport(report);

  const result: {
    content: [{ type: "text"; text: string }];
    structuredContent: PublicRecordCoherenceReport;
    isError: false;
  } = {
    content: [{ type: "text", text: serialized }],
    structuredContent: report,
    isError: false,
  };
  const resultBytes = byteLength(safeJsonStringify(result));
  if (resultBytes > MCP_MAX_RESULT_BYTES) {
    throw new Error("MCP tool result exceeds the output budget");
  }

  // The SDK echoes the request id. Reject an unbounded id so a valid call
  // cannot bypass the complete stdio-message budget through that duplication.
  if (typeof requestId === "string" && byteLength(requestId) > MCP_MAX_REQUEST_ID_BYTES) {
    throw new Error("MCP request identifier exceeds the output budget");
  }
  if (
    (typeof requestId === "number" && !Number.isSafeInteger(requestId)) ||
    (typeof requestId !== "string" && typeof requestId !== "number")
  ) {
    throw new Error("MCP request identifier is invalid");
  }
  // The generated report schema has an explicit object root, so both the
  // legacy and modern SDK codecs preserve the same direct structured result.
  const responseEnvelope = {
    jsonrpc: "2.0",
    id: requestId,
    result,
  };
  // StdioServerTransport frames JSON with one trailing LF; include that
  // delimiter in the complete wire-message budget.
  if (byteLength(safeJsonStringify(responseEnvelope)) + 1 > maxMessageBytes) {
    throw new Error("MCP response exceeds the stdio message budget");
  }

  return result;
}

function assertBoundedMessageSize(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0 || value > MCP_MAX_STDIO_MESSAGE_BYTES) {
    throw new RangeError("maxMessageBytes must be a positive bounded integer");
  }
}

function safeJsonStringify(value: unknown): string {
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string") throw new Error("not JSON");
    return serialized;
  } catch {
    throw new Error("Verifier returned a non-serializable report");
  }
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function abortError(): Error {
  const error = new Error("MCP request cancelled");
  error.name = "AbortError";
  return error;
}

function isAbortError(error: unknown): boolean {
  return (
    isRecord(error) &&
    (error.name === "AbortError" || error.name === "CanceledError" || error.code === "ABORT_ERR")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readGeneratedSchema(fileName: string): JsonSchemaType {
  // Resolve relative to this module, not process.cwd(). The package includes
  // `schemas/`, so this remains valid for an empty consumer launched from any
  // directory as well as for tsx/Vitest source execution.
  const schemaUrl = new URL(`../../schemas/${fileName}`, import.meta.url);
  const parsed: unknown = JSON.parse(readFileSync(schemaUrl, "utf8"));
  if (
    !isRecord(parsed) ||
    typeof parsed.$schema !== "string" ||
    parsed.type !== "object" ||
    typeof parsed.$ref !== "string"
  ) {
    throw new Error(`invalid generated schema: ${fileName}`);
  }
  return parsed as JsonSchemaType;
}

function writeDiagnostic(stderr: Writable | undefined, error: unknown): void {
  void error;
  if (!stderr || typeof stderr.write !== "function") return;
  try {
    stderr.write("[myproof-par] internal MCP error\n");
  } catch {
    // Diagnostics are best effort and can never affect the MCP wire stream.
  }
}
