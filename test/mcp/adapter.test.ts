import { PassThrough } from "node:stream";
import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import {
  MCP_MAX_REPORT_BYTES,
  MCP_MAX_RESULT_BYTES,
  MCP_MAX_STDIO_MESSAGE_BYTES,
  MCP_TOOL_NAME,
  createMcpServer,
  verifyProofAssetRecordOutputSchema,
} from "../../src/mcp/index.js";
import {
  PublicRecordCoherenceReportSchema,
  VerifyProofAssetInputSchema,
} from "../../src/contracts/index.js";
import type {
  PublicRecordCoherenceReport,
  VerifyProofAssetRecord,
} from "../../src/contracts/index.js";
import { MCP_FIXTURE_ASSET_ID, canonicalReport } from "../harness/mcp/canonical-report.js";
import { InMemoryMcpPeer } from "../harness/mcp/in-memory-peer.js";

const ASSET_ID = MCP_FIXTURE_ASSET_ID;

const canonicalInputSchema = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-input.v1.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;
const canonicalReportSchema = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-coherence.v1.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;

const report = (options: Parameters<typeof canonicalReport>[0] = {}): PublicRecordCoherenceReport =>
  canonicalReport(options);

async function connected(
  verifier: VerifyProofAssetRecord,
  options: { stderr?: PassThrough; maxMessageBytes?: number } = {},
): Promise<InMemoryMcpPeer> {
  return InMemoryMcpPeer.connect(createMcpServer(verifier, options));
}

async function initialize(peer: InMemoryMcpPeer): Promise<void> {
  const response = await peer.request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "mcp-adapter-test", version: "0.1.0" },
  }).response;
  expect(response.error).toBeUndefined();
  peer.notify("notifications/initialized");
}

function structuredReport(result: Record<string, unknown>): unknown {
  return result.structuredContent;
}

function findSchemaWithRequired(
  value: unknown,
  required: string[],
): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const object = value as Record<string, unknown>;
  const requiredFields = Array.isArray(object.required) ? object.required : [];
  if (requiredFields.length > 0 && required.every((field) => requiredFields.includes(field))) {
    return object;
  }
  for (const child of Object.values(object)) {
    const found = findSchemaWithRequired(child, required);
    if (found) return found;
  }
  return undefined;
}

function resolveLocalDefinition(
  document: Record<string, unknown>,
  ref: unknown,
): Record<string, unknown> | undefined {
  if (typeof ref !== "string" || !ref.startsWith("#/$defs/")) return undefined;
  const defs = document.$defs;
  if (!defs || typeof defs !== "object" || Array.isArray(defs)) return undefined;
  const definition = (defs as Record<string, unknown>)[ref.slice("#/$defs/".length)];
  if (!definition || typeof definition !== "object" || Array.isArray(definition)) return undefined;
  return definition as Record<string, unknown>;
}

function mutableReportCopy(value: PublicRecordCoherenceReport): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function reportChecks(value: Record<string, unknown>): Array<Record<string, unknown>> {
  if (!Array.isArray(value.checks)) throw new Error("fixture has no checks");
  return value.checks as Array<Record<string, unknown>>;
}

function expectToolError(response: Record<string, unknown>): void {
  expect(response.error).toBeUndefined();
  expect((response.result as Record<string, unknown> | undefined)?.isError).toBe(true);
  expect(
    (response.result as Record<string, unknown> | undefined)?.structuredContent,
  ).toBeUndefined();
}

describe("MyProof PAR MCP adapter", () => {
  it("advertises exactly one read-only tool and no resources or prompts", async () => {
    const peer = await connected(async () => report());
    try {
      await initialize(peer);
      const tools = await peer.request("tools/list").response;
      const listed = tools.result as {
        tools?: Array<{
          name?: string;
          annotations?: Record<string, unknown>;
          inputSchema?: Record<string, unknown>;
          outputSchema?: Record<string, unknown>;
        }>;
      };
      expect(listed.tools).toHaveLength(1);
      expect(listed.tools?.[0]?.name).toBe(MCP_TOOL_NAME);
      expect(listed.tools?.[0]?.annotations).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      });
      const inputSchema = listed.tools?.[0]?.inputSchema as {
        type?: string;
        $ref?: string;
        $defs?: Record<string, { required?: string[]; additionalProperties?: boolean }>;
      };
      expect(inputSchema).toMatchObject({ type: "object" });
      const inputDefinition = resolveLocalDefinition(inputSchema, inputSchema.$ref);
      expect(inputDefinition?.required).toContain("asset_id");
      expect(inputDefinition?.additionalProperties).toBe(false);
      expect(listed.tools?.[0]?.outputSchema).toMatchObject({ type: "object" });
      expect(inputSchema).toEqual(canonicalInputSchema);
      expect(listed.tools?.[0]?.outputSchema).toEqual(canonicalReportSchema);
      expect(
        findSchemaWithRequired(listed.tools?.[0]?.outputSchema, [
          "schema_version",
          "contract_id",
          "checks",
        ]),
      ).toMatchObject({ additionalProperties: false });
      // Zero resources/prompts means their capabilities and handlers are
      // absent; a direct call is the protocol's method-not-found error.
      expect((await peer.request("resources/list").response).error?.code).toBe(-32601);
      expect((await peer.request("resources/templates/list").response).error?.code).toBe(-32601);
      expect((await peer.request("prompts/list").response).error?.code).toBe(-32601);
    } finally {
      await peer.close();
    }
  });

  it("advertises the generated report schema with the same Ajv acceptance corpus", async () => {
    const peer = await connected(async () => report());
    try {
      await initialize(peer);
      const response = await peer.request("tools/list").response;
      const listed = response.result as {
        tools?: Array<{ outputSchema?: Record<string, unknown> }>;
      };
      const advertised = listed.tools?.[0]?.outputSchema;
      expect(advertised).toEqual(canonicalReportSchema);
      const ajv = new Ajv2020({ strict: false });
      const installFormats = addFormats as unknown as (instance: Ajv2020) => Ajv2020;
      installFormats(ajv);
      const canonicalValidate = ajv.compile(canonicalReportSchema);
      const advertisedValidate = ajv.compile(advertised ?? {});
      const valid = report({ outcome: "coherent-active", requireActive: true });
      const wrongTuple = mutableReportCopy(valid);
      reportChecks(wrongTuple)[0] = {
        ...reportChecks(wrongTuple)[0],
        reason_code: "CHECK_FAILED",
      };
      const wrongOrder = mutableReportCopy(valid);
      const checks = reportChecks(wrongOrder);
      const firstCheck = checks[0];
      const secondCheck = checks[1];
      if (!firstCheck || !secondCheck) throw new Error("fixture has too few checks");
      [checks[0], checks[1]] = [secondCheck, firstCheck];
      const coherentUnknown = mutableReportCopy(valid);
      reportChecks(coherentUnknown)[0] = {
        ...reportChecks(coherentUnknown)[0],
        state: "UNKNOWN",
        reason_code: "BUNDLE_MALFORMED",
      };
      const contradictoryWithoutFailure = mutableReportCopy(valid);
      contradictoryWithoutFailure.record_coherence = "CONTRADICTORY";
      contradictoryWithoutFailure.registry_active_condition = "INDETERMINATE";
      const indeterminateWithoutUnknown = mutableReportCopy(valid);
      indeterminateWithoutUnknown.record_coherence = "INDETERMINATE";
      indeterminateWithoutUnknown.registry_active_condition = "INDETERMINATE";
      const reversedLimitations = mutableReportCopy(valid);
      reversedLimitations.limitations = [
        ...(reversedLimitations.limitations as string[]),
      ].reverse();
      const boundaryAssurance = mutableReportCopy(valid);
      const predicate = reportChecks(boundaryAssurance).find(
        (check) => check.id === "predicate_assurance",
      );
      if (!predicate) throw new Error("fixture has no predicate boundary check");
      predicate.state = "PASS";
      const unknownField = mutableReportCopy(valid);
      unknownField.remote_text = "prompt injection";

      const corpus: Array<[string, unknown, boolean]> = [
        ["canonical active report", valid, true],
        ["wrong tuple", wrongTuple, false],
        ["wrong ordered check", wrongOrder, false],
        ["coherent required unknown", coherentUnknown, false],
        ["contradictory without required failure", contradictoryWithoutFailure, false],
        ["indeterminate without required unknown", indeterminateWithoutUnknown, false],
        ["reversed limitation set", reversedLimitations, false],
        ["boundary assurance", boundaryAssurance, false],
        ["unknown output field", unknownField, false],
      ];
      for (const [label, candidate, expected] of corpus) {
        const canonicalResult = canonicalValidate(candidate);
        const advertisedResult = advertisedValidate(candidate);
        expect(canonicalResult, `canonical result for ${label}`).toBe(expected);
        expect(advertisedResult, `advertised result for ${label}`).toBe(canonicalResult);
      }

      expect(VerifyProofAssetInputSchema.safeParse({ asset_id: ASSET_ID }).success).toBe(true);
      expect(
        PublicRecordCoherenceReportSchema.safeParse(valid).success,
        "shared runtime schema accepts canonical report",
      ).toBe(true);
      expect(verifyProofAssetRecordOutputSchema["~standard"].validate(valid)).toMatchObject({
        value: valid,
      });
    } finally {
      await peer.close();
    }
  });

  it("passes only the bounded input and SDK cancellation signal to the shared core", async () => {
    let received: { assetId: string; requireActive: boolean; signal: AbortSignal } | undefined;
    const peer = await connected(async (input, options) => {
      received = {
        assetId: input.asset_id,
        requireActive: input.require_active,
        signal: options?.signal as AbortSignal,
      };
      return canonicalReport({ outcome: "coherent-inactive", requireActive: true });
    });
    try {
      await initialize(peer);
      const response = await peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: ASSET_ID, require_active: true },
      }).response;
      expect(response.error).toBeUndefined();
      const result = response.result as Record<string, unknown>;
      expect(result.isError).not.toBe(true);
      expect(structuredReport(result)).toMatchObject({
        record_coherence: "COHERENT",
        registry_status: "REVOKED",
        registry_active_condition: "NOT_SATISFIED",
      });
      expect(received?.assetId).toBe(ASSET_ID);
      expect(received?.requireActive).toBe(true);
      expect(received?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      await peer.close();
    }
  });

  it.each([
    ["coherent-active", canonicalReport({ outcome: "coherent-active", requireActive: true })],
    ["coherent-inactive", canonicalReport({ outcome: "coherent-inactive", requireActive: true })],
    ["contradictory", canonicalReport({ outcome: "contradictory", requireActive: true })],
    ["indeterminate", canonicalReport({ outcome: "indeterminate", requireActive: true })],
  ])(
    "returns %s as a structured non-error with exact canonical parity",
    async (_name, expected) => {
      const peer = await connected(async () => expected);
      try {
        await initialize(peer);
        const response = await peer.request("tools/call", {
          name: MCP_TOOL_NAME,
          arguments: { asset_id: ASSET_ID, require_active: true },
        }).response;
        expect(response.error).toBeUndefined();
        const result = response.result as {
          isError?: boolean;
          structuredContent?: unknown;
          content?: unknown;
        };
        expect(result.isError).toBe(false);
        expect(structuredReport(result)).toEqual(expected);
        expect(result.content).toEqual([{ type: "text", text: JSON.stringify(expected) }]);
      } finally {
        await peer.close();
      }
    },
  );

  it("rejects extra or malformed input before the shared core runs", async () => {
    expect(() =>
      VerifyProofAssetInputSchema.parse({ asset_id: ASSET_ID, origin: "https://evil.test" }),
    ).toThrow();
    expect(() => VerifyProofAssetInputSchema.parse({ asset_id: "../../etc/passwd" })).toThrow();

    let called = false;
    const peer = await connected(async () => {
      called = true;
      return report();
    });
    try {
      await initialize(peer);
      const response = await peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: "../../etc/passwd" },
      }).response;
      expectToolError(response);
      expect(called).toBe(false);
    } finally {
      await peer.close();
    }
  });

  it("turns a core exception into a stable MCP tool error without leaking details", async () => {
    const stderr = new PassThrough();
    const peer = await connected(
      async () => {
        throw new Error("secret-token https://private.example/session/asset");
      },
      { stderr },
    );
    try {
      await initialize(peer);
      const response = await peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: ASSET_ID },
      }).response;
      expectToolError(response);
      const encoded = JSON.stringify(response);
      expect(encoded).not.toContain("secret-token");
      expect(encoded).not.toContain("private.example");
      expect(stderr.read()?.toString("utf8")).toContain("internal MCP error");
    } finally {
      await peer.close();
    }
  });

  it("fails closed when the core returns a report outside the canonical contract", async () => {
    const peer = await connected(
      async () =>
        ({
          ...report(),
          acceptance_decision: "SATISFIED",
        }) as unknown as PublicRecordCoherenceReport,
    );
    try {
      await initialize(peer);
      const response = await peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: ASSET_ID },
      }).response;
      expectToolError(response);
    } finally {
      await peer.close();
    }
  });

  it("cancels an in-flight verifier through notifications/cancelled", async () => {
    let started: (() => void) | undefined;
    let observedAbort: (() => void) | undefined;
    const startedPromise = new Promise<void>((resolve) => {
      started = resolve;
    });
    const abortPromise = new Promise<void>((resolve) => {
      observedAbort = resolve;
    });
    const peer = await connected(async (_input, options) => {
      const signal = options?.signal as AbortSignal;
      started?.();
      await new Promise<void>((resolve) => {
        if (signal.aborted) return resolve();
        signal.addEventListener(
          "abort",
          () => {
            observedAbort?.();
            resolve();
          },
          { once: true },
        );
      });
      const error = new Error("cancelled");
      error.name = "AbortError";
      throw error;
    });
    try {
      await initialize(peer);
      const pending = peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: ASSET_ID },
      });
      await startedPromise;
      peer.notify("notifications/cancelled", { requestId: pending.id, reason: "test" });
      await expect(abortPromise).resolves.toBeUndefined();
      // The SDK intentionally emits no response for a cancelled request.
      await expect(
        Promise.race([
          pending.response.then(() => "response"),
          new Promise((resolve) => setTimeout(() => resolve("quiet"), 50)),
        ]),
      ).resolves.toBe("quiet");
    } finally {
      await peer.close();
    }
  });

  it("uses the shared strict schema and stays below duplicated-result budgets", () => {
    const parsed = PublicRecordCoherenceReportSchema.parse(report());
    const text = JSON.stringify(parsed);
    const result = JSON.stringify({
      isError: false,
      content: [{ type: "text", text }],
      structuredContent: parsed,
    });
    expect(Buffer.byteLength(text)).toBeLessThan(MCP_MAX_REPORT_BYTES);
    expect(Buffer.byteLength(result)).toBeLessThan(MCP_MAX_STDIO_MESSAGE_BYTES);
    expect(Buffer.byteLength(result)).toBeLessThan(MCP_MAX_RESULT_BYTES);
    expect(MCP_MAX_RESULT_BYTES).toBeLessThan(MCP_MAX_STDIO_MESSAGE_BYTES);
    expect(() =>
      PublicRecordCoherenceReportSchema.parse({ ...parsed, remote_text: "not allowed" }),
    ).toThrow();
  });

  it("enforces the complete JSON-RPC envelope budget, including duplicated content", async () => {
    const peer = await connected(async () => report(), { maxMessageBytes: 128 });
    try {
      await initialize(peer);
      const response = await peer.request("tools/call", {
        name: MCP_TOOL_NAME,
        arguments: { asset_id: ASSET_ID },
      }).response;
      expectToolError(response);
      expect(JSON.stringify(response)).not.toContain("Verifier report exceeds");
    } finally {
      await peer.close();
    }
  });

  it("counts JSON escaping and the request id in the complete response envelope", async () => {
    const expected = report();
    const serialized = JSON.stringify(expected);
    const candidateResult = {
      content: [{ type: "text" as const, text: serialized }],
      structuredContent: expected,
      isError: false as const,
    };
    // Quotes and backslashes are deliberately expensive once JSON-encoded;
    // the raw id remains within the adapter's documented 512-byte id bound.
    const escapedRequestId = '"'.repeat(256) + "\\".repeat(256);
    const candidateEnvelope = JSON.stringify({
      jsonrpc: "2.0",
      id: escapedRequestId,
      result: candidateResult,
    });
    const candidateBytes = Buffer.byteLength(candidateEnvelope, "utf8");
    const peer = await connected(async () => expected, {
      maxMessageBytes: candidateBytes - 1,
    });
    try {
      await initialize(peer);
      const response = await peer.requestWithId(
        "tools/call",
        { name: MCP_TOOL_NAME, arguments: { asset_id: ASSET_ID } },
        escapedRequestId,
      ).response;
      expectToolError(response);
    } finally {
      await peer.close();
    }
  });
});
