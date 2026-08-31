import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createVerifierServiceForTests } from "../../src/service/verify-proof-asset-record.js";
import { runCli } from "../../src/cli/run.js";
import type { CliDependencies, CliStreams } from "../../src/cli/types.js";
import { createMcpServer } from "../../src/mcp/index.js";
import { parseCompactJws } from "../../src/crypto/jws.js";
import { ParProviderError } from "../../src/provider/index.js";
import {
  PublicRecordCoherenceReportSchema,
  parsePublicRecordCoherenceReportForInput,
} from "../../src/contracts/index.js";
import type {
  PublicRecordCoherenceReport,
  VerifyProofAssetInput,
  VerifyProofAssetRecord,
} from "../../src/contracts/index.js";
import {
  PublicRecordEvidenceInputSchema,
  PublicVerificationBundleInputSchema,
  ReceiptJwksInputSchema,
  StatusCredentialEvidenceInputSchema,
} from "../../src/contracts/input.js";
import type { PublicRecordEvidenceInput } from "../../src/contracts/input.js";
import { EXIT_CODES } from "../../src/contracts/constants.js";
import type { CoreEvidenceEnvelope } from "../../src/core/evidence.js";
import {
  FIXTURE_ASSET_ID,
  FIXTURE_NOW_MS,
  createSignedFixture,
} from "../fixtures/core/signed-fixtures.js";
import { InMemoryMcpPeer } from "../harness/mcp/in-memory-peer.js";

function streams(): { streams: CliStreams; stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    streams: {
      stdout: { write: (chunk) => stdout.push(chunk) },
      stderr: { write: (chunk) => stderr.push(chunk) },
    },
  };
}

function readFixtureText(name: string): string {
  return readFileSync(new URL(`../fixtures/provider/${name}`, import.meta.url), "utf8");
}

function readFixtureJson(name: string): unknown {
  return JSON.parse(readFixtureText(name)) as unknown;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("fixture payload must be a JSON object");
  }
  return value as Record<string, unknown>;
}

type DomainParityCase = {
  readonly name: string;
  readonly request: VerifyProofAssetInput;
  readonly verifier: VerifyProofAssetRecord;
  readonly expectedCliCode: number;
  readonly expected: {
    readonly record_coherence: PublicRecordCoherenceReport["record_coherence"];
    readonly registry_status: PublicRecordCoherenceReport["registry_status"];
    readonly registry_active_condition: PublicRecordCoherenceReport["registry_active_condition"];
    readonly errors: readonly PublicRecordCoherenceReport["errors"][number][];
    readonly statusReason?: string;
    readonly bundleReason?: string;
  };
};

function serviceForEvidence(
  fixture: ReturnType<typeof createSignedFixture>,
  evidence: PublicRecordEvidenceInput = fixture.evidence,
): VerifyProofAssetRecord {
  return createVerifierServiceForTests({
    provider: {
      fetchPublicRecordEvidence: async (_assetId, signal) => {
        if (signal?.aborted) throw signal.reason ?? new DOMException("aborted", "AbortError");
        return evidence;
      },
    },
    trust: fixture.trust,
    nowMs: () => FIXTURE_NOW_MS,
  });
}

function providerFailureService(code: "FETCH_FAILED" | "INVALID_RESPONSE"): {
  request: VerifyProofAssetInput;
  verifier: VerifyProofAssetRecord;
} {
  const fixture = createSignedFixture({ requireActive: true });
  return {
    request: fixture.request,
    verifier: createVerifierServiceForTests({
      provider: {
        fetchPublicRecordEvidence: async () => {
          // The provider error is deliberately raised at the provider/core
          // seam; the service owns its mapping to a canonical report.
          throw new ParProviderError(code, "bundle", "upstream details are not public");
        },
      },
      trust: fixture.trust,
      nowMs: () => FIXTURE_NOW_MS,
    }),
  };
}

function domainParityCases(): readonly DomainParityCase[] {
  const active = createSignedFixture({
    requireActive: true,
    statusBit: 0,
    includeConstraintHash: true,
    includeProvenance: true,
  });

  const revoked = createSignedFixture({
    requireActive: true,
    statusBit: 1,
    statusPurpose: "revocation",
    includeConstraintHash: true,
  });

  const suspended = createSignedFixture({
    requireActive: true,
    statusBit: 1,
    statusPurpose: "suspension",
    includeConstraintHash: true,
  });

  const contradictory = createSignedFixture({
    requireActive: true,
    statusBit: 0,
    includeConstraintHash: true,
  });
  const contradictoryEvidence: CoreEvidenceEnvelope = structuredClone(contradictory.evidence);
  contradictoryEvidence.bundle.asset.policyHash = "sha256:" + "e".repeat(64);

  const unavailable = providerFailureService("FETCH_FAILED");
  const malformed = providerFailureService("INVALID_RESPONSE");

  return [
    {
      name: "coherent active",
      request: active.request,
      verifier: serviceForEvidence(active),
      expectedCliCode: EXIT_CODES.OK,
      expected: {
        record_coherence: "COHERENT",
        registry_status: "ACTIVE",
        registry_active_condition: "SATISFIED",
        errors: [],
        statusReason: "STATUS_ACTIVE",
      },
    },
    {
      name: "coherent revoked inactive",
      request: revoked.request,
      verifier: serviceForEvidence(revoked),
      expectedCliCode: EXIT_CODES.COHERENT_BUT_INACTIVE,
      expected: {
        record_coherence: "COHERENT",
        registry_status: "REVOKED",
        registry_active_condition: "NOT_SATISFIED",
        errors: [],
        statusReason: "STATUS_REVOKED",
      },
    },
    {
      name: "coherent suspended inactive",
      request: suspended.request,
      verifier: serviceForEvidence(suspended),
      expectedCliCode: EXIT_CODES.COHERENT_BUT_INACTIVE,
      expected: {
        record_coherence: "COHERENT",
        registry_status: "SUSPENDED",
        registry_active_condition: "NOT_SATISFIED",
        errors: [],
        statusReason: "STATUS_SUSPENDED",
      },
    },
    {
      name: "contradictory public binding",
      request: contradictory.request,
      verifier: serviceForEvidence(contradictory, contradictoryEvidence),
      expectedCliCode: EXIT_CODES.CONTRADICTORY,
      expected: {
        record_coherence: "CONTRADICTORY",
        registry_status: "ACTIVE",
        registry_active_condition: "INDETERMINATE",
        errors: ["POLICY_BINDING_MISMATCH"],
        statusReason: "STATUS_ACTIVE",
      },
    },
    {
      name: "public record unavailable",
      request: unavailable.request,
      verifier: unavailable.verifier,
      expectedCliCode: EXIT_CODES.INDETERMINATE,
      expected: {
        record_coherence: "INDETERMINATE",
        registry_status: "UNKNOWN",
        registry_active_condition: "INDETERMINATE",
        errors: ["PUBLIC_RECORD_UNAVAILABLE"],
        bundleReason: "PUBLIC_RECORD_UNAVAILABLE",
      },
    },
    {
      name: "public record malformed",
      request: malformed.request,
      verifier: malformed.verifier,
      expectedCliCode: EXIT_CODES.INDETERMINATE,
      expected: {
        record_coherence: "INDETERMINATE",
        registry_status: "UNKNOWN",
        registry_active_condition: "INDETERMINATE",
        errors: ["PUBLIC_RECORD_MALFORMED"],
        bundleReason: "PUBLIC_RECORD_MALFORMED",
      },
    },
  ];
}

async function assertDomainParity(testCase: DomainParityCase): Promise<void> {
  // One shared facade invocation is the oracle. Neither adapter is allowed to
  // synthesize or normalize a report independently.
  const expected = await testCase.verifier(testCase.request);
  expect(expected.record_coherence).toBe(testCase.expected.record_coherence);
  expect(expected.registry_status).toBe(testCase.expected.registry_status);
  expect(expected.registry_active_condition).toBe(testCase.expected.registry_active_condition);
  expect(expected.errors).toEqual(testCase.expected.errors);

  const statusCheck = expected.checks.find((check) => check.id === "registry_status");
  if (testCase.expected.statusReason !== undefined) {
    expect(statusCheck?.reason_code).toBe(testCase.expected.statusReason);
  }
  const bundleCheck = expected.checks.find((check) => check.id === "bundle_structure");
  if (testCase.expected.bundleReason !== undefined) {
    expect(bundleCheck?.reason_code).toBe(testCase.expected.bundleReason);
  }

  const cliIo = streams();
  const cliCode = await runCli(
    [
      "verify",
      testCase.request.asset_id,
      ...(testCase.request.require_active ? ["--require-active"] : []),
      "--json",
    ],
    {
      dependencies: {
        verifyProofAssetRecord: testCase.verifier,
        runMcp: async () => undefined,
      } satisfies CliDependencies,
      streams: cliIo.streams,
      processSignals: false,
    },
  );
  expect(cliCode).toBe(testCase.expectedCliCode);
  expect(cliIo.stderr).toEqual([]);
  const cliReport = parsePublicRecordCoherenceReportForInput(
    JSON.parse(cliIo.stdout.join("")) as unknown,
    testCase.request,
  );
  expect(cliReport).toEqual(expected);

  const peer = await InMemoryMcpPeer.connect(createMcpServer(testCase.verifier));
  try {
    const initialized = await peer.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "outcome-parity-test", version: "0.1.0" },
    }).response;
    expect(initialized.error).toBeUndefined();
    peer.notify("notifications/initialized");
    const response = await peer.request("tools/call", {
      name: "verify_proof_asset_record",
      arguments: {
        asset_id: testCase.request.asset_id,
        require_active: testCase.request.require_active,
      },
    }).response;
    expect(response.error).toBeUndefined();
    const result = response.result as Record<string, unknown>;
    expect(result.isError).toBe(false);
    const structured = parsePublicRecordCoherenceReportForInput(
      result.structuredContent,
      testCase.request,
    );
    expect(structured).toEqual(cliReport);
    expect(structured).toEqual(expected);
    expect(result.structuredContent).not.toHaveProperty("result");
    expect(result.content).toEqual([{ type: "text", text: JSON.stringify(expected) }]);
  } finally {
    await peer.close();
  }
}

function cancellableVerifier(): {
  readonly verifier: VerifyProofAssetRecord;
  readonly started: Promise<void>;
  readonly aborted: Promise<void>;
} {
  let resolveStarted!: () => void;
  let resolveAborted!: () => void;
  const started = new Promise<void>((resolve) => {
    resolveStarted = resolve;
  });
  const aborted = new Promise<void>((resolve) => {
    resolveAborted = resolve;
  });
  const verifier: VerifyProofAssetRecord = async (_input, options) => {
    const signal = options?.signal;
    if (!signal) throw new Error("missing cancellation signal");
    resolveStarted();
    await new Promise<never>((_resolve, reject) => {
      const onAbort = (): void => {
        resolveAborted();
        const error = new Error("cancelled");
        error.name = "AbortError";
        reject(error);
      };
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    });
    throw new Error("unreachable");
  };
  return { verifier, started, aborted };
}

describe("CLI and MCP shared-service parity", () => {
  for (const testCase of domainParityCases()) {
    it(`keeps ${testCase.name} identical across CLI JSON and MCP`, async () => {
      await assertDomainParity(testCase);
    });
  }

  it("maps cancellation consistently without fabricating a domain report", async () => {
    const cliCancellation = cancellableVerifier();
    const cliController = new AbortController();
    const cliIo = streams();
    const cliPending = runCli(["verify", FIXTURE_ASSET_ID, "--require-active", "--json"], {
      dependencies: {
        verifyProofAssetRecord: cliCancellation.verifier,
        runMcp: async () => undefined,
      },
      streams: cliIo.streams,
      signal: cliController.signal,
      processSignals: false,
    });
    await cliCancellation.started;
    cliController.abort();
    expect(await cliCancellation.aborted).toBeUndefined();
    expect(await cliPending).toBe(EXIT_CODES.INDETERMINATE);
    expect(cliIo.stdout).toEqual([]);
    expect(cliIo.stderr.join("")).toContain("CLI_CANCELLED");

    const mcpCancellation = cancellableVerifier();
    const peer = await InMemoryMcpPeer.connect(createMcpServer(mcpCancellation.verifier));
    try {
      const initialized = await peer.request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "cancellation-parity-test", version: "0.1.0" },
      }).response;
      expect(initialized.error).toBeUndefined();
      peer.notify("notifications/initialized");
      const pending = peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: FIXTURE_ASSET_ID, require_active: true },
      });
      await mcpCancellation.started;
      peer.notify("notifications/cancelled", {
        requestId: pending.id,
        reason: "cancellation parity",
      });
      await expect(mcpCancellation.aborted).resolves.toBeUndefined();
      // Cancellation is deliberately not a report outcome: CLI emits only a
      // safe stderr diagnostic and MCP emits neither structuredContent nor
      // text for the cancelled request.
      await expect(
        Promise.race([
          pending.response.then(() => "response"),
          new Promise((resolve) => setTimeout(() => resolve("quiet"), 50)),
        ]),
      ).resolves.toBe("quiet");
      expect(peer.responsesFor(pending.id)).toEqual([]);

      const healthy = await peer.request("tools/list").response;
      expect(healthy.error).toBeUndefined();
    } finally {
      await peer.close();
    }
  });

  it("uses one real service/core invocation shape for canonical JSON and MCP content", async () => {
    const fixture = createSignedFixture({
      requireActive: true,
      statusBit: 0,
      includeConstraintHash: true,
      includeProvenance: true,
    });
    const evidence = fixture.evidence;
    // The replay identifier is present only in the signed JWS payload. It is
    // intentionally absent from the producer's public claims projection, and
    // the valid coherent result below proves that omission is not required for
    // a report to be coherent.
    expect(fixture.receiptClaims.jti).toBe("fixture-receipt-0001");
    expect(evidence.bundle.receipt.claims).not.toHaveProperty("jti");
    const verifier = createVerifierServiceForTests({
      provider: {
        fetchPublicRecordEvidence: async (_assetId, signal) => {
          if (signal?.aborted) throw signal.reason ?? new DOMException("aborted", "AbortError");
          return evidence;
        },
      },
      trust: fixture.trust,
      nowMs: () => FIXTURE_NOW_MS,
    });

    // Exercise the real shared service directly once to establish the
    // deterministic oracle used by both adapter transports.
    const expected = await verifier(fixture.request);

    const cliIo = streams();
    const cliDependencies: CliDependencies = {
      verifyProofAssetRecord: verifier,
      runMcp: async () => undefined,
    };
    expect(
      await runCli(["verify", FIXTURE_ASSET_ID, "--require-active", "--json"], {
        dependencies: cliDependencies,
        streams: cliIo.streams,
        processSignals: false,
      }),
    ).toBe(0);
    expect(cliIo.stderr).toEqual([]);
    const cliReport = JSON.parse(cliIo.stdout.join("")) as PublicRecordCoherenceReport;
    expect(cliReport).toEqual(expected);

    const peer = await InMemoryMcpPeer.connect(createMcpServer(verifier));
    try {
      const initialized = await peer.request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "shared-parity-test", version: "0.1.0" },
      }).response;
      expect(initialized.error).toBeUndefined();
      peer.notify("notifications/initialized");
      const response = await peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: FIXTURE_ASSET_ID, require_active: true },
      }).response;
      expect(response.error).toBeUndefined();
      const result = response.result as Record<string, unknown>;
      expect(result.isError).toBe(false);
      expect(result.structuredContent).toEqual(cliReport);
      expect(result.content).toEqual([{ type: "text", text: JSON.stringify(cliReport) }]);
    } finally {
      await peer.close();
    }
  });

  it("preserves exact producer artifact semantics across CLI and MCP without embedded-key or jti projection trust", async () => {
    const exactBundle = PublicVerificationBundleInputSchema.parse(
      readFixtureJson("producer-omit-wire.json"),
    );
    const receiptJwks = ReceiptJwksInputSchema.parse(
      readFixtureJson("structural-receipt-jwks.json"),
    );
    const statusCredential = StatusCredentialEvidenceInputSchema.parse({
      credential: readFixtureText("structural-status.vc-jwt").trim(),
      content_type: "application/vc+jwt",
    });
    const exactEvidence = PublicRecordEvidenceInputSchema.parse({
      bundle: exactBundle,
      receipt_jwks: receiptJwks,
      status_credential: statusCredential,
      status_url: exactBundle.statusCheck.statusListUrl,
    });
    const request: VerifyProofAssetInput = {
      asset_id: exactBundle.asset.proofAssetId,
      require_active: false,
    };
    const control = createSignedFixture();
    const makeVerifier = (evidence: PublicRecordEvidenceInput) =>
      createVerifierServiceForTests({
        provider: {
          fetchPublicRecordEvidence: async (_assetId, signal) => {
            if (signal?.aborted) throw signal.reason ?? new DOMException("aborted", "AbortError");
            return evidence;
          },
        },
        // This trust material is independently generated and deliberately
        // differs from both the embedded producer JWK and fetched structural
        // JWKS. The exact artifact can never turn its embedded key into trust.
        trust: control.trust,
        nowMs: () => Date.parse(exactBundle.generatedAt),
      });
    const verifier = makeVerifier(exactEvidence);

    const signedPayload = record(parseCompactJws(exactBundle.receipt.jws, "JWT").payload);
    expect(signedPayload.jti).toEqual(expect.any(String));
    expect(exactBundle.receipt.claims).not.toHaveProperty("jti");
    expect(exactBundle.receipt.publicJwk?.kid).not.toBe(receiptJwks.keys[0]?.kid);

    // The exact producer wire is structurally accepted, but separately
    // fetched receipt keys do not intersect the independently held release
    // trust material, so this remains a truthful domain report rather than a
    // synthetic coherent result.
    const expected = await verifier(request);
    expect(expected.record_coherence).toBe("INDETERMINATE");
    expect(expected.checks).toContainEqual(
      expect.objectContaining({
        id: "live_key_intersection",
        state: "UNKNOWN",
        reason_code: "TRUST_KEY_INTERSECTION_EMPTY",
      }),
    );
    expect(expected.registry_active_condition).toBe("NOT_REQUESTED");
    expect(expected).not.toHaveProperty("jti");
    expect(expected).not.toHaveProperty("publicJwk");
    expect(expected).not.toHaveProperty("header");

    const cliIo = streams();
    const cliCode = await runCli(["verify", request.asset_id, "--json"], {
      dependencies: {
        verifyProofAssetRecord: verifier,
        runMcp: async () => undefined,
      } satisfies CliDependencies,
      streams: cliIo.streams,
      processSignals: false,
    });
    const expectedCliCode =
      expected.record_coherence === "CONTRADICTORY"
        ? 20
        : expected.record_coherence === "INDETERMINATE"
          ? 21
          : 0;
    expect(cliCode).toBe(expectedCliCode);
    expect(cliIo.stderr).toEqual([]);
    const cliReport = JSON.parse(cliIo.stdout.join("")) as PublicRecordCoherenceReport;
    expect(PublicRecordCoherenceReportSchema.parse(cliReport)).toEqual(expected);

    const peer = await InMemoryMcpPeer.connect(createMcpServer(verifier));
    try {
      const initialized = await peer.request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "exact-artifact-parity-test", version: "0.1.0" },
      }).response;
      expect(initialized.error).toBeUndefined();
      peer.notify("notifications/initialized");
      const response = await peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: request.asset_id },
      }).response;
      expect(response.error).toBeUndefined();
      const result = response.result as Record<string, unknown>;
      expect(result.isError).toBe(false);
      // No legacy SDK `{ result: report }` compatibility wrapper is accepted.
      expect(result.structuredContent).toEqual(cliReport);
      expect(result.structuredContent).not.toHaveProperty("result");
      expect(result.content).toEqual([{ type: "text", text: JSON.stringify(cliReport) }]);
      expect(JSON.parse((result.content as [{ type: "text"; text: string }])[0].text)).toEqual(
        expected,
      );
    } finally {
      await peer.close();
    }

    // Removing the producer's embedded key/header must not change the result;
    // only the separately fetched JWKS and package-owned trust material matter.
    const withoutEmbeddedKey = structuredClone(exactBundle);
    delete withoutEmbeddedKey.receipt.publicJwk;
    delete withoutEmbeddedKey.receipt.header;
    const withoutEmbeddedKeyEvidence = PublicRecordEvidenceInputSchema.parse({
      ...exactEvidence,
      bundle: withoutEmbeddedKey,
    });
    expect(await makeVerifier(withoutEmbeddedKeyEvidence)(request)).toEqual(expected);
  });
});
