import { afterEach, describe, expect, it, vi } from "vitest";
import {
  PublicRecordCoherenceReportSchema,
  type PublicRecordCoherenceReport,
  type ReasonCode,
  type VerifyProofAssetInput,
} from "../../src/contracts/index.js";
import type { PublicRecordEvidenceInput } from "../../src/contracts/input.js";
import {
  createVerifierServiceForTests,
  verifyProofAssetRecord,
  type VerifierServiceDependencies,
} from "../../src/service/verify-proof-asset-record.js";
import {
  CANONICAL_PAR_ORIGIN,
  ParProviderError,
  createParPublicProvider,
  type ProviderErrorCode,
  type ProviderResource,
} from "../../src/provider/index.js";
import {
  FIXTURE_ASSET_ID,
  FIXTURE_NOW_MS,
  createRotatedSignedFixtures,
  createSignedFixture,
} from "../fixtures/core/signed-fixtures.js";

const CONTROL_FIXTURE = createSignedFixture({
  requireActive: true,
  includeConstraintHash: true,
  includeProvenance: true,
});

const VALID_INPUT: VerifyProofAssetInput = {
  asset_id: FIXTURE_ASSET_ID,
  require_active: false,
};
const MISMATCHED_ASSET_ID = "00000000-0000-4000-8000-000000000002";

const BUNDLE_URL = `${CANONICAL_PAR_ORIGIN}/api/public/proof-assets/${FIXTURE_ASSET_ID}/verification-bundle?audit=omit`;
const JWKS_URL = `${CANONICAL_PAR_ORIGIN}/api/public/receipts/jwks.json`;
const STATUS_URL = `${CANONICAL_PAR_ORIGIN}/status/revocation/default`;

afterEach(() => {
  vi.unstubAllGlobals();
});

type Service = ReturnType<typeof createVerifierServiceForTests>;

function serviceFor(
  provider: VerifierServiceDependencies["provider"],
  options: {
    readonly trust?: VerifierServiceDependencies["trust"];
    readonly nowMs?: () => number;
  } = {},
): Service {
  return createVerifierServiceForTests({
    provider,
    trust: options.trust ?? CONTROL_FIXTURE.trust,
    nowMs: options.nowMs ?? (() => FIXTURE_NOW_MS),
  });
}

function providerReturning(
  evidence: PublicRecordEvidenceInput,
): VerifierServiceDependencies["provider"] {
  return {
    fetchPublicRecordEvidence: async () => evidence,
  };
}

function providerThrowing(
  error: unknown,
  calls: string[] = [],
): VerifierServiceDependencies["provider"] {
  return {
    fetchPublicRecordEvidence: async (assetId) => {
      calls.push(assetId);
      throw error;
    },
  };
}

async function invokeRaw(service: Service, input: unknown, options?: unknown): Promise<unknown> {
  return Reflect.apply(service, undefined, [input, options]);
}

function reportFor(value: unknown): PublicRecordCoherenceReport {
  return PublicRecordCoherenceReportSchema.parse(value);
}

function checkFor(report: PublicRecordCoherenceReport, id: string) {
  const check = report.checks.find((candidate) => candidate.id === id);
  if (!check) throw new Error(`missing check ${id}`);
  return check;
}

function responseFor(
  body: string,
  url: string,
  status = 200,
  contentType = "application/json",
): {
  readonly status: number;
  readonly url: string;
  readonly redirected: false;
  readonly headers: { get(name: string): string | null };
  readonly arrayBuffer: () => Promise<ArrayBuffer>;
} {
  const bytes = new TextEncoder().encode(body);
  return {
    status,
    url,
    redirected: false,
    headers: {
      get(name: string): string | null {
        if (name.toLowerCase() === "content-type") return contentType;
        return null;
      },
    },
    arrayBuffer: async () => bytes.slice().buffer,
  };
}

const PROVIDER_FAILURE_CASES = [
  ["INVALID_ASSET_ID", "input", "PUBLIC_RECORD_UNAVAILABLE"],
  ["INVALID_STATUS_REFERENCE", "status", "PUBLIC_RECORD_UNAVAILABLE"],
  ["UNSAFE_URL", "input", "NETWORK_ORIGIN_REJECTED"],
  ["FETCH_FAILED", "bundle", "PUBLIC_RECORD_UNAVAILABLE"],
  ["ABORTED", "bundle", "NETWORK_ABORTED"],
  ["TIMEOUT", "bundle", "NETWORK_TIMEOUT"],
  ["REDIRECT_REJECTED", "bundle", "NETWORK_REDIRECT_REJECTED"],
  ["HTTP_STATUS", "bundle", "PUBLIC_RECORD_UNAVAILABLE"],
  ["CONTENT_TYPE_MISMATCH", "bundle", "NETWORK_CONTENT_TYPE_INVALID"],
  ["CONTENT_ENCODING_UNSUPPORTED", "bundle", "NETWORK_CONTENT_TYPE_INVALID"],
  ["CONTENT_LENGTH_INVALID", "bundle", "PUBLIC_RECORD_UNAVAILABLE"],
  ["BODY_TOO_LARGE", "bundle", "NETWORK_RESPONSE_TOO_LARGE"],
  ["INVALID_TEXT", "bundle", "PUBLIC_RECORD_MALFORMED"],
  ["INVALID_JSON", "bundle", "PUBLIC_RECORD_MALFORMED"],
  ["INVALID_RESPONSE", "bundle", "PUBLIC_RECORD_MALFORMED"],
] as const satisfies ReadonlyArray<
  readonly [ProviderErrorCode, ProviderResource | "input", ReasonCode]
>;

describe("verifyProofAssetRecord service facade", () => {
  it("delegates valid evidence to the core and returns the canonical report", async () => {
    const calls: Array<{ assetId: string; signal?: AbortSignal }> = [];
    const service = serviceFor(
      {
        fetchPublicRecordEvidence: async (assetId, signal) => {
          if (signal === undefined) {
            calls.push({ assetId });
          } else {
            calls.push({ assetId, signal });
          }
          return CONTROL_FIXTURE.evidence;
        },
      },
      { trust: CONTROL_FIXTURE.trust },
    );

    const report = reportFor(await service(CONTROL_FIXTURE.request));

    expect(report.record_coherence).toBe("COHERENT");
    expect(report.registry_status).toBe("ACTIVE");
    expect(report.registry_active_condition).toBe("SATISFIED");
    expect(report.acceptance_decision).toBe("NOT_PERFORMED");
    expect(report.underlying_proof_verification).toBe("NOT_PERFORMED");
    expect(report.predicate_assurance).toBe("PAR_REPORTED_ONLY");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.assetId).toBe(FIXTURE_ASSET_ID);
    expect(calls[0]?.signal).toBeUndefined();
  });

  it("bounds concurrent production-facade requests with one process-wide provider", async () => {
    let active = 0;
    let maxActive = 0;
    let releaseGate: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });

    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      active += 1;
      maxActive = Math.max(maxActive, active);
      try {
        await gate;
        if (url === BUNDLE_URL) {
          return responseFor(JSON.stringify(CONTROL_FIXTURE.evidence.bundle), url);
        }
        if (url === JWKS_URL) {
          return responseFor(JSON.stringify(CONTROL_FIXTURE.evidence.receipt_jwks), url);
        }
        if (url === STATUS_URL) {
          return responseFor(CONTROL_FIXTURE.statusJws, url, 200, "application/vc+jwt");
        }
        throw new Error("unexpected provider URL");
      } finally {
        active -= 1;
      }
    });

    const verifications = [
      verifyProofAssetRecord(VALID_INPUT),
      verifyProofAssetRecord(VALID_INPUT),
    ];
    await vi.waitFor(() => expect(maxActive).toBeGreaterThanOrEqual(3));
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    const observedBeforeRelease = maxActive;
    const release = releaseGate;
    if (!release) throw new Error("concurrency gate was not initialized");
    release();

    const reports = await Promise.all(verifications);
    expect(reports).toHaveLength(2);
    expect(observedBeforeRelease).toBeLessThanOrEqual(3);
    expect(maxActive).toBeLessThanOrEqual(3);
    expect(active).toBe(0);
    for (const report of reports) {
      expect(PublicRecordCoherenceReportSchema.safeParse(report).success).toBe(true);
    }
  });

  it("preserves old and newer receipts through the service during key rotation", async () => {
    const rotated = createRotatedSignedFixtures();
    let evidence = rotated.oldEvidence;
    const service = serviceFor(
      {
        fetchPublicRecordEvidence: async () => evidence,
      },
      { trust: rotated.trust },
    );

    const oldReport = reportFor(await service(rotated.old.request));
    expect(oldReport.record_coherence).toBe("COHERENT");
    expect(oldReport.registry_active_condition).toBe("SATISFIED");

    evidence = rotated.currentEvidence;
    const newerReport = reportFor(await service(rotated.current.request));
    expect(newerReport.record_coherence).toBe("COHERENT");
    expect(newerReport.registry_status).toBe("ACTIVE");

    const removedOld = structuredClone(rotated.oldEvidence);
    removedOld.receipt_jwks = { keys: [rotated.current.publicJwk] };
    evidence = removedOld;
    const removedReport = reportFor(await service(rotated.old.request));
    expect(removedReport.record_coherence).toBe("INDETERMINATE");
    expect(removedReport.registry_active_condition).toBe("INDETERMINATE");
    expect(checkFor(removedReport, "live_key_intersection")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "RECEIPT_KEY_UNKNOWN",
    });
  });

  it.each(PROVIDER_FAILURE_CASES)(
    "maps provider %s failures to the canonical %s report reason",
    async (code, resource, reason) => {
      const secret = "upstream-secret-https://attacker.invalid/hidden";
      const calls: string[] = [];
      const service = serviceFor(
        providerThrowing(new ParProviderError(code, resource, secret, 503), calls),
      );

      const report = reportFor(await service(VALID_INPUT));
      const bundleCheck = checkFor(report, "bundle_structure");

      expect(report.record_coherence).toBe("INDETERMINATE");
      expect(report.registry_status).toBe("UNKNOWN");
      expect(report.registry_active_condition).toBe("NOT_REQUESTED");
      expect(report.warnings).toEqual(["PUBLIC_RECORD_INDETERMINATE"]);
      expect(report.errors).toEqual([reason]);
      expect(bundleCheck).toMatchObject({
        state: "UNKNOWN",
        reason_code: reason,
        verification_method: "STRUCTURAL_VALIDATION",
        authority: "PAR_PUBLIC_EVIDENCE",
        required: true,
      });
      expect(JSON.stringify(report)).not.toContain(secret);
      expect(calls).toEqual([FIXTURE_ASSET_ID]);
    },
  );

  it("maps a status-only failure after bundle and JWKS retrieval to an unavailable report", async () => {
    const calls: string[] = [];
    const privateTransportError = "status upstream failure must never enter the report";
    vi.stubGlobal("fetch", async (input: string | URL, init?: { readonly method?: string }) => {
      const url = String(input);
      calls.push(`${init?.method ?? ""}:${url}`);
      if (url === BUNDLE_URL) {
        return responseFor(JSON.stringify(CONTROL_FIXTURE.evidence.bundle), url);
      }
      if (url === JWKS_URL) {
        return responseFor(JSON.stringify(CONTROL_FIXTURE.evidence.receipt_jwks), url);
      }
      if (url === STATUS_URL) throw new Error(privateTransportError);
      throw new Error("unexpected provider URL");
    });

    const provider = createParPublicProvider();
    const service = serviceFor(provider, { trust: CONTROL_FIXTURE.trust });
    const report = reportFor(await service(CONTROL_FIXTURE.request));

    expect(calls).toHaveLength(3);
    expect(calls).toEqual(expect.arrayContaining([`GET:${BUNDLE_URL}`, `GET:${JWKS_URL}`]));
    expect(calls).toContain(`GET:${STATUS_URL}`);
    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(report.warnings).toEqual(["PUBLIC_RECORD_INDETERMINATE"]);
    expect(report.errors).toEqual(["PUBLIC_RECORD_UNAVAILABLE"]);
    expect(checkFor(report, "bundle_structure")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "PUBLIC_RECORD_UNAVAILABLE",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    });
    expect(JSON.stringify(report)).not.toContain(privateTransportError);
    expect(JSON.stringify(report)).not.toContain(STATUS_URL);
  });

  it("passes a signed bundle asset mismatch to the core as a contradiction", async () => {
    const mismatchedBundle = structuredClone(CONTROL_FIXTURE.evidence.bundle);
    mismatchedBundle.asset.proofAssetId = MISMATCHED_ASSET_ID;
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      if (url === BUNDLE_URL) return responseFor(JSON.stringify(mismatchedBundle), url);
      if (url === JWKS_URL) {
        return responseFor(JSON.stringify(CONTROL_FIXTURE.evidence.receipt_jwks), url);
      }
      if (url === STATUS_URL) {
        return responseFor(CONTROL_FIXTURE.statusJws, url, 200, "application/vc+jwt");
      }
      throw new Error("unexpected provider URL");
    });

    const provider = createParPublicProvider();
    const service = serviceFor(provider, { trust: CONTROL_FIXTURE.trust });
    const report = reportFor(await service(CONTROL_FIXTURE.request));

    expect(report.record_coherence).toBe("CONTRADICTORY");
    expect(report.registry_status).toBe("ACTIVE");
    expect(report.errors).toEqual(["BUNDLE_ASSET_ID_MISMATCH"]);
    expect(checkFor(report, "bundle_structure")).toMatchObject({
      state: "PASS",
      reason_code: "BUNDLE_SCHEMA_VALID",
    });
    expect(checkFor(report, "asset_identifier")).toMatchObject({
      state: "FAIL",
      reason_code: "BUNDLE_ASSET_ID_MISMATCH",
    });
  });

  it("preserves active-status uncertainty when a provider failure occurs", async () => {
    const service = serviceFor(
      providerThrowing(new ParProviderError("TIMEOUT", "bundle", "secret")),
    );
    const report = reportFor(await service({ ...VALID_INPUT, require_active: true }));

    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_active_condition).toBe("INDETERMINATE");
    expect(report.errors).toEqual(["NETWORK_TIMEOUT"]);
  });

  it("forwards a caller signal to the provider without serializing it", async () => {
    const controller = new AbortController();
    let receivedSignal: AbortSignal | undefined;
    const service = serviceFor(
      {
        fetchPublicRecordEvidence: async (_assetId, signal) => {
          receivedSignal = signal;
          return CONTROL_FIXTURE.evidence;
        },
      },
      { trust: CONTROL_FIXTURE.trust },
    );

    const report = reportFor(await service(CONTROL_FIXTURE.request, { signal: controller.signal }));

    expect(report.record_coherence).toBe("COHERENT");
    expect(receivedSignal).toBe(controller.signal);
    expect(JSON.stringify(report)).not.toContain("AbortSignal");
  });

  it("turns malformed provider evidence into a canonical indeterminate report", async () => {
    const malformedEvidence = {} as unknown as PublicRecordEvidenceInput;
    const service = serviceFor(providerReturning(malformedEvidence));

    const report = reportFor(await service(VALID_INPUT));

    expect(report.record_coherence).toBe("INDETERMINATE");
    expect(report.registry_status).toBe("UNKNOWN");
    expect(report.errors).toEqual([]);
    expect(checkFor(report, "bundle_structure")).toMatchObject({
      state: "UNKNOWN",
      reason_code: "BUNDLE_MALFORMED",
      verification_method: "STRUCTURAL_VALIDATION",
      authority: "PAR_PUBLIC_EVIDENCE",
      required: true,
    });
    expect(JSON.stringify(report)).not.toContain("malformed");
  });

  it("rejects malformed caller input before provider I/O", async () => {
    const calls: string[] = [];
    const service = serviceFor(providerThrowing(new Error("provider must not run"), calls));

    await expect(
      invokeRaw(service, { asset_id: "not-a-uuid", require_active: false }),
    ).rejects.toMatchObject({
      name: "ZodError",
    });
    await expect(
      invokeRaw(service, {
        asset_id: FIXTURE_ASSET_ID,
        require_active: false,
        caller_url: "https://attacker.invalid",
      }),
    ).rejects.toMatchObject({ name: "ZodError" });
    expect(calls).toEqual([]);
  });

  it("preserves caller cancellation instead of converting it to a domain report", async () => {
    const calls: string[] = [];
    const controller = new AbortController();
    const reason = new Error("caller cancellation");
    controller.abort(reason);
    const service = serviceFor(
      providerThrowing(new ParProviderError("ABORTED", "bundle", "secret"), calls),
    );

    await expect(service(VALID_INPUT, { signal: controller.signal })).rejects.toBe(reason);
    expect(calls).toEqual([]);
  });

  it("preserves cancellation that arrives after provider completion", async () => {
    const controller = new AbortController();
    const reason = new Error("cancellation after fetch");
    const service = serviceFor(
      {
        fetchPublicRecordEvidence: async () => {
          controller.abort(reason);
          return CONTROL_FIXTURE.evidence;
        },
      },
      { trust: CONTROL_FIXTURE.trust },
    );

    await expect(service(CONTROL_FIXTURE.request, { signal: controller.signal })).rejects.toBe(
      reason,
    );
  });

  it("propagates unknown provider failures without inventing a report", async () => {
    const secretError = new Error("upstream private failure");
    const service = serviceFor(providerThrowing(secretError));

    await expect(service(VALID_INPUT)).rejects.toBe(secretError);
  });

  it.each([Number.NaN, -1, Number.POSITIVE_INFINITY, 1.5])(
    "rejects invalid service clock %s before provider I/O",
    async (nowMs) => {
      const calls: string[] = [];
      const service = serviceFor(providerThrowing(new Error("provider must not run"), calls), {
        nowMs: () => nowMs,
      });

      await expect(service(VALID_INPUT)).rejects.toMatchObject({
        message: "INTERNAL_INVARIANT_FAILURE",
      });
      expect(calls).toEqual([]);
    },
  );

  it("propagates a clock dependency invariant exception unchanged", async () => {
    const invariant = new Error("clock dependency failed");
    const calls: string[] = [];
    const service = serviceFor(providerThrowing(new Error("provider must not run"), calls), {
      nowMs: () => {
        throw invariant;
      },
    });

    await expect(service(VALID_INPUT)).rejects.toBe(invariant);
    expect(calls).toEqual([]);
  });
});
