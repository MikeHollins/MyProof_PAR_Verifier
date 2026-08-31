import { describe, expect, it, vi } from "vitest";
import { runCli, type SignalProcess } from "../../src/cli/run.js";
import type { CanonicalReport, CliDependencies, CliStreams } from "../../src/cli/types.js";
import { canonicalReport } from "../harness/mcp/canonical-report.js";

// These tests exercise runCli with an injected seam. The real static service
// binding is covered by the build and packaged-entry tests; mocking this module
// keeps focused adapter tests independent of provider credentials/config.
vi.mock("../../src/cli/dependencies.js", () => ({
  createDefaultCliDependencies: () => {
    throw new Error("default dependencies are not used by injected adapter tests");
  },
}));

const ASSET_ID = "00000000-0000-4000-8000-000000000001";

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

function fixture(overrides: Partial<CanonicalReport> = {}): CanonicalReport {
  const coherence = overrides.record_coherence ?? "COHERENT";
  const activeCondition = overrides.registry_active_condition ?? "NOT_REQUESTED";
  const registryStatus =
    overrides.registry_status ?? (coherence === "INDETERMINATE" ? "UNKNOWN" : "ACTIVE");
  const outcome =
    coherence === "CONTRADICTORY"
      ? "contradictory"
      : coherence === "INDETERMINATE"
        ? "indeterminate"
        : registryStatus === "REVOKED" || registryStatus === "SUSPENDED"
          ? "coherent-inactive"
          : "coherent-active";
  const generated = canonicalReport({
    assetId: ASSET_ID,
    outcome,
    requireActive: activeCondition !== "NOT_REQUESTED",
  });
  return {
    ...generated,
    ...overrides,
  };
}

function deps(report: CanonicalReport): CliDependencies {
  return {
    verifyProofAssetRecord: vi.fn(async () => report),
    runMcp: vi.fn(async () => undefined),
  };
}

describe("runCli", () => {
  it("writes only human report data to stdout for a coherent result", async () => {
    const io = streams();
    const code = await runCli(["verify", ASSET_ID], {
      dependencies: deps(fixture()),
      streams: io.streams,
      processSignals: false,
    });

    expect(code).toBe(0);
    expect(io.stdout.join("")).toContain("MyProof PAR public-record verification");
    expect(io.stderr).toEqual([]);
  });

  it("writes canonical JSON to stdout and returns inactive exit 10", async () => {
    const io = streams();
    const code = await runCli(["verify", ASSET_ID, "--require-active", "--json"], {
      dependencies: deps(
        fixture({
          registry_status: "REVOKED",
          registry_active_condition: "NOT_SATISFIED",
        }),
      ),
      streams: io.streams,
      processSignals: false,
    });

    expect(code).toBe(10);
    expect(JSON.parse(io.stdout.join(""))).toMatchObject({
      record_coherence: "COHERENT",
      registry_active_condition: "NOT_SATISFIED",
    });
    expect(io.stderr).toEqual([]);
  });

  it.each([
    ["CONTRADICTORY", 20],
    ["INDETERMINATE", 21],
  ] as const)(
    "returns domain exit %i for %s without turning it into a process error",
    async (coherence, code) => {
      const io = streams();
      const result = await runCli(["verify", ASSET_ID, "--json"], {
        dependencies: deps(fixture({ record_coherence: coherence })),
        streams: io.streams,
        processSignals: false,
      });
      expect(result).toBe(code);
      expect(JSON.parse(io.stdout.join(""))).toHaveProperty("record_coherence", coherence);
      expect(io.stderr).toEqual([]);
    },
  );

  it("returns 21 for a canonical unavailable/public-record outcome", async () => {
    const io = streams();
    const result = await runCli(["verify", ASSET_ID, "--json"], {
      dependencies: deps(
        fixture({
          record_coherence: "INDETERMINATE",
          registry_status: "UNKNOWN",
          errors: ["PUBLIC_RECORD_UNAVAILABLE"],
        }),
      ),
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(21);
    expect(JSON.parse(io.stdout.join(""))).toMatchObject({
      record_coherence: "INDETERMINATE",
      errors: ["PUBLIC_RECORD_UNAVAILABLE"],
    });
    expect(io.stderr).toEqual([]);
  });

  it("returns usage 64 and keeps malformed invocations off stdout", async () => {
    const io = streams();
    const result = await runCli(["verify", "../secret", "--json"], {
      dependencies: deps(fixture()),
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(64);
    expect(io.stdout).toEqual([]);
    const diagnostic = JSON.parse(io.stderr.join("")) as {
      error?: { code?: string; message?: string };
    };
    expect(diagnostic).toEqual({
      error: {
        code: "CLI_USAGE",
        message: "invalid asset-id; expected a canonical lowercase UUID",
      },
    });
  });

  it("contains runtime-invalid argv values inside the usage boundary", async () => {
    const io = streams();
    const result = await runCli(["verify", null] as unknown as readonly string[], {
      dependencies: deps(fixture()),
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(64);
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_USAGE");
  });

  it("maps an unexpected verifier exception to safe internal diagnostics", async () => {
    const io = streams();
    const secret = "Bearer super-secret-token https://attacker.invalid/raw";
    const result = await runCli(["verify", ASSET_ID, "--json"], {
      dependencies: {
        verifyProofAssetRecord: vi.fn(async () => {
          throw new Error(secret);
        }),
        runMcp: vi.fn(async () => undefined),
      },
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(70);
    expect(io.stdout).toEqual([]);
    const diagnostic = io.stderr.join("");
    expect(diagnostic).toContain("VERIFIER_FAILURE");
    expect(diagnostic).not.toContain(secret);
    expect(diagnostic).not.toContain("super-secret-token");
  });

  it("returns internal 70 for a malformed shared-core report", async () => {
    const io = streams();
    const result = await runCli(["verify", ASSET_ID], {
      dependencies: {
        verifyProofAssetRecord: vi.fn(
          async () => ({ record_coherence: "COHERENT" }) as unknown as CanonicalReport,
        ),
        runMcp: vi.fn(async () => undefined),
      },
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(70);
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_INVARIANT");
    expect(io.stderr.join("")).not.toContain("record_coherence: COHERENT");
  });

  it("returns internal 70 when a valid report belongs to another asset", async () => {
    const io = streams();
    const result = await runCli(["verify", ASSET_ID, "--json"], {
      dependencies: {
        verifyProofAssetRecord: vi.fn(async () =>
          fixture({ asset_id: "11111111-1111-4111-8111-111111111111" }),
        ),
        runMcp: vi.fn(async () => undefined),
      },
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(70);
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_INVARIANT");
  });

  it.each([
    ["unrequested active condition", false, "SATISFIED"],
    ["missing active condition", true, "NOT_REQUESTED"],
  ] as const)(
    "returns internal 70 for a report/request active-status intent mismatch (%s)",
    async (_caseName, requireActive, activeCondition) => {
      const io = streams();
      const result = await runCli(
        ["verify", ASSET_ID, ...(requireActive ? ["--require-active"] : []), "--json"],
        {
          dependencies: deps(
            fixture({
              registry_status: "ACTIVE",
              registry_active_condition: activeCondition,
            }),
          ),
          streams: io.streams,
          processSignals: false,
        },
      );
      expect(result).toBe(70);
      expect(io.stdout).toEqual([]);
      expect(io.stderr.join("")).toContain("CLI_INVARIANT");
    },
  );

  it("does not invoke a verifier when cancellation is already requested", async () => {
    const io = streams();
    const controller = new AbortController();
    controller.abort();
    const verifyAsset = vi.fn(async () => fixture());
    const result = await runCli(["verify", ASSET_ID, "--json"], {
      dependencies: { verifyProofAssetRecord: verifyAsset, runMcp: vi.fn(async () => undefined) },
      streams: io.streams,
      signal: controller.signal,
      processSignals: false,
    });
    expect(result).toBe(21);
    expect(verifyAsset).not.toHaveBeenCalled();
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_CANCELLED");
  });

  it("propagates cancellation to the shared verifier and returns 21", async () => {
    const io = streams();
    const controller = new AbortController();
    const verifyAsset = vi.fn(
      async (_input: unknown, options?: { readonly signal?: AbortSignal }) => {
        await new Promise<never>((_resolve, reject) => {
          options?.signal?.addEventListener(
            "abort",
            () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
            { once: true },
          );
        });
        throw new Error("unreachable");
      },
    );
    const pending = runCli(["verify", ASSET_ID, "--json"], {
      dependencies: { verifyProofAssetRecord: verifyAsset, runMcp: vi.fn(async () => undefined) },
      streams: io.streams,
      signal: controller.signal,
      processSignals: false,
    });
    controller.abort();
    expect(await pending).toBe(21);
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_CANCELLED");
    expect(io.stderr.join("")).not.toContain("aborted");
  });

  it("delegates mcp without writing protocol/log output itself", async () => {
    const io = streams();
    const runMcp = vi.fn(async () => undefined);
    const result = await runCli(["mcp"], {
      dependencies: { verifyProofAssetRecord: vi.fn(), runMcp },
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(0);
    expect(runMcp).toHaveBeenCalledOnce();
    expect(runMcp).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(io.stdout).toEqual([]);
    expect(io.stderr).toEqual([]);
  });

  it("propagates cancellation through the MCP launcher and returns 21", async () => {
    const io = streams();
    const controller = new AbortController();
    const runMcp = vi.fn(async (signal?: AbortSignal) => {
      await new Promise<never>((_resolve, reject) => {
        if (signal?.aborted) {
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
          return;
        }
        signal?.addEventListener(
          "abort",
          () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
          { once: true },
        );
      });
    });
    const pending = runCli(["mcp"], {
      dependencies: { verifyProofAssetRecord: vi.fn(), runMcp },
      streams: io.streams,
      signal: controller.signal,
      processSignals: false,
    });
    controller.abort();
    expect(await pending).toBe(21);
    expect(runMcp).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_CANCELLED");
  });

  it("maps MCP startup failures to safe internal 70", async () => {
    const io = streams();
    const result = await runCli(["mcp"], {
      dependencies: {
        verifyProofAssetRecord: vi.fn(),
        runMcp: vi.fn(async () => {
          throw new Error("protocol stream contained a token=secret");
        }),
      },
      streams: io.streams,
      processSignals: false,
    });
    expect(result).toBe(70);
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("MCP_FAILURE");
    expect(io.stderr.join("")).not.toContain("token=secret");
  });

  it("installs and removes SIGINT/SIGTERM listeners around verification", async () => {
    const io = streams();
    const listeners = new Map<string, () => void>();
    const processLike: SignalProcess = {
      on: (event, listener) => listeners.set(event, listener),
      removeListener: (event, listener) => {
        if (listeners.get(event) === listener) listeners.delete(event);
      },
    };
    const verifyAsset = vi.fn(async (_input, options?: { readonly signal?: AbortSignal }) => {
      expect(options?.signal?.aborted).toBe(false);
      return fixture();
    });
    expect(
      await runCli(["verify", ASSET_ID], {
        dependencies: { verifyProofAssetRecord: verifyAsset, runMcp: vi.fn(async () => undefined) },
        streams: io.streams,
        processLike,
      }),
    ).toBe(0);
    expect(listeners.size).toBe(0);
  });

  it("aborts the shared verifier when SIGTERM arrives", async () => {
    const io = streams();
    const listeners = new Map<string, () => void>();
    const processLike: SignalProcess = {
      on: (event, listener) => listeners.set(event, listener),
      removeListener: (event, listener) => {
        if (listeners.get(event) === listener) listeners.delete(event);
      },
    };
    const verifyAsset = vi.fn(
      async (_input: unknown, options?: { readonly signal?: AbortSignal }) => {
        await new Promise<never>((_resolve, reject) => {
          if (options?.signal?.aborted) {
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
            return;
          }
          options?.signal?.addEventListener(
            "abort",
            () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
            { once: true },
          );
        });
        throw new Error("unreachable");
      },
    );
    const pending = runCli(["verify", ASSET_ID, "--json"], {
      dependencies: { verifyProofAssetRecord: verifyAsset, runMcp: vi.fn(async () => undefined) },
      streams: io.streams,
      processLike,
    });
    listeners.get("SIGTERM")?.();
    expect(await pending).toBe(21);
    expect(verifyAsset).toHaveBeenCalledOnce();
    expect(io.stdout).toEqual([]);
    expect(io.stderr.join("")).toContain("CLI_CANCELLED");
    expect(listeners.size).toBe(0);
  });
});
