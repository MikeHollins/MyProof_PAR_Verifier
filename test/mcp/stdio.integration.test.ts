import { once } from "node:events";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const CHILD_PROCESS_TIMEOUT_MS = 90_000;
const ASSET_ID = "11111111-1111-4111-8111-111111111111";
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const FIXTURE_STDIO_HARNESS = resolve(PACKAGE_ROOT, "test/harness/mcp/stdio-server.ts");
const CANONICAL_INPUT_SCHEMA = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-input.v1.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;
const CANONICAL_REPORT_SCHEMA = JSON.parse(
  readFileSync(
    new URL("../../schemas/myproof.par.public-record-coherence.v1.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;

interface RawMcpMessage {
  readonly jsonrpc?: unknown;
  readonly id?: string | number | null;
  readonly result?: Record<string, unknown>;
  readonly error?: Record<string, unknown>;
  readonly method?: string;
}

class StdioPeer {
  private nextId = 1;
  private closed = false;
  private readonly pending = new Map<
    number,
    {
      resolve: (value: RawMcpMessage) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private buffer = "";
  private readonly messages: RawMcpMessage[] = [];
  private parseFailure: Error | undefined;
  private stderrText = "";
  private readonly stderrWaiters = new Map<
    string,
    Array<{
      resolve: () => void;
      timer: ReturnType<typeof setTimeout>;
    }>
  >();

  constructor(readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.onData(chunk));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => this.onStderr(chunk));
    child.once("close", () => {
      this.closed = true;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("stdio MCP child closed"));
      }
      this.pending.clear();
    });
  }

  request(
    method: string,
    params: Record<string, unknown>,
  ): {
    readonly id: number;
    readonly response: Promise<RawMcpMessage>;
  } {
    const id = this.nextId++;
    if (this.closed) {
      return { id, response: Promise.reject(new Error("stdio MCP child already closed")) };
    }
    const response = new Promise<RawMcpMessage>((resolveResponse, rejectResponse) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        rejectResponse(new Error(`stdio MCP request timed out: ${method}`));
      }, 15_000);
      this.pending.set(id, { resolve: resolveResponse, reject: rejectResponse, timer });
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    return { id, response };
  }

  notify(method: string, params: Record<string, unknown> = {}): void {
    if (this.closed) return;
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  end(): void {
    if (this.closed) return;
    this.child.stdin.end();
  }

  waitForStderr(marker: string): Promise<void> {
    if (this.stderrText.includes(marker)) return Promise.resolve();
    return new Promise<void>((resolveWait, rejectWait) => {
      const timer = setTimeout(() => {
        const waiters = this.stderrWaiters.get(marker);
        if (waiters) {
          const remaining = waiters.filter((candidate) => candidate !== waiter);
          if (remaining.length === 0) this.stderrWaiters.delete(marker);
          else this.stderrWaiters.set(marker, remaining);
        }
        rejectWait(new Error(`stdio MCP stderr marker timed out: ${marker}`));
      }, 5_000);
      const waiter = {
        resolve: () => {
          clearTimeout(timer);
          resolveWait();
        },
        timer,
      };
      const waiters = this.stderrWaiters.get(marker) ?? [];
      waiters.push(waiter);
      this.stderrWaiters.set(marker, waiters);
    });
  }

  stderr(): string {
    return this.stderrText;
  }

  responsesFor(id: string | number): RawMcpMessage[] {
    return this.messages.filter((message) => message.id === id);
  }

  assertStdoutProtocolOnly(): void {
    expect(this.parseFailure).toBeUndefined();
    expect(this.buffer.trim()).toBe("");
    expect(
      this.messages.every(
        (message) =>
          message.jsonrpc === "2.0" &&
          (typeof message.id === "string" ||
            typeof message.id === "number" ||
            typeof message.method === "string"),
      ),
    ).toBe(true);
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) continue;
      try {
        const message = JSON.parse(line) as RawMcpMessage;
        this.messages.push(message);
        if (typeof message.id === "number") {
          const pending = this.pending.get(message.id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(message.id);
            pending.resolve(message);
          }
        }
      } catch {
        this.parseFailure = new Error("stdout contained a non-JSON MCP line");
      }
    }
  }

  private onStderr(chunk: string): void {
    this.stderrText += chunk;
    for (const [marker, waiters] of this.stderrWaiters) {
      if (!this.stderrText.includes(marker)) continue;
      this.stderrWaiters.delete(marker);
      for (const waiter of waiters) waiter.resolve();
    }
  }
}

async function ensureBuiltPackageExecutable(): Promise<string> {
  await execFileAsync("npm", ["run", "build"], {
    cwd: PACKAGE_ROOT,
    maxBuffer: 20 * 1024 * 1024,
    timeout: CHILD_PROCESS_TIMEOUT_MS,
    killSignal: "SIGTERM",
  });
  // This is the exact package bin entry that npm packs. The package job owns
  // the sole npm pack/install empty-consumer smoke; this protocol test uses a
  // truly empty cwd with the already-built package executable so it does not
  // create a second hidden consumer installation.
  const executable = resolve(PACKAGE_ROOT, "bin/myproof-par.js");
  await access(executable);
  return executable;
}

function spawnPackagedMcp(executable: string, cwd: string): StdioPeer {
  const child = spawn(executable, ["mcp"], {
    cwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      PATH: process.env.PATH ?? "",
      NODE_NO_WARNINGS: "1",
    },
  });
  return new StdioPeer(child);
}

async function closeChild(
  peer: StdioPeer,
): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  peer.end();
  const [code, signal] = (await once(peer.child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  return { code, signal, stderr: peer.stderr() };
}

describe("packaged myproof-par mcp stdio lifecycle", () => {
  it("discovers the sole tool, returns a real shared-service result/error, and exits cleanly on EOF", async () => {
    const emptyCwd = await mkdtemp(join(tmpdir(), "myproof-par-empty-stdio-cwd-"));
    const executable = await ensureBuiltPackageExecutable();
    const peer = spawnPackagedMcp(executable, emptyCwd);
    try {
      const initialized = await peer.request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "empty-cwd-stdio-test", version: "0.1.0" },
      }).response;
      expect(initialized.error).toBeUndefined();
      peer.notify("notifications/initialized");

      const tools = await peer.request("tools/list", {}).response;
      const toolList = tools.result as {
        tools?: Array<{
          name?: string;
          inputSchema?: Record<string, unknown>;
          outputSchema?: Record<string, unknown>;
        }>;
      };
      expect(toolList.tools?.map((tool) => tool.name)).toEqual(["verify_proof_asset_record"]);
      expect(toolList.tools?.[0]?.inputSchema).toEqual(CANONICAL_INPUT_SCHEMA);
      expect(toolList.tools?.[0]?.outputSchema).toMatchObject({ type: "object" });
      expect(toolList.tools?.[0]?.outputSchema).toEqual(CANONICAL_REPORT_SCHEMA);

      const resources = await peer.request("resources/list", {}).response;
      expect(resources.error?.code).toBe(-32601);
      const resourceTemplates = await peer.request("resources/templates/list", {}).response;
      expect(resourceTemplates.error?.code).toBe(-32601);
      const prompts = await peer.request("prompts/list", {}).response;
      expect(prompts.error?.code).toBe(-32601);

      // This is a real packaged executable and real shared provider/core path;
      // network/provider failure remains a structured domain report, while
      // malformed protocol input is an error and never reaches the provider.
      const called = await peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: ASSET_ID, require_active: true },
      }).response;
      expect(called.error).toBeUndefined();
      const result = called.result as {
        isError?: boolean;
        structuredContent?: Record<string, unknown>;
      };
      expect(result.isError).toBe(false);
      const report = result.structuredContent;
      expect(report?.contract_id).toBe("myproof.par.public-record-coherence.v1");
      expect(report?.acceptance_decision).toBe("NOT_PERFORMED");
      expect(report?.underlying_proof_verification).toBe("NOT_PERFORMED");
      expect(report).not.toHaveProperty("result");

      // Exercise the cancellation notification on the packaged binary from
      // the empty cwd as well. The delayed harness below proves the signal
      // reaches an in-flight verifier; this check proves the production binary
      // stays healthy when a fast call races with cancellation.
      const cancellable = peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: ASSET_ID },
      });
      peer.notify("notifications/cancelled", {
        requestId: cancellable.id,
        reason: "packaged cancellation",
      });
      await Promise.race([
        cancellable.response.catch(() => undefined),
        new Promise((resolve) => setTimeout(resolve, 300)),
      ]);

      const invalid = await peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: "../../etc/passwd", origin: "https://evil.example" },
      }).response;
      // MCP input validation is a tool-level error result, not a JSON-RPC
      // transport error. It must not invoke the provider or expose details.
      expect(invalid.error).toBeUndefined();
      expect((invalid.result as { isError?: boolean } | undefined)?.isError).toBe(true);
    } finally {
      const closed = await closeChild(peer);
      expect(closed.code).toBe(0);
      expect(closed.signal).toBeNull();
      expect(closed.stderr).not.toContain("secret");
      peer.assertStdoutProtocolOnly();
      await rm(emptyCwd, { recursive: true, force: true });
    }
  }, 120_000);

  it("propagates protocol cancellation through a real stdio process and remains usable", async () => {
    const child = spawn(process.execPath, ["--import", "tsx/esm", FIXTURE_STDIO_HARNESS], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        PATH: process.env.PATH ?? "",
        NODE_NO_WARNINGS: "1",
        MCP_TEST_DELAY: "1",
      },
    });
    const peer = new StdioPeer(child);
    try {
      const initialized = await peer.request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "stdio-cancellation-test", version: "0.1.0" },
      }).response;
      expect(initialized.error).toBeUndefined();
      peer.notify("notifications/initialized");

      const pending = peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: ASSET_ID, require_active: true },
      });
      await peer.waitForStderr("[mcp-test] verifier-started");
      peer.notify("notifications/cancelled", {
        requestId: pending.id,
        reason: "test cancellation",
      });
      await peer.waitForStderr("[mcp-test] verifier-aborted");
      await expect(
        Promise.race([
          pending.response.then(() => "response").catch(() => "closed"),
          new Promise((resolve) => setTimeout(() => resolve("quiet"), 100)),
        ]),
      ).resolves.toBe("quiet");
      expect(peer.responsesFor(pending.id)).toEqual([]);

      const tools = await peer.request("tools/list", {}).response;
      expect(tools.error).toBeUndefined();
      expect(
        (tools.result as { tools?: Array<{ name?: string }> }).tools?.map((tool) => tool.name),
      ).toEqual(["verify_proof_asset_record"]);
      const subsequent = await peer.request("tools/call", {
        name: "verify_proof_asset_record",
        arguments: { asset_id: ASSET_ID },
      }).response;
      expect(subsequent.error).toBeUndefined();
      expect((subsequent.result as { isError?: boolean }).isError).toBe(false);
      expect(peer.responsesFor(pending.id)).toEqual([]);
    } finally {
      const closed = await closeChild(peer);
      expect(closed.code).toBe(0);
      expect(closed.signal).toBeNull();
      expect(closed.stderr).toContain("[mcp-test] verifier-started");
      expect(closed.stderr).toContain("[mcp-test] verifier-aborted");
      peer.assertStdoutProtocolOnly();
    }
  }, 120_000);
});
