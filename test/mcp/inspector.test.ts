import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const INSPECTOR_ENTRY = resolve(
  PACKAGE_ROOT,
  "node_modules/@modelcontextprotocol/inspector/clients/launcher/build/index.js",
);

function inspectorResult(stdout: string): Record<string, unknown> {
  const message = JSON.parse(stdout) as { result?: unknown };
  if (!message.result || typeof message.result !== "object" || Array.isArray(message.result)) {
    throw new Error("Inspector did not return a JSON-RPC result object");
  }
  return message.result as Record<string, unknown>;
}

describe("MCP Inspector compatibility", () => {
  it("runs the pinned Inspector 2.4.0 stdio tools/list strict check in the legacy era", async () => {
    await execFileAsync("npm", ["run", "build"], {
      cwd: PACKAGE_ROOT,
      maxBuffer: 20 * 1024 * 1024,
    });
    const catalogDir = await mkdtemp(join(tmpdir(), "myproof-par-inspector-"));
    try {
      const result = await execFileAsync(
        process.execPath,
        [
          INSPECTOR_ENTRY,
          "--cli",
          resolve(PACKAGE_ROOT, "bin/myproof-par.js"),
          "mcp",
          "--transport",
          "stdio",
          "--method",
          "tools/list",
          "--strict",
          "--format",
          "json",
        ],
        {
          cwd: PACKAGE_ROOT,
          env: {
            PATH: process.env.PATH ?? "",
            NODE_NO_WARNINGS: "1",
            MCP_CATALOG_PATH: join(catalogDir, "catalog.json"),
          },
          maxBuffer: 20 * 1024 * 1024,
        },
      );
      expect(inspectorResult(result.stdout)).toMatchObject({
        tools: expect.arrayContaining([
          expect.objectContaining({ name: "verify_proof_asset_record" }),
        ]),
      });
      expect(result.stderr).not.toContain("error-severity");
      expect(result.stderr).not.toContain("secret");
    } finally {
      await rm(catalogDir, { recursive: true, force: true });
    }
  }, 120_000);

  it("negotiates the pinned modern 2026-07-28 era through server/discover", async () => {
    await execFileAsync("npm", ["run", "build"], {
      cwd: PACKAGE_ROOT,
      maxBuffer: 20 * 1024 * 1024,
    });
    const catalogDir = await mkdtemp(join(tmpdir(), "myproof-par-inspector-modern-"));
    const configPath = join(catalogDir, "mcp.json");
    await writeFile(
      configPath,
      JSON.stringify(
        {
          mcpServers: {
            myproof: {
              command: process.execPath,
              args: [resolve(PACKAGE_ROOT, "bin/myproof-par.js"), "mcp"],
              protocolEra: "modern",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    try {
      const env = {
        PATH: process.env.PATH ?? "",
        NODE_NO_WARNINGS: "1",
      };
      const initialized = await execFileAsync(
        process.execPath,
        [
          INSPECTOR_ENTRY,
          "--cli",
          "--config",
          configPath,
          "--server",
          "myproof",
          "--method",
          "initialize",
          "--format",
          "json",
        ],
        { cwd: PACKAGE_ROOT, env, maxBuffer: 20 * 1024 * 1024 },
      );
      expect(inspectorResult(initialized.stdout)).toMatchObject({
        protocolVersion: "2026-07-28",
      });
      expect(initialized.stderr).not.toContain("error-severity");
      expect(initialized.stderr).not.toContain("secret");

      const tools = await execFileAsync(
        process.execPath,
        [
          INSPECTOR_ENTRY,
          "--cli",
          "--config",
          configPath,
          "--server",
          "myproof",
          "--method",
          "tools/list",
          "--strict",
          "--format",
          "json",
        ],
        { cwd: PACKAGE_ROOT, env, maxBuffer: 20 * 1024 * 1024 },
      );
      expect(inspectorResult(tools.stdout)).toMatchObject({
        tools: expect.arrayContaining([
          expect.objectContaining({ name: "verify_proof_asset_record" }),
        ]),
      });
      expect(tools.stderr).not.toContain("error-severity");
      expect(tools.stderr).not.toContain("secret");
    } finally {
      await rm(catalogDir, { recursive: true, force: true });
    }
  }, 120_000);
});
