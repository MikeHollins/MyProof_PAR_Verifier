#!/usr/bin/env node

/**
 * Verify the release shape without publishing anything.
 *
 * This is deliberately implemented with Node's standard library so the check
 * works on every supported runner and does not add a package-manager helper to
 * the published dependency graph.  npm's JSON pack manifest is the source for
 * content and mode checks; the final assertion executes the installed bin
 * shim from a genuinely empty consumer directory.
 */

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(process.cwd());
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);
const MCP_REQUEST_TIMEOUT_MS = 30_000;
const MCP_CLOSE_TIMEOUT_MS = 10_000;
const MCP_QUIET_CANCELLATION_MS = 250;
const MCP_MAX_STREAM_BYTES = 4 * 1024 * 1024;
const MCP_TOOL_NAME = "verify_proof_asset_record";
const MCP_ASSET_ID = "11111111-1111-4111-8111-111111111111";
let localNpmCache;

class CommandFailure extends Error {
  constructor(command, code) {
    super(`${command} failed (${String(code ?? "unknown")})`);
    this.name = "CommandFailure";
    this.command = command;
    this.code = code;
  }
}

async function run(command, args, options = {}) {
  try {
    const result = await execFileAsync(command, args, {
      cwd: packageRoot,
      env: {
        ...process.env,
        ...(localNpmCache === undefined ? {} : { npm_config_cache: localNpmCache }),
        npm_config_audit: "false",
        npm_config_fund: "false",
        npm_config_update_notifier: "false",
      },
      maxBuffer: 20 * 1024 * 1024,
      timeout: 120_000,
      ...options,
    });
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? error.code : null;
    throw new CommandFailure([command, ...args].join(" "), code);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parsePackJson(stdout) {
  const first = stdout.indexOf("[");
  const last = stdout.lastIndexOf("]");
  assert(first >= 0 && last > first, "npm pack did not return a JSON manifest");
  const parsed = JSON.parse(stdout.slice(first, last + 1));
  assert(Array.isArray(parsed) && parsed.length === 1, "npm pack returned an unexpected manifest");
  assert(parsed[0] && typeof parsed[0] === "object", "npm pack manifest is malformed");
  return parsed[0];
}

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalizeJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    assert(Number.isFinite(value), "manifest contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  assert(value && typeof value === "object", "manifest contains an unsupported value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`)
    .join(",")}}`;
}

function safeFailure(error) {
  if (error instanceof CommandFailure) return error.message;
  if (error instanceof Error) return error.message.slice(0, 240);
  return "package smoke failed";
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

class McpChild {
  constructor(child) {
    this.child = child;
    this.closed = false;
    this.nextId = 1;
    this.buffer = "";
    this.messages = [];
    this.pending = new Map();
    this.stdoutBytes = 0;
    this.stderrBytes = 0;
    this.stderr = "";
    this.parseFailure = null;
    this.closeResult = new Promise((resolveClose) => {
      child.once("close", (code, signal) => {
        this.closed = true;
        for (const pending of this.pending.values()) {
          clearTimeout(pending.timer);
          pending.reject(new Error("installed MCP child closed before response"));
        }
        this.pending.clear();
        resolveClose({ code, signal });
      });
    });
    child.once("error", (error) => {
      this.parseFailure ??= new Error(`installed MCP child failed to start: ${error.message}`);
    });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => this.onStdout(chunk));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => this.onStderr(chunk));
  }

  request(method, params) {
    const id = this.nextId++;
    if (this.closed) throw new Error("installed MCP child is already closed");
    const response = new Promise((resolveResponse, rejectResponse) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        rejectResponse(new Error(`installed MCP request timed out: ${method}`));
      }, MCP_REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve: resolveResponse, reject: rejectResponse, timer });
    });
    this.write({ jsonrpc: "2.0", id, method, params });
    return { id, response };
  }

  notify(method, params = {}) {
    if (this.closed) return;
    this.write({ jsonrpc: "2.0", method, params });
  }

  end() {
    if (!this.child.stdin.destroyed) this.child.stdin.end();
  }

  async close() {
    this.end();
    let timer;
    try {
      return await Promise.race([
        this.closeResult,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("installed MCP child did not exit on EOF")),
            MCP_CLOSE_TIMEOUT_MS,
          );
        }),
      ]);
    } catch (error) {
      if (!this.closed) this.child.kill("SIGTERM");
      throw error;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  write(message) {
    const line = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(line, "utf8") > MCP_MAX_STREAM_BYTES) {
      throw new Error("installed MCP request exceeds the stream byte bound");
    }
    try {
      this.child.stdin.write(line);
    } catch (error) {
      throw new Error("installed MCP child stdin write failed", { cause: error });
    }
  }

  onStdout(chunk) {
    this.stdoutBytes += Buffer.byteLength(chunk, "utf8");
    if (this.stdoutBytes > MCP_MAX_STREAM_BYTES) {
      this.parseFailure ??= new Error("installed MCP stdout exceeded the stream byte bound");
      this.child.kill("SIGTERM");
      return;
    }
    this.buffer += chunk;
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (line.length === 0) continue;
      if (Buffer.byteLength(line, "utf8") > MCP_MAX_STREAM_BYTES) {
        this.parseFailure ??= new Error("installed MCP message exceeded the stream byte bound");
        this.child.kill("SIGTERM");
        return;
      }
      try {
        const message = JSON.parse(line);
        this.messages.push(message);
        if (typeof message?.id === "number") {
          const pending = this.pending.get(message.id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(message.id);
            pending.resolve(message);
          }
        }
      } catch {
        this.parseFailure ??= new Error("installed MCP stdout contained a non-JSON line");
      }
    }
  }

  onStderr(chunk) {
    this.stderrBytes += Buffer.byteLength(chunk, "utf8");
    if (this.stderr.length < MCP_MAX_STREAM_BYTES) {
      this.stderr += chunk.slice(0, MCP_MAX_STREAM_BYTES - this.stderr.length);
    }
    if (this.stderrBytes > MCP_MAX_STREAM_BYTES) {
      this.parseFailure ??= new Error("installed MCP stderr exceeded the stream byte bound");
      this.child.kill("SIGTERM");
    }
  }
}

async function runInstalledMcpSmoke(executable, consumerDir, installedPackageDir, tarballSha256) {
  const inputSchema = JSON.parse(
    await readFile(
      join(installedPackageDir, "schemas", "myproof.par.public-record-input.v1.json"),
      "utf8",
    ),
  );
  const outputSchema = JSON.parse(
    await readFile(
      join(installedPackageDir, "schemas", "myproof.par.public-record-coherence.v1.json"),
      "utf8",
    ),
  );
  const child = new McpChild(
    spawn(executable, ["mcp"], {
      cwd: consumerDir,
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    }),
  );
  let closeResult;
  try {
    const initialized = await child.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "package-smoke", version: "1.0.0" },
    }).response;
    assert(
      initialized?.jsonrpc === "2.0" && initialized?.error === undefined,
      "installed MCP initialize failed",
    );
    assert(
      initialized?.result?.serverInfo?.name === "myproof-par-verifier",
      "installed MCP initialize server identity is unexpected",
    );
    child.notify("notifications/initialized");

    const listed = await child.request("tools/list", {}).response;
    assert(
      listed?.jsonrpc === "2.0" && listed?.error === undefined,
      "installed MCP tools/list failed",
    );
    const tools = listed?.result?.tools;
    assert(
      Array.isArray(tools) && tools.length === 1,
      "installed MCP tools/list is not exactly one tool",
    );
    const tool = tools[0];
    assert(tool?.name === MCP_TOOL_NAME, "installed MCP tool name is not canonical");
    assert(
      Object.keys(tool).sort().join(",") ===
        "annotations,description,inputSchema,name,outputSchema,title",
      "installed MCP tool surface has unexpected fields",
    );
    assert(
      canonicalizeJson(tool.inputSchema) === canonicalizeJson(inputSchema),
      "installed MCP input schema drifted",
    );
    assert(
      canonicalizeJson(tool.outputSchema) === canonicalizeJson(outputSchema),
      "installed MCP output schema drifted",
    );
    const toolsListSha256 = hashBytes(Buffer.from(canonicalizeJson({ tools }), "utf8"));

    const called = await child.request("tools/call", {
      name: MCP_TOOL_NAME,
      arguments: { asset_id: MCP_ASSET_ID, require_active: true },
    }).response;
    assert(
      called?.jsonrpc === "2.0" && called?.error === undefined,
      "installed MCP tools/call returned a protocol error",
    );
    const result = called?.result;
    assert(result?.isError === false, "installed MCP tools/call returned an MCP tool error");
    const report = result?.structuredContent;
    assert(
      report?.contract_id === "myproof.par.public-record-coherence.v1" &&
        ["COHERENT", "CONTRADICTORY", "INDETERMINATE"].includes(report?.record_coherence),
      "installed MCP tools/call did not return the canonical report",
    );
    assert(
      Array.isArray(result?.content) &&
        result.content.length === 1 &&
        result.content[0]?.type === "text" &&
        JSON.stringify(JSON.parse(result.content[0].text)) === JSON.stringify(report),
      "installed MCP tools/call text and structured report diverged",
    );
    const boundedUnavailable = report.record_coherence === "INDETERMINATE";
    if (boundedUnavailable) {
      assert(
        Array.isArray(report.checks) &&
          report.checks.some((check) =>
            /^(?:PUBLIC_RECORD_|NETWORK_|TRUST_)/.test(String(check?.reason_code)),
          ),
        "installed MCP unavailable result lacks a bounded public/network reason",
      );
    }

    const cancelled = child.request("tools/call", {
      name: MCP_TOOL_NAME,
      arguments: { asset_id: MCP_ASSET_ID },
    });
    const cancellationResponse = cancelled.response.then(
      () => "response",
      () => "closed",
    );
    child.notify("notifications/cancelled", {
      requestId: cancelled.id,
      reason: "package smoke cancellation",
    });
    const cancellationState = await Promise.race([
      cancellationResponse,
      delay(MCP_QUIET_CANCELLATION_MS).then(() => "quiet"),
    ]);
    assert(
      cancellationState === "quiet",
      "installed MCP cancellation did not suppress the in-flight response",
    );
    const afterCancellation = await child.request("tools/list", {}).response;
    assert(
      afterCancellation?.error === undefined,
      "installed MCP was not usable after cancellation",
    );
    await delay(50);
    assert(
      !child.messages.some((message) => message?.id === cancelled.id),
      "installed MCP emitted a response for a cancelled request",
    );

    closeResult = await child.close();
    assert(
      closeResult.code === 0 && closeResult.signal === null,
      "installed MCP did not exit cleanly on EOF",
    );
    assert(
      child.parseFailure === null,
      child.parseFailure?.message ?? "installed MCP stream parse failed",
    );
    assert(child.buffer.trim() === "", "installed MCP stdout ended with a partial message");
    assert(
      child.stderr === "",
      "installed MCP wrote diagnostics to stderr during a successful smoke",
    );
    assert(
      child.messages.every(
        (message) =>
          message?.jsonrpc === "2.0" &&
          (typeof message?.id === "number" || typeof message?.method === "string"),
      ),
      "installed MCP stdout contained a non-protocol message",
    );
    return {
      tarballSha256,
      initialize: true,
      toolsList: true,
      toolsListSha256,
      toolName: MCP_TOOL_NAME,
      toolsCall: boundedUnavailable ? "bounded-unavailable" : "canonical-report",
      cancellation: true,
      eof: true,
      cleanShutdown: true,
      exitCode: closeResult.code,
      signal: closeResult.signal,
      stdoutMessages: child.messages.length,
      stdoutBytes: child.stdoutBytes,
      stderrBytes: child.stderrBytes,
    };
  } finally {
    if (!closeResult && !child.closed) {
      child.child.kill("SIGTERM");
      await Promise.race([child.closeResult, delay(MCP_CLOSE_TIMEOUT_MS)]);
    }
  }
}

async function main() {
  if (process.env.CI !== "true") {
    // Local npm caches can be owned by another package-manager invocation. An
    // ephemeral cache keeps this read-only smoke usable without chmod/chown.
    localNpmCache = await mkdtemp(join(tmpdir(), "myproof-par-npm-cache-"));
  }
  const packDir = await mkdtemp(join(tmpdir(), "myproof-par-pack-"));
  const consumerDir = await mkdtemp(join(tmpdir(), "myproof-par-empty-consumer-"));
  const evidence = {
    check: "package-smoke",
    ok: false,
    node: process.version,
    npm: null,
    package: null,
    tarball: null,
    files: [],
    consumer: null,
  };

  try {
    const npmVersion = await run(npmCommand, ["--version"]);
    evidence.npm = npmVersion.stdout.trim();

    const packageJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
    evidence.package = { name: packageJson.name, version: packageJson.version };
    assert(
      typeof packageJson.name === "string" && typeof packageJson.version === "string",
      "package metadata is incomplete",
    );

    const packed = parsePackJson(
      (await run(npmCommand, ["pack", "--json", "--ignore-scripts", "--pack-destination", packDir]))
        .stdout,
    );
    const filename = packed.filename;
    assert(
      typeof filename === "string" && filename.endsWith(".tgz"),
      "npm pack did not produce a tarball",
    );
    const tarball = join(packDir, filename);
    await access(tarball);
    const tarballBytes = await readFile(tarball);
    const files = Array.isArray(packed.files) ? packed.files : [];
    const paths = files
      .map((entry) => (entry && typeof entry.path === "string" ? entry.path : null))
      .filter((path) => path !== null);
    assert(paths.length > 0 && paths.length === files.length, "npm pack listed malformed files");

    const required = [
      "package.json",
      "README.md",
      "LICENSE",
      "bin/myproof-par.js",
      "configs/release-trust-manifest.json",
      "dist/index.js",
      "dist/cli/main.js",
      "dist/mcp/index.js",
    ];
    for (const path of required) assert(paths.includes(path), `packed package is missing ${path}`);
    const configPaths = paths.filter((path) => path.startsWith("configs/"));
    assert(
      configPaths.length === 1 && configPaths[0] === "configs/release-trust-manifest.json",
      "package must ship only the release trust manifest under configs/",
    );

    const forbidden = /^(?:src|test|docs|node_modules|\.git|\.github)\//;
    for (const path of paths) {
      assert(!forbidden.test(path), `development-only path leaked into package: ${path}`);
      assert(
        !/(?:^|\/)(?:\.env|.*\.(?:pem|key|p12|pfx))$/i.test(path),
        `secret-like path leaked into package: ${path}`,
      );
      if (path.startsWith("schemas/")) {
        assert(path.endsWith(".json"), `schema generator/source leaked into package: ${path}`);
      }
    }

    const binEntry = files.find((entry) => entry?.path === "bin/myproof-par.js");
    assert(binEntry && typeof binEntry.mode === "number", "packaged bin mode is missing");
    assert((binEntry.mode & 0o777) === 0o755, "packaged bin mode must be exactly 0755");

    evidence.files = files.map((entry) => ({
      path: entry.path,
      size: entry.size,
      mode: entry.mode,
    }));
    evidence.tarball = {
      filename,
      bytes: tarballBytes.byteLength,
      sha256: hashBytes(tarballBytes),
      integrity: typeof packed.integrity === "string" ? packed.integrity : null,
      npmShasum: typeof packed.shasum === "string" ? packed.shasum : null,
    };

    await run(
      npmCommand,
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", tarball],
      { cwd: consumerDir },
    );

    const installedPackageDir = join(consumerDir, "node_modules", "@myproof", "par-verifier");
    const installedPackage = JSON.parse(
      await readFile(join(installedPackageDir, "package.json"), "utf8"),
    );
    assert(
      installedPackage.name === packageJson.name,
      "consumer installed a different package name",
    );
    assert(
      installedPackage.version === packageJson.version,
      "consumer installed a different package version",
    );
    // Resolve the package by name from a file physically inside the empty
    // consumer. This exercises the published export map rather than merely
    // importing a known dist path from the source checkout.
    const publicImportProbe = join(consumerDir, "public-import-probe.mjs");
    await writeFile(
      publicImportProbe,
      [
        `import * as publicPackage from ${JSON.stringify(packageJson.name)};`,
        `import * as publicContracts from ${JSON.stringify(`${packageJson.name}/contracts`)};`,
        `const expected = ${JSON.stringify(
          [
            "AssetIdSchema",
            "CheckAuthoritySchema",
            "CheckIdSchema",
            "CheckSchema",
            "CheckStateSchema",
            "CHECK_AUTHORITY_VALUES",
            "CHECK_IDS",
            "CHECK_STATE_VALUES",
            "LimitationCodeSchema",
            "LIMITATION_CODES",
            "PublicRecordCoherenceReportSchema",
            "REASON_CODES",
            "ReasonCodeSchema",
            "RecordCoherenceSchema",
            "RECORD_COHERENCE_VALUES",
            "RegistryActiveConditionSchema",
            "RegistryStatusSchema",
            "REGISTRY_ACTIVE_CONDITION_VALUES",
            "REGISTRY_STATUS_VALUES",
            "REPORT_CONTRACT_ID",
            "REPORT_SCHEMA_VERSION",
            "VerificationMethodSchema",
            "VERIFICATION_METHOD_VALUES",
            "VerifyProofAssetInputSchema",
            "assertPublicRecordReportBytes",
            "parsePublicRecordCoherenceReport",
            "parsePublicRecordCoherenceReportForInput",
            "parseVerifyProofAssetInput",
            "serializePublicRecordCoherenceReport",
          ].sort(),
        )};`,
        "const rootKeys = Object.keys(publicPackage).sort();",
        "const contractKeys = Object.keys(publicContracts).sort();",
        "if (JSON.stringify(rootKeys) !== JSON.stringify(expected)) {",
        '  throw new Error("consumer package root exports are not the public allowlist");',
        "}",
        "if (JSON.stringify(contractKeys) !== JSON.stringify(expected)) {",
        '  throw new Error("consumer contracts exports differ from the package root");',
        "}",
      ].join("\n"),
      "utf8",
    );
    const publicImport = await run(process.execPath, [publicImportProbe], { cwd: consumerDir });
    assert(publicImport.stdout.trim() === "", "consumer package import wrote output");
    assert(publicImport.stderr.trim() === "", "consumer package import wrote diagnostics");
    const manifestPath = join(installedPackageDir, "configs", "release-trust-manifest.json");
    const manifestBytes = await readFile(manifestPath);
    assert(manifestBytes.byteLength <= 64 * 1024, "release trust manifest exceeds its size bound");
    const manifestText = manifestBytes.toString("utf8");
    assert(
      !/-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|\b(?:ghp|npm)_[A-Za-z0-9]{20,}\b/.test(
        manifestText,
      ),
      "release trust manifest contains secret-like material",
    );
    const manifest = JSON.parse(manifestText);
    const allowedManifestKeys = new Set([
      "schema_version",
      "canonical_origin",
      "receipt_issuer",
      "receipt_keys",
      "manifest_digest",
      "key_retention",
    ]);
    assert(
      Object.keys(manifest).length === allowedManifestKeys.size,
      "release trust manifest is missing a required field",
    );
    for (const key of Object.keys(manifest)) {
      assert(allowedManifestKeys.has(key), `release trust manifest contains unknown field ${key}`);
    }
    assert(
      manifest.schema_version === "myproof.par.release-trust-manifest.v1",
      "release trust manifest schema is not canonical",
    );
    assert(
      manifest.canonical_origin === "https://par.myproof.ai",
      "release trust manifest origin is not canonical",
    );
    assert(
      manifest.receipt_issuer === "did:web:par.myproof.ai",
      "release trust manifest issuer is not canonical",
    );
    assert(
      Array.isArray(manifest.receipt_keys) && manifest.receipt_keys.length <= 32,
      "release trust key ring is not bounded",
    );
    assert(
      manifest.receipt_keys.length > 0,
      "release trust manifest must contain a non-empty release key ring",
    );
    const expectedJwkKeys = new Set([
      "kty",
      "crv",
      "x",
      "y",
      "kid",
      "alg",
      "use",
      "key_ops",
      "ext",
    ]);
    for (const key of manifest.receipt_keys) {
      assert(
        key && typeof key === "object" && !Array.isArray(key),
        "release trust key is malformed",
      );
      assert(
        Object.keys(key).length === expectedJwkKeys.size &&
          Object.keys(key).every((field) => expectedJwkKeys.has(field)),
        "release trust key has an unexpected field",
      );
      assert(
        key.kty === "EC" &&
          key.crv === "P-256" &&
          typeof key.x === "string" &&
          typeof key.y === "string" &&
          typeof key.kid === "string" &&
          key.kid.length > 0 &&
          key.kid.length <= 256 &&
          key.alg === "ES256" &&
          key.use === "sig" &&
          Array.isArray(key.key_ops) &&
          key.key_ops.length === 1 &&
          key.key_ops[0] === "verify" &&
          key.ext === true,
        "release trust key is not the canonical public ES256 shape",
      );
    }
    assert(
      typeof manifest.manifest_digest === "string" &&
        /^[a-f0-9]{64}$/.test(manifest.manifest_digest),
      "release trust manifest digest must be a lower-case SHA-256 hex digest",
    );
    assert(
      manifest.key_retention &&
        typeof manifest.key_retention === "object" &&
        Object.keys(manifest.key_retention).length === 3 &&
        Number.isSafeInteger(manifest.key_retention.receipt_validity_horizon_seconds) &&
        manifest.key_retention.receipt_validity_horizon_seconds > 0 &&
        Number.isSafeInteger(manifest.key_retention.rollback_horizon_seconds) &&
        manifest.key_retention.rollback_horizon_seconds > 0 &&
        typeof manifest.key_retention.historical_keys_required === "boolean",
      "release trust key-retention metadata is malformed",
    );
    const unsignedManifest = { ...manifest };
    delete unsignedManifest.manifest_digest;
    const computedManifestDigest = hashBytes(
      Buffer.from(canonicalizeJson(unsignedManifest), "utf8"),
    );
    assert(
      computedManifestDigest === manifest.manifest_digest,
      "release trust manifest digest does not match canonical content",
    );
    const trustConfig = await import(
      pathToFileURL(join(installedPackageDir, "dist", "config", "trust.js")).href
    );
    assert(
      typeof trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN === "string" &&
        /^[a-f0-9]{64}$/.test(trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN),
      "compiled release trust digest pin is missing or malformed",
    );
    assert(
      trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN === manifest.manifest_digest,
      "compiled release trust digest pin does not match the package manifest",
    );
    assert(
      typeof trustConfig.loadPackageTrustMaterial === "function",
      "package trust loader is missing",
    );
    const loadedTrust = trustConfig.loadPackageTrustMaterial();
    assert(
      loadedTrust &&
        typeof loadedTrust === "object" &&
        loadedTrust.expected_manifest_digest === manifest.manifest_digest &&
        loadedTrust.expected_manifest_digest === trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN &&
        loadedTrust.manifest &&
        typeof loadedTrust.manifest === "object" &&
        loadedTrust.manifest.authenticated === true &&
        loadedTrust.manifest.manifest_digest === trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN &&
        Array.isArray(loadedTrust.manifest.receipt_keys) &&
        loadedTrust.manifest.receipt_keys.length > 0,
      "installed trust loader did not authenticate the pinned manifest",
    );
    evidence.trustManifest = {
      path: "configs/release-trust-manifest.json",
      bytes: manifestBytes.byteLength,
      sha256: hashBytes(manifestBytes),
      digestState: "pinned",
      keyCount: manifest.receipt_keys.length,
      manifestDigest: manifest.manifest_digest,
      compiledDigestPin: trustConfig.RELEASE_TRUST_MANIFEST_DIGEST_PIN,
      loaderAuthenticated: true,
    };
    await import(pathToFileURL(join(installedPackageDir, "dist", "cli", "dependencies.js")).href);

    const binName = process.platform === "win32" ? "myproof-par.cmd" : "myproof-par";
    const executable = join(consumerDir, "node_modules", ".bin", binName);
    const executableStat = await stat(executable);
    assert(executableStat.isFile(), "consumer bin shim is missing");
    const help = await run(executable, ["--help"], { cwd: consumerDir });
    assert(
      help.stdout.includes("myproof-par verify <asset-id>"),
      "consumer CLI help is incomplete",
    );
    assert(help.stderr.trim() === "", "consumer CLI wrote diagnostics for --help");
    const mcp = await runInstalledMcpSmoke(
      executable,
      consumerDir,
      installedPackageDir,
      evidence.tarball.sha256,
    );
    evidence.consumer = {
      packageDir: relative(consumerDir, installedPackageDir),
      executable: relative(consumerDir, executable),
      publicImport: true,
      trustLoaderImport: true,
      helpExitCode: 0,
      stdoutBytes: Buffer.byteLength(help.stdout),
      stderrBytes: Buffer.byteLength(help.stderr),
      mcp,
    };

    evidence.ok = true;
    process.stdout.write(
      `${JSON.stringify({
        check: evidence.check,
        ok: true,
        package: evidence.package,
        tarballSha256: evidence.tarball.sha256,
        tarballBytes: evidence.tarball.bytes,
        fileCount: evidence.files.length,
        trustManifest: evidence.trustManifest,
        publicImport: evidence.consumer.publicImport,
        consumerHelp: true,
        mcp: evidence.consumer.mcp,
      })}\n`,
    );
  } catch (error) {
    evidence.error = safeFailure(error);
    throw error;
  } finally {
    await mkdir(evidenceDir, { recursive: true });
    await writeFile(
      join(evidenceDir, "package-smoke.json"),
      `${JSON.stringify(evidence, null, 2)}\n`,
      "utf8",
    );
    await rm(consumerDir, { recursive: true, force: true });
    await rm(packDir, { recursive: true, force: true });
    if (localNpmCache !== undefined) await rm(localNpmCache, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${safeFailure(error)}\n`);
  process.exitCode = 1;
});
