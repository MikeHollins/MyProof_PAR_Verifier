#!/usr/bin/env node

/**
 * Produce the dependency, license, secret-scan, audit, and SBOM evidence used
 * by CI.  The checks are intentionally local and deterministic except for the
 * package-manager audit service; an unavailable audit is a failed gate, never
 * silently advisory.  No credentialed registry configuration is accepted.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(process.cwd());
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);
let localNpmCache;

const ignoredDirectories = new Set([".git", "node_modules", "dist", "coverage"]);
const secretPatterns = [
  { name: "private-key", pattern: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/ },
  { name: "github-token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/ },
  { name: "npm-token", pattern: /\bnpm_[A-Za-z0-9]{20,}\b/ },
  { name: "aws-access-key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  {
    name: "credential-assignment",
    pattern:
      /\b(?:AWS_SECRET_ACCESS_KEY|VERCEL_TOKEN|NPM_TOKEN|GITHUB_TOKEN)\s*[:=]\s*["']?[A-Za-z0-9/+_=-]{16,}/,
  },
];

class CommandFailure extends Error {
  constructor(command, code, stdout = "", stderr = "") {
    super(`${command} failed (${String(code ?? "unknown")})`);
    this.name = "CommandFailure";
    this.command = command;
    this.code = code;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

async function run(command, args, options = {}) {
  try {
    return await execFileAsync(command, args, {
      cwd: packageRoot,
      env: {
        ...process.env,
        ...(localNpmCache === undefined ? {} : { npm_config_cache: localNpmCache }),
        npm_config_fund: "false",
        npm_config_update_notifier: "false",
      },
      maxBuffer: 20 * 1024 * 1024,
      timeout: 120_000,
      ...options,
    });
  } catch (error) {
    const code = error && typeof error === "object" ? error.code : null;
    const stdout = error && typeof error === "object" ? error.stdout : "";
    const stderr = error && typeof error === "object" ? error.stderr : "";
    throw new CommandFailure(
      [command, ...args].join(" "),
      code,
      typeof stdout === "string" ? stdout : "",
      typeof stderr === "string" ? stderr : "",
    );
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function packageLicense(value) {
  if (typeof value === "string" && value.trim() !== "") return value;
  if (Array.isArray(value) && value.length > 0) {
    const values = value
      .map((entry) => {
        if (typeof entry === "string") return entry;
        if (
          entry &&
          typeof entry === "object" &&
          "type" in entry &&
          typeof entry.type === "string"
        ) {
          return entry.type;
        }
        return null;
      })
      .filter((entry) => entry !== null);
    if (values.length > 0) return values.join(" OR ");
  }
  return null;
}

async function collectSourceFiles(directory, result = []) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await collectSourceFiles(path, result);
      continue;
    }
    if (!entry.isFile()) continue;
    result.push(path);
  }
  return result;
}

async function scanSecrets() {
  const files = await collectSourceFiles(packageRoot);
  const findings = [];
  for (const path of files) {
    const fileStat = await stat(path);
    if (fileStat.size > 4 * 1024 * 1024) continue;
    const text = await readFile(path, "utf8");
    for (const candidate of secretPatterns) {
      const match = candidate.pattern.exec(text);
      if (match) {
        findings.push({
          rule: candidate.name,
          file: relative(packageRoot, path),
          line: text.slice(0, match.index).split("\n").length,
        });
      }
    }
  }
  return { filesScanned: files.length, findings };
}

async function writeJson(name, value) {
  await writeFile(join(evidenceDir, name), `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function safeFailure(error) {
  if (error instanceof CommandFailure) return error.message;
  if (error instanceof Error) return error.message.slice(0, 240);
  return "security evidence failed";
}

async function main() {
  if (process.env.CI !== "true") {
    // Avoid mutating or relying on a user cache that may be owned by another
    // package-manager invocation when this gate is run locally.
    localNpmCache = await mkdtemp(join(tmpdir(), "myproof-par-npm-cache-"));
  }
  await mkdir(evidenceDir, { recursive: true });
  const packageJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(join(packageRoot, "package-lock.json"), "utf8"));
  const lockRoot = lock.packages?.[""];
  assert(lock.lockfileVersion === 3, "package-lock.json must use lockfileVersion 3");
  assert(lockRoot && typeof lockRoot === "object", "package-lock.json root metadata is missing");
  assert(lockRoot.name === packageJson.name, "package-lock name does not match package.json");
  assert(
    lockRoot.version === packageJson.version,
    "package-lock version does not match package.json",
  );

  const declaredDependencies = {
    ...(packageJson.dependencies ?? {}),
    ...(packageJson.devDependencies ?? {}),
  };
  for (const [name, version] of Object.entries(declaredDependencies)) {
    const lockVersion = lockRoot.dependencies?.[name] ?? lockRoot.devDependencies?.[name];
    assert(lockVersion === version, `lockfile root does not pin ${name} to ${version}`);
  }

  const packageEntries = Object.entries(lock.packages).filter(([path]) =>
    path.startsWith("node_modules/"),
  );
  const licenses = [];
  const missingLicense = [];
  const missingIntegrity = [];
  const missingResolved = [];
  const nonRegistrySources = [];
  for (const [path, metadata] of packageEntries) {
    const license = packageLicense(metadata.license ?? metadata.licenses);
    if (license === null) missingLicense.push(path);
    if (typeof metadata.integrity !== "string" || metadata.integrity.length === 0) {
      missingIntegrity.push(path);
    }
    if (typeof metadata.resolved !== "string" || metadata.resolved.length === 0) {
      missingResolved.push(path);
    } else if (!metadata.resolved.startsWith("https://registry.npmjs.org/")) {
      nonRegistrySources.push({ path, resolved: metadata.resolved });
    }
    licenses.push({
      path,
      name: path.slice("node_modules/".length),
      version: metadata.version ?? null,
      license,
      dev: metadata.dev === true,
      optional: metadata.optional === true,
    });
  }
  const dependencyEvidence = {
    package: { name: packageJson.name, version: packageJson.version },
    lockfileVersion: lock.lockfileVersion,
    directDependencyCount: Object.keys(declaredDependencies).length,
    transitivePackageCount: packageEntries.length,
    allDirectSpecsPinned: true,
    allPackageIntegritiesPresent: missingIntegrity.length === 0,
    allResolvedSourcesPresent: missingResolved.length === 0,
    allResolvedFromNpmRegistry: nonRegistrySources.length === 0,
    missingIntegrity,
    missingResolved,
    nonRegistrySources,
  };
  const licenseEvidence = {
    package: { name: packageJson.name, version: packageJson.version },
    packageCount: licenses.length,
    missingLicense,
    licenses,
  };
  await writeJson("dependency-evidence.json", dependencyEvidence);
  await writeJson("license-evidence.json", licenseEvidence);
  assert(missingIntegrity.length === 0, "one or more lockfile packages lack integrity metadata");
  assert(
    missingResolved.length === 0,
    "one or more lockfile packages lack resolved source metadata",
  );
  assert(nonRegistrySources.length === 0, "lockfile contains a non-registry dependency source");
  assert(missingLicense.length === 0, "one or more lockfile packages lack license metadata");

  const secretEvidence = await scanSecrets();
  await writeJson("secret-scan.json", secretEvidence);
  assert(
    secretEvidence.findings.length === 0,
    "secret scan found high-confidence credential material",
  );

  let auditResult;
  try {
    const audit = await run(npmCommand, [
      "audit",
      "--json",
      "--omit=optional",
      "--audit-level=high",
    ]);
    const report = JSON.parse(audit.stdout);
    auditResult = {
      ok: true,
      exitCode: 0,
      vulnerabilities: report.metadata?.vulnerabilities ?? null,
      dependencyCount: report.metadata?.dependencies ?? null,
    };
  } catch (error) {
    auditResult = {
      ok: false,
      exitCode: error instanceof CommandFailure ? error.code : 1,
      error: safeFailure(error),
    };
    if (error instanceof CommandFailure && error.stdout.trim() !== "") {
      try {
        const report = JSON.parse(error.stdout);
        auditResult.vulnerabilities = report.metadata?.vulnerabilities ?? null;
        auditResult.dependencyCount = report.metadata?.dependencies ?? null;
      } catch {
        // Network/service failures are represented by the stable command code.
      }
    }
    await writeJson("npm-audit.json", auditResult);
    throw error;
  }
  await writeJson("npm-audit.json", auditResult);

  const sbom = await run(npmCommand, ["sbom", "--sbom-format=cyclonedx", "--omit=optional"]);
  const sbomDocument = JSON.parse(sbom.stdout);
  assert(sbomDocument.bomFormat === "CycloneDX", "npm sbom did not produce a CycloneDX document");
  await writeJson("sbom.cdx.json", sbomDocument);

  const summary = {
    check: "security-evidence",
    ok: true,
    node: process.version,
    npm: (await run(npmCommand, ["--version"])).stdout.trim(),
    generatedAt: new Date().toISOString(),
    dependency: {
      packageCount: packageEntries.length,
      directDependencyCount: Object.keys(declaredDependencies).length,
    },
    licenses: { packageCount: licenses.length },
    secrets: { filesScanned: secretEvidence.filesScanned, findings: 0 },
    audit: { ok: true },
    sbom: { format: sbomDocument.bomFormat, specVersion: sbomDocument.specVersion },
    lockfileSha256: createHash("sha256")
      .update(await readFile(join(packageRoot, "package-lock.json")))
      .digest("hex"),
  };
  await writeJson("security-summary.json", summary);
  process.stdout.write(`${JSON.stringify(summary)}\n`);
  if (localNpmCache !== undefined) await rm(localNpmCache, { recursive: true, force: true });
}

main().catch(async (error) => {
  try {
    await writeJson("security-summary.json", {
      check: "security-evidence",
      ok: false,
      error: safeFailure(error),
    });
  } catch {
    // Preserve the original failure when the evidence directory itself is unavailable.
  }
  process.stderr.write(`${safeFailure(error)}\n`);
  if (localNpmCache !== undefined) {
    await rm(localNpmCache, { recursive: true, force: true }).catch(() => undefined);
  }
  process.exitCode = 1;
});
