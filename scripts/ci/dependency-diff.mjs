#!/usr/bin/env node

/**
 * Equivalent PR dependency-review gate for repositories where the hosted
 * dependency-review provider is not part of the available enforcement plan.
 *
 * On pull requests this compares the immutable base and head lockfiles, then
 * validates the complete head lock metadata for exact direct specs, registry
 * provenance, integrity, and license presence. It deliberately does not claim
 * vulnerability-database coverage; npm audit remains the separate blocking
 * vulnerability gate in security-evidence.mjs.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(process.cwd());
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);
const registryPrefix = "https://registry.npmjs.org/";
const enforcedClassification =
  "enforced for pull_request; base-vs-head lock metadata/integrity/license diff gate; vulnerability database review remains npm-audit-owned";
const notEvaluatedClassification =
  "not evaluated; no pull_request base SHA is available on this event; npm-audit and full lock metadata gates still run";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function commitSha(value, label) {
  assert(
    typeof value === "string" && /^[a-f0-9]{40}$/i.test(value),
    `${label} is not a commit SHA`,
  );
  return value.toLowerCase();
}

function packageLicense(value) {
  if (typeof value === "string" && value.trim() !== "") return value;
  if (Array.isArray(value) && value.length > 0) {
    const values = value
      .map((entry) => {
        if (typeof entry === "string") return entry;
        if (entry && typeof entry === "object" && typeof entry.type === "string") {
          return entry.type;
        }
        return null;
      })
      .filter((entry) => entry !== null);
    if (values.length > 0) return values.join(" OR ");
  }
  return null;
}

async function runGit(args) {
  try {
    const result = await execFileAsync("git", ["-C", packageRoot, ...args], {
      cwd: packageRoot,
      env: { ...process.env },
      maxBuffer: 8 * 1024 * 1024,
      timeout: 30_000,
    });
    return result.stdout;
  } catch (error) {
    const code = error && typeof error === "object" ? error.code : null;
    throw new Error(`git ${args.join(" ")} failed (${String(code ?? "unknown")})`, {
      cause: error,
    });
  }
}

function parseLock(bytes, label) {
  let lock;
  try {
    lock = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  assert(lock && typeof lock === "object" && !Array.isArray(lock), `${label} is malformed`);
  assert(lock.lockfileVersion === 3, `${label} must use lockfileVersion 3`);
  assert(lock.packages && typeof lock.packages === "object", `${label} packages are missing`);
  return lock;
}

function validateLock(lock, packageJson, label) {
  const root = lock.packages[""];
  assert(root && typeof root === "object", `${label} root metadata is missing`);
  assert(root.name === packageJson.name, `${label} name differs from package.json`);
  assert(root.version === packageJson.version, `${label} version differs from package.json`);
  const declared = {
    ...(packageJson.dependencies ?? {}),
    ...(packageJson.devDependencies ?? {}),
  };
  for (const [name, spec] of Object.entries(declared)) {
    assert(
      typeof spec === "string" && spec.length > 0 && !/[~^*<>=|\s]/.test(spec),
      `${label} direct dependency ${name} is not exact-pinned`,
    );
    const locked = root.dependencies?.[name] ?? root.devDependencies?.[name];
    assert(locked === spec, `${label} direct dependency ${name} differs from package.json`);
  }

  const missingIntegrity = [];
  const missingResolved = [];
  const nonRegistrySources = [];
  const missingLicense = [];
  for (const [path, metadata] of Object.entries(lock.packages)) {
    if (!path.startsWith("node_modules/")) continue;
    if (!metadata || typeof metadata !== "object") {
      missingIntegrity.push(path);
      missingResolved.push(path);
      missingLicense.push(path);
      continue;
    }
    if (typeof metadata.integrity !== "string" || metadata.integrity.length === 0) {
      missingIntegrity.push(path);
    }
    if (typeof metadata.resolved !== "string" || metadata.resolved.length === 0) {
      missingResolved.push(path);
    } else if (!metadata.resolved.startsWith(registryPrefix)) {
      nonRegistrySources.push(path);
    }
    if (packageLicense(metadata.license ?? metadata.licenses) === null) {
      missingLicense.push(path);
    }
  }
  assert(missingIntegrity.length === 0, `${label} packages are missing integrity metadata`);
  assert(missingResolved.length === 0, `${label} packages are missing resolved metadata`);
  assert(nonRegistrySources.length === 0, `${label} contains non-registry dependency sources`);
  assert(missingLicense.length === 0, `${label} packages are missing license metadata`);
  return {
    packageCount: Object.keys(lock.packages).filter((path) => path.startsWith("node_modules/"))
      .length,
    directDependencyCount: Object.keys(declared).length,
  };
}

function packageChanges(baseLock, headLock) {
  const paths = new Set([...Object.keys(baseLock.packages), ...Object.keys(headLock.packages)]);
  const changed = [];
  for (const path of paths) {
    const before = JSON.stringify(baseLock.packages[path] ?? null);
    const after = JSON.stringify(headLock.packages[path] ?? null);
    if (before !== after && path.startsWith("node_modules/")) changed.push(path);
  }
  return changed.sort();
}

async function writeEvidence(value) {
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(
    join(evidenceDir, "dependency-review.json"),
    `${JSON.stringify(value, null, 2)}\n`,
    "utf8",
  );
}

function safeFailure(error) {
  return error instanceof Error ? error.message.slice(0, 240) : "dependency review failed";
}

async function main() {
  const event = process.env.GITHUB_EVENT_NAME?.trim() ?? "local";
  const base = process.env.GITHUB_BASE_SHA?.trim();
  const head = process.env.GITHUB_SHA?.trim();
  const packageBytes = await readFile(join(packageRoot, "package.json"));
  const lockBytes = await readFile(join(packageRoot, "package-lock.json"));
  const packageJson = JSON.parse(packageBytes.toString("utf8"));
  const headLock = parseLock(lockBytes, "head package-lock.json");
  const headSummary = validateLock(headLock, packageJson, "head lockfile");

  if (event !== "pull_request" && !base) {
    const evidence = {
      schema: "myproof.par.ci-dependency-review.v1",
      check: "dependency-review",
      ok: true,
      classification: notEvaluatedClassification,
      event,
      headCommit: head && /^[a-f0-9]{40}$/i.test(head) ? head.toLowerCase() : null,
      baseCommit: null,
      changedFiles: [],
      changedPackages: [],
      head: { ...headSummary, lockfileSha256: sha256(lockBytes) },
    };
    await writeEvidence(evidence);
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
    return;
  }

  assert(base, "pull_request dependency review requires GITHUB_BASE_SHA");
  const baseCommit = commitSha(base, "GITHUB_BASE_SHA");
  const headCommit = commitSha(head ?? (await runGit(["rev-parse", "HEAD"])).trim(), "GITHUB_SHA");
  const basePackageBytes = Buffer.from(
    await runGit(["show", `${baseCommit}:package.json`]),
    "utf8",
  );
  const baseLockBytes = Buffer.from(
    await runGit(["show", `${baseCommit}:package-lock.json`]),
    "utf8",
  );
  const basePackageJson = JSON.parse(basePackageBytes.toString("utf8"));
  const baseLock = parseLock(baseLockBytes, "base package-lock.json");
  const baseSummary = validateLock(baseLock, basePackageJson, "base lockfile");
  const changedFiles = (
    await runGit([
      "diff",
      "--name-only",
      baseCommit,
      headCommit,
      "--",
      "package.json",
      "package-lock.json",
    ])
  )
    .split(/\r?\n/)
    .filter(Boolean);
  const changedPackages = packageChanges(baseLock, headLock);
  const evidence = {
    schema: "myproof.par.ci-dependency-review.v1",
    check: "dependency-review",
    ok: true,
    classification: enforcedClassification,
    event,
    baseCommit,
    headCommit,
    changedFiles,
    changedPackages,
    base: { ...baseSummary, lockfileSha256: sha256(baseLockBytes) },
    head: { ...headSummary, lockfileSha256: sha256(lockBytes) },
  };
  await writeEvidence(evidence);
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
}

main().catch(async (error) => {
  const evidence = {
    schema: "myproof.par.ci-dependency-review.v1",
    check: "dependency-review",
    ok: false,
    classification:
      process.env.GITHUB_EVENT_NAME?.trim() === "pull_request"
        ? "enforced for pull_request; base-vs-head lock metadata/integrity/license diff gate"
        : notEvaluatedClassification,
    error: safeFailure(error),
  };
  await writeEvidence(evidence).catch(() => undefined);
  process.stderr.write(`${safeFailure(error)}\n`);
  process.exitCode = 1;
});
